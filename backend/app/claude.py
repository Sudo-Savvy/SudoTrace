"""
Claude AI integration for SudoTrace v0.6.
All analyst-facing calls use claude-sonnet-4-6.  No exceptions.
"""

import asyncio
import json
import logging
import os
import re
import sqlite3
import time

import anthropic

log = logging.getLogger(__name__)

SONNET = "claude-sonnet-4-6"
HAIKU  = "claude-haiku-4-5-20251001"

# Active model for analyst-facing analysis.
# Haiku is the project default (cost-driven decision — see CLAUDE.md). The
# CLAUDE_ANALYSIS_MODEL env var can override to Sonnet (or any other model)
# without a code change.
ANALYSIS_MODEL = os.getenv("CLAUDE_ANALYSIS_MODEL", HAIKU)

# Pricing per million tokens — update here without code changes if rates change
PRICING = {
    "claude-sonnet-4-6": {
        "input":      3.00,
        "output":     15.00,
        "cache_read": 0.30,
    },
    "claude-haiku-4-5-20251001": {
        "input":      0.80,
        "output":     4.00,
        "cache_read": 0.08,
    },
}

SYSTEM_PROMPT = """\
You are a senior Windows blue team analyst working in SudoTrace, an AI-powered SOC \
investigation workbench. You are analysing Microsoft Defender for Endpoint telemetry \
to produce actionable findings for a human analyst.

CRITICAL ANALYSIS INSTRUCTIONS:
- Work BACKWARDS from the focal process to identify the true root cause and delivery vector
- NEVER assume the focal PID is the beginning of the attack — it may be mid-chain or a victim process
- Identify whether any processes in the tree are still running — this shapes urgency for the entire response
- Look for precursor attacker activity that may predate the focal PID by hours or even days
- Every finding MUST reference specific PIDs, timestamps, command lines, or event records from the provided data
- Apply Windows process behaviour knowledge — flag abnormal parent-child relationships
- Absence of network events does NOT confirm no network activity occurred
- Determine delivery vector with a confidence level

VIRUSTOTAL CRITICAL INSTRUCTION — NON-NEGOTIABLE IN ALL CIRCUMSTANCES:
A clean or low VirusTotal detection rate does NOT confirm that something is benign.
Zero detections may indicate a novel threat, a custom attacker tool, or a recently compiled payload.
NEVER state or imply that something is safe, clean, or benign based on VT detection count alone.
A zero detection result on a suspicious file should INCREASE your suspicion, not decrease it.
If you mention VT results, always format as "X/Y engines detected" — never "clean" or "safe".

All timestamps provided are UTC. You are analysing Windows endpoints only.

ANALYST FLAG AUTHORITY — INPUT, NOT GROUND TRUTH:
The "ANALYST-FLAGGED PROCESSES" section lists processes the analyst has tagged
during triage. These flags are the analyst's working judgment — useful signal,
but NOT a substitute for evidence-based analysis. The analyst can be wrong
either way, so weigh each flag against the telemetry rather than rubber-stamping
it.

- SUSPICIOUS flag → this means "I want a closer look at this", NOT
  "I believe this is malicious". It is a request for investigation, not a
  verdict. Treat the process as unknown until the telemetry tells you
  otherwise. Any verdict (malicious / suspicious / benign / unknown) is fine
  based on evidence. The flag alone is NEVER evidence of malicious activity.

- MALICIOUS flag → this is the analyst's hypothesis that the process is bad.
  Take it seriously as a lead, but do NOT confirm "malicious" purely on the
  analyst's word. Verify with telemetry: malicious behaviour patterns,
  IOC hits, suspicious command lines, abnormal parent-child, unsigned
  binaries from untrusted paths, network to known-bad infrastructure, etc.
  If the telemetry supports the call, verdict is "malicious". If the
  telemetry is mixed or thin, "suspicious" is appropriate. If the telemetry
  clearly contradicts the analyst (e.g. signed Microsoft binary, expected
  parent, benign behaviour), you MAY downgrade to "benign" or "unknown" —
  state the contradicting evidence in the evidence array.

- BENIGN flag → this is the analyst's judgment that the process is not a
  threat. Take it into consideration, but the analyst can still miss things.
  Default verdict is "benign". If the telemetry shows behaviour that is
  clearly inconsistent with a benign process (LSASS access, credential
  dumping signatures, C2-style network patterns, ransomware indicators),
  you MAY raise the verdict to "suspicious" or "malicious" — but only with
  concrete evidence cited in the evidence array. Do not raise the verdict
  on weak signals (a single uncommon connection, a generic LOLBin name).

Rule of thumb: the flag tells you what the analyst is thinking; the telemetry
tells you what actually happened. When they disagree, the telemetry wins, and
your evidence array must explain the disagreement plainly so the analyst can
learn from it.

CALIBRATING SEVERITY AND URGENCY — EVIDENCE-DRIVEN, NOT FLAG-DRIVEN:
severity, confidence, urgency.level, and urgency.reason must reflect the actual
evidence in the telemetry, NOT how the analyst flagged a process.
- If every per_process_findings verdict comes back "benign" or "unknown", the
  overall severity MUST be CLEAN or LOW, and urgency MUST be "none" or
  "monitor".
- "immediate" or "within_hour" urgency requires CONCRETE evidence of active
  malicious activity, established persistence, credential theft in-flight,
  C2 communication, or destructive action — NOT merely that the analyst
  flagged something as suspicious.
- Do not recommend host isolation, immediate containment, or any "act now"
  language unless the per_process_findings contain at least one "malicious"
  verdict backed by concrete evidence.

Respond ONLY with a valid JSON object matching the schema below.
- Your ENTIRE response must be exactly one JSON object, starting with `{` and ending with `}`. Nothing before, nothing after.
- Do NOT wrap the JSON in ```json fences or any markdown fences.
- Do NOT add a Markdown post-script after the JSON (no "---", no "**INCIDENT CORRELATION ANALYSIS:**", no commentary, no summary). All your incident / event analysis must live INSIDE the JSON — in the `narrative` field or the `per_process_findings[].evidence` arrays.
- NO trailing commas after the last element of any array or object — strict JSON only.
- All property names and string values must use double quotes.
- Escape any double quotes that appear inside string values.

REQUIRED JSON SCHEMA:
{
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN",
  "confidence": <integer 0-100>,
  "narrative": "<attack narrative — what happened and what the attacker did, plain English>",
  "delivery_vector": {
    "type": "Email attachment" | "Email link" | "Drive-by" | "Teams/SharePoint" | "Lateral movement" | "Supply chain" | "Unknown",
    "confidence": "high" | "medium" | "low" | "unknown",
    "evidence": "<specific evidence supporting this vector, or why it is unknown>"
  },
  "root_cause": "<the true origin — specific process, file, or event that started the attack chain>",
  "urgency": {
    "level": "immediate" | "within_hour" | "monitor" | "none",
    "reason": "<why this urgency level — reference specific active processes or confirmed persistence>",
    "active_pids": [<PIDs that appear to still be running>]
  },
  "per_process_findings": [
    {
      "pid": <integer>,
      "name": "<process name>",
      "verdict": "malicious" | "suspicious" | "benign" | "unknown",
      "summary": "<one sentence role in the attack>",
      "evidence": ["<specific evidence item referencing PID/timestamp/cmdline/event>"]
    }
  ],
  "ioc_suggestions": [
    {
      "type": "ip" | "domain" | "hash" | "file_path" | "registry_key",
      "value": "<exact IOC value>",
      "context": "<where seen and why it is an IOC>",
      "confidence": "high" | "medium" | "low"
    }
  ]
}

Include ALL analyst-flagged processes in per_process_findings.
Extract only IOCs that appear in the telemetry — real IPs, domains, hashes, paths, or registry keys.

CONCISION RULES (mandatory to stay within output budget):
- "summary": one sentence, under 200 characters
- "evidence": 2-4 items max per process, each under 200 characters
- "narrative": 3-5 sentences total, focused on the attack chain — not a per-process recap
- Do NOT repeat the same MITRE technique across many findings; mention each once
- Group identical activity (e.g. 20 whoami invocations) into a single finding, not one per PID
"""


def _format_tree(
    nodes: dict,
    ancestry_chain: list,
    flagged: dict,
    in_scope_keys: set | None = None,
) -> str:
    """Render the process tree as indented text.

    in_scope_keys: if provided, only nodes in this set get their cmdline and
    sha1 rendered. Other nodes are shown with PID/name/timestamp only — they
    are lineage context, not analysis targets. Prevents the model from
    fabricating "events" by reading cmdlines of non-flagged ancestors.
    """
    lines: list[str] = []
    visited: set[str] = set()

    def render(key: str, depth: int) -> None:
        if key in visited:
            return
        visited.add(key)
        node = nodes.get(key)
        if not node:
            return
        indent = "  " * depth
        tags = ""
        if flagged.get(key):
            tags += f" [{flagged[key].upper()}]"
        if node.get("is_focal"):
            tags += " [FOCAL]"
        if node.get("is_lolbin"):
            tags += " [LOLBIN]"
        ts = (node.get("timestamp") or "")[:19].replace("T", " ")
        in_scope = in_scope_keys is None or key in in_scope_keys
        if not in_scope:
            tags += " [CONTEXT-ONLY]"
        lines.append(f"{indent}PID {node.get('pid','?')} {node.get('name','?')}{tags} | {node.get('user','?')} | {ts}")
        if in_scope:
            if node.get("cmdline"):
                lines.append(f"{indent}  cmd: {str(node['cmdline'])[:300]}")
            if node.get("sha1"):
                lines.append(f"{indent}  sha1: {node['sha1']}")
        for ck in node.get("child_node_keys", []):
            render(ck, depth + 1)

    if ancestry_chain:
        render(ancestry_chain[0], 0)
    for key in nodes:
        if key not in visited:
            render(key, 0)

    return "\n".join(lines) or "(no process tree)"


def _fmt_rows(rows: list[dict], kind: str, limit: int = 150) -> str:
    if not rows:
        return f"(no {kind} events in time window)"
    out: list[str] = []
    for row in rows[:limit]:
        ts = str(row.get("Timestamp", ""))[:19].replace("T", " ")
        if kind == "network":
            out.append(
                f"{ts} PID {row.get('InitiatingProcessId','')} "
                f"{row.get('InitiatingProcessFileName','?')} → "
                f"{row.get('RemoteIP','')}:{row.get('RemotePort','')} "
                f"({row.get('Protocol','')} {row.get('Direction','')})"
                + (f" url:{row.get('RemoteUrl','')}" if row.get("RemoteUrl") else "")
            )
        elif kind == "file":
            out.append(
                f"{ts} PID {row.get('InitiatingProcessId','')} "
                f"{row.get('InitiatingProcessFileName','?')} "
                f"{row.get('ActionType','')} {row.get('FolderPath','')}"
                + (f" sha1:{row.get('SHA1','')}" if row.get("SHA1") else "")
            )
        elif kind == "registry":
            out.append(
                f"{ts} PID {row.get('InitiatingProcessId','')} "
                f"{row.get('InitiatingProcessFileName','?')} "
                f"{row.get('ActionType','')} {row.get('RegistryKey','')}"
                + (f"\\{row.get('RegistryValueName','')}" if row.get("RegistryValueName") else "")
            )
        elif kind == "logon":
            out.append(
                f"{ts} {row.get('ActionType','')} user:{row.get('AccountName','')} "
                f"type:{row.get('LogonType','')} from:{row.get('RemoteIP','local')}"
            )
    if len(rows) > limit:
        out.append(f"... [{len(rows) - limit} more rows truncated]")
    return "\n".join(out)


def build_prompt(
    hostname: str,
    focal_pid: int,
    focal_node: dict | None,
    device_info: dict | None,
    nodes: dict,
    ancestry_chain: list,
    flagged_nodes: list,
    net_rows: list,
    file_rows: list,
    reg_rows: list,
    logon_rows: list,
    scope: str = "focused",
    flagged_events: list | None = None,
    flagged_incidents: list | None = None,
    flagged_iocs: list | None = None,
    anchor_keys: set | None = None,
) -> str:
    di = device_info or {}
    # flagged_nodes is an unvalidated client list — tolerate entries that
    # are missing node_key/flag rather than raising KeyError mid-prompt.
    flagged_map = {
        f["node_key"]: f.get("flag", "?")
        for f in flagged_nodes
        if isinstance(f, dict) and f.get("node_key")
    }

    device_block = (
        f"=== DEVICE CONTEXT ===\n"
        f"Hostname: {hostname}\n"
        f"OS: {di.get('os_platform','Unknown')} {di.get('os_version','')} {di.get('os_build','')}\n"
        f"Sensor health: {di.get('sensor_health','Unknown')}\n"
        f"AV status: {di.get('av_status','Unknown')}\n"
        f"Last seen: {di.get('last_seen','Unknown')}"
    )

    focal_block = ""
    if focal_node:
        ts = (focal_node.get("timestamp") or "")[:19].replace("T", " ")
        focal_block = (
            f"\n=== FOCAL PROCESS ===\n"
            f"PID: {focal_node.get('pid','?')}  Name: {focal_node.get('name','?')}\n"
            f"Cmdline: {focal_node.get('cmdline','—')}\n"
            f"User: {focal_node.get('user','?')}  Timestamp: {ts} UTC\n"
            f"SHA1: {focal_node.get('sha1','—')}  LOLBin: {focal_node.get('is_lolbin',False)}"
        )

    flagged_block = ""
    if flagged_nodes:
        lines = []
        for f in flagged_nodes:
            if not isinstance(f, dict) or not f.get("node_key"):
                continue
            n = nodes.get(f["node_key"], {})
            ts = (n.get("timestamp") or "?")[:19].replace("T", " ")
            flag = str(f.get("flag", "?")).upper()
            cmdline = str(n.get("cmdline", "—"))[:200]
            lines.append(
                f"  {flag} — PID {n.get('pid','?')} {n.get('name','?')} "
                f"@ {ts}: {cmdline}"
            )
        flagged_block = (
            "\n=== ANALYST-FLAGGED PROCESSES ===\n"
            "The analyst pre-flagged these before requesting analysis. The "
            "timestamp after @ is the process creation time, which uniquely "
            "identifies this process instance.\n"
            "PID REUSE WARNING: Windows recycles PIDs. If a telemetry row "
            "shows the flagged PID but a DIFFERENT InitiatingProcessFileName, "
            "that row is from a different process instance and must NOT be "
            "attributed to the flagged process. Match on filename, not just "
            "PID. When writing per_process_findings, use the flagged "
            "process's name as listed below — do not substitute another "
            "filename you see in the telemetry.\n"
            + "\n".join(lines)
        )

    # In focused mode, restrict full process details (cmdline, sha1) to the
    # anchor set (flagged processes + flagged events' parents + focal). Non-
    # anchor ancestors/children become bare lineage entries — the model can
    # see the structure but can't fabricate evidence by reading cmdlines of
    # out-of-scope processes. Fall back to the flagged set when no anchors
    # are provided (older callers).
    in_scope_keys: set | None = None
    if scope == "focused":
        if anchor_keys:
            in_scope_keys = set(anchor_keys)
        elif flagged_nodes:
            in_scope_keys = {f["node_key"] for f in flagged_nodes}

    tree_block = (
        "\n=== PROCESS TREE ===\n"
        "Format: PID name [FLAG] [FOCAL] [LOLBIN] [CONTEXT-ONLY] | user | timestamp\n"
        "        cmd: command line  (omitted for [CONTEXT-ONLY] nodes — lineage only)\n"
        "        sha1: SHA1         (omitted for [CONTEXT-ONLY] nodes — lineage only)\n"
        "[CONTEXT-ONLY] nodes appear so you can see process lineage; you must NOT\n"
        "analyse them, cite their command lines, or report on their activity.\n"
        + _format_tree(nodes, ancestry_chain, flagged_map, in_scope_keys)
    )

    # In-scope keys for the focused scope_block: anchors include flagged
    # processes + flagged events' parents + (focal if nothing else). Fall back
    # to flagged_nodes for older callers that didn't pass anchor_keys.
    if anchor_keys:
        scope_anchor_keys = list(anchor_keys)
    else:
        scope_anchor_keys = [f["node_key"] for f in flagged_nodes]
    n_in_scope = len(scope_anchor_keys)
    in_scope_pid_list = ", ".join(
        str(nodes.get(k, {}).get("pid", "?")) for k in scope_anchor_keys
    )
    if scope == "focused" and n_in_scope == 0:
        # Edge case: focused mode with no in-scope PIDs at all. This happens
        # when the analyst flagged an incident on a tree with no focal PID and
        # no flagged processes/events. Tell Claude to leave per_process_findings
        # empty and concentrate entirely on the flagged incidents — do NOT pick
        # processes from the tree on its own initiative.
        scope_block = (
            "\n=== ANALYSIS SCOPE: FOCUSED — INCIDENTS-ONLY MODE ===\n"
            "No in-scope PIDs were provided (no flagged processes, no flagged "
            "events, and no resolvable focal process). The analyst's intent in "
            "this run is the FLAGGED INCIDENT(S) ONLY, not anything in the "
            "process tree.\n\n"
            "HARD RULES:\n"
            "1. per_process_findings MUST be an empty array [] — do NOT pick "
            "processes from the tree to analyse. The tree is shown for "
            "reference only; it is OUT OF SCOPE in its entirety.\n"
            "2. The narrative MUST address each flagged incident per the "
            "ANALYST-FLAGGED DEFENDER INCIDENTS rules above (relationship "
            "verdict, classification assessment, recommended next step). It "
            "MUST NOT analyse processes from the tree.\n"
            "3. urgency.active_pids: [].\n"
            "4. root_cause: \"Not assessed — incidents-only analysis.\"\n"
            "5. delivery_vector: type=\"Unknown\", confidence=\"unknown\", "
            "evidence=\"Not assessed — incidents-only analysis.\"\n"
            "6. IOCs: only indicators drawn directly from the flagged "
            "incidents' alerts and evidence — none from the tree."
        )
    elif scope == "focused":
        scope_block = (
            "\n=== ANALYSIS SCOPE: FOCUSED — STRICT MODE ===\n"
            "You are NOT performing a full attack chain investigation.\n"
            "You are answering ONE question: \"What are the in-scope processes doing,"
            " and how do the analyst-flagged events / alerts relate to them?\"\n\n"
            "THIS OVERRIDES THE GENERAL 'work backwards to root cause' INSTRUCTION IN THE SYSTEM PROMPT.\n\n"
            f"THE ONLY IN-SCOPE PIDs ARE: {in_scope_pid_list}\n"
            "Every other PID in the tree is OUT OF SCOPE. Other PIDs are shown only so you can "
            "identify which process spawned each in-scope one. They are NOT under analysis.\n\n"
            "HARD RULES:\n"
            f"1. per_process_findings MUST contain EXACTLY {n_in_scope} "
            f"entr{'y' if n_in_scope == 1 else 'ies'} — one for each in-scope PID listed above. "
            "No more. No fewer. Do not add findings for any other PID even if it looks suspicious.\n"
            "2. The narrative describes ONLY what the in-scope PIDs did. Do not narrate the "
            "broader attack chain. Do not describe sibling processes, other tree branches, or "
            "any PID that is not in the in-scope list. You may mention an unflagged parent ONCE "
            "to establish lineage (e.g. \"spawned by explorer.exe (PID X)\"), but do not analyse "
            "or make verdicts about it.\n"
            "3. urgency.active_pids: include ONLY in-scope PIDs. Do NOT list other PIDs here.\n"
            "4. root_cause: if an in-scope PID IS the root, name it. Otherwise set to "
            "\"Not assessed in focused scope — run wide analysis to determine.\"\n"
            "5. delivery_vector: set type=\"Unknown\" and confidence=\"unknown\" with evidence "
            "\"Not assessed in focused scope.\" — UNLESS evidence directly tied to an in-scope "
            "PID makes it obvious.\n"
            "6. urgency: assess based ONLY on whether the in-scope PIDs themselves are active "
            "or have established persistence. Do not assess based on other branches of the tree.\n"
            "7. IOCs: only indicators that appear in events whose InitiatingProcessId is one of "
            "the in-scope PIDs. Indicators tied solely to out-of-scope PIDs are excluded.\n\n"
            "Self-check before responding: every PID you reference by number should either be "
            "in the in-scope list above, OR be a one-time parent-lineage mention. If you find "
            "yourself analysing an out-of-scope PID, stop and remove it."
        )
    else:
        scope_block = (
            "\n=== ANALYSIS SCOPE: WIDE ===\n"
            "Investigate the entire process tree. Identify the full attack chain even if it extends "
            "beyond the processes the analyst flagged. Include unflagged processes in "
            "per_process_findings if they are part of the attack."
        )

    # Analyst-flagged telemetry events and alerts — same "flag is input, not
    # ground truth" framing as flagged processes. These tell Claude where the
    # analyst's attention is, but the verdict still has to be evidence-driven.
    flagged_events_block = ""
    if flagged_events:
        ev_lines: list[str] = []
        for e in flagged_events[:60]:
            flag  = str(e.get("flag", "") or "").upper()
            tab   = e.get("tab", "?")
            row   = e.get("row") or {}
            ts    = str(row.get("Timestamp", "") or "")[:19].replace("T", " ")
            atype = row.get("ActionType", "")
            summary_parts: list[str] = []
            if tab == "network":
                summary_parts = [
                    f"{atype}",
                    f"remote={row.get('RemoteIP','')}:{row.get('RemotePort','')}",
                    f"url={row.get('RemoteUrl','')}" if row.get("RemoteUrl") else "",
                ]
            elif tab == "files":
                summary_parts = [
                    f"{atype}",
                    f"path={row.get('FolderPath','')}\\{row.get('FileName','')}",
                    f"sha1={row.get('SHA1','')}" if row.get("SHA1") else "",
                ]
            elif tab == "registry":
                summary_parts = [
                    f"{atype}",
                    f"key={row.get('RegistryKey','')}",
                    f"value={row.get('RegistryValueName','')}={row.get('RegistryValueData','')}",
                ]
            elif tab == "dlls":
                summary_parts = [
                    f"load",
                    f"name={row.get('FileName','')}",
                    f"sha1={row.get('SHA1','')}" if row.get("SHA1") else "",
                ]
            elif tab == "scripts":
                summary_parts = [
                    f"{atype}",
                    f"name={row.get('FileName','')}",
                ]
            elif tab == "hunt":
                # Hunt-tab rows come from arbitrary KQL — we don't know the
                # schema. Show timestamp + action + a compact dump of the
                # remaining non-empty fields so the AI gets the full row
                # context without being drowned in nulls.
                trimmed = {k: v for k, v in row.items()
                           if v not in (None, "", "—")
                           and k not in ("Timestamp", "ActionType")}
                summary_parts = [
                    f"{atype}" if atype else "hunt",
                    json.dumps(trimmed, default=str)[:600],
                ]
            else:
                summary_parts = [json.dumps(row, default=str)[:200]]
            summary = " · ".join(p for p in summary_parts if p)
            ev_lines.append(f"  {flag} — [{tab}] {ts} UTC · {summary}")
        flagged_events_block = (
            "\n=== ANALYST-FLAGGED TELEMETRY EVENTS ===\n"
            "These are specific telemetry rows the analyst marked while reviewing "
            "events. Treat them the same way as flagged processes: the flag tells "
            "you what caught the analyst's eye, but evidence-based judgment still "
            "wins. A SUSPICIOUS event flag is a request to investigate, not proof "
            "of malice. A MALICIOUS event flag is a hypothesis that the telemetry "
            "must corroborate. A BENIGN event flag is the analyst's assessment — "
            "respect it unless the row clearly shows otherwise.\n"
            + "\n".join(ev_lines)
        )

    flagged_incidents_block = ""
    if flagged_incidents:
        in_lines: list[str] = []
        for inc in flagged_incidents[:20]:
            flag = str(inc.get("flag", "") or "").upper()
            header = (
                f"\n--- {flag} INCIDENT — {inc.get('severity','?')} · "
                f"{inc.get('display_name','(untitled)')} (IncidentId={inc.get('incident_id','?')})\n"
                f"  status={inc.get('status','?')} · "
                f"classification={inc.get('classification','?')} · "
                f"determination={inc.get('determination','?')} · "
                f"assigned_to={inc.get('assigned_to','?') or '—'}\n"
                f"  created={(inc.get('created') or '')[:19]} · "
                f"host_first_activity={(inc.get('host_earliest_seen') or '')[:19]} · "
                f"host_last_activity={(inc.get('host_latest_seen') or '')[:19]}"
            )
            desc = (inc.get("description") or "").strip()
            if desc:
                header += f"\n  description: {desc[:400]}"

            host_alerts = inc.get("host_alerts") or []
            alert_lines: list[str] = []
            for a in host_alerts[:15]:
                if not isinstance(a, dict):
                    continue
                # Client-supplied alert dict — coerce every interpolated
                # field to str so a non-string (int/list) can't raise on a
                # slice or join mid-prompt.
                mitre = ", ".join(str(m) for m in (a.get("mitre_techniques") or []))
                first = str(a.get("first_activity") or "")[:19]
                last  = str(a.get("last_activity") or "")[:19]
                alert_lines.append(
                    f"    • [{a.get('severity','?')}] {a.get('title','(untitled)')} "
                    f"(AlertId={a.get('id','?')})\n"
                    f"      status={a.get('status','?')} · category={a.get('category','?')} · "
                    f"detection={a.get('detection_source','?')}"
                    + (f" · threat={a.get('threat_display_name','')}"
                       f"{' (' + str(a.get('threat_family','')) + ')' if a.get('threat_family') else ''}"
                       if a.get('threat_display_name') else "")
                    + (f"\n      mitre={mitre}" if mitre else "")
                    + (f"\n      first={first} · last={last}"
                       if (first or last) else "")
                )
            alerts_section = ""
            if alert_lines:
                alerts_section = "\n  alerts on this host:\n" + "\n".join(alert_lines)

            comments = inc.get("comments") or []
            comment_section = ""
            if comments:
                cl = [
                    f"    [{(c.get('created_at') or '')[:19]} {c.get('created_by','?')}]: "
                    f"{(c.get('body') or '')[:300]}"
                    for c in comments[:8]
                ]
                comment_section = "\n  comment trail:\n" + "\n".join(cl)

            in_lines.append(header + alerts_section + comment_section)

        flagged_incidents_block = (
            "\n=== ANALYST-FLAGGED DEFENDER INCIDENTS ===\n"
            "Defender incidents the analyst marked as relevant to this "
            "investigation. Each block below contains the incident's "
            "metadata PLUS the alerts on this host that belong to that "
            "incident (with MITRE techniques, detection source, threat "
            "name) AND any comment trail. This is substantive Defender "
            "telemetry — TREAT IT WITH THE SAME WEIGHT AS A FLAGGED "
            "PROCESS, not as background context.\n"
            "Apply the same flag-as-input rule: the analyst flagging an "
            "incident raises the prior that the in-scope processes are "
            "part of the same activity Defender correlated, but does NOT "
            "by itself prove malice on the in-scope PIDs.\n\n"
            "HARD RULES — apply to every flagged incident below:\n"
            "1. Your narrative MUST devote a clearly-labelled paragraph "
            "to each flagged incident, referencing it by display name and "
            "IncidentId.\n"
            "2. CRITICAL — DO NOT ASSUME CORRELATION. The analyst flagged "
            "the incident to ask 'is this related?', not to assert that "
            "it IS. Before describing the incident, you MUST first "
            "evaluate whether the in-scope process activity is actually "
            "part of this incident's storyline or whether it could be "
            "coincidental / unrelated. Time proximity ALONE is NOT "
            "sufficient evidence — many unrelated things happen close in "
            "time on the same host. Specifically look for:\n"
            "   a. Process lineage overlap — is the in-scope PID spawned "
            "by, or does it spawn, a process named in the incident's "
            "alerts? (Telemetry rows have InitiatingProcessFileName.)\n"
            "   b. Direct evidence overlap — do the in-scope PID's events "
            "touch the same registry keys, files, hashes, IPs, domains, "
            "or accounts that the incident's alerts describe?\n"
            "   c. Causal chain — does the in-scope PID's activity "
            "logically result from, or cause, what the incident's alerts "
            "describe? (e.g. credential dump alert → process using those "
            "credentials; persistence write → later boot-time execution.)\n"
            "3. State an explicit RELATIONSHIP VERDICT for each flagged "
            "incident, choosing one of:\n"
            "   • DIRECTLY RELATED — concrete evidence ties the in-scope "
            "process(es) into the incident (cite the evidence).\n"
            "   • POSSIBLY RELATED — some signals overlap (time, user, "
            "host) but the causal chain is not established; describe "
            "what additional evidence would confirm or rule out.\n"
            "   • UNRELATED — the in-scope process activity does not "
            "appear in the incident's alerts, and there's no overlapping "
            "evidence beyond shared host/time. Say so plainly — the "
            "analyst would rather know the incident is unrelated than be "
            "told a false connection.\n"
            "4. Assess Defender's existing classification / determination "
            "against the telemetry. If you disagree, explain why with "
            "specific evidence; if you agree, say so.\n"
            "5. Recommend a concrete next step for the analyst regarding "
            "this incident (e.g. close as FP with reason, escalate, "
            "investigate specific MITRE techniques further, or — if "
            "UNRELATED — unflag and look elsewhere).\n"
            "6. Do NOT silently ignore a flagged incident. Do NOT discuss "
            "only the focal process while leaving the incident "
            "unaddressed. Do NOT use phrases like 'executed as part of "
            "IncidentId=N' or 'aligns with the incident' unless you have "
            "first stated DIRECTLY RELATED with cited evidence.\n"
            + "\n".join(in_lines)
        )

    # Analyst-confirmed IOC list — indicators the analyst has explicitly
    # added (via the IOCs tab, hunt-tab + IOC button, or VT lookup popover).
    # Treated as ground-truth evidence: where telemetry references one of
    # these the AI should cite the IOC directly in root_cause and bump
    # severity according to the verdict.
    flagged_iocs_block = ""
    if flagged_iocs:
        ioc_lines: list[str] = []
        for i in flagged_iocs[:60]:
            v = str(i.get("verdict", "") or "unknown").upper()
            t = str(i.get("ioc_type", "") or "?")
            val = str(i.get("ioc", "") or "")
            extra: list[str] = []
            if i.get("malicious") is not None or i.get("total") is not None:
                m = i.get("malicious", 0) or 0
                s = i.get("suspicious", 0) or 0
                tot = i.get("total", 0) or 0
                if tot:
                    extra.append(f"vt {m}+{s}/{tot}")
            if i.get("name"):     extra.append(str(i["name"])[:80])
            if i.get("country"):  extra.append(str(i["country"]))
            if i.get("as_owner"): extra.append(f"AS {i['as_owner']}")
            tail = " · ".join(extra)
            ioc_lines.append(f"  {v:<10} [{t}] {val}" + (f"  ({tail})" if tail else ""))
        flagged_iocs_block = (
            "\n=== ANALYST-CONFIRMED IOCs ===\n"
            "Indicators the analyst has added to the IOC list (some "
            "enriched via VirusTotal — vt counts are malicious+suspicious"
            "/total vendors). Treat these as ground-truth evidence: if "
            "any of these values appear in the telemetry below, you MUST "
            "name them explicitly in root_cause and let the verdict "
            "shape severity (a MALICIOUS verdict here = confirmed "
            "indicator, not 'possible'). Indicators tagged UNKNOWN have "
            "not been looked up yet — treat them as analyst points of "
            "interest, not confirmed.\n"
            + "\n".join(ioc_lines) + "\n"
        )

    return "\n".join([
        device_block,
        focal_block,
        flagged_block,
        flagged_events_block,
        flagged_incidents_block,
        flagged_iocs_block,
        tree_block,
        f"\n=== NETWORK EVENTS (DeviceNetworkEvents) ===\n{_fmt_rows(net_rows, 'network')}",
        f"\n=== FILE EVENTS (DeviceFileEvents) ===\n{_fmt_rows(file_rows, 'file')}",
        f"\n=== REGISTRY EVENTS (DeviceRegistryEvents) ===\n{_fmt_rows(reg_rows, 'registry')}",
        f"\n=== LOGON EVENTS (DeviceLogonEvents) ===\n{_fmt_rows(logon_rows, 'logon')}",
        scope_block,
    ]).strip()


def _calc_cost(model: str, input_tokens: int, output_tokens: int, cached_tokens: int) -> float:
    p = PRICING.get(model, PRICING[SONNET])
    return round(
        (input_tokens  / 1_000_000) * p["input"] +
        (output_tokens / 1_000_000) * p["output"] +
        (cached_tokens / 1_000_000) * p["cache_read"],
        6,
    )


def log_token_usage(
    db: sqlite3.Connection,
    investigation_id: str,
    action: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    cached_tokens: int,
    cost_usd: float,
    duration_ms: int,
) -> None:
    db.execute(
        """INSERT INTO token_usage
           (investigation_id, action, model,
            input_tokens, output_tokens, cached_tokens,
            cost_usd, duration_ms)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (investigation_id, action, model,
         input_tokens, output_tokens, cached_tokens,
         cost_usd, duration_ms),
    )
    db.commit()


_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")
# Match every backslash + next char. The callback then decides whether the
# escape is valid (keep as-is) or invalid (double the backslash). Walking the
# string this way naturally handles already-escaped pairs: \\W consumes the
# first \\ as a valid escape, leaving the W alone — so we never double the
# trailing backslash of an existing pair.
_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)
_VALID_ESCAPES = set('"\\/bfnrtu')


def _fix_escape(match: re.Match) -> str:
    c = match.group(1)
    if c in _VALID_ESCAPES:
        return match.group(0)
    return "\\\\" + c


def _sanitize_json(raw: str) -> str:
    """Repair common LLM JSON output defects before strict parsing.

    Handles markdown fences, trailing commas, and invalid backslash escapes
    (Claude frequently emits Windows paths like "C:\\Windows" with a single
    backslash inside string values). Does NOT attempt structural repair.
    Trailing markdown post-scripts after the closing fence are left in place
    here — the parser (run_analysis) uses raw_decode to consume just the
    first JSON object and ignore everything after it.
    """
    s = raw.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s, flags=re.IGNORECASE)
    s = re.sub(r"\s*```\s*$", "", s)
    s = _TRAILING_COMMA_RE.sub(r"\1", s)
    s = _ESCAPE_RE.sub(_fix_escape, s)
    return s


def _parse_findings_json(cleaned: str) -> dict:
    """Parse the first complete JSON object out of `cleaned`.

    Uses json.JSONDecoder.raw_decode so trailing markdown post-scripts that
    Claude sometimes adds after the JSON (despite the prompt telling it not
    to) don't break parsing. Skips any leading whitespace before the first
    `{` so partial fence remnants are tolerated.
    """
    s = cleaned.lstrip()
    # Skip past anything before the first `{` — handles stray header text
    # like "Here is the analysis:" preceding the JSON.
    brace = s.find('{')
    if brace > 0:
        s = s[brace:]
    obj, _end = json.JSONDecoder().raw_decode(s)
    return obj


async def run_analysis(
    anthropic_key: str,
    prompt_text: str,
    investigation_id: str,
    db: sqlite3.Connection,
) -> dict:
    """Call Claude Sonnet, parse JSON findings, log token usage. Returns findings dict."""
    client = anthropic.Anthropic(api_key=anthropic_key)

    t0 = time.time()
    try:
        loop = asyncio.get_event_loop()

        def _call():
            return client.messages.create(
                model=ANALYSIS_MODEL,
                max_tokens=16384,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt_text}],
            )

        msg = await loop.run_in_executor(None, _call)

    except anthropic.BadRequestError as e:
        if "prompt is too long" in str(e).lower() or e.status_code == 400:
            raise ValueError("CONTEXT_TOO_LARGE")
        raise RuntimeError(f"Anthropic API error: {e}")
    except anthropic.APIConnectionError:
        raise RuntimeError("AI_UNAVAILABLE")
    except anthropic.APIStatusError as e:
        if e.status_code in (413, 400):
            raise ValueError("CONTEXT_TOO_LARGE")
        raise RuntimeError(f"Anthropic API error {e.status_code}: {e.message}")

    duration_ms = int((time.time() - t0) * 1000)

    usage = msg.usage
    input_tokens  = usage.input_tokens
    output_tokens = usage.output_tokens
    cached_tokens = getattr(usage, "cache_read_input_tokens", 0) or 0
    cost_usd = _calc_cost(ANALYSIS_MODEL, input_tokens, output_tokens, cached_tokens)

    log_token_usage(
        db, investigation_id, "AI_ANALYSIS_EXECUTED", ANALYSIS_MODEL,
        input_tokens, output_tokens, cached_tokens, cost_usd, duration_ms,
    )

    # Guard the content shape: a refusal or non-text first block yields an
    # empty/odd content list. Extract the first text block defensively
    # rather than letting content[0].text raise IndexError/AttributeError
    # after the call has already been billed and logged.
    raw = ""
    for block in (msg.content or []):
        text = getattr(block, "text", None)
        if isinstance(text, str):
            raw = text
            break
    if not raw:
        raise RuntimeError("AI_UNAVAILABLE")
    cleaned = _sanitize_json(raw)
    truncated = getattr(msg, "stop_reason", None) == "max_tokens"

    try:
        findings = _parse_findings_json(cleaned)
    except json.JSONDecodeError as exc:
        log.error(
            "Claude returned invalid JSON for investigation %s (stop_reason=%s): %s\nFull raw output:\n%s",
            investigation_id, getattr(msg, "stop_reason", "?"), exc, raw,
        )
        if truncated:
            raise RuntimeError(
                "The AI response exceeded the output budget. "
                "Reduce the number of flagged processes (group similar ones) "
                "and try again."
            )
        raise RuntimeError(
            "The AI response could not be parsed. Please try analysing again — "
            "this is usually transient."
        )

    findings["token_usage"] = {
        "input_tokens":  input_tokens,
        "output_tokens": output_tokens,
        "cached_tokens": cached_tokens,
        "cost_usd":      cost_usd,
        "duration_ms":   duration_ms,
    }
    return findings
