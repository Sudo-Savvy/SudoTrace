import asyncio
import logging
import re
from typing import Annotated

from fastapi import APIRouter, Cookie, HTTPException

log = logging.getLogger(__name__)

from app.database import get_db
from app.encryption import decrypt_field, get_key
from app.security import get_session
from app.graph import get_graph_token, run_hunting_query, parse_time_window
from app.models import AnalyseRequest
from app import claude
from app.audit import write_audit

router = APIRouter()

_ROW_LIMIT = 500   # KQL take per telemetry table


def _err(code: str, msg: str) -> dict:
    return {"ok": False, "error": code, "error_message": msg}


def _compute_focused_subset(
    all_nodes: dict[str, dict],
    flagged_keys: set[str],
    focal_key: str | None,  # kept for API stability; intentionally unused
) -> dict[str, dict]:
    """Return a pruned copy of all_nodes for focused analysis. For each flagged
    node we keep: the node itself, its immediate parent, and its immediate
    children. No grandparents, siblings, or cousins — unrelated lineage just
    inflates the prompt without adding signal, and risks dragging in PID-reuse
    collisions on Windows.

    Each kept node's child_node_keys is rewritten to reference only descendants
    that are also in the kept set.
    """
    _ = focal_key  # unused — see docstring
    keep: set[str] = set()

    for fk in flagged_keys:
        node = all_nodes.get(fk)
        if not node:
            continue
        keep.add(fk)
        parent = node.get("parent_node_key")
        if parent and parent in all_nodes:
            keep.add(parent)
        for ck in node.get("child_node_keys") or []:
            if ck in all_nodes:
                keep.add(ck)

    pruned: dict[str, dict] = {}
    for k in keep:
        node = dict(all_nodes[k])
        node["child_node_keys"] = [
            ck for ck in (node.get("child_node_keys") or []) if ck in keep
        ]
        pruned[k] = node
    return pruned


_TS_RE   = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?$')
_NAME_RE = re.compile(r'^[A-Za-z0-9_.\- ]{1,128}$')


def _safe_ts(ts: str | None) -> str | None:
    """Validate an ISO 8601 timestamp before injecting into KQL. Returns None
    if the value doesn't strictly match the expected format."""
    if not ts:
        return None
    return ts if _TS_RE.match(ts) else None


def _safe_name(name: str | None) -> str | None:
    """Validate a process filename for KQL injection safety. Allows letters,
    digits, underscore, dot, dash, and space (Windows binary names can include
    spaces, e.g. "Some App.exe"). Returns None if the value contains anything
    else — we then fall back to PID+time matching without the name filter."""
    if not name:
        return None
    return name if _NAME_RE.match(name) else None


async def _fetch_telemetry(
    token: str, host: str,
    pid_times: list[tuple[int, str | None, str | None]],
    start_s: str, end_s: str,
) -> tuple[list, list, list, list]:
    """Run 4 aggregate telemetry KQL queries in parallel.

    pid_times tuples each PID with its (creation_time, filename). The KQL
    filter ANDs all three:
      InitiatingProcessId == pid
      AND InitiatingProcessCreationTime BETWEEN (t-2s .. t+2s)
      AND InitiatingProcessFileName =~ name   (case-insensitive)
    All three are needed to disambiguate Windows PID reuse — relying on PID
    alone (or PID + time, without filename) can leak events from a different
    process instance that happened to share the PID at a close timestamp.
    Creation time / name are dropped from the AND if missing or unsafe.
    """
    # Build an OR'd per-process where clause — max 50 entries
    pid_clause = ""
    if pid_times:
        clauses: list[str] = []
        for pid, t, name in pid_times[:50]:
            parts = [f"InitiatingProcessId == {pid}"]
            safe_t = _safe_ts(t)
            if safe_t:
                parts.append(
                    f"InitiatingProcessCreationTime between "
                    f"(datetime_add('second', -2, datetime({safe_t})) .. "
                    f"datetime_add('second',  2, datetime({safe_t})))"
                )
            safe_n = _safe_name(name)
            if safe_n:
                parts.append(f'InitiatingProcessFileName =~ "{safe_n}"')
            clauses.append("(" + " and ".join(parts) + ")")
        pid_clause = "| where " + " or ".join(clauses)

    def kql(table: str, cols: str, extra: str | None = None) -> str:
        # extra="" explicitly means "no filter"; extra=None falls back to PID.
        where_clause = extra if extra is not None else pid_clause
        return "\n".join([
            f"{table}",
            f'| where DeviceName contains "{host}"',
            f"| where Timestamp between (datetime({start_s}) .. datetime({end_s}))",
            where_clause,
            f"| project {cols}",
            f"| order by Timestamp asc | take {_ROW_LIMIT}",
        ])

    net = kql(
        "DeviceNetworkEvents",
        "Timestamp, InitiatingProcessId, InitiatingProcessFileName, "
        "RemoteIP, RemotePort, LocalIP, LocalPort, Protocol, Direction, RemoteUrl",
    )
    fil = kql(
        "DeviceFileEvents",
        "Timestamp, InitiatingProcessId, InitiatingProcessFileName, "
        "ActionType, FileName, FolderPath, SHA1, SHA256, FileSize",
    )
    reg = kql(
        "DeviceRegistryEvents",
        "Timestamp, InitiatingProcessId, InitiatingProcessFileName, "
        "ActionType, RegistryKey, RegistryValueName, RegistryValueData",
    )
    log = kql(
        "DeviceLogonEvents",
        "Timestamp, AccountName, LogonType, ActionType, RemoteIP, RemoteDeviceName",
        extra="",  # logon events not filtered by PID — broader context
    )

    async def safe(q: str) -> list:
        try:
            return await run_hunting_query(token, q)
        except Exception:
            return []

    results = await asyncio.gather(safe(net), safe(fil), safe(reg), safe(log))
    return results[0], results[1], results[2], results[3]


@router.post("/")
async def analyse(
    body: AnalyseRequest,
    session_id: Annotated[str | None, Cookie()] = None,
):
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    key = get_key(session_id)
    if key is None:
        raise HTTPException(status_code=401, detail="Session expired.")

    db = get_db()
    try:
        if not get_session(session_id, db):
            raise HTTPException(status_code=401, detail="Session expired.")

        row = db.execute("SELECT * FROM credentials WHERE id=1").fetchone()
        if not row:
            return _err("CREDENTIALS_MISSING", "MDE credentials not configured.")

        def dec(val):
            if not val:
                return None
            try:
                return decrypt_field(val, key)
            except Exception:
                return None

        tenant_id     = dec(row["tenant_id"])
        client_id     = dec(row["client_id"])
        client_secret = dec(row["client_secret"])
        anthropic_key = dec(row["anthropic_key"])
    finally:
        db.close()

    if not anthropic_key:
        return _err("NO_ANTHROPIC_KEY", "Anthropic API key not configured. Add it in Settings.")

    if not all([tenant_id, client_id, client_secret]):
        return _err("CREDENTIALS_MISSING", "MDE credentials not configured.")

    try:
        token = await get_graph_token(tenant_id, client_id, client_secret)
    except Exception as e:
        log.warning("Graph token acquisition failed: %s", e)
        return _err("GRAPH_ERROR",
                    "Could not connect to Microsoft Graph. Check the MDE credentials in Settings.")

    try:
        start, end = parse_time_window(body.focal_time_iso, body.time_window)
    except Exception:
        start, end = parse_time_window(None, "±24h")

    start_s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_s   = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    host    = body.hostname.replace('"', "").replace("'", "")

    # Locate focal node in the submitted tree. Prefer an explicit is_focal flag,
    # but fall back to the last entry of ancestry_chain (focal-to-root) when no
    # node is marked — this happens in trees where the focal PID didn't resolve
    # cleanly during process-map build but still has lineage. Without this
    # fallback, focused mode bails (no anchors found), the whole tree gets sent,
    # and the scope_block instructs Claude to produce 0 per_process_findings
    # while implicitly inviting it to pick PIDs itself.
    focal_key = next(
        (k for k, n in body.all_nodes.items() if n.get("is_focal")), None
    )
    if not focal_key and body.ancestry_chain:
        candidate = body.ancestry_chain[-1]
        if candidate in body.all_nodes:
            focal_key = candidate
    focal_node = body.all_nodes.get(focal_key) if focal_key else None

    # Anchor set for focused mode: flagged processes + flagged events' parent
    # processes. If the analyst flagged only alerts (or nothing process-level),
    # fall back to the focal node so the prune still has something to attach
    # to. Without this, focused mode would bail and send the whole tree.
    flagged_keys = {f["node_key"] for f in body.flagged_nodes if f.get("node_key")}
    event_keys: set[str] = set()
    for e in body.flagged_events or []:
        nk = e.get("node_key")
        if nk:
            event_keys.add(nk)
    anchor_keys = flagged_keys | event_keys
    if not anchor_keys and focal_key:
        anchor_keys = {focal_key}
    use_focused_prune = body.scope == "focused" and bool(anchor_keys)

    if use_focused_prune:
        nodes_for_prompt = _compute_focused_subset(body.all_nodes, anchor_keys, focal_key)
    else:
        nodes_for_prompt = body.all_nodes

    # In focused mode, telemetry filter is limited to JUST the anchor nodes —
    # NOT the whole pruned tree. Including ancestors/children would leak events
    # from unrelated process instances that happen to share a PID with an
    # anchor (Windows PID reuse). The ancestors/children remain in the tree
    # section of the prompt for lineage context, but their events don't.
    if use_focused_prune:
        telemetry_nodes = {k: body.all_nodes[k] for k in anchor_keys if k in body.all_nodes}
    else:
        telemetry_nodes = nodes_for_prompt

    # Build (pid, creation_time, filename) triples — dedupe and skip invalid.
    # Filename is included so KQL can match on InitiatingProcessFileName too —
    # the strictest possible filter for the analyst's specific process instance.
    seen: set[tuple[int, str | None, str | None]] = set()
    pid_times: list[tuple[int, str | None, str | None]] = []
    for n in telemetry_nodes.values():
        try:
            pid = int(n.get("pid", 0))
        except (ValueError, TypeError):
            continue
        if pid == 0:
            continue
        ts = n.get("timestamp")
        name = n.get("name")
        key = (pid, ts, name)
        if key in seen:
            continue
        seen.add(key)
        pid_times.append((pid, ts, name))

    net_rows, file_rows, reg_rows, logon_rows = await _fetch_telemetry(
        token, host, pid_times, start_s, end_s
    )

    # Defensive post-fetch filter for focused mode: drop telemetry rows whose
    # InitiatingProcessFileName doesn't match any node in the telemetry set.
    # KQL's (PID, CreationTime) filter SHOULD already exclude these, but if
    # MDE's CreationTime precision differs from our node.timestamp, an event
    # from a same-PID-different-instance can slip through. Drop them here as
    # a second line of defense.
    if use_focused_prune:
        allowed_pid_name: set[tuple[int, str]] = set()
        for n in telemetry_nodes.values():
            try:
                pid = int(n.get("pid", 0))
            except (ValueError, TypeError):
                continue
            name = (n.get("name") or "").lower()
            if pid and name:
                allowed_pid_name.add((pid, name))

        def _keep(row: dict) -> bool:
            try:
                rpid = int(row.get("InitiatingProcessId", 0) or 0)
            except (ValueError, TypeError):
                return False
            rname = (row.get("InitiatingProcessFileName") or "").lower()
            return (rpid, rname) in allowed_pid_name

        pre = (len(net_rows), len(file_rows), len(reg_rows))
        net_rows  = [r for r in net_rows  if _keep(r)]
        file_rows = [r for r in file_rows if _keep(r)]
        reg_rows  = [r for r in reg_rows  if _keep(r)]
        post = (len(net_rows), len(file_rows), len(reg_rows))
        if pre != post:
            log.warning(
                "Focused-mode defensive filter dropped same-PID rows: net %d→%d, files %d→%d, reg %d→%d. "
                "Allowed (pid, name): %s",
                pre[0], post[0], pre[1], post[1], pre[2], post[2],
                sorted(allowed_pid_name),
            )

    def _as_pid(v) -> int:
        # all_nodes is an unvalidated client dict — pid may be a string,
        # None, or junk. Coerce defensively; this only feeds a log line.
        try:
            return int(v)
        except (ValueError, TypeError):
            return 0

    anchor_names = [
        (_as_pid(body.all_nodes.get(k, {}).get("pid", 0)),
         body.all_nodes.get(k, {}).get("name", "?"))
        for k in anchor_keys
    ]
    log.warning(
        "Analyse: scope=%s, flagged_procs=%d, flagged_events=%d, flagged_incidents=%d, "
        "anchors=%d %s, telemetry_nodes=%d, pid_times=%d, rows net/file/reg/logon=%d/%d/%d/%d",
        body.scope, len(flagged_keys), len(event_keys), len(body.flagged_incidents or []),
        len(anchor_keys), sorted(anchor_names),
        len(telemetry_nodes), len(pid_times),
        len(net_rows), len(file_rows), len(reg_rows), len(logon_rows),
    )

    prompt_text = claude.build_prompt(
        hostname=host,
        focal_pid=body.focal_pid,
        focal_node=focal_node,
        device_info=body.device_info,
        nodes=nodes_for_prompt,
        ancestry_chain=body.ancestry_chain,
        flagged_nodes=body.flagged_nodes,
        net_rows=net_rows,
        file_rows=file_rows,
        reg_rows=reg_rows,
        logon_rows=logon_rows,
        scope=body.scope,
        flagged_events=body.flagged_events,
        flagged_incidents=body.flagged_incidents,
        flagged_iocs=body.flagged_iocs,
        anchor_keys=anchor_keys,
    )

    db = get_db()
    try:
        # Resolve the analyst's identity once so we can audit the run.
        sess = get_session(session_id, db) if session_id else None
        findings = await claude.run_analysis(
            anthropic_key=anthropic_key,
            prompt_text=prompt_text,
            investigation_id=body.investigation_id,
            db=db,
        )
        if sess is not None:
            usage = findings.get("token_usage") or {}
            write_audit(
                db, action="ai.analyse",
                user_id=int(sess["user_id"]), username=sess["username"],
                target=body.investigation_id or "",
                detail={
                    "scope":       body.scope,
                    "hostname":    host,
                    "focal_pid":   body.focal_pid,
                    "input_tokens":  usage.get("input_tokens"),
                    "output_tokens": usage.get("output_tokens"),
                    "cost_usd":      usage.get("cost_usd"),
                    "duration_ms":   usage.get("duration_ms"),
                    "model":         usage.get("model"),
                },
            )
    except ValueError as e:
        if "CONTEXT_TOO_LARGE" in str(e):
            return _err(
                "CONTEXT_TOO_LARGE",
                "Investigation too large for a single analysis. "
                "Narrow the time window or reduce the number of visible processes, then try again.",
            )
        log.warning("Analysis failed (ValueError): %s", e)
        return _err("ANALYSIS_FAILED",
                    "The AI analysis could not be completed. See the audit log for detail.")
    except RuntimeError as e:
        if "AI_UNAVAILABLE" in str(e):
            return _err(
                "AI_UNAVAILABLE",
                "AI service is currently unavailable. "
                "Your investigation data is still accessible. Please try again.",
            )
        log.warning("Analysis failed (RuntimeError): %s", e)
        return _err("ANALYSIS_FAILED",
                    "The AI analysis could not be completed. See the audit log for detail.")
    except Exception as e:
        # Full detail to the server log only — the analyst gets plain English.
        log.exception("Unexpected analysis failure: %s", e)
        return _err("ANALYSIS_FAILED",
                    "The AI analysis could not be completed. See the audit log for detail.")
    finally:
        db.close()

    return {"ok": True, **findings}
