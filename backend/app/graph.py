import re
import json
import random
import logging
import msal
import httpx
import asyncio
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
# The bearer token must only ever be sent to Microsoft Graph. We follow
# @odata.nextLink URLs verbatim from response bodies; this allowlist
# ensures a tampered/unexpected nextLink can't redirect the token off-host.
_GRAPH_ALLOWED_HOSTS = ("graph.microsoft.com",)


def _is_graph_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme != "https":
        return False
    host = (parsed.hostname or "").lower()
    return any(host == h or host.endswith("." + h) for h in _GRAPH_ALLOWED_HOSTS)

log = logging.getLogger(__name__)

# Retry config for Graph API. Microsoft Graph documents throttling via
# HTTP 429 with a Retry-After header (seconds). We also retry 5xx with
# exponential backoff and transient network failures. Other 4xx are
# *not* retried — the caller inspects them (403 → permissions message,
# 404 → "not found", etc).
_GRAPH_MAX_ATTEMPTS = 4
_GRAPH_BACKOFF_BASE = 1.0
_GRAPH_BACKOFF_CAP  = 60.0
_GRAPH_RETRY_STATUSES = {429, 500, 502, 503, 504}
_GRAPH_TRANSIENT_EXC  = (
    httpx.NetworkError, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)


def _parse_retry_after(value: str | None) -> float | None:
    """Retry-After header is either delta-seconds or an HTTP-date."""
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    try:
        target = parsedate_to_datetime(value)
        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)
        delta = (target - datetime.now(timezone.utc)).total_seconds()
        return delta if delta > 0 else None
    except Exception:
        return None


async def graph_request(
    method: str,
    url: str,
    *,
    token: str,
    json_body: dict | None = None,
    params: dict | None = None,
    extra_headers: dict | None = None,
    timeout: float = 60.0,
) -> httpx.Response:
    """
    Execute a single Graph API request with retry on 429, 5xx and
    transient network errors. Returns the final httpx.Response — does
    NOT call raise_for_status, because callers need to inspect specific
    non-retryable statuses (403 for permissions, 404 for missing).
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/json",
    }
    if json_body is not None:
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)

    last_exc: Exception | None = None
    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(_GRAPH_MAX_ATTEMPTS):
            try:
                resp = await client.request(
                    method, url,
                    headers=headers,
                    json=json_body,
                    params=params,
                )
            except _GRAPH_TRANSIENT_EXC as exc:
                last_exc = exc
                if attempt + 1 >= _GRAPH_MAX_ATTEMPTS:
                    raise
                wait = min(_GRAPH_BACKOFF_CAP, _GRAPH_BACKOFF_BASE * (2 ** attempt))
                wait += random.uniform(0, max(0.1, wait * 0.25))
                log.warning(
                    "Graph %s %s transient %r (attempt %d/%d) — retrying in %.1fs",
                    method, url, exc, attempt + 1, _GRAPH_MAX_ATTEMPTS, wait,
                )
                await asyncio.sleep(wait)
                continue

            if resp.status_code not in _GRAPH_RETRY_STATUSES:
                return resp

            if attempt + 1 >= _GRAPH_MAX_ATTEMPTS:
                log.warning(
                    "Graph %s %s returned HTTP %d after %d attempts — giving up",
                    method, url, resp.status_code, _GRAPH_MAX_ATTEMPTS,
                )
                return resp

            wait = _parse_retry_after(resp.headers.get("Retry-After"))
            if wait is None:
                wait = _GRAPH_BACKOFF_BASE * (2 ** attempt)
            wait = min(wait, _GRAPH_BACKOFF_CAP)
            wait += random.uniform(0, max(0.1, wait * 0.25))
            log.warning(
                "Graph %s %s returned HTTP %d (attempt %d/%d) — retrying in %.1fs",
                method, url, resp.status_code, attempt + 1, _GRAPH_MAX_ATTEMPTS, wait,
            )
            await asyncio.sleep(wait)

    if last_exc:
        raise last_exc
    raise RuntimeError("graph_request: retry loop exited without a response")

LOLBINS: frozenset[str] = frozenset({
    "certutil.exe", "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "msiexec.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
    "bitsadmin.exe", "wmic.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "sc.exe", "schtasks.exe", "at.exe", "net.exe", "net1.exe",
    "nltest.exe", "ping.exe", "tracert.exe", "nslookup.exe", "curl.exe",
    "wget.exe", "ftp.exe", "tftp.exe", "expand.exe", "extrac32.exe",
    "makecab.exe", "xcopy.exe", "robocopy.exe", "forfiles.exe", "esentutl.exe",
    "ntdsutil.exe", "vssadmin.exe", "wbadmin.exe", "diskshadow.exe",
    "dnscmd.exe", "odbcconf.exe", "pcalua.exe", "print.exe", "replace.exe",
    "xwizard.exe", "ie4uinit.exe", "msconfig.exe",
})


def _get_token_sync(tenant_id: str, client_id: str, client_secret: str) -> str:
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        desc = result.get("error_description") or result.get("error") or "MSAL token acquisition failed"
        raise RuntimeError(desc)
    return result["access_token"]


async def get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _get_token_sync, tenant_id, client_id, client_secret)


async def run_hunting_query(token: str, kql: str, timespan: str | None = None) -> list[dict]:
    # Optional `timespan` is the ISO 8601 duration / range Graph applies
    # as an implicit Timestamp filter before the analyst's KQL runs. Use
    # this for the timeframe selector instead of mangling the KQL string
    # — string injection breaks any query shape other than the trivial
    # `Table\n| where …` form (union, let, materialize, …).
    body: dict = {"Query": kql}
    if timespan:
        body["Timespan"] = timespan
    resp = await graph_request(
        "POST",
        f"{GRAPH_BASE}/security/runHuntingQuery",
        token=token,
        json_body=body,
    )
    if resp.status_code == 403:
        raise PermissionError(
            "Graph API 403 — check ThreatHunting.Read.All permission and admin consent."
        )
    resp.raise_for_status()
    data = resp.json()
    return data.get("Results") or data.get("results") or []


def parse_time_window(focal_time: str | None, time_window: str) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)

    # Custom absolute range: "custom:<startISO>..<endISO>" (both UTC).
    # focal_time is ignored — the range is fully specified.
    if time_window.startswith("custom:"):
        parts = time_window[len("custom:"):].split("..")
        if len(parts) == 2:
            try:
                start = datetime.fromisoformat(parts[0].replace("Z", "+00:00"))
                end = datetime.fromisoformat(parts[1].replace("Z", "+00:00"))
                if start.tzinfo is None:
                    start = start.replace(tzinfo=timezone.utc)
                if end.tzinfo is None:
                    end = end.replace(tzinfo=timezone.utc)
                if start < end:
                    return start, end
            except ValueError:
                pass
        # Malformed custom range — fall back to ±1h default below.

    if time_window == "last24h":
        return now - timedelta(hours=24), now
    if time_window == "last7d":
        return now - timedelta(days=7), now
    if time_window == "last30d":
        return now - timedelta(days=30), now

    if focal_time:
        try:
            focal_dt = datetime.fromisoformat(focal_time.replace("Z", "+00:00"))
        except ValueError:
            focal_dt = now
    else:
        focal_dt = now

    # Strip leading ± / +/- chars (handles U+00B1 and ASCII)
    w = re.sub(r"^[±+\-/\s]+", "", time_window).strip()
    if w.endswith("m"):
        delta = timedelta(minutes=int(w[:-1]))
    elif w.endswith("h"):
        delta = timedelta(hours=int(w[:-1]))
    else:
        delta = timedelta(hours=1)

    return focal_dt - delta, focal_dt + delta


def _node_key(pid: int | None, creation_time: str | None, unique_id: str | None = None) -> str:
    # ProcessUniqueId is the Process Start Key — globally unique on Windows.
    # Use it when available; fall back to pid+creation_time for Linux/missing data.
    if unique_id:
        return unique_id
    if not pid:
        return "unknown_0"
    if creation_time:
        ct = re.sub(r"[^0-9]", "", creation_time[:19])
        return f"{pid}_{ct}"
    return str(pid)


def build_process_map(rows: list[dict], focal_pid: int, pinned_node_key: str | None = None) -> dict:
    """
    Build process tree from DeviceProcessEvents rows.
    Uses ProcessId + ProcessCreationTime as stable node keys.

    Processes that started before the query window only appear in the
    InitiatingProcess* columns, never as ProcessId. We extract them from
    both columns so the focal PID is always found.
    """
    nodes: dict[str, dict] = {}
    pid_to_keys: dict[int, list[str]] = {}
    # Maps pid+creation_digits → canonical node key, to prevent duplicate nodes
    # when a process is seen with UniqueId from ProcessId columns but without it
    # in InitiatingProcess* columns of another row.
    pid_ct_to_key: dict[str, str] = {}

    def upsert(
        pid: int,
        creation_time: str | None,
        unique_id: str | None,
        name: str,
        cmdline: str,
        user: str,
        timestamp: str,
        folder: str,
        sha1: str,
        sha256: str,
        md5: str,
        parent_pid: int,
        parent_creation: str | None,
        parent_unique_id: str | None,
    ) -> str | None:
        if not pid:
            return None

        # Compute the natural key for this call
        nk = _node_key(pid, creation_time, unique_id)

        # If this node would get a UniqueId-based key, register a pid+ct alias
        # so that later calls without UniqueId resolve to the same node.
        ct_digits = re.sub(r"[^0-9]", "", (creation_time or "")[:19]) if creation_time else ""
        alias = f"{pid}_{ct_digits}" if ct_digits else None

        # If we computed a non-alias key (unique_id path) and an alias exists
        # that already points to a different key, merge by using that key.
        if alias and alias != nk and alias in pid_ct_to_key:
            nk = pid_ct_to_key[alias]
        elif alias and alias != nk and nk not in nodes:
            # Register this unique_id key as the canonical key for this pid+ct
            pid_ct_to_key[alias] = nk
        elif alias and alias == nk:
            # This is a pid+ct key — if there's already a canonical uid-based key,
            # redirect to it so we don't create a duplicate node.
            if alias in pid_ct_to_key:
                nk = pid_ct_to_key[alias]
            else:
                pid_ct_to_key[alias] = nk

        pk = _node_key(parent_pid, parent_creation, parent_unique_id) if parent_pid else None

        if nk not in nodes:
            nodes[nk] = {
                "node_key": nk,
                "pid": pid,
                "name": name or "(unknown)",
                "cmdline": cmdline,
                "user": user,
                "timestamp": timestamp,
                "folder": folder,
                "sha1":   sha1   if sha1   else "",
                "sha256": sha256 if sha256 else "",
                "md5":    md5    if md5    else "",
                "parent_node_key": pk,
                "child_node_keys": [],
                "is_focal": pid == focal_pid,
                "is_lolbin": (name or "").lower() in LOLBINS,
            }
            if pid not in pid_to_keys:
                pid_to_keys[pid] = []
            if nk not in pid_to_keys[pid]:
                pid_to_keys[pid].append(nk)
        return nk

    for row in rows:
        pid        = int(row.get("ProcessId") or 0)
        ct         = row.get("ProcessCreationTime") or row.get("Timestamp")
        uid        = row.get("ProcessUniqueId") or None
        parent_pid = int(row.get("InitiatingProcessId") or 0)
        parent_ct  = row.get("InitiatingProcessCreationTime")
        parent_uid = row.get("InitiatingProcessUniqueId") or None
        gp_pid     = int(row.get("InitiatingProcessParentId") or 0)

        name    = (row.get("FileName") or "").lower()
        cmdline = row.get("ProcessCommandLine") or ""
        user    = row.get("AccountName") or ""
        ts      = row.get("Timestamp") or ""
        sha1    = row.get("SHA1") or ""
        sha256  = row.get("SHA256") or ""
        md5     = row.get("MD5") or ""
        folder  = row.get("FolderPath") or ""

        p_name    = (row.get("InitiatingProcessFileName") or "").lower()
        p_cmdline = row.get("InitiatingProcessCommandLine") or ""
        p_user    = row.get("InitiatingProcessAccountName") or ""
        p_folder  = row.get("InitiatingProcessFolderPath") or ""
        p_sha1    = row.get("InitiatingProcessSHA1") or ""
        p_sha256  = row.get("InitiatingProcessSHA256") or ""
        p_md5     = row.get("InitiatingProcessMD5") or ""

        # Register the created process (main row subject)
        upsert(pid, ct, uid, name, cmdline, user, ts, folder,
               sha1, sha256, md5,
               parent_pid, parent_ct, parent_uid)

        # Register the parent process — it may not appear as ProcessId if it
        # pre-dates the query window; extracting it here prevents PID_NOT_FOUND.
        if parent_pid:
            upsert(parent_pid, parent_ct, parent_uid,
                   p_name, p_cmdline, p_user, ts, p_folder,
                   p_sha1, p_sha256, p_md5,
                   gp_pid, None, None)

    # Wire parent → children
    for nk, node in nodes.items():
        pk = node.get("parent_node_key")
        if pk and pk in nodes and nk not in nodes[pk]["child_node_keys"]:
            nodes[pk]["child_node_keys"].append(nk)

    if pinned_node_key and pinned_node_key in nodes:
        focal_candidates = [pinned_node_key]
    else:
        focal_candidates = pid_to_keys.get(focal_pid, [])
    focal_node_key = focal_candidates[0] if len(focal_candidates) == 1 else None

    # Build ancestry chain root → focal
    ancestry_chain: list[str] = []
    if focal_node_key:
        key: str | None = focal_node_key
        seen: set[str] = set()
        while key and key not in seen:
            ancestry_chain.insert(0, key)
            seen.add(key)
            parent = nodes[key].get("parent_node_key")
            key = parent if (parent and parent in nodes) else None

    return {
        "nodes": nodes,
        "ancestry_chain": ancestry_chain,
        "focal_node_key": focal_node_key,
        "pid_candidates": focal_candidates,
    }


_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


async def _resolve_alert_guid(token: str, alert_id: str) -> dict | None:
    """
    Resolve a GUID-format alert.
    Strategy:
      1. Call alerts_v2 API — extract systemAlertId (da637xxx) and evidence.
      2. Try AlertEvidence hunting with systemAlertId if available (richer process data).
      3. Fall back to evidence parsing from the API response.
      4. If alerts_v2 is 403/unavailable, try AlertEvidence hunting directly with the GUID.
    """
    api_data = None
    try:
        resp = await graph_request(
            "GET",
            f"{GRAPH_BASE}/security/alerts_v2/{alert_id}",
            token=token,
            timeout=30.0,
        )
        if resp.status_code == 404:
            api_data = None
        elif resp.status_code == 403:
            api_data = None
        else:
            resp.raise_for_status()
            api_data = resp.json()
    except Exception as exc:
        log.warning("alerts_v2 exception: %s", exc)
        api_data = None

    if api_data is not None:
        # Prefer AlertEvidence hunting using the da637xxx systemAlertId if present
        system_alert_id = api_data.get("systemAlertId") or ""
        if system_alert_id:
            hunting_result = await _resolve_alert_hunting(token, system_alert_id)
            if hunting_result:
                return hunting_result

        # Fall back to parsing evidence from the API response directly
        evidence = api_data.get("evidence") or []
        hostname = ""
        pid = 0
        creation_time = None

        for ev in evidence:
            etype = ev.get("@odata.type", "")
            if "deviceEvidence" in etype and not hostname:
                hostname = (ev.get("deviceDnsName") or ev.get("deviceName") or "").split(".")[0]
            if "processEvidence" in etype and not pid:
                pid = int(ev.get("processId") or 0)
                creation_time = ev.get("processCreationDateTime")

        if hostname:
            return {"hostname": hostname, "pid": pid, "creation_time": creation_time}

    # Last resort: try AlertEvidence with the GUID directly (unlikely but costs nothing)
    return await _resolve_alert_hunting(token, alert_id)


async def _resolve_alert_hunting(token: str, alert_id: str) -> dict | None:
    """Resolve a da637xxx-format alert via the AlertEvidence hunting table."""
    safe_id = alert_id.replace('"', '').replace("'", '')
    kql = "\n".join([
        'AlertEvidence',
        f'| where AlertId == "{safe_id}"',
        '| where EntityType == "Process"',
        '| where isnotempty(DeviceName) and ProcessId > 0',
        '| project DeviceName, ProcessId, ProcessCreationTime',
        '| take 1',
    ])
    rows = await run_hunting_query(token, kql)
    if rows:
        r = rows[0]
        return {
            "hostname": (r.get("DeviceName") or "").split(".")[0],
            "pid": int(r.get("ProcessId") or 0),
            "creation_time": r.get("ProcessCreationTime"),
        }
    # Fallback: any device entity so we at least know the hostname
    kql2 = "\n".join([
        'AlertEvidence',
        f'| where AlertId == "{safe_id}"',
        '| where isnotempty(DeviceName)',
        '| project DeviceName',
        '| take 1',
    ])
    rows2 = await run_hunting_query(token, kql2)
    if rows2:
        return {
            "hostname": (rows2[0].get("DeviceName") or "").split(".")[0],
            "pid": 0,
            "creation_time": None,
        }
    return None


async def resolve_alert(token: str, alert_id: str) -> dict | None:
    """
    Look up an alert by ID and return the device + focal process.
    Supports:
      - GUID format (7d26a717-…): Graph Security alerts_v2 API + AlertEvidence fallback
      - da637xxx format: AlertEvidence hunting table
    Returns {hostname, pid, creation_time} or None if not found.
    Raises ValueError for clearly invalid formats (numeric-only).
    """
    safe_id = alert_id.strip().replace('"', '').replace("'", '')
    if safe_id.isdigit():
        raise ValueError(
            f"'{safe_id}' looks like an incident number, not an alert ID. "
            "Use the alert ID (da637xxx format from Advanced Hunting, or GUID from the Defender portal)."
        )
    if _UUID_RE.match(safe_id):
        return await _resolve_alert_guid(token, safe_id)
    return await _resolve_alert_hunting(token, safe_id)


async def get_device_info(token: str, hostname: str) -> dict:
    host = hostname.replace('"', '').replace("'", '')
    # arg_max keeps the freshest row per DeviceId. column_ifexists guards the
    # projection against schema variance — DefenderAvStatus, MachineGroup, and
    # OSVersionInfo aren't present on every tenant's DeviceInfo, and a missing
    # column otherwise fails the whole query with a 400.
    kql = "\n".join([
        'DeviceInfo',
        f'| where DeviceName contains "{host}"',
        '| extend IngestionTime = ingestion_time()',
        '| summarize arg_max(IngestionTime, *) by DeviceId',
        '| take 1',
        '| project',
        '    Timestamp, DeviceName, DeviceId,',
        '    OSPlatform, OSVersion, OSBuild,',
        '    OSArchitecture, ClientVersion, PublicIP,',
        '    ExposureLevel, OnboardingStatus, LoggedOnUsers,',
        '    IsAzureADJoined, SensorHealthState,',
        '    JoinType         = column_ifexists("JoinType", ""),',
        '    OSVersionInfo    = column_ifexists("OSVersionInfo", ""),',
        '    DeviceCategory   = column_ifexists("DeviceCategory", ""),',
        '    DeviceType       = column_ifexists("DeviceType", ""),',
        '    MachineGroup     = column_ifexists("MachineGroup", ""),',
        '    IsIsolated       = column_ifexists("IsIsolated", false),',
        '    DefenderAvStatus = column_ifexists("DefenderAvStatus", "")',
    ])
    rows = await run_hunting_query(token, kql)
    if not rows:
        return {}
    r = rows[0]

    # LoggedOnUsers comes back as a JSON string like
    # '[{"UserName":"alice","DomainName":"CORP","Sid":"..."}, ...]'. Reduce
    # to a comma-separated "DOMAIN\\user" list for the UI.
    raw_users = r.get("LoggedOnUsers")
    users_summary = ""
    if raw_users:
        try:
            parsed = raw_users if isinstance(raw_users, list) else json.loads(raw_users)
            parts: list[str] = []
            for u in parsed or []:
                if not isinstance(u, dict):
                    continue
                name = u.get("UserName") or ""
                domain = u.get("DomainName") or ""
                parts.append(f"{domain}\\{name}" if domain else name)
            users_summary = ", ".join([p for p in parts if p])
        except Exception:
            users_summary = str(raw_users)

    return {
        # Original fields — kept for backwards compatibility with existing UI.
        "os_platform": r.get("OSPlatform") or "",
        "os_version": r.get("OSVersion") or "",
        "os_build": str(r.get("OSBuild") or ""),
        "sensor_health": r.get("SensorHealthState") or "",
        "av_status": r.get("DefenderAvStatus") or "",
        "last_seen": r.get("Timestamp") or "",
        # Extended fields shown in the Host Details tab.
        "device_name":       r.get("DeviceName") or "",
        "device_id":         r.get("DeviceId") or "",
        "os_architecture":   r.get("OSArchitecture") or "",
        "os_version_info":   r.get("OSVersionInfo") or "",
        "client_version":    r.get("ClientVersion") or "",
        "public_ip":         r.get("PublicIP") or "",
        "exposure_level":    r.get("ExposureLevel") or "",
        "onboarding_status": r.get("OnboardingStatus") or "",
        "logged_on_users":   users_summary,
        "is_azure_ad_joined": r.get("IsAzureADJoined"),
        "join_type":         r.get("JoinType") or "",
        "device_category":   r.get("DeviceCategory") or "",
        "device_type":       r.get("DeviceType") or "",
        "machine_group":     r.get("MachineGroup") or "",
        "is_isolated":       r.get("IsIsolated"),
    }


async def get_network_adapters(token: str, hostname: str) -> list[dict]:
    """Return the latest network-adapter snapshot for the host, deduplicated.

    Driver renames or transient duplicates can produce multiple
    DeviceNetworkInfo rows for the same physical adapter (different
    NetworkAdapterName, same MacAddress). We keep the freshest row per
    MacAddress; rows with no MAC fall back to NetworkAdapterName as the
    dedup key. IPAddresses / DnsAddresses / DefaultGateways come back as
    JSON strings — parsed here so the UI sees plain lists/strings."""
    host = hostname.replace('"', '').replace("'", '')
    kql = "\n".join([
        'DeviceNetworkInfo',
        f'| where DeviceName contains "{host}"',
        '| extend IngestionTime = ingestion_time()',
        '| summarize arg_max(IngestionTime, *) by NetworkAdapterName, MacAddress',
        '| project',
        '    Timestamp, NetworkAdapterName, NetworkAdapterType,',
        '    NetworkAdapterStatus, MacAddress, IPAddresses, DnsAddresses,',
        '    DefaultGateways, ConnectedNetworks,',
        '    TunnelType = column_ifexists("TunnelType", ""),',
        '    IPv4Dhcp   = column_ifexists("IPv4Dhcp", ""),',
        '    IPv6Dhcp   = column_ifexists("IPv6Dhcp", "")',
        '| order by NetworkAdapterName asc',
    ])
    rows = await run_hunting_query(token, kql)

    def _parse_json(v):
        if not v:
            return []
        if isinstance(v, list):
            return v
        try:
            return json.loads(v)
        except Exception:
            return []

    adapters: list[dict] = []
    for r in rows or []:
        # IPAddresses comes back as a list of {IPAddress, SubnetPrefix, AddressType}.
        ip_entries = _parse_json(r.get("IPAddresses"))
        ips: list[dict] = []
        for ip in ip_entries:
            if isinstance(ip, dict):
                ips.append({
                    "ip":            ip.get("IPAddress") or "",
                    "subnet_prefix": ip.get("SubnetPrefix"),
                    "address_type":  ip.get("AddressType") or "",
                })

        # DnsAddresses, DefaultGateways, ConnectedNetworks can be lists of
        # strings or lists of dicts depending on tenant — coerce to strings.
        def _flatten(items):
            out: list[str] = []
            for it in items:
                if isinstance(it, str):
                    out.append(it)
                elif isinstance(it, dict):
                    name = it.get("Name") or it.get("Address") or it.get("IPAddress")
                    if name:
                        out.append(str(name))
            return out

        adapters.append({
            "name":        r.get("NetworkAdapterName") or "",
            "type":        r.get("NetworkAdapterType") or "",
            "status":      r.get("NetworkAdapterStatus") or "",
            "mac":         r.get("MacAddress") or "",
            "tunnel_type": r.get("TunnelType") or "",
            "ipv4_dhcp":   r.get("IPv4Dhcp") or "",
            "ipv6_dhcp":   r.get("IPv6Dhcp") or "",
            "ip_addresses":      ips,
            "dns_addresses":     _flatten(_parse_json(r.get("DnsAddresses"))),
            "default_gateways":  _flatten(_parse_json(r.get("DefaultGateways"))),
            "connected_networks": _flatten(_parse_json(r.get("ConnectedNetworks"))),
            "last_seen":   r.get("Timestamp") or "",
        })

    # Second-pass dedup: collapse rows that share a MacAddress (driver rename
    # or transient dupe) to the one with the freshest last_seen. Rows with an
    # empty MAC use NetworkAdapterName as the dedup key instead.
    best: dict[str, dict] = {}
    for a in adapters:
        key = (a.get("mac") or "").lower() or f"name:{(a.get('name') or '').lower()}"
        if key not in best or (a.get("last_seen") or "") > (best[key].get("last_seen") or ""):
            best[key] = a
    deduped = list(best.values())
    deduped.sort(key=lambda a: a.get("name") or "")
    return deduped


async def get_alerts(token: str, hostname: str) -> list[dict]:
    """Return the host's alerts from the last 30 days, deduplicated by AlertId
    (latest evidence row per alert kept via arg_max). Categories and
    AdditionalFields come back as JSON strings — parsed server-side so the UI
    sees an array and a dict respectively."""
    host = hostname.replace('"', '').replace("'", '')
    kql = "\n".join([
        'AlertEvidence',
        f'| where DeviceName =~ "{host}"',
        '| where Timestamp > ago(30d)',
        '| summarize arg_max(Timestamp, *) by AlertId',
        '| order by Timestamp desc',
        '| take 200',
        '| project Timestamp, AlertId, Title, Severity, Categories,',
        '          ServiceSource, DetectionSource, AdditionalFields',
    ])
    rows = await run_hunting_query(token, kql)

    def _parse_json(v):
        if v is None or v == "":
            return None
        if not isinstance(v, str):
            return v
        try:
            return json.loads(v)
        except Exception:
            return None

    alerts: list[dict] = []
    for r in rows or []:
        cats = _parse_json(r.get("Categories"))
        if not isinstance(cats, list):
            cats = [str(cats)] if cats else []
        add = _parse_json(r.get("AdditionalFields"))
        add_dict = add if isinstance(add, dict) else {}
        alerts.append({
            "timestamp":         r.get("Timestamp") or "",
            "alert_id":          r.get("AlertId") or "",
            "title":             r.get("Title") or "",
            "severity":          r.get("Severity") or "",
            "categories":        [str(c) for c in cats],
            "service_source":    r.get("ServiceSource") or "",
            "detection_source":  r.get("DetectionSource") or "",
            "last_verdict":      add_dict.get("LastVerdict") or "",
            "remediation_state": add_dict.get("LastRemediationState") or "",
            "additional_fields": add_dict,
        })
    return alerts


async def get_host_incidents(token: str, hostname: str) -> list[dict]:
    """Return Defender incidents this host was involved in over the last 30 days.

    Queries the Graph Security Incidents API directly:
      GET /v1.0/security/incidents?$filter=createdDateTime ge <30d ago>
          &$expand=alerts&$top=50
    The lambda filter `alerts/any(...)` against the alert's deviceEvidence is
    not reliably supported across tenants (the hostname lives inside the
    alert's nested evidence collection, not at the top level), so host
    matching is done in Python: for each incident, walk every alert's evidence
    list and check for a deviceEvidence entry whose hostName matches.

    Paginates @odata.nextLink up to a safety cap (10 pages × 50 = 500 incidents
    scanned) — well above what a normal SOC tenant produces in 30 days for one
    org-scope, but bounded so a noisy tenant doesn't hang the request.
    """
    host_lc   = hostname.replace('"', '').replace("'", '').lower()
    host_short = host_lc.split('.')[0]
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)) \
                .strftime("%Y-%m-%dT%H:%M:%SZ")

    def _is_match(ev: dict) -> bool:
        if not isinstance(ev, dict):
            return False
        otype = (ev.get("@odata.type") or "").lower()
        if "deviceevidence" not in otype:
            return False
        hn = (ev.get("hostName") or "").lower()
        if not hn:
            return False
        return hn == host_lc or hn.split('.')[0] == host_short

    out: list[dict] = []
    seen = 0
    url: str | None = f"{GRAPH_BASE}/security/incidents"
    params: dict | None = {
        "$filter": f"createdDateTime ge {cutoff}",
        "$expand": "alerts",
        "$top":    "50",
    }
    pages = 0

    while url and pages < 10:
        resp = await graph_request(
            "GET", url,
            token=token,
            params=params,
        )
        if resp.status_code == 403:
            raise PermissionError(
                "Graph API 403 on /security/incidents — the app registration is "
                "missing SecurityIncident.Read.All (Application permission). "
                "Add it in Entra → App registrations → API permissions → "
                "Microsoft Graph, then click Grant admin consent."
            )
        resp.raise_for_status()
        data = resp.json()
        for inc in data.get("value") or []:
            seen += 1
            # Walk every alert's evidence to find any deviceEvidence match.
            host_alerts: list[dict] = []
            earliest = ""
            latest = ""
            for a in inc.get("alerts") or []:
                matched_this_alert = False
                for ev in a.get("evidence") or []:
                    if _is_match(ev):
                        matched_this_alert = True
                        break
                if not matched_this_alert:
                    continue
                first = a.get("firstActivityDateTime") or a.get("createdDateTime") or ""
                last  = a.get("lastActivityDateTime")  or a.get("lastUpdateDateTime") or ""
                if first and (not earliest or first < earliest):
                    earliest = first
                if last and (not latest or last > latest):
                    latest = last
                mitre = a.get("mitreTechniques") or []
                host_alerts.append({
                    "id":               str(a.get("id") or ""),
                    "title":            a.get("title") or "",
                    "severity":         a.get("severity") or "",
                    "status":           a.get("status") or "",
                    "classification":   a.get("classification") or "",
                    "determination":    a.get("determination") or "",
                    "category":         a.get("category") or "",
                    "detection_source": a.get("detectionSource") or "",
                    "service_source":   a.get("serviceSource") or "",
                    "mitre_techniques": [str(m) for m in mitre],
                    "threat_display_name": a.get("threatDisplayName") or "",
                    "threat_family":    a.get("threatFamilyName") or "",
                    "first_activity":   first,
                    "last_activity":    last,
                    "alert_web_url":    a.get("alertWebUrl") or "",
                })
            if not host_alerts:
                continue
            comments_raw = inc.get("comments") or []
            comments = [
                {
                    "body":            c.get("comment") or "",
                    "created_by":      c.get("createdByDisplayName") or "",
                    "created_at":      c.get("createdDateTime") or "",
                }
                for c in comments_raw if isinstance(c, dict)
            ]
            out.append({
                "id":                str(inc.get("id") or ""),
                "display_name":      inc.get("displayName") or "",
                "severity":          inc.get("severity") or "",
                "status":            inc.get("status") or "",
                "classification":    inc.get("classification") or "",
                "determination":     inc.get("determination") or "",
                "assigned_to":       inc.get("assignedTo") or "",
                "created":           inc.get("createdDateTime") or "",
                "last_update":       inc.get("lastUpdateDateTime") or "",
                "incident_web_url":  inc.get("incidentWebUrl") or "",
                "redirect_incident_id": inc.get("redirectIncidentId") or "",
                "description":       inc.get("description") or "",
                "summary":           inc.get("summary") or "",
                "custom_tags":       inc.get("customTags") or [],
                "system_tags":       inc.get("systemTags") or [],
                "comments":          comments,
                "comments_count":    len(comments),
                "host_alert_count":  len(host_alerts),
                "host_alerts":       host_alerts,
                "host_earliest_seen": earliest,
                "host_latest_seen":   latest,
            })
        next_url = data.get("@odata.nextLink")
        # Only follow a nextLink that stays on Microsoft Graph — never send
        # the bearer token to an unexpected host.
        if next_url and not _is_graph_url(next_url):
            log.warning("Refusing off-host @odata.nextLink: %s", next_url)
            next_url = None
        url = next_url
        params = None  # nextLink already carries the query
        pages += 1

    # Most-recent first, capped at 50 displayed
    out.sort(key=lambda i: i.get("last_update") or i.get("created") or "", reverse=True)
    return out[:50]


_VALID_TELEMETRY_TABLES = frozenset({"network", "files", "registry", "dlls", "scripts"})


async def get_telemetry(
    token: str, hostname: str, pid: int, username: str,
    start: "datetime", end: "datetime", table: str,
) -> list[dict]:
    if table not in _VALID_TELEMETRY_TABLES:
        return []
    start_s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_s   = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    host    = hostname.replace('"', '').replace("'", '')
    uname   = username.replace('"', '').replace("'", '')

    if table == "network":
        # DeviceNetworkEvents has no separate ProcessId column (the row already
        # represents the initiating process) and no BytesSent / BytesReceived
        # — those don't exist in the standard MDE schema. Filter on
        # InitiatingProcessId only and project only fields that exist.
        kql = "\n".join([
            'DeviceNetworkEvents',
            f'| where DeviceName contains "{host}"',
            f'| where InitiatingProcessId == {pid}',
            f'| where Timestamp between (datetime({start_s}) .. datetime({end_s}))',
            '| project Timestamp, ActionType, RemoteIP, RemotePort, RemoteUrl, LocalPort, Protocol',
            '| order by Timestamp desc',
            '| take 200',
        ])
    elif table == "files":
        # DeviceFileEvents has only InitiatingProcessId — no separate ProcessId.
        kql = "\n".join([
            'DeviceFileEvents',
            f'| where DeviceName contains "{host}"',
            f'| where InitiatingProcessId == {pid}',
            f'| where Timestamp between (datetime({start_s}) .. datetime({end_s}))',
            '| project Timestamp, ActionType, FileName, FolderPath, SHA256, MD5',
            '| order by Timestamp desc',
            '| take 200',
        ])
    elif table == "registry":
        kql = "\n".join([
            'DeviceRegistryEvents',
            f'| where DeviceName contains "{host}"',
            f'| where InitiatingProcessId == {pid}',
            f'| where Timestamp between (datetime({start_s}) .. datetime({end_s}))',
            '| project Timestamp, ActionType, RegistryKey, PreviousRegistryKey, RegistryValueName, PreviousRegistryValueName, RegistryValueData, PreviousRegistryValueData',
            '| order by Timestamp asc',
            '| take 200',
        ])
    elif table == "scripts":
        # Behavioural events — script execution, AMSI bypasses, ETW tampering,
        # plus the broad "ProcessCreated"/"FileCreated" hooks. Useful for
        # spotting in-memory script activity that doesn't surface in the
        # narrower DeviceFileEvents / DeviceProcessEvents projections.
        kql = "\n".join([
            'DeviceEvents',
            f'| where DeviceName contains "{host}"',
            f'| where InitiatingProcessId == {pid} or ProcessId == {pid}',
            f'| where Timestamp between (datetime({start_s}) .. datetime({end_s}))',
            '| where ActionType in ("ScriptBlockLogged", "AmsiBypass", "EtWDisable", "ProcessCreated", "FileCreated")',
            '| project Timestamp, ActionType, FileName, ProcessCommandLine, AdditionalFields',
            '| order by Timestamp desc',
            '| take 200',
        ])
    elif table == "dlls":
        # DeviceImageLoadEvents only exposes InitiatingProcessId (the process
        # that loaded the image). No separate ProcessId column. Also no
        # IsSigned — image-load signing info is exposed via the related
        # DeviceFileCertificateInfo table, not directly on this one.
        kql = "\n".join([
            'DeviceImageLoadEvents',
            f'| where DeviceName contains "{host}"',
            f'| where InitiatingProcessId == {pid}',
            f'| where Timestamp between (datetime({start_s}) .. datetime({end_s}))',
            '| project Timestamp, FileName, FolderPath, SHA256, MD5, InitiatingProcessFileName',
            '| order by Timestamp desc',
            '| take 200',
        ])
    else:
        return []

    return await run_hunting_query(token, kql)
