from typing import Annotated
from fastapi import APIRouter, Cookie, HTTPException

from app.database import get_db
from app.encryption import decrypt_field, get_key
from app.security import get_session
from app.graph import get_graph_token, run_hunting_query, parse_time_window, build_process_map, get_device_info, get_network_adapters, get_alerts, get_host_incidents, get_telemetry, resolve_alert
from app.models import InvestigateRequest, TelemetryRequest
from app.audit import write_audit

router = APIRouter()


def _require_key(session_id: str | None) -> bytes:
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    key = get_key(session_id)
    if key is None:
        raise HTTPException(status_code=401, detail="Session expired.")
    return key


def _load_creds(db, key: bytes) -> dict:
    row = db.execute("SELECT * FROM credentials WHERE id=1").fetchone()
    if not row:
        return {}

    def _dec(val):
        if not val:
            return None
        try:
            return decrypt_field(val, key)
        except Exception:
            return None

    return {
        "tenant_id":     _dec(row["tenant_id"]),
        "client_id":     _dec(row["client_id"]),
        "client_secret": _dec(row["client_secret"]),
    }


def _err(code: str, msg: str | None = None) -> dict:
    return {
        "ok": False,
        "error_code": code,
        "error_message": msg,
        "nodes": {},
        "ancestry_chain": [],
        "focal_node_key": None,
        "pid_candidates": [],
        "clock_skew_seconds": 0,
    }


@router.get("/ping")
async def investigate_ping(session_id: Annotated[str | None, Cookie()] = None):
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    db = get_db()
    try:
        if not get_session(session_id, db):
            raise HTTPException(status_code=401, detail="Session expired.")
    finally:
        db.close()
    return {"ok": True}


@router.post("/process-tree")
async def process_tree(
    body: InvestigateRequest,
    session_id: Annotated[str | None, Cookie()] = None,
):
    key = _require_key(session_id)
    db = get_db()
    try:
        session = get_session(session_id, db)
        if not session:
            raise HTTPException(status_code=401, detail="Session expired.")
        creds = _load_creds(db, key)
        # Audit one row per investigation start. Captures the input
        # request shape — the focal pid / window / alert id — so the
        # audit log shows what the analyst was actually pivoting on.
        write_audit(
            db, action="investigation.start",
            user_id=int(session["user_id"]), username=session["username"],
            target=body.hostname or body.alert_id or "",
            detail={
                "hostname":    body.hostname,
                "focal_pid":   body.focal_pid,
                "alert_id":    body.alert_id,
                "time_window": body.time_window,
            },
        )
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return _err("CREDENTIALS_MISSING", "MDE credentials not configured.")

    try:
        token = await get_graph_token(
            creds["tenant_id"], creds["client_id"], creds["client_secret"]
        )
    except Exception as e:
        return _err("GRAPH_ERROR", str(e))

    # ── Alert-ID mode: resolve alert → get hostname + focal PID ─────────────
    focal_time_override = body.focal_time
    hostname_resolved = body.hostname
    focal_pid_resolved = body.focal_pid

    if body.alert_id:
        try:
            alert_info = await resolve_alert(token, body.alert_id)
        except ValueError as e:
            return _err("ALERT_NOT_FOUND", str(e))
        except PermissionError as e:
            return _err("GRAPH_ERROR", str(e))
        except Exception as e:
            return _err("GRAPH_ERROR", str(e))
        if not alert_info:
            return _err("ALERT_NOT_FOUND",
                        f"Alert '{body.alert_id}' not found. "
                        "Use the da637xxx format (from MDE Advanced Hunting) or a GUID "
                        "(from the Graph Security API / Microsoft Defender portal).")
        hostname_resolved = alert_info["hostname"]
        focal_pid_resolved = alert_info["pid"]
        if alert_info.get("creation_time"):
            focal_time_override = alert_info["creation_time"]

    try:
        start, end = parse_time_window(focal_time_override, body.time_window)
    except Exception:
        start, end = parse_time_window(None, "±1h")

    start_s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_s = end.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Strip any quotes from hostname
    host = hostname_resolved.replace('"', "").replace("'", "")

    # Quick existence check
    kql_ping = "\n".join([
        f'DeviceProcessEvents',
        f'| where DeviceName contains "{host}"',
        f'| where Timestamp between (datetime({start_s}) .. datetime({end_s}))',
        f'| take 1',
    ])
    try:
        if not await run_hunting_query(token, kql_ping):
            return _err("DEVICE_NOT_FOUND", f"No events for '{host}' in the selected time window.")
    except PermissionError as e:
        return _err("GRAPH_ERROR", str(e))
    except Exception as e:
        return _err("GRAPH_ERROR", str(e))

    # Main bulk query
    kql = "\n".join([
        f'DeviceProcessEvents',
        f'| where DeviceName contains "{host}"',
        f'| where Timestamp between (datetime({start_s}) .. datetime({end_s}))',
        f'| project Timestamp, ProcessId, ProcessCreationTime, ProcessUniqueId,',
        f'          FileName, FolderPath, ProcessCommandLine, AccountName,',
        f'          SHA1, SHA256, MD5,',
        f'          InitiatingProcessId, InitiatingProcessCreationTime, InitiatingProcessUniqueId,',
        f'          InitiatingProcessFileName, InitiatingProcessFolderPath,',
        f'          InitiatingProcessCommandLine, InitiatingProcessAccountName,',
        f'          InitiatingProcessSHA1, InitiatingProcessSHA256, InitiatingProcessMD5,',
        f'          InitiatingProcessParentId',
        f'| order by Timestamp asc',
        f'| take 2000',
    ])
    try:
        rows = await run_hunting_query(token, kql)
    except Exception as e:
        return _err("GRAPH_ERROR", str(e))

    if not rows:
        return _err("NO_DATA", "Device found but no process events returned.")

    result = build_process_map(rows, focal_pid_resolved, body.focal_node_key)
    limit_exceeded = len(rows) >= 2000

    if not result["focal_node_key"]:
        ec = "PID_AMBIGUOUS" if len(result["pid_candidates"]) > 1 else "PID_NOT_FOUND"
        return {
            "ok": False,
            "error_code": ec,
            "error_message": None,
            "clock_skew_seconds": 0,
            "nodes":              result["nodes"],
            "ancestry_chain":     result["ancestry_chain"],
            "focal_node_key":     result["focal_node_key"],
            "pid_candidates":     result["pid_candidates"],
            "resolved_hostname":  hostname_resolved if body.alert_id else None,
            "resolved_pid":       focal_pid_resolved if body.alert_id else None,
        }

    return {
        "ok": True,
        "error_code":       "LIMIT_EXCEEDED" if limit_exceeded else None,
        "error_message":    "2 000 process events returned — tree may be incomplete." if limit_exceeded else None,
        "clock_skew_seconds": 0,
        "nodes":            result["nodes"],
        "ancestry_chain":   result["ancestry_chain"],
        "focal_node_key":   result["focal_node_key"],
        "pid_candidates":   result["pid_candidates"],
        "resolved_hostname": hostname_resolved if body.alert_id else None,
        "resolved_pid":     focal_pid_resolved if body.alert_id else None,
    }


def _info_err(msg: str) -> dict:
    return {"ok": False, "error": msg, "os_platform": "", "os_version": "", "os_build": "", "sensor_health": "", "av_status": "", "last_seen": ""}


@router.get("/lookup")
async def lookup(
    q:    str,
    kind: str = "auto",   # 'auto' | 'hostname' | 'device_id'
    session_id: Annotated[str | None, Cookie()] = None,
):
    """Resolve a hostname or device ID to one or more DeviceInfo rows.

    Used by the Welcome screen so the analyst can search by either
    identifier. 'auto' kind infers from shape: a long hex/GUID string
    is treated as device_id, anything else as hostname.

    Returns up to 25 most-recently-seen matches so the analyst can
    disambiguate when one hostname maps to several devices (common in
    AAD-joined fleets where machines get renamed or re-imaged).
    """
    key = _require_key(session_id)
    db = get_db()
    try:
        if not get_session(session_id, db):
            raise HTTPException(status_code=401, detail="Session expired.")
        creds = _load_creds(db, key)
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return {"ok": False, "error": "CREDENTIALS_MISSING", "matches": []}

    raw = (q or "").strip()
    if not raw:
        return {"ok": False, "error": "Empty query.", "matches": []}

    # Infer kind when 'auto'. MDE device IDs are 40-char lowercase hex.
    resolved_kind = kind
    if resolved_kind == "auto":
        if len(raw) >= 32 and all(c in "0123456789abcdefABCDEF-" for c in raw):
            resolved_kind = "device_id"
        else:
            resolved_kind = "hostname"

    # Escape any double-quote in the query so the KQL string literal
    # stays valid. KQL strings don't support backslash escapes, so we
    # just strip quotes — the analyst's input shouldn't contain any.
    safe = raw.replace('"', "")

    if resolved_kind == "device_id":
        kql = (
            'DeviceInfo\n'
            f'| where DeviceId == "{safe.lower()}"\n'
            '| summarize arg_max(Timestamp, *) by DeviceId\n'
            '| project DeviceId, DeviceName, OSPlatform, OSVersion, '
            'PublicIP, MachineGroup, JoinType, ExposureLevel, '
            'OnboardingStatus, Timestamp\n'
            '| take 25'
        )
    else:
        # Hostname matching: case-insensitive contains so the analyst
        # can type a partial. summarize-by-DeviceId so we dedupe per
        # physical device (DeviceInfo is event-style — one row per
        # check-in, many rows per device).
        kql = (
            'DeviceInfo\n'
            f'| where DeviceName contains "{safe}"\n'
            '| summarize arg_max(Timestamp, *) by DeviceId\n'
            '| project DeviceId, DeviceName, OSPlatform, OSVersion, '
            'PublicIP, MachineGroup, JoinType, ExposureLevel, '
            'OnboardingStatus, Timestamp\n'
            '| top 25 by Timestamp desc'
        )

    try:
        token = await get_graph_token(creds["tenant_id"], creds["client_id"], creds["client_secret"])
        rows  = await run_hunting_query(token, kql)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(
            "Device lookup failed q=%r kind=%s: %s", raw, resolved_kind, e,
        )
        return {"ok": False, "error": str(e), "matches": []}

    matches = []
    for r in rows or []:
        matches.append({
            "device_id":         r.get("DeviceId") or "",
            "device_name":       r.get("DeviceName") or "",
            "os_platform":       r.get("OSPlatform") or "",
            "os_version":        r.get("OSVersion") or "",
            "public_ip":         r.get("PublicIP") or "",
            "machine_group":     r.get("MachineGroup") or "",
            "join_type":         r.get("JoinType") or "",
            "exposure_level":    r.get("ExposureLevel") or "",
            "onboarding_status": r.get("OnboardingStatus") or "",
            "last_seen":         r.get("Timestamp") or "",
        })

    return {
        "ok": True,
        "error": None,
        "resolved_kind": resolved_kind,
        "matches": matches,
    }


@router.get("/device-info")
async def device_info(
    hostname: str,
    session_id: Annotated[str | None, Cookie()] = None,
):
    key = _require_key(session_id)
    db = get_db()
    try:
        if not get_session(session_id, db):
            raise HTTPException(status_code=401, detail="Session expired.")
        creds = _load_creds(db, key)
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return _info_err("CREDENTIALS_MISSING")

    try:
        token = await get_graph_token(creds["tenant_id"], creds["client_id"], creds["client_secret"])
    except Exception as e:
        return _info_err(str(e))

    try:
        info = await get_device_info(token, hostname)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(
            "DeviceInfo query failed for hostname=%r: %s", hostname, e,
        )
        return _info_err(str(e))

    return {"ok": True, "error": None, **info}


@router.get("/network-adapters")
async def network_adapters(
    hostname: str,
    session_id: Annotated[str | None, Cookie()] = None,
):
    key = _require_key(session_id)
    db = get_db()
    try:
        if not get_session(session_id, db):
            raise HTTPException(status_code=401, detail="Session expired.")
        creds = _load_creds(db, key)
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return {"ok": False, "error": "CREDENTIALS_MISSING", "adapters": []}

    try:
        token = await get_graph_token(creds["tenant_id"], creds["client_id"], creds["client_secret"])
    except Exception as e:
        return {"ok": False, "error": str(e), "adapters": []}

    try:
        adapters = await get_network_adapters(token, hostname)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(
            "NetworkAdapter query failed for hostname=%r: %s", hostname, e,
        )
        return {"ok": False, "error": str(e), "adapters": []}

    return {"ok": True, "error": None, "adapters": adapters}


@router.get("/alerts")
async def alerts(
    hostname: str,
    session_id: Annotated[str | None, Cookie()] = None,
):
    key = _require_key(session_id)
    db = get_db()
    try:
        if not get_session(session_id, db):
            raise HTTPException(status_code=401, detail="Session expired.")
        creds = _load_creds(db, key)
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return {"ok": False, "error": "CREDENTIALS_MISSING", "alerts": []}

    try:
        token = await get_graph_token(creds["tenant_id"], creds["client_id"], creds["client_secret"])
    except Exception as e:
        return {"ok": False, "error": str(e), "alerts": []}

    try:
        items = await get_alerts(token, hostname)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(
            "Alerts query failed for hostname=%r: %s", hostname, e,
        )
        return {"ok": False, "error": str(e), "alerts": []}

    return {"ok": True, "error": None, "alerts": items}


@router.get("/incidents")
async def incidents(
    hostname: str,
    session_id: Annotated[str | None, Cookie()] = None,
):
    key = _require_key(session_id)
    db = get_db()
    try:
        if not get_session(session_id, db):
            raise HTTPException(status_code=401, detail="Session expired.")
        creds = _load_creds(db, key)
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return {"ok": False, "error": "CREDENTIALS_MISSING", "incidents": []}

    try:
        token = await get_graph_token(creds["tenant_id"], creds["client_id"], creds["client_secret"])
    except Exception as e:
        return {"ok": False, "error": str(e), "incidents": []}

    try:
        items = await get_host_incidents(token, hostname)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(
            "Incidents query failed for hostname=%r: %s", hostname, e,
        )
        return {"ok": False, "error": str(e), "incidents": []}

    return {"ok": True, "error": None, "incidents": items}


@router.post("/telemetry")
async def telemetry(
    body: TelemetryRequest,
    session_id: Annotated[str | None, Cookie()] = None,
):
    key = _require_key(session_id)
    db = get_db()
    try:
        if not get_session(session_id, db):
            raise HTTPException(status_code=401, detail="Session expired.")
        creds = _load_creds(db, key)
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return {"ok": False, "error": "CREDENTIALS_MISSING", "rows": []}

    try:
        token = await get_graph_token(creds["tenant_id"], creds["client_id"], creds["client_secret"])
    except Exception as e:
        return {"ok": False, "error": str(e), "rows": []}

    try:
        start, end = parse_time_window(body.focal_time, body.time_window)
    except Exception:
        start, end = parse_time_window(None, "±1h")

    try:
        rows = await get_telemetry(token, body.hostname, body.pid, body.username, start, end, body.table)
    except Exception as e:
        return {"ok": False, "error": str(e), "rows": []}

    return {"ok": True, "error": None, "rows": rows}
