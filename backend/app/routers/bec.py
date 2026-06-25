"""
BEC / account-compromise module — Phase 1 (access-origin triage).

Resolves a suspected-compromised account and pulls its recent sign-ins from
Entra (/auditLogs/signIns), then aggregates them into the access-origin
triage table the analyst uses to separate the attacker's sessions from the
legitimate user's.

Read-only. Microsoft Graph only. Degrades gracefully (with a precise reason)
when a required permission or licence tier is absent, rather than 500ing.
"""
import json
import logging
from typing import Annotated
from fastapi import APIRouter, Cookie, HTTPException, Body

from app.database import get_db
from app.encryption import decrypt_field, get_key
from app.security import get_session
from app.audit import write_audit
from app.graph import get_graph_token, parse_time_window
from app.graph_identity import (
    resolve_user, get_signins, build_access_origins,
    get_directory_audits, classify_persistence,
    query_unified_audit, classify_ual,
    hunt_objective_email, classify_objective,
    get_risk_state, get_risk_detections, get_directory_roles,
    hunt_subjects_for_messages,
)
from app.models import (
    BecSigninsRequest, BecScopeRequest, BecEnrichRequest, BecWatchRequest,
    BecCommsRequest,
)
from app import claude

log = logging.getLogger(__name__)
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


def _err(code: str, msg: str) -> dict:
    return {"ok": False, "error_code": code, "error_message": msg,
            "account": None, "origins": [], "anomalies": {}}


@router.post("/signins")
async def signins(
    body: BecSigninsRequest,
    session_id: Annotated[str | None, Cookie()] = None,
):
    key = _require_key(session_id)
    db = get_db()
    try:
        sess = get_session(session_id, db)
        if not sess:
            raise HTTPException(status_code=401, detail="Session expired.")
        creds = _load_creds(db, key)
        write_audit(
            db, action="bec.signins",
            user_id=int(sess["user_id"]), username=sess["username"],
            target=body.account or "",
            detail={"time_window": body.time_window},
        )
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return _err("CREDENTIALS_MISSING", "MDE / Entra credentials not configured. Add them in Settings.")

    account = (body.account or "").strip()
    if not account:
        return _err("NO_ACCOUNT", "Enter a UPN (user@domain) or Entra object id.")

    try:
        token = await get_graph_token(creds["tenant_id"], creds["client_id"], creds["client_secret"])
    except Exception as e:
        log.warning("Graph token acquisition failed: %s", e)
        return _err("GRAPH_ERROR", "Could not connect to Microsoft Graph. Check the credentials in Settings.")

    # Resolve the account first — gives us the object id the sign-in filter
    # needs, plus accountEnabled (early containment signal).
    try:
        user = await resolve_user(token, account)
    except PermissionError as e:
        return _err("DIRECTORY_FORBIDDEN", str(e))
    except Exception as e:
        log.warning("User resolve failed for %r: %s", account, e)
        return _err("GRAPH_ERROR", "Could not resolve the account against Entra.")
    if not user:
        return _err("ACCOUNT_NOT_FOUND", f"No Entra user found for '{account}'.")

    try:
        start, end = parse_time_window(None, body.time_window)
    except Exception:
        start, end = parse_time_window(None, "last7d")

    try:
        raw = await get_signins(token, user["id"], start, end)
    except PermissionError as e:
        # Account resolved fine; only the sign-in pull is gated. Return the
        # account context so the UI can still show who we're looking at,
        # plus the precise reason (missing AuditLog.Read.All or no P1/P2).
        return {
            "ok": False, "error_code": "SIGNINS_FORBIDDEN", "error_message": str(e),
            "account": _account_view(user), "origins": [], "anomalies": {},
        }
    except Exception as e:
        log.warning("Sign-in pull failed for %r: %s", account, e)
        return _err("GRAPH_ERROR", "Could not pull sign-in logs from Entra.")

    agg = build_access_origins(raw)
    return {
        "ok": True,
        "error_code": None,
        "error_message": None,
        "account": _account_view(user),
        "signin_count": len(raw),
        "window": {"start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "end": end.strftime("%Y-%m-%dT%H:%M:%SZ")},
        "origins": agg["origins"],
        "anomalies": agg["anomalies"],
    }


def _account_view(user: dict) -> dict:
    return {
        "id":              user.get("id"),
        "display_name":    user.get("displayName"),
        "upn":             user.get("userPrincipalName"),
        "account_enabled": user.get("accountEnabled"),
        "mail":            user.get("mail"),
        "job_title":       user.get("jobTitle"),
        "created":         user.get("createdDateTime"),
        "on_prem_synced":  user.get("onPremisesSyncEnabled"),
        "sessions_valid_from": user.get("signInSessionsValidFromDateTime"),
    }


async def _enrich_mail_read_subjects(token: str, recon_findings: list, end) -> None:
    """Resolve the InternetMessageIds behind each mailbox-read finding to the
    actual subjects (via EmailEvents) and fold them into the finding's detail —
    answering 'what did the attacker read'. Best-effort; never fails the scope."""
    all_ids: list[str] = []
    for f in recon_findings:
        if f.get("category") == "mail_read":
            all_ids.extend(f.get("message_ids") or [])
    id_subj: dict = {}
    if all_ids:
        try:
            id_subj = await hunt_subjects_for_messages(token, list(dict.fromkeys(all_ids)), end)
        except Exception as e:
            log.warning("Mail-read subject enrichment failed: %s", e)

    for f in recon_findings:
        if f.get("category") != "mail_read":
            f.pop("message_ids", None)
            f.pop("access_type", None)
            continue
        mids = f.get("message_ids") or []
        subs = [id_subj[m] for m in mids if m in id_subj]
        if subs:
            f["detail"] = "read: " + " · ".join(f'“{s}”' for s in subs[:8]) + \
                          (f" +{len(subs) - 8} more" if len(subs) > 8 else "")
        elif (f.get("access_type") or "").lower() == "sync":
            f["detail"] = "synced the entire folder (bulk read of all items)"
        elif mids:
            f["detail"] = (f"{len(mids)} message(s) opened — subjects not resolvable "
                           "(older than 30 days or internal-only mail)")
        # Drop the (potentially large) id list before returning to the client.
        f.pop("message_ids", None)
        f.pop("access_type", None)


# Still-deferred categories (data source not wired yet).
_DEFERRED_CATEGORIES: dict[str, str] = {}


@router.post("/scope")
async def scope(
    body: BecScopeRequest,
    session_id: Annotated[str | None, Cookie()] = None,
):
    """Scope attacker activity for the account within the selected window.
    Phase-1 of Milestone B: persistence via directory audit (live now);
    mailbox/exfil/objective returned as needs-permission until their data
    sources are wired."""
    key = _require_key(session_id)
    db = get_db()
    try:
        sess = get_session(session_id, db)
        if not sess:
            raise HTTPException(status_code=401, detail="Session expired.")
        creds = _load_creds(db, key)
        write_audit(
            db, action="bec.scope",
            user_id=int(sess["user_id"]), username=sess["username"],
            target=body.account or "", detail={"time_window": body.time_window},
        )
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return {"ok": False, "error_code": "CREDENTIALS_MISSING",
                "error_message": "Entra credentials not configured.", "findings": {}}

    try:
        token = await get_graph_token(creds["tenant_id"], creds["client_id"], creds["client_secret"])
    except Exception as e:
        log.warning("Graph token acquisition failed: %s", e)
        return {"ok": False, "error_code": "GRAPH_ERROR",
                "error_message": "Could not connect to Microsoft Graph.", "findings": {}}

    try:
        user = await resolve_user(token, (body.account or "").strip())
    except PermissionError as e:
        return {"ok": False, "error_code": "DIRECTORY_FORBIDDEN",
                "error_message": str(e), "findings": {}}
    except Exception as e:
        log.warning("User resolve failed: %s", e)
        return {"ok": False, "error_code": "GRAPH_ERROR",
                "error_message": "Could not resolve the account.", "findings": {}}
    if not user:
        return {"ok": False, "error_code": "ACCOUNT_NOT_FOUND",
                "error_message": f"No Entra user found for '{body.account}'.", "findings": {}}

    try:
        start, end = parse_time_window(None, body.time_window)
    except Exception:
        start, end = parse_time_window(None, "last7d")

    findings: dict = {}

    # Persistence + defence/policy tampering — both live via directory audit.
    try:
        audits = await get_directory_audits(token, user["id"], start, end)
        pbuckets = classify_persistence(audits)
        findings["persistence"] = {"available": True, "events": pbuckets["persistence"]}
        findings["defense"]     = {"available": True, "events": pbuckets["defense"]}
    except PermissionError as e:
        findings["persistence"] = {"available": False, "reason": str(e), "events": []}
        findings["defense"]     = {"available": False, "reason": str(e), "events": []}
    except Exception as e:
        log.warning("Persistence hunt failed: %s", e)
        msg = "Could not pull directory audit events from Entra."
        findings["persistence"] = {"available": False, "reason": msg, "events": []}
        findings["defense"]     = {"available": False, "reason": msg, "events": []}

    # Mailbox manipulation, exfiltration, recon (read/search) and anti-forensics
    # — all via one Unified Audit Log query, split into buckets. Degrades to a
    # precise needs-permission / still-running message rather than failing scope.
    upn = user.get("userPrincipalName") or body.account
    _UAL_BUCKETS = ("mailbox", "exfil", "recon", "antiforensic")
    try:
        ual = await query_unified_audit(token, upn, start, end)
        buckets = classify_ual(ual)
        # Enrich mailbox-read findings with the SUBJECTS of the messages opened —
        # resolve the InternetMessageIds from MailItemsAccessed via EmailEvents.
        await _enrich_mail_read_subjects(token, buckets.get("recon", []), end)
        for name in _UAL_BUCKETS:
            findings[name] = {"available": True, "events": buckets.get(name, [])}
    except PermissionError as e:
        for name in _UAL_BUCKETS:
            findings[name] = {"available": False, "reason": str(e), "events": []}
    except TimeoutError:
        msg = ("The unified audit log query is still running (these can take a "
               "minute on a busy tenant) — fetching automatically, or re-run Scope.")
        for name in _UAL_BUCKETS:
            findings[name] = {"available": False, "reason": msg, "events": []}
    except Exception as e:
        log.warning("UAL hunt failed: %s", e)
        msg = "Could not query the unified audit log."
        for name in _UAL_BUCKETS:
            findings[name] = {"available": False, "reason": msg, "events": []}

    # Action on objectives — outbound mail-sent / thread-hijack via EmailEvents
    # (advanced hunting, on the ThreatHunting.Read.All permission already in use).
    try:
        rows = await hunt_objective_email(token, upn, start, end)
        findings["objective"] = {"available": True, "events": classify_objective(rows)}
    except PermissionError as e:
        findings["objective"] = {"available": False, "reason": str(e), "events": []}
    except Exception as e:
        log.warning("Objective hunt failed: %s", e)
        findings["objective"] = {
            "available": False,
            "reason": "Could not run the EmailEvents hunt against advanced hunting.",
            "events": [],
        }

    # Categories not yet sourced.
    for cat, reason in _DEFERRED_CATEGORIES.items():
        findings[cat] = {"available": False, "reason": reason, "events": []}

    return {
        "ok": True,
        "error_code": None,
        "error_message": None,
        "account": _account_view(user),
        "window": {"start": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "end": end.strftime("%Y-%m-%dT%H:%M:%SZ")},
        "findings": findings,
    }


@router.post("/enrich")
async def enrich(
    body: BecEnrichRequest,
    session_id: Annotated[str | None, Cookie()] = None,
):
    """Identity Protection risk + directory-role / PIM enrichment for the
    account. Each source degrades independently (P2 / permission gated) so a
    missing licence on one doesn't blank the others."""
    key = _require_key(session_id)
    db = get_db()
    try:
        sess = get_session(session_id, db)
        if not sess:
            raise HTTPException(status_code=401, detail="Session expired.")
        creds = _load_creds(db, key)
        write_audit(
            db, action="bec.enrich",
            user_id=int(sess["user_id"]), username=sess["username"],
            target=body.account or "", detail=None,
        )
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return {"ok": False, "error_code": "CREDENTIALS_MISSING",
                "error_message": "Entra credentials not configured.",
                "risk": None, "roles": None}

    try:
        token = await get_graph_token(creds["tenant_id"], creds["client_id"], creds["client_secret"])
    except Exception as e:
        log.warning("Graph token acquisition failed: %s", e)
        return {"ok": False, "error_code": "GRAPH_ERROR",
                "error_message": "Could not connect to Microsoft Graph.",
                "risk": None, "roles": None}

    try:
        user = await resolve_user(token, (body.account or "").strip())
    except PermissionError as e:
        return {"ok": False, "error_code": "DIRECTORY_FORBIDDEN",
                "error_message": str(e), "risk": None, "roles": None}
    except Exception as e:
        log.warning("User resolve failed: %s", e)
        return {"ok": False, "error_code": "GRAPH_ERROR",
                "error_message": "Could not resolve the account.", "risk": None, "roles": None}
    if not user:
        return {"ok": False, "error_code": "ACCOUNT_NOT_FOUND",
                "error_message": f"No Entra user found for '{body.account}'.",
                "risk": None, "roles": None}

    # Identity Protection — risky-user state + detections.
    risk: dict
    try:
        state = await get_risk_state(token, user["id"])
        detections = await get_risk_detections(token, user["id"])
        risk = {"available": True, "state": state, "detections": detections}
    except PermissionError as e:
        risk = {"available": False, "reason": str(e), "state": None, "detections": []}
    except Exception as e:
        log.warning("Risk enrichment failed: %s", e)
        risk = {"available": False,
                "reason": "Could not pull Identity Protection risk data.",
                "state": None, "detections": []}

    # Directory roles — active + PIM-eligible.
    roles: dict
    try:
        r = await get_directory_roles(token, user["id"])
        roles = {"available": True, "active": r["active"], "eligible": r["eligible"]}
    except PermissionError as e:
        roles = {"available": False, "reason": str(e), "active": [], "eligible": []}
    except Exception as e:
        log.warning("Role enrichment failed: %s", e)
        roles = {"available": False,
                 "reason": "Could not pull directory-role assignments.",
                 "active": [], "eligible": []}

    return {
        "ok": True, "error_code": None, "error_message": None,
        "account": _account_view(user),
        "risk": risk, "roles": roles,
    }


def _parse_iso(ts: str | None):
    if not ts:
        return None
    try:
        from datetime import datetime as _dt
        return _dt.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


@router.post("/watch")
async def watch(
    body: BecWatchRequest,
    session_id: Annotated[str | None, Cookie()] = None,
):
    """Containment-invariant re-check (§5). Containment is performed out-of-band;
    this verifies it holds: the account is disabled AND no session survived the
    token-revocation watermark (a successful sign-in after it = the attacker
    still has working access). Read-only — it verifies, it does not execute."""
    key = _require_key(session_id)
    db = get_db()
    try:
        sess = get_session(session_id, db)
        if not sess:
            raise HTTPException(status_code=401, detail="Session expired.")
        creds = _load_creds(db, key)
        write_audit(
            db, action="bec.watch",
            user_id=int(sess["user_id"]), username=sess["username"],
            target=body.account or "", detail=None,
        )
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return {"ok": False, "error_code": "CREDENTIALS_MISSING",
                "error_message": "Entra credentials not configured."}

    try:
        token = await get_graph_token(creds["tenant_id"], creds["client_id"], creds["client_secret"])
    except Exception as e:
        log.warning("Graph token acquisition failed: %s", e)
        return {"ok": False, "error_code": "GRAPH_ERROR",
                "error_message": "Could not connect to Microsoft Graph."}

    try:
        user = await resolve_user(token, (body.account or "").strip())
    except PermissionError as e:
        return {"ok": False, "error_code": "DIRECTORY_FORBIDDEN", "error_message": str(e)}
    except Exception as e:
        log.warning("User resolve failed: %s", e)
        return {"ok": False, "error_code": "GRAPH_ERROR",
                "error_message": "Could not resolve the account."}
    if not user:
        return {"ok": False, "error_code": "ACCOUNT_NOT_FOUND",
                "error_message": f"No Entra user found for '{body.account}'."}

    acct = _account_view(user)
    account_disabled = acct["account_enabled"] is False
    valid_from = _parse_iso(acct.get("sessions_valid_from"))
    created = _parse_iso(acct.get("created"))

    # signInSessionsValidFromDateTime defaults to the account-creation time and
    # only moves forward when an admin revokes sessions. If it's still at (or
    # within a few seconds of) creation, NO revocation has happened — the
    # session invariant cannot be "holding", it's simply unmet.
    sessions_revoked = bool(
        valid_from and (created is None or abs((valid_from - created).total_seconds()) > 5)
    )

    # Spot any successful session that post-dates the revocation watermark (=
    # access re-established / token still live). 30-day window matches sign-in
    # log retention so we don't miss a survivor from earlier in the incident.
    breaches: list[dict] = []
    signins_available = True
    signins_reason = None
    if sessions_revoked:
        try:
            start, end = parse_time_window(None, "last30d")
            raw = await get_signins(token, user["id"], start, end)
            for si in raw:
                status = si.get("status") or {}
                ok_sign = status.get("errorCode") in (0, None) and not status.get("failureReason")
                ts = _parse_iso(si.get("createdDateTime"))
                if ok_sign and ts and valid_from and ts > valid_from:
                    loc = si.get("location") or {}
                    breaches.append({
                        "ip":        si.get("ipAddress") or "",
                        "timestamp": si.get("createdDateTime") or "",
                        "country":   loc.get("countryOrRegion") or "",
                        "city":      loc.get("city") or "",
                    })
        except PermissionError as e:
            signins_available = False
            signins_reason = str(e)
        except Exception as e:
            log.warning("Watch sign-in pull failed: %s", e)
            signins_available = False
            signins_reason = "Could not pull sign-in logs to verify the session invariant."

    breaches.sort(key=lambda b: b["timestamp"], reverse=True)
    # Sessions hold only if they were actually revoked, we could check, and no
    # successful sign-in post-dates the revocation.
    sessions_holding = sessions_revoked and signins_available and len(breaches) == 0
    invariants_held = account_disabled and sessions_holding

    return {
        "ok": True, "error_code": None, "error_message": None,
        "account": acct,
        "checked_at": parse_time_window(None, "last7d")[1].strftime("%Y-%m-%dT%H:%M:%SZ"),
        "invariants": {
            "account_disabled":   account_disabled,
            "sessions_valid_from": acct.get("sessions_valid_from"),
            "sessions_revoked":   sessions_revoked,
            "sessions_available": signins_available,
            "sessions_reason":    signins_reason,
            "sessions_holding":   sessions_holding,
            "breaches":           breaches,
            "held":               invariants_held,
        },
    }


@router.post("/comms")
async def comms(
    body: BecCommsRequest,
    session_id: Annotated[str | None, Cookie()] = None,
):
    """Draft a client / stakeholder / affected-user notification from the case
    facts the analyst assembled. AI-assisted (Haiku default); token usage logged.
    Returns a DRAFT for the analyst to review and edit — nothing is sent."""
    key = _require_key(session_id)
    db = get_db()
    try:
        sess = get_session(session_id, db)
        if not sess:
            raise HTTPException(status_code=401, detail="Session expired.")
        row = db.execute("SELECT * FROM credentials WHERE id=1").fetchone()
        anthropic_key = None
        if row:
            try:
                anthropic_key = decrypt_field(row["anthropic_key"], key) if row["anthropic_key"] else None
            except Exception:
                anthropic_key = None

        if not anthropic_key:
            return {"ok": False, "error_code": "NO_ANTHROPIC_KEY",
                    "error_message": "Anthropic API key not configured. Add it in Settings.",
                    "draft": None}

        facts = (body.facts or "").strip()
        if not facts:
            return {"ok": False, "error_code": "NO_FACTS",
                    "error_message": "No case facts to draft from — run triage / scope first.",
                    "draft": None}

        try:
            result = await claude.draft_comms(
                anthropic_key=anthropic_key,
                audience=body.audience,
                facts=facts,
                investigation_id=body.account or "bec",
                db=db,
            )
        except RuntimeError as e:
            if "AI_UNAVAILABLE" in str(e):
                return {"ok": False, "error_code": "AI_UNAVAILABLE",
                        "error_message": "AI service is currently unavailable. Please try again.",
                        "draft": None}
            log.warning("Comms drafting failed: %s", e)
            return {"ok": False, "error_code": "COMMS_FAILED",
                    "error_message": "The notification draft could not be generated.",
                    "draft": None}

        usage = result.get("token_usage") or {}
        write_audit(
            db, action="bec.comms",
            user_id=int(sess["user_id"]), username=sess["username"],
            target=body.account or "",
            detail={"audience": body.audience,
                    "input_tokens": usage.get("input_tokens"),
                    "output_tokens": usage.get("output_tokens"),
                    "cost_usd": usage.get("cost_usd"),
                    "model": usage.get("model")},
        )
        return {"ok": True, "error_code": None, "error_message": None,
                "draft": result["text"], "token_usage": usage}
    finally:
        db.close()


# ── Case auto-save (Milestone C) ────────────────────────────────────────────
# A BEC case (account, suspected IP, window, selected origins, checklist ticks +
# notes) is serialised by the frontend and PUT here so a reload resumes it.
# One active case per analyst, mirroring investigation_state. The findings/
# triage tables are NOT persisted — they re-fetch from Graph on resume so the
# analyst gets fresh data with their selections + notes restored on top.
_MAX_CASE_BYTES = 500_000


def _require_user(session_id: str | None) -> int:
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    db = get_db()
    try:
        sess = get_session(session_id, db)
        if not sess:
            raise HTTPException(status_code=401, detail="Session expired.")
        return int(sess["user_id"])
    finally:
        db.close()


@router.get("/case")
async def get_case(session_id: Annotated[str | None, Cookie()] = None) -> dict:
    """Return the analyst's saved BEC case, or null if none."""
    user_id = _require_user(session_id)
    db = get_db()
    try:
        row = db.execute(
            "SELECT state_json, updated_at FROM bec_case_state WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    finally:
        db.close()
    if not row:
        return {"case": None, "updated_at": None}
    try:
        case = json.loads(row["state_json"])
    except json.JSONDecodeError:
        return {"case": None, "updated_at": None}
    return {"case": case, "updated_at": row["updated_at"]}


@router.put("/case")
async def put_case(
    payload: dict = Body(...),
    session_id: Annotated[str | None, Cookie()] = None,
) -> dict:
    """Overwrite the analyst's saved BEC case."""
    user_id = _require_user(session_id)
    state_json = json.dumps(payload, separators=(",", ":"))
    if len(state_json.encode("utf-8")) > _MAX_CASE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="BEC case state is too large to auto-save. Trim notes or selections.",
        )
    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO bec_case_state (user_id, state_json, updated_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(user_id) DO UPDATE SET
                state_json = excluded.state_json,
                updated_at = excluded.updated_at
            """,
            (user_id, state_json),
        )
        db.commit()
    finally:
        db.close()
    return {"ok": True}


@router.delete("/case")
async def delete_case(session_id: Annotated[str | None, Cookie()] = None) -> dict:
    """Drop the analyst's saved BEC case — used when they close it / start fresh."""
    user_id = _require_user(session_id)
    db = get_db()
    try:
        db.execute("DELETE FROM bec_case_state WHERE user_id = ?", (user_id,))
        db.commit()
    finally:
        db.close()
    return {"ok": True}
