"""
Read-only observability endpoints for the Settings → Usage / Audit panels:

  GET /api/admin/token-usage  — recent AI calls + per-window totals
  GET /api/admin/audit-log    — recent audited events

Both endpoints require an authenticated session. Single-user system for
now (one root user) so we don't bother gating by role; if the user
table grows past one row, add an "is_admin" check here.
"""
import json
from typing import Annotated
from fastapi import APIRouter, Cookie, HTTPException

from app.database import get_db
from app.security import get_session

router = APIRouter()


def _require_user(session_id: str | None) -> tuple[int, str]:
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    db = get_db()
    try:
        sess = get_session(session_id, db)
        if not sess:
            raise HTTPException(status_code=401, detail="Session expired.")
        return int(sess["user_id"]), sess["username"]
    finally:
        db.close()


@router.get("/token-usage")
async def token_usage(
    limit: int = 50,
    session_id: Annotated[str | None, Cookie()] = None,
) -> dict:
    """Return recent AI calls + rolling totals for last 24h / 7d / 30d."""
    _require_user(session_id)
    limit = max(1, min(int(limit), 500))
    db = get_db()
    try:
        rows = db.execute(
            """
            SELECT id, timestamp, investigation_id, action, model,
                   input_tokens, output_tokens, cached_tokens,
                   cost_usd, duration_ms, chunks
            FROM token_usage
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        recent = [dict(r) for r in rows]

        totals = {}
        for window_label, sql_window in (
            ("last24h", "datetime('now', '-1 day')"),
            ("last7d",  "datetime('now', '-7 days')"),
            ("last30d", "datetime('now', '-30 days')"),
            ("alltime", "datetime('1970-01-01')"),
        ):
            agg = db.execute(
                f"""
                SELECT
                    COUNT(*)                       AS calls,
                    COALESCE(SUM(input_tokens), 0)  AS input_tokens,
                    COALESCE(SUM(output_tokens), 0) AS output_tokens,
                    COALESCE(SUM(cached_tokens), 0) AS cached_tokens,
                    COALESCE(SUM(cost_usd), 0)     AS cost_usd
                FROM token_usage
                WHERE timestamp >= {sql_window}
                """
            ).fetchone()
            totals[window_label] = dict(agg)
    finally:
        db.close()
    return {"recent": recent, "totals": totals}


@router.get("/audit-log")
async def audit_log(
    limit:  int = 100,
    action: str | None = None,
    session_id: Annotated[str | None, Cookie()] = None,
) -> dict:
    """Return the most recent audited events, newest first. Optionally
    filtered by exact action string."""
    _require_user(session_id)
    limit = max(1, min(int(limit), 1000))
    db = get_db()
    try:
        if action:
            rows = db.execute(
                """
                SELECT id, timestamp, user_id, username, action, target, ip, detail
                FROM audit_log
                WHERE action = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (action, limit),
            ).fetchall()
        else:
            rows = db.execute(
                """
                SELECT id, timestamp, user_id, username, action, target, ip, detail
                FROM audit_log
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        # Decode the detail JSON so the frontend doesn't have to nest a
        # second parse call. Invalid blobs are surfaced as null rather
        # than blowing the response.
        entries: list[dict] = []
        for r in rows:
            d = dict(r)
            raw = d.pop("detail", None)
            if raw:
                try:
                    d["detail"] = json.loads(raw)
                except json.JSONDecodeError:
                    d["detail"] = None
            else:
                d["detail"] = None
            entries.append(d)
        # Distinct action list for the filter dropdown.
        actions = [
            r["action"] for r in db.execute(
                "SELECT DISTINCT action FROM audit_log ORDER BY action ASC"
            ).fetchall()
        ]
    finally:
        db.close()
    return {"entries": entries, "actions": actions}
