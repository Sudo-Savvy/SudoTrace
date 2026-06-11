"""
Per-user investigation auto-save.

The analyst's in-progress investigation (host context, flags, IOCs, timeline
notes, analysis history) is serialised by the frontend and PUT here whenever
it changes. On the next login we surface a "resume previous investigation?"
dialog by reading it back.

We deliberately do NOT persist the process tree, incidents list, or device
info blobs — those re-fetch on resume so the analyst gets fresh data with
their flags / notes restored on top. Keeps the JSON blob small (the analyst
state itself is typically a few KB) and avoids serving stale telemetry on
recovery.
"""
import json
from typing import Annotated
from fastapi import APIRouter, Cookie, HTTPException, Body

from app.database import get_db
from app.security import get_session

router = APIRouter()

# Hard cap on the persisted blob — if the analyst flags so many things they
# generate hundreds of KB of JSON, something has gone wrong and we'd rather
# reject the write than fill SQLite with runaway state.
_MAX_STATE_BYTES = 1_000_000


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


@router.get("/state")
async def get_state(session_id: Annotated[str | None, Cookie()] = None) -> dict:
    """Return the analyst's last saved investigation state, or null if none."""
    user_id = _require_user(session_id)
    db = get_db()
    try:
        row = db.execute(
            "SELECT state_json, updated_at FROM investigation_state WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    finally:
        db.close()
    if not row:
        return {"state": None, "updated_at": None}
    try:
        state = json.loads(row["state_json"])
    except json.JSONDecodeError:
        # Corrupted blob — treat as "no saved state" rather than 500ing the UI.
        return {"state": None, "updated_at": None}
    return {"state": state, "updated_at": row["updated_at"]}


@router.put("/state")
async def put_state(
    payload: dict = Body(...),
    session_id: Annotated[str | None, Cookie()] = None,
) -> dict:
    """Overwrite the analyst's saved investigation state."""
    user_id = _require_user(session_id)
    state_json = json.dumps(payload, separators=(",", ":"))
    if len(state_json.encode("utf-8")) > _MAX_STATE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Investigation state is too large to auto-save. Trim flagged items or analysis history.",
        )
    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO investigation_state (user_id, state_json, updated_at)
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


@router.delete("/state")
async def delete_state(session_id: Annotated[str | None, Cookie()] = None) -> dict:
    """Drop the analyst's saved state — used when they pick 'Start fresh'."""
    user_id = _require_user(session_id)
    db = get_db()
    try:
        db.execute("DELETE FROM investigation_state WHERE user_id = ?", (user_id,))
        db.commit()
    finally:
        db.close()
    return {"ok": True}
