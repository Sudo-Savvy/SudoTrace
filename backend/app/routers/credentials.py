import asyncio
from typing import Annotated

from fastapi import APIRouter, Cookie, HTTPException

from app.database import get_db
from app.encryption import decrypt_field, encrypt_field, get_key
from app.mde import test_anthropic_connection, test_graph_connection
from app.models import CredentialsRequest, TestConnectionsRequest
from app.security import get_session
from app.audit import write_audit

router = APIRouter()


def _require_key(session_id: str | None) -> bytes:
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    key = get_key(session_id)
    if key is None:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    return key


def _require_session(session_id: str | None, db):
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    session = get_session(session_id, db)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired.")
    return session


@router.get("/status")
async def credentials_status(session_id: Annotated[str | None, Cookie()] = None):
    """Returns whether credentials are configured — no key required, session only."""
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    db = get_db()
    try:
        _require_session(session_id, db)
        row = db.execute(
            "SELECT tenant_id FROM credentials WHERE id=1"
        ).fetchone()
        return {"configured": bool(row and row["tenant_id"])}
    finally:
        db.close()


@router.get("")
async def get_credentials(session_id: Annotated[str | None, Cookie()] = None):
    key = _require_key(session_id)
    db = get_db()
    try:
        _require_session(session_id, db)
        row = db.execute("SELECT * FROM credentials WHERE id=1").fetchone()
        if not row:
            return {"tenant_id": None, "client_id": None, "client_secret": None, "anthropic_key": None, "vt_api_key": None}

        def _dec(val):
            # Tolerate decrypt failures (e.g. ciphertext written under an
            # older KDF work factor, or a password mismatch) so the
            # Settings page loads with the field blank rather than 500ing.
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
            "anthropic_key": _dec(row["anthropic_key"]),
            "vt_api_key":    _dec(row["vt_api_key"]),
        }
    finally:
        db.close()


@router.post("")
async def save_credentials(
    body: CredentialsRequest,
    session_id: Annotated[str | None, Cookie()] = None,
):
    key = _require_key(session_id)
    db = get_db()
    try:
        session = _require_session(session_id, db)

        # Load existing encrypted values so we only overwrite fields that were submitted
        existing = db.execute("SELECT * FROM credentials WHERE id=1").fetchone()

        def _merge(field: str, new_val: str | None) -> str | None:
            stripped = new_val.strip() if new_val else None
            if stripped:
                return encrypt_field(stripped, key)
            return existing[field] if existing else None

        enc = {
            "tenant_id":     _merge("tenant_id",     body.tenant_id),
            "client_id":     _merge("client_id",     body.client_id),
            "client_secret": _merge("client_secret", body.client_secret),
            "anthropic_key": _merge("anthropic_key", body.anthropic_key),
            "vt_api_key":    _merge("vt_api_key",    body.vt_api_key),
        }

        db.execute(
            """INSERT INTO credentials (id, tenant_id, client_id, client_secret, anthropic_key, vt_api_key)
               VALUES (1, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                 tenant_id=excluded.tenant_id,
                 client_id=excluded.client_id,
                 client_secret=excluded.client_secret,
                 anthropic_key=excluded.anthropic_key,
                 vt_api_key=excluded.vt_api_key,
                 updated_at=datetime('now')""",
            (enc["tenant_id"], enc["client_id"], enc["client_secret"], enc["anthropic_key"], enc["vt_api_key"]),
        )
        db.commit()
        # Audit which credential fields the analyst submitted (not the
        # values themselves — those are encrypted at rest and must never
        # leak into the audit log).
        changed = [
            k for k, v in {
                "tenant_id":     body.tenant_id,
                "client_id":     body.client_id,
                "client_secret": body.client_secret,
                "anthropic_key": body.anthropic_key,
                "vt_api_key":    body.vt_api_key,
            }.items() if v and v.strip()
        ]
        write_audit(
            db, action="credentials.save",
            user_id=int(session["user_id"]), username=session["username"],
            detail={"fields": changed},
        )
        return {"ok": True}
    finally:
        db.close()


def _load_decrypted(db, key: bytes) -> dict:
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
        "anthropic_key": _dec(row["anthropic_key"]),
        "vt_api_key":    _dec(row["vt_api_key"]),
    }


@router.post("/test/graph")
async def test_graph(session_id: Annotated[str | None, Cookie()] = None):
    key = _require_key(session_id)
    db = get_db()
    try:
        _require_session(session_id, db)
        creds = _load_decrypted(db, key)
    finally:
        db.close()

    if not all([creds.get("tenant_id"), creds.get("client_id"), creds.get("client_secret")]):
        return {"ok": False, "error": "Defender credentials not saved yet."}

    return await test_graph_connection(creds["tenant_id"], creds["client_id"], creds["client_secret"])


@router.post("/test/anthropic")
async def test_anthropic(session_id: Annotated[str | None, Cookie()] = None):
    key = _require_key(session_id)
    db = get_db()
    try:
        _require_session(session_id, db)
        creds = _load_decrypted(db, key)
    finally:
        db.close()

    if not creds.get("anthropic_key"):
        return {"ok": False, "error": "Anthropic API key not saved yet."}

    return await test_anthropic_connection(creds["anthropic_key"])
