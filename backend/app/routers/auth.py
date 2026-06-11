import asyncio
from typing import Annotated

from fastapi import APIRouter, Cookie, HTTPException, Request, Response

from app.database import get_db, get_pbkdf2_salt
from app.encryption import (
    clear_key,
    decrypt_field,
    derive_key,
    encrypt_field,
    get_key,
    store_key,
)
from app.models import ChangePasswordRequest, LoginRequest
from app.security import (
    check_lockout,
    create_session,
    delete_session,
    get_session,
    hash_password,
    record_attempt,
    verify_password,
)
from app.audit import write_audit

router = APIRouter()

_COOKIE = "session_id"
_COOKIE_MAX_AGE = 8 * 3600


def _get_ip(request: Request) -> str:
    return request.headers.get("X-Real-IP") or request.client.host


def _set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        key=_COOKIE,
        value=session_id,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=_COOKIE_MAX_AGE,
    )


@router.post("/login")
async def login(request: Request, response: Response, body: LoginRequest):
    await asyncio.sleep(1)  # Server-side minimum delay — always fires

    ip = _get_ip(request)
    db = get_db()
    try:
        locked, remaining = check_lockout(ip, db)
        if locked:
            mins, secs = divmod(remaining, 60)
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed attempts. Try again in {mins}m {secs}s.",
            )

        user = db.execute(
            "SELECT id, password_hash, must_change_password FROM users WHERE username=?",
            (body.username,),
        ).fetchone()

        if not user or not verify_password(body.password, user["password_hash"]):
            record_attempt(ip, False, db)
            write_audit(db, action="login.failure", username=body.username, ip=ip)
            raise HTTPException(status_code=401, detail="Incorrect username or password.")

        record_attempt(ip, True, db)
        session_id = create_session(user["id"], db)
        write_audit(
            db, action="login.success",
            user_id=int(user["id"]), username=body.username, ip=ip,
        )

        # Derive encryption key from password and store in memory for this session
        salt = get_pbkdf2_salt(db)
        key = derive_key(body.password, salt)
        store_key(session_id, key)

        _set_session_cookie(response, session_id)
        return {"must_change_password": bool(user["must_change_password"])}
    finally:
        db.close()


@router.post("/logout")
async def logout(response: Response, session_id: Annotated[str | None, Cookie()] = None):
    if session_id:
        clear_key(session_id)
        db = get_db()
        try:
            # Resolve the user before tearing down the session so the
            # audit entry can attribute the logout correctly.
            sess = get_session(session_id, db)
            if sess:
                write_audit(
                    db, action="logout",
                    user_id=int(sess["user_id"]), username=sess["username"],
                )
            delete_session(session_id, db)
        finally:
            db.close()
    response.delete_cookie(_COOKIE)
    return {"ok": True}


@router.get("/me")
async def me(session_id: Annotated[str | None, Cookie()] = None):
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    db = get_db()
    try:
        session = get_session(session_id, db)
        if not session:
            raise HTTPException(status_code=401, detail="Session expired.")
        return {
            "username": session["username"],
            "must_change_password": bool(session["must_change_password"]),
            "key_available": get_key(session_id) is not None,
        }
    finally:
        db.close()


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    session_id: Annotated[str | None, Cookie()] = None,
):
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    key = get_key(session_id)
    if key is None:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")

    db = get_db()
    try:
        session = get_session(session_id, db)
        if not session:
            raise HTTPException(status_code=401, detail="Session expired.")

        user = db.execute(
            "SELECT id, password_hash FROM users WHERE id=?",
            (session["user_id"],),
        ).fetchone()

        if not verify_password(body.current_password, user["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")

        if len(body.new_password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

        if body.new_password == body.current_password:
            raise HTTPException(
                status_code=400,
                detail="New password must be different from your current password.",
            )

        # Derive new key and re-encrypt any stored credentials
        salt = get_pbkdf2_salt(db)
        new_key = derive_key(body.new_password, salt)

        creds_row = db.execute("SELECT * FROM credentials WHERE id=1").fetchone()
        if creds_row:
            # Re-encrypt EVERY stored credential under the new key. Missing
            # any field here leaves it encrypted under the old key, which
            # then fails to decrypt on next use (AES-GCM tag mismatch) and
            # is silently lost — vt_api_key was previously omitted.
            fields = ["tenant_id", "client_id", "client_secret", "anthropic_key", "vt_api_key"]
            re_encrypted = {}
            for field in fields:
                val = creds_row[field]
                if val:
                    re_encrypted[field] = encrypt_field(decrypt_field(val, key), new_key)
                else:
                    re_encrypted[field] = None

            db.execute(
                "UPDATE credentials SET tenant_id=?, client_id=?, client_secret=?, "
                "anthropic_key=?, vt_api_key=?, updated_at=datetime('now') WHERE id=1",
                (re_encrypted["tenant_id"], re_encrypted["client_id"],
                 re_encrypted["client_secret"], re_encrypted["anthropic_key"],
                 re_encrypted["vt_api_key"]),
            )

        db.execute(
            "UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
            (hash_password(body.new_password), user["id"]),
        )
        db.commit()

        # Swap the in-memory key for this session
        store_key(session_id, new_key)
        write_audit(
            db, action="password.change",
            user_id=int(user["id"]), username=session["username"],
        )
        return {"ok": True}
    finally:
        db.close()
