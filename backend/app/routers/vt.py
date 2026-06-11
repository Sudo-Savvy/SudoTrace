from typing import Annotated

from fastapi import APIRouter, Cookie, HTTPException, Query

from app.database import get_db
from app.encryption import decrypt_field, get_key
from app.security import get_session
from app.virustotal import lookup_domain, lookup_hash, lookup_ip

router = APIRouter()


@router.get("/lookup")
async def vt_lookup(
    ioc: str = Query(...),
    ioc_type: str = Query(...),
    session_id: Annotated[str | None, Cookie()] = None,
):
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    key = get_key(session_id)
    if key is None:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")

    db = get_db()
    try:
        if not get_session(session_id, db):
            raise HTTPException(status_code=401, detail="Session expired.")
        row = db.execute("SELECT vt_api_key FROM credentials WHERE id=1").fetchone()
        if not row or not row["vt_api_key"]:
            raise HTTPException(status_code=400, detail="VirusTotal API key not configured. Go to Settings.")
        vt_key = decrypt_field(row["vt_api_key"], key)
    finally:
        db.close()

    if not vt_key:
        raise HTTPException(status_code=400, detail="VirusTotal API key not configured. Go to Settings.")

    if ioc_type == "hash":
        return await lookup_hash(vt_key, ioc)
    elif ioc_type == "ip":
        return await lookup_ip(vt_key, ioc)
    elif ioc_type == "domain":
        return await lookup_domain(vt_key, ioc)
    else:
        raise HTTPException(status_code=400, detail="ioc_type must be 'hash', 'ip', or 'domain'")
