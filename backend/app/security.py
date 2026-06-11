import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import bcrypt

SESSION_HOURS = 8
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


_FMT = "%Y-%m-%d %H:%M:%S"  # matches SQLite datetime('now') format


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _fmt(dt: datetime) -> str:
    return dt.strftime(_FMT)


def check_lockout(ip: str, db: sqlite3.Connection) -> tuple[bool, int]:
    cutoff = _fmt(_utcnow() - timedelta(minutes=LOCKOUT_MINUTES))
    count = db.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND success=0 AND attempted_at>?",
        (ip, cutoff),
    ).fetchone()[0]

    if count < MAX_FAILED_ATTEMPTS:
        return False, 0

    fifth = db.execute(
        "SELECT attempted_at FROM login_attempts "
        "WHERE ip=? AND success=0 AND attempted_at>? "
        "ORDER BY attempted_at ASC LIMIT 1 OFFSET ?",
        (ip, cutoff, MAX_FAILED_ATTEMPTS - 1),
    ).fetchone()

    if fifth:
        lockout_until = datetime.strptime(fifth[0], _FMT) + timedelta(minutes=LOCKOUT_MINUTES)
        remaining = int((lockout_until - _utcnow()).total_seconds())
        if remaining > 0:
            return True, remaining

    return False, 0


def record_attempt(ip: str, success: bool, db: sqlite3.Connection) -> None:
    db.execute(
        "INSERT INTO login_attempts (ip, success) VALUES (?, ?)",
        (ip, 1 if success else 0),
    )
    db.commit()


def create_session(user_id: int, db: sqlite3.Connection) -> str:
    session_id = secrets.token_urlsafe(32)
    expires_at = _fmt(_utcnow() + timedelta(hours=SESSION_HOURS))
    db.execute(
        "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
        (session_id, user_id, expires_at),
    )
    db.commit()
    return session_id


def get_session(session_id: str, db: sqlite3.Connection) -> sqlite3.Row | None:
    return db.execute(
        "SELECT s.id, s.user_id, s.expires_at, u.username, u.must_change_password "
        "FROM sessions s JOIN users u ON s.user_id = u.id "
        "WHERE s.id = ? AND s.expires_at > ?",
        (session_id, _fmt(_utcnow())),
    ).fetchone()


def delete_session(session_id: str, db: sqlite3.Connection) -> None:
    db.execute("DELETE FROM sessions WHERE id=?", (session_id,))
    db.commit()
