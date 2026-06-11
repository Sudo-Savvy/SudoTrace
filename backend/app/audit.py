"""
Audit log helper. Append-only writes to the audit_log table for
security-relevant operations: authentication, credential changes,
investigation starts, AI analyse runs, etc.

Detail is a free-form JSON blob — keep it small (caller is responsible
for pruning huge payloads). The action string is the stable key the
audit-log panel filters on, so keep it short and stable
("login.success", "ai.analyse", "investigation.start", …).
"""
import json
import sqlite3
import logging

log = logging.getLogger(__name__)


def write_audit(
    db: sqlite3.Connection,
    *,
    action: str,
    user_id: int | None = None,
    username: str | None = None,
    target: str | None = None,
    ip: str | None = None,
    detail: dict | None = None,
) -> None:
    """
    Write one audit row. Failures are logged and swallowed — the audit
    log should never block or break the operation it's recording.
    """
    try:
        detail_json = json.dumps(detail, separators=(",", ":")) if detail else None
        db.execute(
            """
            INSERT INTO audit_log (user_id, username, action, target, ip, detail)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, action, target, ip, detail_json),
        )
        db.commit()
    except Exception as exc:
        log.warning("audit write failed for action=%r: %s", action, exc)
