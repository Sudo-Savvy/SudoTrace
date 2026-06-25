import os
import secrets
import sqlite3
import bcrypt

DB_PATH = os.getenv("DATABASE_URL", "/data/sudotrace.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                username            TEXT    NOT NULL UNIQUE,
                password_hash       TEXT    NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 1,
                created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id         TEXT    PRIMARY KEY,
                user_id    INTEGER NOT NULL REFERENCES users(id),
                expires_at TEXT    NOT NULL,
                created_at TEXT    NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

            CREATE TABLE IF NOT EXISTS login_attempts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ip           TEXT    NOT NULL,
                success      INTEGER NOT NULL,
                attempted_at TEXT    NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_attempts_ip_time ON login_attempts(ip, attempted_at);

            CREATE TABLE IF NOT EXISTS token_usage (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp        TEXT    NOT NULL DEFAULT (datetime('now')),
                investigation_id TEXT,
                action           TEXT,
                model            TEXT,
                input_tokens     INTEGER,
                output_tokens    INTEGER,
                cached_tokens    INTEGER,
                cost_usd         REAL,
                duration_ms      INTEGER,
                chunks           INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_token_usage_model          ON token_usage(model);
            CREATE INDEX IF NOT EXISTS idx_token_usage_action         ON token_usage(action);
            CREATE INDEX IF NOT EXISTS idx_token_usage_date           ON token_usage(timestamp);
            CREATE INDEX IF NOT EXISTS idx_token_usage_investigation   ON token_usage(investigation_id);

            CREATE TABLE IF NOT EXISTS config (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id            INTEGER PRIMARY KEY CHECK (id = 1),
                tenant_id     TEXT,
                client_id     TEXT,
                client_secret TEXT,
                anthropic_key TEXT,
                vt_api_key    TEXT,
                updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- One persisted investigation per user. The state_json blob carries
            -- what the analyst authored (investigation metadata + flags + IOCs
            -- + timeline notes + analysis history). Telemetry / process trees
            -- are *not* persisted — they re-fetch on resume so the analyst gets
            -- fresh data, just with their flags restored on top.
            CREATE TABLE IF NOT EXISTS investigation_state (
                user_id    INTEGER PRIMARY KEY REFERENCES users(id),
                state_json TEXT    NOT NULL,
                updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            -- Append-only audit trail for security-relevant operations:
            -- login / logout, credential changes, investigation start, AI
            -- analyse runs, etc. ip is captured where available (auth
            -- endpoints) and left null otherwise. detail is a free-form
            -- JSON blob with action-specific context (hostname, pid,
            -- model, cost, …).
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT    NOT NULL DEFAULT (datetime('now')),
                user_id   INTEGER REFERENCES users(id),
                username  TEXT,
                action    TEXT    NOT NULL,
                target    TEXT,
                ip        TEXT,
                detail    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_log_action    ON audit_log(action);
            CREATE INDEX IF NOT EXISTS idx_audit_log_user      ON audit_log(user_id);

            -- Per-user BEC / account-compromise case auto-save. Mirrors
            -- investigation_state: one active case per analyst, serialised by
            -- the frontend (account, suspected IP, window, selected origins,
            -- checklist ticks + notes) so a reload resumes where they left off.
            CREATE TABLE IF NOT EXISTS bec_case_state (
                user_id    INTEGER PRIMARY KEY REFERENCES users(id),
                state_json TEXT    NOT NULL,
                updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
            );
        """)

        existing = conn.execute(
            "SELECT id FROM users WHERE username = 'root'"
        ).fetchone()
        if not existing:
            password_hash = bcrypt.hashpw(b"root", bcrypt.gensalt(rounds=12)).decode()
            conn.execute(
                "INSERT INTO users (username, password_hash, must_change_password) VALUES (?, ?, 1)",
                ("root", password_hash),
            )

        # Migration: add vt_api_key column for existing databases
        try:
            conn.execute("ALTER TABLE credentials ADD COLUMN vt_api_key TEXT")
            conn.commit()
        except Exception:
            pass  # column already exists

        salt_row = conn.execute(
            "SELECT value FROM config WHERE key='pbkdf2_salt'"
        ).fetchone()
        if not salt_row:
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('pbkdf2_salt', ?)",
                (secrets.token_hex(32),),
            )

        conn.commit()
    finally:
        conn.close()


def get_pbkdf2_salt(conn: sqlite3.Connection) -> bytes:
    row = conn.execute("SELECT value FROM config WHERE key='pbkdf2_salt'").fetchone()
    return bytes.fromhex(row["value"])
