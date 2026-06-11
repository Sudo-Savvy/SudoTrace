"""Hunt tab — analyst-authored KQL executed via Graph API runHuntingQuery."""
import logging
import re
import time
from typing import Annotated

from fastapi import APIRouter, Cookie, HTTPException

from app.database import get_db
from app.encryption import decrypt_field, get_key
from app.security import get_session
from app.graph import get_graph_token, run_hunting_query
from app.models import HuntRequest

log = logging.getLogger(__name__)
router = APIRouter()


_PRESET_TIMEFRAMES = {"24h", "7d", "14d", "30d"}
# Strict ISO 8601 UTC: YYYY-MM-DDTHH:MM:SS(Z)? — same shape RangePicker emits.
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?$")
# Soft cap on returned rows so a runaway query (especially one with no time
# filter at all) can't lock the UI. The browser-side table renders every row
# eagerly with per-row state, so a few thousand rows is enough to thrash.
_MAX_ROWS = 1000


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


_PRESET_TO_ISO_DURATION = {
    "24h": "P1D",
    "7d":  "P7D",
    "14d": "P14D",
    "30d": "P30D",
}


def _build_timespan(timeframe: str) -> str | None:
    """Translate the analyst's timeframe spec into a Graph hunting
    `Timespan` value — ISO 8601 duration for presets, ISO 8601 range
    (`<start>/<end>`) for custom. Graph applies this implicitly as a
    Timestamp filter before the analyst's KQL runs, which means we
    don't need to mangle the query string. String injection broke
    every non-trivial query shape (union, let, materialize) — moving
    to the native parameter eliminates the whole class of bug.
    """
    if timeframe in _PRESET_TO_ISO_DURATION:
        return _PRESET_TO_ISO_DURATION[timeframe]
    if timeframe.startswith("custom:"):
        rng = timeframe[len("custom:"):]
        if ".." not in rng:
            return None
        s, e = rng.split("..", 1)
        if not _ISO_RE.match(s) or not _ISO_RE.match(e):
            return None
        return f"{s}/{e}"
    return None


_KQL_ERROR_PATTERNS = [
    # Match the Kusto-style error blob and pull the human bit out.
    (re.compile(r"Failed to resolve table or column expression named '([^']+)'", re.I),
     lambda m: f"Unknown column or table: {m.group(1)}. Check the spelling and the source table name."),
    (re.compile(r"Syntax error: (.+)", re.I),
     lambda m: f"KQL syntax error: {m.group(1)[:200]}"),
    (re.compile(r"SemanticError.*?:\s*(.+)", re.I | re.DOTALL),
     lambda m: f"Semantic error: {m.group(1)[:200].splitlines()[0]}"),
]


def _friendly_error(raw: str) -> str:
    """Translate raw Graph / Kusto error blobs into something an analyst can
    act on. Falls back to the first 250 chars of the raw message if nothing
    matches — better than a giant JSON tower with stack traces."""
    s = (raw or "").strip()
    for pattern, render in _KQL_ERROR_PATTERNS:
        m = pattern.search(s)
        if m:
            return render(m)
    if "403" in s:
        return ("Graph API 403 — check the ThreatHunting.Read.All permission "
                "and that admin consent has been granted.")
    if "401" in s:
        return "Graph API 401 — credentials missing or expired."
    if "429" in s:
        return "Graph API 429 — rate limit hit. Wait a few seconds and retry."
    if "BadRequest" in s or "400" in s:
        return ("The query was rejected by Graph API as malformed. "
                "Common causes: unknown column, missing pipe, mismatched quotes.")
    return s[:300] or "Unknown error."


# Internal columns Graph API tags onto hunt results that aren't useful
# to the analyst (and just clutter the row-expand panel). Stripped from
# every row before serialising the response.
_NOISE_COLUMNS = frozenset({"$table"})


def _strip_noise_columns(rows: list[dict]) -> None:
    """Mutates rows in place to remove columns we never want to surface."""
    for r in rows:
        for col in _NOISE_COLUMNS:
            r.pop(col, None)


def _columns(rows: list[dict]) -> list[str]:
    """Stable column order: take keys from the first row in order, then add
    any keys that appear later but aren't in the first row."""
    if not rows:
        return []
    cols: list[str] = list(rows[0].keys())
    seen = set(cols)
    for r in rows[1:]:
        for k in r.keys():
            if k not in seen:
                cols.append(k)
                seen.add(k)
    return cols


@router.post("/run")
async def run(
    body: HuntRequest,
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
        return {
            "ok": False,
            "error_message": "MDE credentials not configured. Add them in Settings.",
            "rows": [], "columns": [], "row_count": 0, "duration_ms": 0,
        }

    if not body.kql or not body.kql.strip():
        return {
            "ok": False,
            "error_message": "Enter a KQL query before running.",
            "rows": [], "columns": [], "row_count": 0, "duration_ms": 0,
        }

    timespan = _build_timespan(body.timeframe)
    if not timespan:
        return {
            "ok": False,
            "error_message": ("Invalid timeframe. Pick a preset (Last 24h / 7d / 14d / 30d) "
                              "or a custom range from the calendar."),
            "rows": [], "columns": [], "row_count": 0, "duration_ms": 0,
        }
    # The analyst's KQL goes to Graph verbatim — the timeframe is
    # applied via Graph's native `Timespan` parameter so any query
    # shape (union, let, materialize, …) works without string surgery.
    final_kql = body.kql.strip()

    try:
        token = await get_graph_token(creds["tenant_id"], creds["client_id"], creds["client_secret"])
    except Exception as e:
        return {
            "ok": False,
            "error_message": _friendly_error(str(e)),
            "rows": [], "columns": [], "row_count": 0, "duration_ms": 0,
        }

    t0 = time.time()
    try:
        rows = await run_hunting_query(token, final_kql, timespan=timespan)
    except PermissionError as e:
        return {
            "ok": False,
            "error_message": str(e),
            "rows": [], "columns": [], "row_count": 0,
            "duration_ms": int((time.time() - t0) * 1000),
            "executed_kql": final_kql,
        }
    except Exception as e:
        log.warning("Hunt query failed: %s", e)
        return {
            "ok": False,
            "error_message": _friendly_error(str(e)),
            "rows": [], "columns": [], "row_count": 0,
            "duration_ms": int((time.time() - t0) * 1000),
            "executed_kql": final_kql,
        }

    duration_ms = int((time.time() - t0) * 1000)
    truncated = False
    if len(rows) > _MAX_ROWS:
        rows = rows[:_MAX_ROWS]
        truncated = True

    _strip_noise_columns(rows)

    return {
        "ok": True,
        "error_message": None,
        "rows": rows,
        "columns": _columns(rows),
        "row_count": len(rows),
        "duration_ms": duration_ms,
        "executed_kql": final_kql,
        "truncated": truncated,
    }
