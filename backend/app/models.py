from typing import Literal

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class CredentialsRequest(BaseModel):
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    anthropic_key: str | None = None
    vt_api_key: str | None = None


class TestConnectionsRequest(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str
    anthropic_key: str


class InvestigateRequest(BaseModel):
    hostname: str = ""
    focal_pid: int = 0
    focal_time: str | None = None   # ISO 8601 UTC; None for relative windows
    time_window: str = "±1h"        # ±30m / ±1h / … / last7d / last30d
    focal_node_key: str | None = None  # bypasses PID resolution when set (disambiguates)
    alert_id: str | None = None       # when set, resolves alert → hostname + pid automatically


class TelemetryRequest(BaseModel):
    hostname: str
    pid: int
    username: str
    focal_time: str | None = None
    time_window: str = "±1h"
    table: str  # "network" | "files" | "registry" | "logon"


class AnalyseRequest(BaseModel):
    investigation_id: str
    hostname: str
    focal_pid: int
    focal_time_iso: str | None = None
    time_window: str = "±24h"
    flagged_nodes: list[dict] = []      # [{node_key, flag}]
    all_nodes: dict[str, dict] = {}     # full visible process tree
    ancestry_chain: list[str] = []
    device_info: dict | None = None
    scope: Literal["focused", "wide"] = "focused"  # focused = flagged only; wide = whole tree
    flagged_events: list[dict] = []     # [{node_key, tab, row_idx, flag, row}]
    flagged_incidents: list[dict] = []  # [{incident_id, display_name, severity, status, classification, determination, flag}]
    flagged_iocs: list[dict] = []       # [{ioc, ioc_type, verdict, name, country, as_owner, asn, total, malicious, suspicious, link}]


class HuntRequest(BaseModel):
    kql: str
    # One of: '24h' | '7d' | '14d' | '30d' or 'custom:<startIso>..<endIso>'.
    # The backend ALWAYS injects the timeframe filter — no opt-out — so
    # analysts can't accidentally hit MDE's 30-day default lookback on an
    # unbounded query.
    timeframe: str = "24h"


class BecSigninsRequest(BaseModel):
    # UPN (user@domain) or Entra object id.
    account: str
    # 'last7d' | 'last30d' | 'custom:<startIso>..<endIso>'. Sign-in log
    # retention is 30 days on Entra ID P1/P2, so last30d is the practical max.
    time_window: str = "last7d"


class BecScopeRequest(BaseModel):
    # Account to scope, and the window of the selected origin(s). The window
    # is normally 'custom:<startIso>..<endIso>' derived from the selected
    # access-origin rows, but accepts the same presets as sign-ins.
    account: str
    time_window: str = "last7d"


class BecEnrichRequest(BaseModel):
    # Identity Protection risk + directory-role / PIM enrichment for the account.
    account: str


class BecWatchRequest(BaseModel):
    # Containment-invariant re-check for the account (§5).
    account: str


class BecCommsRequest(BaseModel):
    # Draft a client / stakeholder notification from the case facts (§7).
    account: str
    audience: str = "client"           # client | internal | affected_user
    facts: str                         # analyst-assembled established-facts block
