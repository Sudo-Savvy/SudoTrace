// Client for the BEC / account-compromise module.

export interface BecAccount {
  id:              string | null
  display_name:    string | null
  upn:             string | null
  account_enabled: boolean | null
  mail:            string | null
  job_title:       string | null
  created:         string | null
  on_prem_synced:  boolean | null
}

export interface BecOrigin {
  ip:             string
  country:        string
  city:           string
  asn:            number | null
  asn_org:        string | null
  is_hosting_asn: boolean
  devices:        string[]
  user_agents:    string[]
  client_apps:    string[]
  first_seen:     string
  last_seen:      string
  success:        number
  failure:        number
  mfa:            Record<string, number>
  session_ids:    string[]
  device_trust:     string[]   // e.g. ["Azure AD registered"] / ["Azure AD joined"]
  device_managed:   boolean
  device_compliant: boolean
  device_ids:       string[]
  signins:          BecSignin[]   // per-event detail behind the aggregate (newest first, capped)
  flags:          string[]   // hosting-asn | legacy-auth | aitm-token-reuse | impossible-travel
}

export interface BecSignin {
  timestamp:        string
  success:          boolean
  error_code:       number | null
  failure_reason:   string | null
  mfa:              string
  auth_requirement: string | null
  app:              string | null
  resource:         string | null
  client_app:       string | null
  user_agent:       string | null
  device:           string | null
  trust_type:       string | null
  ca_status:        string | null
  risk_state:       string | null
  risk_level:       string | null
  correlation_id:   string | null
  session_id:       string | null
}

export interface BecSigninsResponse {
  ok:            boolean
  error_code:    string | null
  error_message: string | null
  account:       BecAccount | null
  signin_count?: number
  window?:       { start: string; end: string }
  origins:       BecOrigin[]
  anomalies:     {
    aitm_sessions?:         string[]
    impossible_travel_ips?: string[]
    hosting_asn_ips?:       string[]
  }
}

export interface BecPersistenceEvent {
  category:        string   // oauth_grant | mfa_method | device | credential | group_role
  activity:        string
  timestamp:       string
  result:          string
  target:          string
  initiated_by_ip: string
  device?:         string   // client / device string from the audit record
  detail?:         string   // 'what changed' — registered method value, app permissions, etc.
  event_count?:    number   // raw audit events this finding collapses
  ip_count?:       number   // distinct source IPs across those events
  id:              string
  raw?:            Record<string, unknown>
}

export interface BecFindingCategory {
  available: boolean
  reason?:   string
  events:    BecPersistenceEvent[]
}

export interface BecScopeResponse {
  ok:            boolean
  error_code:    string | null
  error_message: string | null
  account?:      BecAccount | null
  window?:       { start: string; end: string }
  findings:      Record<string, BecFindingCategory>
}

export async function fetchBecScope(account: string, timeWindow: string): Promise<BecScopeResponse> {
  const res = await fetch('/api/bec/scope', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ account, time_window: timeWindow }),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    return { ok: false, error_code: 'HTTP_ERROR', error_message: data.detail || `Request failed (HTTP ${res.status}).`, findings: {} }
  }
  return data
}

// ── Identity Protection + directory-role enrichment (P2) ─────────────────────
export interface BecRiskDetection {
  risk_event_type: string | null
  risk_level:      string | null
  risk_state:      string | null
  detected:        string
  ip:              string
  location:        string
  detail:          string | null
  source:          string | null
  id:              string
}

export interface BecRole {
  role_name:       string
  role_id:         string
  assignment_type: 'active' | 'eligible'
  scope:           string
}

export interface BecEnrichResponse {
  ok:            boolean
  error_code:    string | null
  error_message: string | null
  account?:      BecAccount | null
  risk:  {
    available:  boolean
    reason?:    string
    state:      { risk_level: string | null; risk_state: string | null; risk_detail: string | null; updated: string | null } | null
    detections: BecRiskDetection[]
  } | null
  roles: {
    available: boolean
    reason?:   string
    active:    BecRole[]
    eligible:  BecRole[]
  } | null
}

export async function fetchBecEnrich(account: string): Promise<BecEnrichResponse> {
  const res = await fetch('/api/bec/enrich', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ account }),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    return { ok: false, error_code: 'HTTP_ERROR', error_message: data.detail || `Request failed (HTTP ${res.status}).`, risk: null, roles: null }
  }
  return data
}

// ── Containment watcher (§5) ─────────────────────────────────────────────────
export interface BecBreach {
  ip:        string
  timestamp: string
  country:   string
  city:      string
}

export interface BecWatchResponse {
  ok:            boolean
  error_code:    string | null
  error_message: string | null
  account?:      BecAccount & { sessions_valid_from?: string | null }
  checked_at?:   string
  invariants?: {
    account_disabled:    boolean
    sessions_valid_from: string | null
    sessions_revoked:    boolean
    sessions_available:  boolean
    sessions_reason:     string | null
    sessions_holding:    boolean
    breaches:            BecBreach[]
    held:                boolean
  }
}

export async function fetchBecWatch(account: string): Promise<BecWatchResponse> {
  const res = await fetch('/api/bec/watch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ account }),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    return { ok: false, error_code: 'HTTP_ERROR', error_message: data.detail || `Request failed (HTTP ${res.status}).` }
  }
  return data
}

// ── Client comms drafting (§7) ───────────────────────────────────────────────
export interface BecCommsResponse {
  ok:            boolean
  error_code:    string | null
  error_message: string | null
  draft:         string | null
  token_usage?:  { input_tokens?: number; output_tokens?: number; cost_usd?: number; model?: string }
}

export async function fetchBecComms(account: string, audience: string, facts: string): Promise<BecCommsResponse> {
  const res = await fetch('/api/bec/comms', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ account, audience, facts }),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    return { ok: false, error_code: 'HTTP_ERROR', error_message: data.detail || `Request failed (HTTP ${res.status}).`, draft: null }
  }
  return data
}

// ── Case auto-save (Milestone C) ────────────────────────────────────────────
// The persisted shape: case identity + analyst-authored state. Triage/findings
// are NOT stored — they re-fetch on resume.
export interface BecTimelineCustom {
  id:    string
  ts:    string
  label: string
  sub:   string
}

export interface BecCaseState {
  account:     string
  ip:          string
  time_window: string
  offline?:    boolean
  selected:    string[]
  checked:     string[]
  notes:       Record<string, string>
  timeline_custom?: BecTimelineCustom[]
  timeline_hidden?: string[]
  manual_ips?: string[]
}

export async function getBecCase(): Promise<{ case: BecCaseState | null; updated_at: string | null }> {
  const res = await fetch('/api/bec/case', { credentials: 'include' })
  if (!res.ok) return { case: null, updated_at: null }
  return res.json().catch(() => ({ case: null, updated_at: null }))
}

export async function putBecCase(state: BecCaseState): Promise<void> {
  await fetch('/api/bec/case', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(state),
  }).catch(() => { /* surfaced on next attempt */ })
}

export async function deleteBecCase(): Promise<void> {
  await fetch('/api/bec/case', { method: 'DELETE', credentials: 'include' })
    .catch(() => { /* best-effort */ })
}

export async function fetchBecSignins(account: string, timeWindow: string): Promise<BecSigninsResponse> {
  const res = await fetch('/api/bec/signins', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ account, time_window: timeWindow }),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    return {
      ok: false,
      error_code: 'HTTP_ERROR',
      error_message: data.detail || `Request failed (HTTP ${res.status}).`,
      account: null, origins: [], anomalies: {},
    }
  }
  return data
}
