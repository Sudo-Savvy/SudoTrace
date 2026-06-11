const BASE = '/api/admin'

export interface TokenUsageRow {
  id:               number
  timestamp:        string
  investigation_id: string | null
  action:           string | null
  model:            string | null
  input_tokens:     number | null
  output_tokens:    number | null
  cached_tokens:    number | null
  cost_usd:         number | null
  duration_ms:      number | null
  chunks:           number | null
}

export interface TokenUsageTotals {
  calls:         number
  input_tokens:  number
  output_tokens: number
  cached_tokens: number
  cost_usd:      number
}

export interface TokenUsageResponse {
  recent: TokenUsageRow[]
  totals: {
    last24h: TokenUsageTotals
    last7d:  TokenUsageTotals
    last30d: TokenUsageTotals
    alltime: TokenUsageTotals
  }
}

export interface AuditEntry {
  id:        number
  timestamp: string
  user_id:   number | null
  username:  string | null
  action:    string
  target:    string | null
  ip:        string | null
  detail:    Record<string, unknown> | null
}

export interface AuditLogResponse {
  entries: AuditEntry[]
  actions: string[]
}

export async function fetchTokenUsage(limit = 50): Promise<TokenUsageResponse> {
  const res = await fetch(`${BASE}/token-usage?limit=${limit}`, { credentials: 'include' })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`)
  return data
}

export async function fetchAuditLog(opts: { limit?: number; action?: string } = {}): Promise<AuditLogResponse> {
  const params = new URLSearchParams()
  params.set('limit', String(opts.limit ?? 100))
  if (opts.action) params.set('action', opts.action)
  const res = await fetch(`${BASE}/audit-log?${params}`, { credentials: 'include' })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`)
  return data
}
