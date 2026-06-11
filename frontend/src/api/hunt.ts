export type HuntTimeframe = '24h' | '7d' | '14d' | '30d' | 'custom'

// Wire format for timeframe: presets are sent as the bare string; for a
// custom range we send `custom:<startIso>..<endIso>`. The backend builds
// the appropriate `where Timestamp` clause from this.
export interface HuntRequest {
  kql: string
  timeframe: string
}

export interface HuntResponse {
  ok: boolean
  error_message: string | null
  rows: Record<string, unknown>[]
  columns: string[]
  row_count: number
  duration_ms: number
  executed_kql?: string
  truncated?: boolean
}

export async function runHunt(req: HuntRequest, signal?: AbortSignal): Promise<HuntResponse> {
  const res = await fetch('/api/hunt/run', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
    signal,
  })
  if (!res.ok) {
    return {
      ok: false,
      error_message: `Hunt service returned HTTP ${res.status}.`,
      rows: [], columns: [], row_count: 0, duration_ms: 0,
    }
  }
  return res.json()
}
