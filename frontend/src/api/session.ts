// Client for the per-user session auto-save endpoints. Stays minimal —
// the shape of the persisted blob is the frontend's concern; the
// backend just stores opaque JSON keyed by user.

const BASE = '/api/session'

export interface SessionStateResponse {
  state:      unknown
  updated_at: string | null
}

export async function getSessionState(): Promise<SessionStateResponse> {
  const res = await fetch(`${BASE}/state`, { credentials: 'include' })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`)
  return data
}

export async function putSessionState(state: unknown): Promise<void> {
  const res = await fetch(`${BASE}/state`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(state),
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error(data.detail || `HTTP ${res.status}`)
  }
}

export async function deleteSessionState(): Promise<void> {
  const res = await fetch(`${BASE}/state`, {
    method: 'DELETE',
    credentials: 'include',
  })
  if (!res.ok) {
    const data = await res.json().catch(() => ({}))
    throw new Error(data.detail || `HTTP ${res.status}`)
  }
}
