const BASE = '/api/credentials'

export interface Credentials {
  tenant_id: string | null
  client_id: string | null
  client_secret: string | null
  anthropic_key: string | null
  vt_api_key: string | null
}

export interface TestResult {
  ok: boolean
  error?: string
}

export interface TestConnectionsResult {
  graph: TestResult
  anthropic: TestResult
}

export async function getCredentials(): Promise<Credentials> {
  const res = await fetch(BASE, { credentials: 'include' })
  if (!res.ok) throw new Error('Failed to load credentials.')
  return res.json()
}

export async function saveCredentials(creds: Partial<Credentials>): Promise<void> {
  const res = await fetch(BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(creds),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'Failed to save credentials.')
}

export async function testGraphConnection(): Promise<TestResult> {
  const res = await fetch(`${BASE}/test/graph`, { method: 'POST', credentials: 'include' })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'Test failed.')
  return data
}

export async function testAnthropicConnection(): Promise<TestResult> {
  const res = await fetch(`${BASE}/test/anthropic`, { method: 'POST', credentials: 'include' })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'Test failed.')
  return data
}

export async function getCredentialStatus(): Promise<{ configured: boolean }> {
  const res = await fetch(`${BASE}/status`, { credentials: 'include' })
  if (!res.ok) return { configured: false }
  return res.json()
}
