import type { User } from '../types'

const BASE = '/api/auth'

export async function login(username: string, password: string): Promise<{ must_change_password: boolean }> {
  const res = await fetch(`${BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ username, password }),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'Login failed.')
  return data
}

export async function logout(): Promise<void> {
  await fetch(`${BASE}/logout`, { method: 'POST', credentials: 'include' })
}

export async function getMe(): Promise<User | null> {
  const res = await fetch(`${BASE}/me`, { credentials: 'include' })
  if (!res.ok) return null
  return res.json()
}

export async function changePassword(current_password: string, new_password: string): Promise<void> {
  const res = await fetch(`${BASE}/change-password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ current_password, new_password }),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'Failed to change password.')
}
