import { useState, useEffect } from 'react'

// Analyst-selected display timezone for all formatted timestamps.
// 'UTC'    → match MDE / Defender portal (the default; keeps timestamps
//            comparable to what the analyst sees in the source data).
// 'Local'  → the browser's IANA timezone, resolved lazily via Intl.
// Anything else is treated as an IANA timezone name (e.g.
// 'America/New_York'). Stored in localStorage so the preference is
// per-browser-profile rather than per-server-account.

const KEY = 'sudotrace.timezone'

function readInitial(): string {
  try {
    const v = typeof localStorage !== 'undefined' ? localStorage.getItem(KEY) : null
    if (v && typeof v === 'string') return v
  } catch { /* ignore */ }
  return 'UTC'
}

let _tz: string = readInitial()
const _listeners = new Set<() => void>()

export function getTimezone(): string {
  return _tz
}

export function setTimezone(tz: string): void {
  const next = (tz || 'UTC').trim()
  if (next === _tz) return
  _tz = next
  try { localStorage.setItem(KEY, _tz) } catch { /* ignore */ }
  _listeners.forEach(fn => fn())
}

// Resolves 'Local' to the actual IANA name the browser is using. For
// any other value, passes through unchanged (UTC, America/New_York, …).
export function resolveTimezone(tz: string): string {
  if (tz === 'Local') {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' } catch { return 'UTC' }
  }
  return tz
}

// Short label shown next to formatted times. UTC stays "UTC"; named
// zones show their short locale name (EDT, GMT+1, …) when available.
export function timezoneShortLabel(tz: string, iso?: string): string {
  const real = resolveTimezone(tz)
  if (real === 'UTC') return 'UTC'
  try {
    const d = iso ? new Date(iso) : new Date()
    if (isNaN(d.getTime())) return real
    const parts = new Intl.DateTimeFormat('en-GB', {
      timeZone: real,
      timeZoneName: 'short',
    }).formatToParts(d)
    const name = parts.find(p => p.type === 'timeZoneName')?.value
    if (name) return name
  } catch { /* fall through */ }
  return real
}

export function useTimezone(): string {
  const [, setV] = useState(0)
  useEffect(() => {
    const bump = () => setV(v => v + 1)
    _listeners.add(bump)
    return () => { _listeners.delete(bump) }
  }, [])
  return _tz
}

// Curated picker options. Analysts can paste any IANA name in the
// "Custom" input if their zone isn't here.
export const TIMEZONE_OPTIONS: { value: string; label: string }[] = [
  { value: 'UTC',                  label: 'UTC — default (matches Defender)' },
  { value: 'Local',                label: 'Local browser time' },
  { value: 'Europe/London',        label: 'Europe/London (GMT/BST)' },
  { value: 'Europe/Berlin',        label: 'Europe/Berlin (CET/CEST)' },
  { value: 'Europe/Paris',         label: 'Europe/Paris (CET/CEST)' },
  { value: 'America/New_York',     label: 'America/New_York (EST/EDT)' },
  { value: 'America/Chicago',      label: 'America/Chicago (CST/CDT)' },
  { value: 'America/Denver',       label: 'America/Denver (MST/MDT)' },
  { value: 'America/Los_Angeles',  label: 'America/Los_Angeles (PST/PDT)' },
  { value: 'America/Sao_Paulo',    label: 'America/Sao_Paulo (BRT)' },
  { value: 'Asia/Tokyo',           label: 'Asia/Tokyo (JST)' },
  { value: 'Asia/Shanghai',        label: 'Asia/Shanghai (CST)' },
  { value: 'Asia/Kolkata',         label: 'Asia/Kolkata (IST)' },
  { value: 'Asia/Dubai',           label: 'Asia/Dubai (GST)' },
  { value: 'Australia/Sydney',     label: 'Australia/Sydney (AEST/AEDT)' },
]
