// Single source of truth for date/time formatting across SudoTrace.
// Project-wide convention: dates display as DD/MM/YYYY, times as HH:MM
// or HH:MM:SS in 24-hour form. Dates / times that come from the API
// are ISO strings in UTC; the analyst-selected display timezone in
// Settings determines what we render. UTC stays the default so the
// timestamps match the Defender portal out of the box.

import { getTimezone, resolveTimezone, timezoneShortLabel } from './timezone'

function pad2(n: number): string { return String(n).padStart(2, '0') }

function isoSliceUtcDate(iso: string): string | null {
  const m = iso.slice(0, 10).match(/^(\d{4})-(\d{2})-(\d{2})$/)
  return m ? `${m[3]}/${m[2]}/${m[1]}` : null
}
function isoSliceUtcTime(iso: string, withSeconds: boolean): string | null {
  const m = iso.slice(11, 19).match(/^(\d{2}):(\d{2})(?::(\d{2}))?$/)
  if (!m) return null
  return withSeconds ? `${m[1]}:${m[2]}:${m[3] ?? '00'}` : `${m[1]}:${m[2]}`
}

// "12/05/2026" from an ISO string. Returns '—' for empty / invalid input.
export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—'
  if (getTimezone() === 'UTC') {
    const fast = isoSliceUtcDate(iso)
    if (fast) return fast
  }
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  try {
    return new Intl.DateTimeFormat('en-GB', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      timeZone: resolveTimezone(getTimezone()),
    }).format(d)
  } catch {
    return `${pad2(d.getUTCDate())}/${pad2(d.getUTCMonth() + 1)}/${d.getUTCFullYear()}`
  }
}

// "17:37:11" from an ISO string. Always 24-hour. Returns '' for empty.
export function fmtTime(iso: string | null | undefined, withSeconds = true): string {
  if (!iso) return ''
  if (getTimezone() === 'UTC') {
    const fast = isoSliceUtcTime(iso, withSeconds)
    if (fast) return fast
  }
  const d = new Date(iso)
  if (isNaN(d.getTime())) return ''
  try {
    return new Intl.DateTimeFormat('en-GB', {
      hour: '2-digit', minute: '2-digit',
      ...(withSeconds ? { second: '2-digit' } : {}),
      hour12: false,
      timeZone: resolveTimezone(getTimezone()),
    }).format(d)
  } catch {
    return withSeconds
      ? `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`
      : `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}`
  }
}

// "12/05/2026 17:37:11 UTC" — the full timestamp form used in most
// analyst-facing places (incident metadata, tree rows, telemetry, hunt
// cells). Drops the timezone suffix when withSuffix=false.
export function fmtDateTime(iso: string | null | undefined, withSuffix = true): string {
  if (!iso) return '—'
  const date = fmtDate(iso)
  const time = fmtTime(iso, true)
  if (date === '—' || date === iso) return iso ?? '—'
  if (!withSuffix) return `${date} ${time}`.trim()
  return `${date} ${time} ${timezoneShortLabel(getTimezone(), iso)}`.trim()
}

// "12/05 17:37" — compact form for the RangePicker chip and similar
// tight UI spots where the year is redundant.
export function fmtDateTimeShort(iso: string | null | undefined): string {
  if (!iso) return '—'
  if (getTimezone() === 'UTC') {
    const m = iso.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/)
    if (m) return `${m[3]}/${m[2]} ${m[4]}:${m[5]}`
  }
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  try {
    return new Intl.DateTimeFormat('en-GB', {
      day: '2-digit', month: '2-digit',
      hour: '2-digit', minute: '2-digit',
      hour12: false,
      timeZone: resolveTimezone(getTimezone()),
    }).format(d).replace(',', '')
  } catch {
    return `${pad2(d.getUTCDate())}/${pad2(d.getUTCMonth() + 1)} ${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}`
  }
}
