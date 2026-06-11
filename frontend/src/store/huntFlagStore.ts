import { useState, useEffect } from 'react'
import type { FlagStatus } from '../types'

// Hunt-tab flagged events. A module-level store (parallel to iocStore) so
// the AnalysisTab can fold them into the AI Analyse payload without having
// to lift state through the shared Layout parent. Cleared on "New
// Investigation" alongside the IOC list.
//
// Keying: rows from a hunt query don't carry a natural ID, so we hash the
// row's JSON form. That keeps the key stable across re-runs of the same
// query (an analyst can re-run the query and still see "this row is
// flagged") while differentiating two structurally different rows.

export interface HuntFlagEntry {
  key: string
  row: Record<string, unknown>
  flag: NonNullable<FlagStatus>
  addedAt: number
  // Query context captured at flag time so the analyst can jump back to
  // the exact event even after running a different KQL search.
  kql: string
  timeframe: string
}

const _entries: HuntFlagEntry[] = []
const _listeners = new Set<() => void>()

function _notify() {
  _listeners.forEach(fn => fn())
}

export function rowKey(row: Record<string, unknown>): string {
  // Identity fingerprint based on stable event identifiers (Timestamp +
  // DeviceId + ReportId). This is what MDE itself uses to uniquely
  // identify an event and — crucially — the fingerprint stays the same
  // whether the query that produced the row used `| project` to slim
  // columns or returned the full schema. That means a row flagged from
  // a wide query still matches the same row when re-loaded via a
  // narrow targeted "where ReportId == …" query.
  const ts  = typeof row.Timestamp === 'string' ? row.Timestamp : ''
  const dev = typeof row.DeviceId  === 'string' ? row.DeviceId  : ''
  const rid = row.ReportId != null ? String(row.ReportId) : ''
  if (ts && dev && rid) return `id:${ts}|${dev}|${rid}`
  // Aggregated / projected-away rows that lack those columns fall back
  // to a sorted-key JSON hash. Less robust to schema changes but the
  // best we can do without identifiers.
  const keys = Object.keys(row).sort()
  const ordered: Record<string, unknown> = {}
  for (const k of keys) ordered[k] = row[k]
  return `content:${JSON.stringify(ordered)}`
}

export function setHuntFlag(
  row: Record<string, unknown>,
  flag: FlagStatus,
  context?: { kql: string; timeframe: string },
): void {
  const key = rowKey(row)
  const idx = _entries.findIndex(e => e.key === key)
  if (flag === null) {
    if (idx >= 0) {
      _entries.splice(idx, 1)
      _notify()
    }
    return
  }
  if (idx >= 0) {
    _entries[idx] = {
      ..._entries[idx], flag,
      kql:       context?.kql       ?? _entries[idx].kql,
      timeframe: context?.timeframe ?? _entries[idx].timeframe,
    }
  } else {
    _entries.push({
      key, row, flag, addedAt: Date.now(),
      kql:       context?.kql       ?? '',
      timeframe: context?.timeframe ?? '24h',
    })
  }
  _notify()
}

export function getHuntFlag(row: Record<string, unknown>): FlagStatus {
  const key = rowKey(row)
  return _entries.find(e => e.key === key)?.flag ?? null
}

export function getHuntFlags(): HuntFlagEntry[] {
  return _entries.slice()
}

export function clearHuntFlags(): void {
  if (_entries.length === 0) return
  _entries.splice(0, _entries.length)
  _notify()
}

// Replace all entries wholesale — used by session recovery to restore the
// auto-saved hunt-flag list after login.
export function hydrateHuntFlags(list: HuntFlagEntry[]): void {
  _entries.splice(0, _entries.length)
  for (const e of list) {
    if (!e || typeof e.key !== 'string' || !e.row) continue
    _entries.push(e)
  }
  _notify()
}

export function useHuntFlagCount(): number {
  const [, setV] = useState(0)
  useEffect(() => {
    const bump = () => setV(v => v + 1)
    _listeners.add(bump)
    return () => { _listeners.delete(bump) }
  }, [])
  return _entries.length
}

// Reactive accessor for the full list — used by AnalysisTab when building
// the AI Analyse payload so the cost estimate refreshes as flags change.
//
// IMPORTANT: returns a fresh array snapshot each render. The previous
// version returned `_entries` directly — but because it's mutated in
// place, downstream `useMemo` calls that depend on the array saw the
// same reference and never re-ran (the AnalyseBar's ready-count stayed
// stale at 0 even after a flag was added).
export function useHuntFlags(): HuntFlagEntry[] {
  const [, setV] = useState(0)
  useEffect(() => {
    const bump = () => setV(v => v + 1)
    _listeners.add(bump)
    return () => { _listeners.delete(bump) }
  }, [])
  return _entries.slice()
}
