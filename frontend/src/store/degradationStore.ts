import { useState, useEffect } from 'react'

// Tracks which sub-fetches in the current investigation failed (or are
// retrying) so the UI can surface a non-blocking banner instead of
// silently rendering empty panels. Each call site reports under a
// stable `source` key and supplies a retry callback so the analyst can
// re-attempt without re-doing the whole investigation.
//
// Module-level (no React context) for the same reason as the other
// stores in this folder — sub-fetches fire from many places and we
// want them to feed a single banner without prop-drilling.

export interface DegradedEntry {
  source:   string       // stable id, e.g. 'incidents'
  label:    string       // analyst-facing name, e.g. 'host incidents'
  message:  string       // friendly explanation, e.g. 'Graph API timed out.'
  retry?:   () => void   // optional re-attempt callback
  at:       number       // ms epoch — used to sort newest first
}

const _entries = new Map<string, DegradedEntry>()
const _listeners = new Set<() => void>()

function _notify() {
  _listeners.forEach(fn => fn())
}

// friendlyError lives in utils/errors.ts so it can be used by call sites that
// aren't tied to the degradation banner (HuntTab, VtButton, etc). Re-exported
// here so existing imports keep working.
export { friendlyError } from '../utils/errors'

export function setDegraded(entry: Omit<DegradedEntry, 'at'>): void {
  _entries.set(entry.source, { ...entry, at: Date.now() })
  _notify()
}

export function clearDegraded(source: string): void {
  if (_entries.delete(source)) _notify()
}

export function clearAllDegraded(): void {
  if (_entries.size === 0) return
  _entries.clear()
  _notify()
}

export function useDegradedSources(): DegradedEntry[] {
  const [, setV] = useState(0)
  useEffect(() => {
    const bump = () => setV(v => v + 1)
    _listeners.add(bump)
    return () => { _listeners.delete(bump) }
  }, [])
  // Newest first so a fresh retry attempt that fails again moves to top.
  return Array.from(_entries.values()).sort((a, b) => b.at - a.at)
}
