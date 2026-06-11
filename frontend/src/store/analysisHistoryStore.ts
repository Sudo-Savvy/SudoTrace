import { useState, useEffect } from 'react'
import type { AnalysisResult } from '../types'

// Per-investigation cache of completed AI analyses so the analyst can
// dismiss output and recall it later without re-spending tokens. Lives
// in module state for the page session; cleared alongside the other
// per-investigation stores on "New Investigation".
//
// We intentionally don't persist to localStorage — analysis results
// can be sizable (multiple KB each) and persisting would risk filling
// the quota silently. Session-only is enough to cover the common case
// of "I dismissed it five minutes ago, give it back to me."

export interface AnalysisHistoryEntry {
  id:        string
  ranAt:     number              // epoch ms
  scope:     'focused' | 'wide'
  // The original payload counts at submission time, for a one-line
  // summary in the history list ("5 procs · 2 events · 1 IOC").
  summary:   string
  // Real token usage / cost from the response, for the analyst's
  // benefit when comparing runs.
  inputTokens?:  number
  outputTokens?: number
  costUsd?:      number
  durationMs?:   number
  result:    AnalysisResult
}

const _entries: AnalysisHistoryEntry[] = []
const _listeners = new Set<() => void>()
function _notify() { _listeners.forEach(fn => fn()) }

export function recordAnalysis(entry: AnalysisHistoryEntry): void {
  _entries.unshift(entry)  // newest first
  _notify()
}

export function removeAnalysisEntry(id: string): void {
  const idx = _entries.findIndex(e => e.id === id)
  if (idx < 0) return
  _entries.splice(idx, 1)
  _notify()
}

export function clearAnalysisHistory(): void {
  if (_entries.length === 0) return
  _entries.splice(0, _entries.length)
  _notify()
}

// Snapshot for session auto-save.
export function getAnalysisHistory(): AnalysisHistoryEntry[] {
  return _entries.slice()
}

// Replace the list wholesale — used by session recovery on login.
export function hydrateAnalysisHistory(list: AnalysisHistoryEntry[]): void {
  _entries.splice(0, _entries.length)
  for (const e of list) {
    if (!e || typeof e.id !== 'string' || !e.result) continue
    _entries.push(e)
  }
  _notify()
}

export function useAnalysisHistory(): AnalysisHistoryEntry[] {
  const [, setV] = useState(0)
  useEffect(() => {
    const bump = () => setV(v => v + 1)
    _listeners.add(bump)
    return () => { _listeners.delete(bump) }
  }, [])
  return _entries.slice()
}
