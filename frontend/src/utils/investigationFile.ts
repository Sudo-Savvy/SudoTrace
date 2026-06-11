// Manual save / load of an investigation to a local JSON file. Reuses
// the same snapshot shape as the auto-save endpoint so an exported
// file can be re-imported into a fresh session and pick up where the
// analyst left off — including IOCs, hunt flags, timeline notes,
// title / detail / icon overrides, hidden events and AI analysis
// history. The file is for analyst-driven backup / handover; the
// auto-save endpoint covers crash recovery within the same instance.

import type { Investigation } from '../types'
import {
  captureSessionState, restoreSessionState, parseSnapshot,
  SESSION_STATE_VERSION, type PersistedSessionState,
} from './sessionState'

// Wrapper around the persisted shape so the file format is explicit and
// versioned independently of the on-server schema. We tag the file with
// a `kind` so we can reject the wrong JSON at import time.
export interface InvestigationFile {
  kind:    'sudotrace.investigation'
  format:  1
  exportedAt: string             // ISO timestamp of the export
  hostname:   string | null      // for the analyst's reference only
  state:   PersistedSessionState
}

function safeForFilename(s: string): string {
  return (s || 'investigation').replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60)
}

// Trigger a download of the analyst's current snapshot as a JSON file.
// The filename embeds the host + a UTC timestamp so multiple exports
// remain distinguishable on disk.
export function exportInvestigationToFile(investigation: Investigation | null): void {
  const snap = captureSessionState(investigation)
  const file: InvestigationFile = {
    kind:       'sudotrace.investigation',
    format:     1,
    exportedAt: new Date().toISOString(),
    hostname:   investigation?.hostname ?? null,
    state:      snap,
  }
  const stamp = (() => {
    const d = new Date()
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`
  })()
  const host = safeForFilename(investigation?.hostname || 'no-host')
  const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = `sudotrace-${host}-${stamp}.json`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export interface ImportResult {
  ok:            boolean
  error?:        string
  investigation?: Investigation | null
}

// Read + validate an investigation file. On success the analyst-authored
// state is pushed into the stores (same path the auto-save uses) and
// the caller receives the persisted investigation metadata so it can
// be applied to AuthenticatedApp's local state.
export async function importInvestigationFromFile(file: File): Promise<ImportResult> {
  let raw: string
  try {
    raw = await file.text()
  } catch (e) {
    return { ok: false, error: `Could not read the file: ${e instanceof Error ? e.message : String(e)}` }
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return { ok: false, error: 'File is not valid JSON.' }
  }
  if (!parsed || typeof parsed !== 'object') {
    return { ok: false, error: 'File contents are not an object.' }
  }
  const r = parsed as Partial<InvestigationFile>
  if (r.kind !== 'sudotrace.investigation') {
    return { ok: false, error: 'Not a SudoTrace investigation file.' }
  }
  if (r.format !== 1) {
    return { ok: false, error: `Unsupported file format version (${r.format}).` }
  }
  const snap = parseSnapshot(r.state)
  if (!snap) {
    return { ok: false, error: `Saved state is missing or uses an incompatible schema (expected v${SESSION_STATE_VERSION}).` }
  }
  restoreSessionState(snap)
  return { ok: true, investigation: snap.investigation }
}
