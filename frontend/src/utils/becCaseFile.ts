// Portable BEC case file — lets an analyst save the current account-compromise
// case to a JSON file and re-import it (archive a case, or hand it to another
// analyst). The case's analyst-authored state already lives server-side in
// bec_case_state (auto-saved); this just wraps it in a versioned file envelope.

import type { BecCaseState } from '../api/bec'

const BEC_KIND = 'sudotrace.bec-case'

interface BecCaseFile {
  kind: typeof BEC_KIND
  format: 1
  exportedAt: string
  case: BecCaseState
}

function safeForFilename(s: string): string {
  return (s || 'case').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 60)
}

export function exportBecCaseToFile(c: BecCaseState): void {
  const file: BecCaseFile = {
    kind: BEC_KIND, format: 1, exportedAt: new Date().toISOString(), case: c,
  }
  const d = new Date(); const pad = (n: number) => String(n).padStart(2, '0')
  const stamp = `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`
  const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `sudotrace-bec-${safeForFilename(c.account)}-${stamp}.json`
  document.body.appendChild(a); a.click(); a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

// Detect whether an uploaded file is a BEC case (vs an endpoint investigation).
// Returns the parsed case on success so the caller can route it.
export async function parseBecCaseFile(file: File): Promise<
  { ok: true; case: BecCaseState } | { ok: false; reason: string }
> {
  let text: string
  try { text = await file.text() } catch { return { ok: false, reason: 'Could not read the file.' } }
  let data: unknown
  try { data = JSON.parse(text) } catch { return { ok: false, reason: 'Not a valid JSON file.' } }
  const obj = data as Partial<BecCaseFile>
  if (!obj || obj.kind !== BEC_KIND || !obj.case || typeof obj.case.account !== 'string') {
    return { ok: false, reason: 'NOT_BEC' }   // caller falls back to the endpoint importer
  }
  const c = obj.case
  // Normalise — tolerate older/partial files.
  return {
    ok: true,
    case: {
      account: c.account,
      ip: c.ip ?? '',
      time_window: c.time_window ?? 'last24h',
      offline: c.offline ?? false,
      selected: c.selected ?? [],
      checked: c.checked ?? [],
      notes: c.notes ?? {},
      timeline_custom: c.timeline_custom ?? [],
      timeline_hidden: c.timeline_hidden ?? [],
      manual_ips: c.manual_ips ?? [],
    },
  }
}

export function isBecCaseFilename(name: string): boolean {
  return /sudotrace-bec-/i.test(name)
}
