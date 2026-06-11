// Serialize / restore the analyst-authored portion of the investigation.
// Source of truth lives in the module-level stores; this file just
// gathers them into one blob for the auto-save endpoint and pushes a
// saved blob back into the stores on resume.
//
// Deliberately scoped to authored state: telemetry rows, the process
// tree, host incidents and device info are NOT persisted. They
// re-fetch on resume so the analyst gets a fresh view with their
// notes / IOCs / hunt flags / analysis history layered on top.

import type { Investigation } from '../types'
import {
  getIocs, hydrateIocs, type IocEntry,
} from '../store/iocStore'
import {
  getHuntFlags, hydrateHuntFlags, type HuntFlagEntry,
} from '../store/huntFlagStore'
import {
  getTimelineNotes, getEventAnnotations, getEventTitleOverrides, getEventDetailOverrides,
  getEventIconOverrides, getHiddenTimelineIds,
  hydrateAnalystTimelineState, type TimelineNote,
} from '../store/investigationStore'
import {
  getAnalysisHistory, hydrateAnalysisHistory, type AnalysisHistoryEntry,
} from '../store/analysisHistoryStore'

// Bump if the persisted shape changes in a way that requires us to
// drop older snapshots. We accept v1 only — anything else is treated
// as "no saved state" so the analyst gets a fresh start.
export const SESSION_STATE_VERSION = 1

export interface PersistedSessionState {
  v:                SESSION_STATE_V
  savedAt:          number
  investigation:    Investigation | null
  iocs:             IocEntry[]
  huntFlags:        HuntFlagEntry[]
  timelineNotes:    TimelineNote[]
  eventAnnotations: Record<string, string>
  eventTitleOverrides:  Record<string, string>
  eventDetailOverrides: Record<string, string>
  eventIconOverrides:   Record<string, string>
  hiddenTimelineIds: string[]
  analysisHistory:  AnalysisHistoryEntry[]
}
type SESSION_STATE_V = typeof SESSION_STATE_VERSION

// Build a snapshot of everything we persist. Cheap to call — just
// shallow copies of arrays / maps — so it can run on every change.
export function captureSessionState(investigation: Investigation | null): PersistedSessionState {
  return {
    v:                SESSION_STATE_VERSION,
    savedAt:          Date.now(),
    investigation,
    iocs:             getIocs(),
    huntFlags:        getHuntFlags(),
    timelineNotes:    getTimelineNotes(),
    eventAnnotations: getEventAnnotations(),
    eventTitleOverrides:  getEventTitleOverrides(),
    eventDetailOverrides: getEventDetailOverrides(),
    eventIconOverrides:   getEventIconOverrides(),
    hiddenTimelineIds: getHiddenTimelineIds(),
    analysisHistory:  getAnalysisHistory(),
  }
}

// Returns true if the snapshot carries anything worth resuming. An
// empty blob (e.g. the analyst opened the app but never started an
// investigation) shouldn't trigger the resume prompt on next login.
export function hasResumableContent(snap: PersistedSessionState | null): boolean {
  if (!snap || snap.v !== SESSION_STATE_VERSION) return false
  if (snap.investigation) return true
  if (snap.iocs.length) return true
  if (snap.huntFlags.length) return true
  if (snap.timelineNotes.length) return true
  if (Object.keys(snap.eventAnnotations).length) return true
  if (Object.keys(snap.eventTitleOverrides).length) return true
  if (Object.keys(snap.eventDetailOverrides).length) return true
  if (Object.keys(snap.eventIconOverrides).length) return true
  if (snap.hiddenTimelineIds.length) return true
  if (snap.analysisHistory.length) return true
  return false
}

// Validate-then-hydrate. Tolerates missing fields so older snapshots
// don't blow up — anything unparseable is silently dropped.
export function restoreSessionState(snap: PersistedSessionState): void {
  hydrateIocs(Array.isArray(snap.iocs) ? snap.iocs : [])
  hydrateHuntFlags(Array.isArray(snap.huntFlags) ? snap.huntFlags : [])
  hydrateAnalystTimelineState({
    notes:           Array.isArray(snap.timelineNotes) ? snap.timelineNotes : [],
    annotations:     (snap.eventAnnotations && typeof snap.eventAnnotations === 'object') ? snap.eventAnnotations : {},
    titleOverrides:  (snap.eventTitleOverrides && typeof snap.eventTitleOverrides === 'object') ? snap.eventTitleOverrides : {},
    detailOverrides: (snap.eventDetailOverrides && typeof snap.eventDetailOverrides === 'object') ? snap.eventDetailOverrides : {},
    iconOverrides:   (snap.eventIconOverrides && typeof snap.eventIconOverrides === 'object') ? snap.eventIconOverrides : {},
    hiddenIds:       Array.isArray(snap.hiddenTimelineIds) ? snap.hiddenTimelineIds : [],
  })
  hydrateAnalysisHistory(Array.isArray(snap.analysisHistory) ? snap.analysisHistory : [])
}

// An Investigation is only usable if the fields HomePage reads (hostname,
// id, the mode/window strings) are actually strings. A hand-edited or
// version-mismatched file could set `investigation` to a primitive or a
// half-formed object, which would crash HomePage (`investigation.hostname.…`)
// and — because autosave persists it — recur as a poison-pill on every
// resume. Reject anything that isn't well-formed; null is always safe.
function validateInvestigation(v: unknown): Investigation | null {
  if (!v || typeof v !== 'object') return null
  const o = v as Record<string, unknown>
  if (typeof o.id !== 'string' || typeof o.hostname !== 'string') return null
  if (typeof o.timeWindow !== 'string' || typeof o.rawTimeWindow !== 'string') return null
  if (typeof o.startedAt !== 'string') return null
  if (o.mode !== 'host-pid' && o.mode !== 'alert-id') return null
  // pid / alertId / focalTimeIso are nullable strings — coerce a wrong type to null.
  return {
    id:            o.id,
    hostname:      o.hostname,
    pid:           typeof o.pid === 'string' ? o.pid : null,
    alertId:       typeof o.alertId === 'string' ? o.alertId : null,
    mode:          o.mode,
    timeWindow:    o.timeWindow,
    rawTimeWindow: o.rawTimeWindow,
    focalTimeIso:  typeof o.focalTimeIso === 'string' ? o.focalTimeIso : null,
    startedAt:     o.startedAt,
  }
}

// Keep only notes whose load-bearing fields are the right type: a string
// id, a finite numeric tsMs (it's sorted with `a.tsMs - b.tsMs`), and a
// string text (rendered with `.trim()`). Coerce/drop the rest.
function validateNotes(v: unknown): TimelineNote[] {
  if (!Array.isArray(v)) return []
  const out: TimelineNote[] = []
  for (const n of v) {
    if (!n || typeof n !== 'object') continue
    const o = n as Record<string, unknown>
    if (typeof o.id !== 'string') continue
    if (typeof o.tsMs !== 'number' || !Number.isFinite(o.tsMs)) continue
    out.push({
      id:        o.id,
      tsMs:      o.tsMs,
      text:      typeof o.text === 'string' ? o.text : '',
      createdAt: typeof o.createdAt === 'number' ? o.createdAt : 0,
    })
  }
  return out
}

// Loose narrowing of an unknown blob from the server. Returns null if
// the blob is missing or doesn't match our current schema version.
export function parseSnapshot(raw: unknown): PersistedSessionState | null {
  if (!raw || typeof raw !== 'object') return null
  const r = raw as Record<string, unknown>
  if (r.v !== SESSION_STATE_VERSION) return null
  return {
    v:                 SESSION_STATE_VERSION,
    savedAt:           typeof r.savedAt === 'number' ? r.savedAt : 0,
    investigation:     validateInvestigation(r.investigation),
    iocs:              Array.isArray(r.iocs) ? (r.iocs as IocEntry[]) : [],
    huntFlags:         Array.isArray(r.huntFlags) ? (r.huntFlags as HuntFlagEntry[]) : [],
    timelineNotes:     validateNotes(r.timelineNotes),
    eventAnnotations:  (r.eventAnnotations && typeof r.eventAnnotations === 'object')
                         ? (r.eventAnnotations as Record<string, string>) : {},
    eventTitleOverrides: (r.eventTitleOverrides && typeof r.eventTitleOverrides === 'object')
                         ? (r.eventTitleOverrides as Record<string, string>) : {},
    eventDetailOverrides: (r.eventDetailOverrides && typeof r.eventDetailOverrides === 'object')
                         ? (r.eventDetailOverrides as Record<string, string>) : {},
    eventIconOverrides: (r.eventIconOverrides && typeof r.eventIconOverrides === 'object')
                         ? (r.eventIconOverrides as Record<string, string>) : {},
    hiddenTimelineIds: Array.isArray(r.hiddenTimelineIds) ? (r.hiddenTimelineIds as string[]) : [],
    analysisHistory:   Array.isArray(r.analysisHistory) ? (r.analysisHistory as AnalysisHistoryEntry[]) : [],
  }
}
