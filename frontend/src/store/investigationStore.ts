import { useState, useEffect } from 'react'
import type { InvestigateResponse, HostIncident, FlagStatus } from '../types'

export interface FlaggedNodeRef     { node_key: string; flag: NonNullable<FlagStatus> }
export interface FlaggedEventRef    {
  key: string; flag: NonNullable<FlagStatus>
  row: Record<string, unknown>; tab: string
}
export interface FlaggedIncidentRef { incident_id: string; flag: NonNullable<FlagStatus> }

// Module-level store for cross-tab investigation data. AnalysisTab owns
// the loading lifecycle and pushes data in via setters; other top-level
// tabs (Timeline, future Report tab) subscribe via the hooks. Mirrors
// the pattern of iocStore / huntFlagStore so the codebase has one
// consistent shape for "data this tab loaded, other tabs need to read".
//
// Cleared on "New Investigation" alongside the IOC list and hunt flags.

interface InvestigationState {
  treeData:       InvestigateResponse | null
  hostIncidents:  HostIncident[] | null
  hostname:       string | null
}

const _state: InvestigationState = {
  treeData:       null,
  hostIncidents:  null,
  hostname:       null,
}

// Timeline events the analyst has chosen to hide. Kept here (rather
// than in TimelineTab's local state) because the tab unmounts when the
// analyst switches away — without a persistent store the hide list
// would reset on every tab change. Reset on new investigation.
const _hiddenTimelineIds = new Set<string>()

// Snapshots of analyst flags pushed in from AnalysisTab so the Timeline
// can include malicious-flagged items as their own category. AnalysisTab
// remains the source of truth; these are just read-views.
let _flaggedNodes:     FlaggedNodeRef[]     = []
let _flaggedEvents:    FlaggedEventRef[]    = []
let _flaggedIncidents: FlaggedIncidentRef[] = []

// Analyst-authored notes on the Timeline — used to record off-host
// context (USB stolen from user, social engineering, physical
// access, …) that the telemetry can't capture. Each note has an
// editable text and a manual timestamp the analyst can drag to
// reposition in the chronology.
export interface TimelineNote {
  id:        string
  tsMs:      number     // manual timestamp; sorted alongside event tsMs
  text:      string
  createdAt: number
}
let _timelineNotes: TimelineNote[] = []

// Per-event analyst annotations — keyed by the event's timeline id
// (`flag:proc:…`, `alert:…`, `inc:…`, `note:…` etc.). Lets the analyst
// add commentary on top of auto-pulled timeline events without
// modifying the underlying data. Cleared on new investigation.
const _eventAnnotations = new Map<string, string>()
// Per-event title overrides — same keying as annotations. When set, the
// timeline renders the analyst's text in place of the auto-generated
// "Flagged MALICIOUS — …" line so they can give an event a meaningful
// short name (e.g. "Initial PowerShell payload"). Notes don't use this
// — their text is already the title and is edited inline.
const _eventTitleOverrides = new Map<string, string>()
// Same idea for the detail line. Lets the analyst rewrite the
// command-line / network / hash dump into a sentence the report reader
// can understand at a glance ("Spawned by Excel macro, dumped LSASS via
// MiniDumpWriteDump"). Saved + restored alongside title overrides.
const _eventDetailOverrides = new Map<string, string>()
// Optional custom icon for an event ("💣", "🔓", a unicode char) so the
// analyst can convey severity / nature at a glance instead of the
// auto-assigned ⚠ / 🛡 / 🚩 / 📝. Persisted with the other overrides.
const _eventIconOverrides = new Map<string, string>()
const _listeners = new Set<() => void>()

function _notify() {
  _listeners.forEach(fn => fn())
}

export function setInvTreeData(d: InvestigateResponse | null): void {
  if (_state.treeData === d) return
  _state.treeData = d
  _notify()
}

export function setInvHostIncidents(list: HostIncident[] | null): void {
  if (_state.hostIncidents === list) return
  _state.hostIncidents = list
  _notify()
}

export function setInvHostname(h: string | null): void {
  if (_state.hostname === h) return
  _state.hostname = h
  _notify()
}

export function clearInvestigation(): void {
  const wasEmpty = _state.treeData === null && _state.hostIncidents === null
                  && _state.hostname === null && _hiddenTimelineIds.size === 0
                  && _flaggedNodes.length === 0 && _flaggedEvents.length === 0
                  && _flaggedIncidents.length === 0 && _timelineNotes.length === 0
                  && _eventAnnotations.size === 0 && _eventTitleOverrides.size === 0
                  && _eventDetailOverrides.size === 0 && _eventIconOverrides.size === 0
  if (wasEmpty) return
  _state.treeData = null
  _state.hostIncidents = null
  _state.hostname = null
  _hiddenTimelineIds.clear()
  _flaggedNodes = []
  _flaggedEvents = []
  _flaggedIncidents = []
  _timelineNotes = []
  _eventAnnotations.clear()
  _eventTitleOverrides.clear()
  _eventDetailOverrides.clear()
  _eventIconOverrides.clear()
  _notify()
}

export function setEventAnnotation(eventId: string, text: string): void {
  const trimmed = text.trim()
  if (!trimmed) _eventAnnotations.delete(eventId)
  else          _eventAnnotations.set(eventId, trimmed)
  _notify()
}

// Empty string clears the override (back to the auto-generated title).
export function setEventTitleOverride(eventId: string, text: string): void {
  const trimmed = text.trim()
  if (!trimmed) _eventTitleOverrides.delete(eventId)
  else          _eventTitleOverrides.set(eventId, trimmed)
  _notify()
}
export function setEventDetailOverride(eventId: string, text: string): void {
  const trimmed = text.trim()
  if (!trimmed) _eventDetailOverrides.delete(eventId)
  else          _eventDetailOverrides.set(eventId, trimmed)
  _notify()
}
export function setEventIconOverride(eventId: string, icon: string): void {
  const trimmed = icon.trim()
  if (!trimmed) _eventIconOverrides.delete(eventId)
  else          _eventIconOverrides.set(eventId, trimmed)
  _notify()
}

export function addTimelineNote(note: TimelineNote): void {
  _timelineNotes.push(note)
  _notify()
}

export function updateTimelineNote(id: string, updates: Partial<TimelineNote>): void {
  const idx = _timelineNotes.findIndex(n => n.id === id)
  if (idx < 0) return
  _timelineNotes[idx] = { ..._timelineNotes[idx], ...updates }
  _notify()
}

export function removeTimelineNote(id: string): void {
  const idx = _timelineNotes.findIndex(n => n.id === id)
  if (idx < 0) return
  _timelineNotes.splice(idx, 1)
  _notify()
}

export function setInvFlaggedNodes(list: FlaggedNodeRef[]): void {
  _flaggedNodes = list
  _notify()
}
export function setInvFlaggedEvents(list: FlaggedEventRef[]): void {
  _flaggedEvents = list
  _notify()
}
export function setInvFlaggedIncidents(list: FlaggedIncidentRef[]): void {
  _flaggedIncidents = list
  _notify()
}

export function hideTimelineEvent(id: string): void {
  if (_hiddenTimelineIds.has(id)) return
  _hiddenTimelineIds.add(id)
  _notify()
}

export function unhideTimelineEvent(id: string): void {
  if (!_hiddenTimelineIds.has(id)) return
  _hiddenTimelineIds.delete(id)
  _notify()
}

export function clearHiddenTimelineEvents(): void {
  if (_hiddenTimelineIds.size === 0) return
  _hiddenTimelineIds.clear()
  _notify()
}

// Snapshots for session auto-save.
export function getTimelineNotes(): TimelineNote[] {
  return _timelineNotes.slice()
}
export function getEventAnnotations(): Record<string, string> {
  return Object.fromEntries(_eventAnnotations)
}
export function getEventTitleOverrides(): Record<string, string> {
  return Object.fromEntries(_eventTitleOverrides)
}
export function getEventDetailOverrides(): Record<string, string> {
  return Object.fromEntries(_eventDetailOverrides)
}
export function getEventIconOverrides(): Record<string, string> {
  return Object.fromEntries(_eventIconOverrides)
}
export function getHiddenTimelineIds(): string[] {
  return Array.from(_hiddenTimelineIds)
}

// Restore analyst-authored timeline state from a saved snapshot. Used by
// session recovery on login; the hydrate side only touches notes /
// annotations / title overrides / hidden IDs — treeData / hostIncidents
// / hostname re-fetch.
export function hydrateAnalystTimelineState(snapshot: {
  notes?:           TimelineNote[]
  annotations?:     Record<string, string>
  titleOverrides?:  Record<string, string>
  detailOverrides?: Record<string, string>
  iconOverrides?:   Record<string, string>
  hiddenIds?:       string[]
}): void {
  _timelineNotes = (snapshot.notes ?? []).filter(n => n && typeof n.id === 'string')
  _eventAnnotations.clear()
  if (snapshot.annotations) {
    for (const [k, v] of Object.entries(snapshot.annotations)) {
      if (typeof v === 'string' && v) _eventAnnotations.set(k, v)
    }
  }
  _eventTitleOverrides.clear()
  if (snapshot.titleOverrides) {
    for (const [k, v] of Object.entries(snapshot.titleOverrides)) {
      if (typeof v === 'string' && v) _eventTitleOverrides.set(k, v)
    }
  }
  _eventDetailOverrides.clear()
  if (snapshot.detailOverrides) {
    for (const [k, v] of Object.entries(snapshot.detailOverrides)) {
      if (typeof v === 'string' && v) _eventDetailOverrides.set(k, v)
    }
  }
  _eventIconOverrides.clear()
  if (snapshot.iconOverrides) {
    for (const [k, v] of Object.entries(snapshot.iconOverrides)) {
      if (typeof v === 'string' && v) _eventIconOverrides.set(k, v)
    }
  }
  _hiddenTimelineIds.clear()
  for (const id of snapshot.hiddenIds ?? []) {
    if (typeof id === 'string') _hiddenTimelineIds.add(id)
  }
  _notify()
}

function useInvState<T>(pick: (s: InvestigationState) => T): T {
  const [, setV] = useState(0)
  useEffect(() => {
    const bump = () => setV(v => v + 1)
    _listeners.add(bump)
    return () => { _listeners.delete(bump) }
  }, [])
  return pick(_state)
}

export function useInvTreeData(): InvestigateResponse | null {
  return useInvState(s => s.treeData)
}

export function useInvHostIncidents(): HostIncident[] | null {
  return useInvState(s => s.hostIncidents)
}

export function useInvHostname(): string | null {
  return useInvState(s => s.hostname)
}

// Returns a fresh Set snapshot so downstream useMemo deps reliably
// invalidate when entries are added/removed.
export function useHiddenTimelineIds(): Set<string> {
  const [, setV] = useState(0)
  useEffect(() => {
    const bump = () => setV(v => v + 1)
    _listeners.add(bump)
    return () => { _listeners.delete(bump) }
  }, [])
  return new Set(_hiddenTimelineIds)
}

// Flag accessors — fresh array snapshots so useMemo invalidates cleanly.
export function useInvFlaggedNodes(): FlaggedNodeRef[] {
  return useInvState(() => _flaggedNodes.slice())
}
export function useInvFlaggedEvents(): FlaggedEventRef[] {
  return useInvState(() => _flaggedEvents.slice())
}
export function useInvFlaggedIncidents(): FlaggedIncidentRef[] {
  return useInvState(() => _flaggedIncidents.slice())
}
export function useTimelineNotes(): TimelineNote[] {
  return useInvState(() => _timelineNotes.slice())
}
export function useEventAnnotations(): Map<string, string> {
  return useInvState(() => new Map(_eventAnnotations))
}
export function useEventTitleOverrides(): Map<string, string> {
  return useInvState(() => new Map(_eventTitleOverrides))
}
export function useEventDetailOverrides(): Map<string, string> {
  return useInvState(() => new Map(_eventDetailOverrides))
}
export function useEventIconOverrides(): Map<string, string> {
  return useInvState(() => new Map(_eventIconOverrides))
}
