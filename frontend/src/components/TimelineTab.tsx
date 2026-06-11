import { useMemo, useState, useRef } from 'react'
import { createPortal } from 'react-dom'
import {
  useInvTreeData, useInvHostIncidents, useInvHostname,
  useHiddenTimelineIds, hideTimelineEvent, unhideTimelineEvent,
  clearHiddenTimelineEvents,
  useInvFlaggedNodes, useInvFlaggedEvents, useInvFlaggedIncidents,
  useTimelineNotes, addTimelineNote, updateTimelineNote, removeTimelineNote,
  useEventAnnotations, setEventAnnotation,
  useEventTitleOverrides, setEventTitleOverride,
  useEventDetailOverrides, setEventDetailOverride,
  useEventIconOverrides, setEventIconOverride,
  type TimelineNote,
} from '../store/investigationStore'
import { useHuntFlags } from '../store/huntFlagStore'
import { buildTimeline, buildHuntRequestForEvent, type TimelineEvent, type TimelineCategory } from '../utils/timelineBuilder'
import { fmtDate, fmtTime } from '../utils/dateFormat'
import { useTimezone } from '../utils/timezone'
import type { HuntJumpRequest } from './HuntTab'
import RangePicker from './RangePicker'

const CATEGORY_LABEL: Record<TimelineCategory, string> = {
  incident: 'incident',
  alert:    'alert',
  flag:     'analyst flag',
  note:     'analyst note',
}

// Compact one-line view of every event. Filters at the top let the
// analyst hide noisy categories (e.g. drop process spawns once they're
// focused on alert correlation).
export default function TimelineTab({ onNavigate }: {
  onNavigate?: (req: HuntJumpRequest) => void
}) {
  const treeData         = useInvTreeData()
  const hostIncidents    = useInvHostIncidents()
  const hostname         = useInvHostname()
  const flaggedNodes     = useInvFlaggedNodes()
  const flaggedEvents    = useInvFlaggedEvents()
  const flaggedIncidents = useInvFlaggedIncidents()
  const huntFlags        = useHuntFlags()
  const notes            = useTimelineNotes()
  useTimezone()  // re-render when the analyst changes the display tz in Settings
  const autoEvents = useMemo(
    () => buildTimeline(treeData, hostIncidents, flaggedNodes, flaggedEvents, flaggedIncidents, huntFlags),
    [treeData, hostIncidents, flaggedNodes, flaggedEvents, flaggedIncidents, huntFlags],
  )
  // Notes are folded in as timeline events so they sort alongside the
  // auto-pulled entries by their (analyst-set) timestamp.
  const events = useMemo(() => {
    const noteEvents: TimelineEvent[] = notes.map(n => ({
      id:       `note:${n.id}`,
      tsMs:     n.tsMs,
      tsIso:    new Date(n.tsMs).toISOString(),
      category: 'note',
      icon:     '📝',
      // Prefix every analyst-authored note so it's unmistakably an
      // off-host annotation (USB swap, social engineering, physical
      // access, etc.) rather than something pulled from telemetry.
      title:    n.text || '(empty note)',
      detail:   '',
      colour:   '#A878FF',
    }))
    return [...autoEvents, ...noteEvents].sort((a, b) => a.tsMs - b.tsMs)
  }, [autoEvents, notes])

  const [filter, setFilter] = useState<Set<TimelineCategory>>(
    () => new Set<TimelineCategory>(['incident', 'alert', 'flag', 'note']),
  )
  const hiddenIds = useHiddenTimelineIds()
  const [showHidden, setShowHidden] = useState(false)
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null)
  const [draggingNoteId, setDraggingNoteId] = useState<string | null>(null)
  const [annotatingEventId, setAnnotatingEventId] = useState<string | null>(null)
  const [editingEventId, setEditingEventId] = useState<string | null>(null)
  const annotations     = useEventAnnotations()
  const titleOverrides  = useEventTitleOverrides()
  const detailOverrides = useEventDetailOverrides()
  const iconOverrides   = useEventIconOverrides()
  const visible = events.filter(e =>
    filter.has(e.category) && (showHidden || !hiddenIds.has(e.id))
  )

  function toggle(c: TimelineCategory) {
    setFilter(prev => {
      const n = new Set(prev)
      if (n.has(c)) n.delete(c); else n.add(c)
      return n
    })
  }

  const countByCat: Record<TimelineCategory, number> = {
    incident: 0, alert: 0, flag: 0, note: 0,
  }
  for (const e of events) countByCat[e.category]++

  function addNote() {
    // Anchor the new note at the timestamp of the latest auto-event
    // (or now if there are none), so it lands at the bottom of the
    // timeline by default — the analyst can drag it earlier.
    const anchorMs = autoEvents.length > 0
      ? autoEvents[autoEvents.length - 1].tsMs + 1000
      : Date.now()
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
    addTimelineNote({
      id, tsMs: anchorMs, text: '', createdAt: Date.now(),
    })
    setEditingNoteId(id)
  }

  function exportCsv() {
    const csv = buildTimelineCsv(visible, annotations, titleOverrides, detailOverrides, hostname)
    const stamp = (() => {
      const d = new Date()
      const pad = (n: number) => String(n).padStart(2, '0')
      return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`
    })()
    const safeHost = (hostname || 'host').replace(/[^A-Za-z0-9._-]+/g, '_')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `timeline-${safeHost}-${stamp}.csv`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  // Drop handler — derive the dragged note's new timestamp as the
  // midpoint between the event above the drop target and the target
  // itself. If dropped on the very first row, place 1s before it; if
  // dropped past the last row, place 1s after it.
  function handleDropOn(targetId: string) {
    if (!draggingNoteId || draggingNoteId === targetId) return
    const idx = visible.findIndex(e => e.id === targetId)
    if (idx < 0) return
    const above = idx > 0 ? visible[idx - 1] : null
    const target = visible[idx]
    let newMs: number
    if (!above) {
      newMs = target.tsMs - 1000
    } else if (above.id === `note:${draggingNoteId}`) {
      // The dragged note is currently directly above the target — do nothing.
      setDraggingNoteId(null)
      return
    } else {
      newMs = Math.floor((above.tsMs + target.tsMs) / 2)
      // Ensure strict ordering even if neighbours share a timestamp.
      if (newMs === above.tsMs) newMs = above.tsMs + 1
    }
    updateTimelineNote(draggingNoteId, { tsMs: newMs })
    setDraggingNoteId(null)
  }

  if (!treeData && !hostIncidents) {
    return (
      <div style={{
        flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexDirection: 'column', gap: 6,
        color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11.5,
      }}>
        <div style={{ color: 'var(--accent)', fontSize: 12 }}>▌ no investigation loaded</div>
        <div>Start an investigation to populate the timeline.</div>
      </div>
    )
  }

  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0,
      background: 'var(--bg-panel)', fontFamily: 'var(--font-mono)', fontSize: 11,
    }}>
      {/* Title strip + filter chips */}
      <div style={{
        padding: '8px 14px', borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', gap: 14, flexShrink: 0,
      }}>
        <span style={{ color: 'var(--accent)', fontWeight: 600, fontSize: 12 }}>▌ timeline</span>
        <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>
          {events.length} event{events.length === 1 ? '' : 's'}
          {hostname && <> · host <span style={{ color: 'var(--text)' }}>{hostname}</span></>}
        </span>
        <span style={{ flex: 1 }} />
        {hiddenIds.size > 0 && (
          <>
            <span
              onClick={() => setShowHidden(s => !s)}
              title={showHidden ? 'Hide dismissed events again' : 'Show dismissed events'}
              style={{
                cursor: 'pointer', userSelect: 'none',
                padding: '2px 8px', borderRadius: 3,
                fontSize: 10.5,
                color: showHidden ? 'var(--text)' : 'var(--text-muted)',
                background: showHidden ? 'var(--bg-elevated)' : 'transparent',
                border: `1px solid ${showHidden ? 'var(--border)' : 'transparent'}`,
              }}>
              {showHidden ? '◉' : '◯'} show hidden · {hiddenIds.size}
            </span>
            <span
              onClick={() => { clearHiddenTimelineEvents(); setShowHidden(false) }}
              title="Restore all hidden events"
              style={{
                cursor: 'pointer', userSelect: 'none',
                padding: '2px 8px', borderRadius: 3, fontSize: 10.5,
                color: 'var(--text-muted)', border: '1px solid var(--border)',
              }}
              onMouseEnter={e => { e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.borderColor = 'var(--accent)' }}
              onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}>
              restore all
            </span>
          </>
        )}
        <FilterChip label="incidents" icon="🛡" active={filter.has('incident')}
          count={countByCat.incident} onClick={() => toggle('incident')} />
        <FilterChip label="alerts" icon="⚠" active={filter.has('alert')}
          count={countByCat.alert} onClick={() => toggle('alert')} />
        <FilterChip label="flags" icon="🚩" active={filter.has('flag')}
          count={countByCat.flag} onClick={() => toggle('flag')} />
        <FilterChip label="notes" icon="📝" active={filter.has('note')}
          count={countByCat.note} onClick={() => toggle('note')} />
        <span
          onClick={addNote}
          title="Add an analyst note (USB swap, social engineering, physical access, etc.) — drag to position in the chronology"
          style={{
            cursor: 'pointer', userSelect: 'none',
            padding: '2px 8px', borderRadius: 3,
            fontSize: 10.5, fontWeight: 600,
            color: 'var(--accent)',
            border: '1px solid var(--accent)',
            background: 'rgba(168,85,247,0.10)',
          }}
          onMouseEnter={e => { e.currentTarget.style.background = 'rgba(168,85,247,0.22)' }}
          onMouseLeave={e => { e.currentTarget.style.background = 'rgba(168,85,247,0.10)' }}>
          + add note
        </span>
        <span
          onClick={visible.length === 0 ? undefined : exportCsv}
          title={
            visible.length === 0
              ? 'Nothing to export — timeline is empty or fully filtered out'
              : `Download ${visible.length} visible event${visible.length === 1 ? '' : 's'} as CSV`
          }
          style={{
            cursor: visible.length === 0 ? 'not-allowed' : 'pointer',
            userSelect: 'none',
            padding: '2px 8px', borderRadius: 3,
            fontSize: 10.5, fontWeight: 600,
            color: visible.length === 0 ? 'var(--text-muted)' : 'var(--accent)',
            border: `1px solid ${visible.length === 0 ? 'var(--border)' : 'var(--accent)'}`,
            background: 'transparent',
            opacity: visible.length === 0 ? 0.6 : 1,
            transition: 'background 100ms',
          }}
          onMouseEnter={e => {
            if (visible.length > 0) e.currentTarget.style.background = 'rgba(168,85,247,0.18)'
          }}
          onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}>
          ⤓ export CSV
        </span>
      </div>

      {/* Body */}
      {visible.length === 0 ? (
        <div style={{
          flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: 'var(--text-muted)', fontSize: 11,
        }}>
          {events.length === 0
            ? 'Nothing to show yet — wait for the investigation to finish loading.'
            : 'All categories are hidden — re-enable a filter above.'}
        </div>
      ) : (
        <div style={{ flex: 1, minHeight: 0, overflow: 'auto' }}>
          <table style={{
            borderCollapse: 'separate', borderSpacing: 0,
            width: '100%', fontSize: 11,
            color: '#fff',
          }}>
            <tbody>
              {visible.map(e => {
                const req = e.category !== 'note' && onNavigate
                  ? buildHuntRequestForEvent(e, treeData, hostname, huntFlags)
                  : null
                const noteId = e.id.startsWith('note:') ? e.id.slice('note:'.length) : null
                const note: TimelineNote | null = noteId
                  ? notes.find(n => n.id === noteId) ?? null
                  : null
                return (
                  <TimelineRow
                    key={e.id}
                    event={e}
                    hidden={hiddenIds.has(e.id)}
                    onHide={() => hideTimelineEvent(e.id)}
                    onUnhide={() => unhideTimelineEvent(e.id)}
                    onJump={req && onNavigate ? () => onNavigate(req) : undefined}
                    note={note}
                    isEditingNote={editingNoteId === noteId}
                    onEditNote={() => setEditingNoteId(noteId)}
                    onSaveNote={(text, tsMs, icon) => {
                      if (note) {
                        const updates: Partial<TimelineNote> = { text }
                        if (typeof tsMs === 'number' && !isNaN(tsMs)) updates.tsMs = tsMs
                        updateTimelineNote(note.id, updates)
                      }
                      // Icon override is keyed by the timeline event id
                      // (`note:${noteId}`) so it lives in the shared icon
                      // override map alongside auto-event overrides.
                      if (typeof icon === 'string') {
                        setEventIconOverride(e.id, icon === '📝' ? '' : icon)
                      }
                      setEditingNoteId(null)
                    }}
                    onCancelEdit={() => setEditingNoteId(null)}
                    onDeleteNote={() => { if (note) removeTimelineNote(note.id) }}
                    isDraggingNote={draggingNoteId === noteId}
                    onDragStartNote={() => { if (noteId) setDraggingNoteId(noteId) }}
                    onDragEndNote={() => setDraggingNoteId(null)}
                    onDropOnRow={() => handleDropOn(e.id)}
                    canAcceptDrop={!!draggingNoteId && draggingNoteId !== noteId}
                    annotation={annotations.get(e.id) ?? null}
                    isAnnotating={annotatingEventId === e.id}
                    onStartAnnotate={() => setAnnotatingEventId(e.id)}
                    onSaveAnnotation={(text) => {
                      setEventAnnotation(e.id, text)
                      setAnnotatingEventId(null)
                    }}
                    onCancelAnnotate={() => setAnnotatingEventId(null)}
                    titleOverride={titleOverrides.get(e.id) ?? null}
                    detailOverride={detailOverrides.get(e.id) ?? null}
                    iconOverride={iconOverrides.get(e.id) ?? null}
                    isEditingEvent={editingEventId === e.id}
                    onStartEditEvent={() => setEditingEventId(e.id)}
                    onSaveEditEvent={(title, detail, icon) => {
                      setEventTitleOverride(e.id, title)
                      setEventDetailOverride(e.id, detail)
                      setEventIconOverride(e.id, icon)
                      setEditingEventId(null)
                    }}
                    onCancelEditEvent={() => setEditingEventId(null)}
                  />
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function FilterChip({ label, icon, active, count, onClick }: {
  label: string; icon: string; active: boolean; count: number
  onClick: () => void
}) {
  return (
    <span
      onClick={onClick}
      style={{
        cursor: 'pointer', userSelect: 'none',
        padding: '2px 8px', borderRadius: 3,
        fontSize: 10.5,
        color: active ? 'var(--text)' : 'var(--text-muted)',
        background: active ? 'var(--bg-elevated)' : 'transparent',
        border: `1px solid ${active ? 'var(--border)' : 'transparent'}`,
        transition: 'color 100ms, background 100ms, border-color 100ms',
      }}
      title={active ? `Hide ${label}` : `Show ${label}`}>
      {icon} {label} <span style={{ color: 'var(--text-muted)' }}>· {count}</span>
    </span>
  )
}

// Wrap a value as a CSV field — quote if it contains a comma, quote,
// CR or LF; double internal quotes per RFC 4180. Excel + Sheets handle
// embedded newlines inside quoted fields, which we want for command
// lines and analyst annotations that often run long.
function csvField(v: string | number | null | undefined): string {
  if (v === null || v === undefined) return ''
  const s = String(v)
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`
  return s
}

function buildTimelineCsv(
  events: TimelineEvent[],
  annotations: Map<string, string>,
  titleOverrides:  Map<string, string>,
  detailOverrides: Map<string, string>,
  hostname: string | null,
): string {
  const headers = [
    'Timestamp (UTC ISO)',
    'Date (DD/MM/YYYY)',
    'Time (UTC)',
    'Category',
    'Title',
    'Detail',
    'Analyst Annotation',
    'Host',
  ]
  const rows: string[] = [headers.join(',')]
  for (const e of events) {
    const ts = fmtTimestamp(e.tsIso)
    const title  = titleOverrides.get(e.id)  ?? e.title
    const detail = detailOverrides.get(e.id) ?? e.detail
    rows.push([
      csvField(e.tsIso),
      csvField(ts.date),
      csvField(ts.time),
      csvField(CATEGORY_LABEL[e.category]),
      csvField(title),
      csvField(detail),
      csvField(annotations.get(e.id) ?? ''),
      csvField(hostname ?? ''),
    ].join(','))
  }
  // BOM so Excel picks UTF-8 correctly on Windows.
  return '﻿' + rows.join('\r\n') + '\r\n'
}

function fmtTimestamp(iso: string): { date: string; time: string } {
  // Notes use an ISO produced by `new Date(tsMs).toISOString()` (always
  // UTC). Auto-events come straight from MDE as UTC ISO. Display uses
  // the analyst-selected timezone — fmtDate / fmtTime read it from the
  // module-level store.
  if (!iso) return { date: '', time: '' }
  return { date: fmtDate(iso), time: fmtTime(iso, true) }
}

function TimelineRow({
  event, hidden, onHide, onUnhide, onJump,
  note, isEditingNote, onEditNote, onSaveNote, onCancelEdit, onDeleteNote,
  isDraggingNote, onDragStartNote, onDragEndNote, onDropOnRow, canAcceptDrop,
  annotation, isAnnotating, onStartAnnotate, onSaveAnnotation, onCancelAnnotate,
  titleOverride, detailOverride, iconOverride, isEditingEvent,
  onStartEditEvent, onSaveEditEvent, onCancelEditEvent,
}: {
  event: TimelineEvent
  hidden: boolean
  onHide: () => void
  onUnhide: () => void
  onJump?: () => void
  note?: TimelineNote | null
  isEditingNote?: boolean
  onEditNote?: () => void
  onSaveNote?: (text: string, tsMs?: number, icon?: string) => void
  onCancelEdit?: () => void
  onDeleteNote?: () => void
  isDraggingNote?: boolean
  onDragStartNote?: () => void
  onDragEndNote?: () => void
  onDropOnRow?: () => void
  canAcceptDrop?: boolean
  annotation?: string | null
  isAnnotating?: boolean
  onStartAnnotate?: () => void
  onSaveAnnotation?: (text: string) => void
  onCancelAnnotate?: () => void
  titleOverride?:    string | null
  detailOverride?:   string | null
  iconOverride?:     string | null
  isEditingEvent?:   boolean
  onStartEditEvent?: () => void
  onSaveEditEvent?:  (title: string, detail: string, icon: string) => void
  onCancelEditEvent?: () => void
}) {
  const ts = fmtTimestamp(event.tsIso)
  // Fall back to accent purple rather than muted grey when an event
  // has no severity-derived colour. The grey fallback made the whole
  // timeline feel washed out.
  const accent = event.colour ?? 'var(--accent)'
  const isNote = !!note
  const [dragOver, setDragOver] = useState(false)
  const [hovered, setHovered] = useState(false)
  // Hover treatment is louder for draggable note rows so the analyst
  // can clearly see which one they're about to pick up. Auto events
  // get a softer tint since they're not draggable.
  const hoverBg = isNote && !isEditingNote
    ? 'rgba(168,85,247,0.15)'
    : 'rgba(168,85,247,0.06)'
  return (
    <>
      {/* Bold drop indicator — a 4px purple bar with a glow that sits
          *above* the target row when a note is dragged over it. Much
          more visible than a thin border on the row itself. */}
      {dragOver && (
        <tr>
          <td colSpan={5} style={{
            padding: 0, height: 4,
            background: 'var(--accent)',
            boxShadow: '0 0 8px 1px rgba(168,85,247,0.6)',
          }} />
        </tr>
      )}
      <tr
      draggable={isNote && !isEditingNote}
      onDragStart={isNote ? (e) => {
        e.dataTransfer.effectAllowed = 'move'
        onDragStartNote?.()
      } : undefined}
      onDragEnd={isNote ? () => onDragEndNote?.() : undefined}
      onDragOver={canAcceptDrop ? (e) => {
        e.preventDefault()
        e.dataTransfer.dropEffect = 'move'
        if (!dragOver) setDragOver(true)
      } : undefined}
      onDragLeave={canAcceptDrop ? () => setDragOver(false) : undefined}
      onDrop={canAcceptDrop ? (e) => {
        e.preventDefault()
        setDragOver(false)
        onDropOnRow?.()
      } : undefined}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        borderBottom: '1px solid var(--border-soft)',
        // Was opacity-dimmed for hidden/dragging — but opacity also
        // washes out white text into grey. Use a faded text colour
        // for hidden / dragging instead, leaving full opacity so the
        // active rows render as solid white.
        opacity: 1,
        transition: 'background 100ms, box-shadow 100ms',
        cursor: isNote && !isEditingNote ? 'grab' : 'default',
        background: dragOver
          ? 'rgba(168,85,247,0.10)'
          : hovered
            ? hoverBg
            : (hidden ? 'rgba(255,255,255,0.02)' : 'transparent'),
        // A bright accent inset on the left when hovered makes it
        // unmistakable which row is under the cursor — especially
        // important for the draggable notes.
        boxShadow: hovered
          ? `inset 3px 0 0 var(--accent)`
          : 'none',
        // Dim the row's text only when it's a hidden event being
        // surfaced via showHidden, or when being dragged. Doesn't
        // touch the .tl-white-text override.
        ...((hidden || isDraggingNote) && { color: 'rgba(255,255,255,0.55)' }),
      }}>
      {/* Timestamp column */}
      <td style={{
        padding: '6px 12px 6px 14px', verticalAlign: 'top',
        whiteSpace: 'nowrap', color: '#fff',
        fontSize: 12,
        borderRight: '1px solid var(--border-soft)',
        position: 'relative',
      }}>
        {/* Drag-grip indicator — only on note rows when hovered, so
            the analyst sees the "this is grabbable" affordance only
            for the row their cursor is on. */}
        {isNote && !isEditingNote && hovered && (
          <span
            title="Drag to reposition this note in the chronology"
            style={{
              position: 'absolute', left: 2, top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--accent)', fontSize: 11, lineHeight: 1,
              fontWeight: 700, userSelect: 'none', cursor: 'grab',
            }}>⠿</span>
        )}
        <div className="tl-white-text" style={{ fontSize: 12 }}>{ts.time}</div>
        <div className="tl-white-text" style={{ fontSize: 11 }}>{ts.date}</div>
      </td>
      {/* Icon column — analyst icon override takes precedence over the
          auto-assigned ⚠ / 🛡 / 🚩 / 📝. Click opens the same editor as
          the title / detail double-click so the analyst can rebind it
          quickly. */}
      <td
        onClick={
          isNote && onEditNote ? () => onEditNote()
          : !isNote && onStartEditEvent ? () => onStartEditEvent()
          : undefined
        }
        title={
          isNote && onEditNote ? 'Click to change icon / text / time'
          : !isNote && onStartEditEvent ? 'Click to change icon / title / detail'
          : undefined
        }
        style={{
          padding: '6px 8px', verticalAlign: 'top',
          textAlign: 'center', width: 28,
          color: accent, fontSize: 14, lineHeight: 1.2,
          cursor: (isNote && onEditNote) || (!isNote && onStartEditEvent) ? 'pointer' : undefined,
          userSelect: (isNote && onEditNote) || (!isNote && onStartEditEvent) ? 'none' : undefined,
        }}>
        {iconOverride || event.icon}
      </td>
      {/* Title + detail */}
      <td style={{
        padding: '6px 14px 6px 4px', verticalAlign: 'top',
      }}>
        {isNote && isEditingNote ? (
          <NoteEditor
            initial={note?.text ?? ''}
            initialTsMs={note?.tsMs}
            initialIcon={iconOverride ?? event.icon}
            onSave={(text, tsMs, icon) => onSaveNote?.(text, tsMs, icon)}
            onCancel={() => onCancelEdit?.()}
          />
        ) : !isNote && isEditingEvent ? (
          <EventEditor
            initialTitle={titleOverride  ?? event.title}
            initialDetail={detailOverride ?? event.detail}
            initialIcon={iconOverride ?? event.icon}
            originalTitle={event.title}
            originalDetail={event.detail}
            originalIcon={event.icon}
            onSave={(title, detail, icon) => onSaveEditEvent?.(title, detail, icon)}
            onCancel={() => onCancelEditEvent?.()}
          />
        ) : (
          <>
            <div
              className="tl-white-text"
              onClick={isNote && onEditNote ? () => onEditNote() : undefined}
              onDoubleClick={!isNote && onStartEditEvent ? () => onStartEditEvent() : undefined}
              title={
                isNote ? 'Click to edit · drag to reposition'
                : onStartEditEvent ? 'Double-click to edit title / detail'
                : undefined
              }
              style={{
                wordBreak: 'break-word', lineHeight: 1.45,
                cursor: isNote ? 'pointer' : (onStartEditEvent ? 'pointer' : undefined),
                fontStyle: isNote && !event.title ? 'italic' : 'normal',
                fontSize: 12.5,
                userSelect: !isNote && onStartEditEvent ? 'none' : undefined,
              }}>
              {titleOverride ?? event.title}
            </div>
            {(detailOverride ?? event.detail) && (
              <div
                className="tl-white-text"
                onDoubleClick={!isNote && onStartEditEvent ? () => onStartEditEvent() : undefined}
                title={!isNote && onStartEditEvent ? 'Double-click to edit title / detail' : undefined}
                style={{
                  fontSize: 11.5, marginTop: 4,
                  wordBreak: 'break-word', lineHeight: 1.55,
                  cursor: !isNote && onStartEditEvent ? 'pointer' : undefined,
                  userSelect: !isNote && onStartEditEvent ? 'none' : undefined,
                }}>
                {detailOverride ?? event.detail}
              </div>
            )}
          </>
        )}
        {/* Analyst annotation — context the analyst adds on top of any
            timeline event. Inline editor when active, otherwise the
            saved annotation rendered with a left accent border. */}
        {isAnnotating ? (
          <div style={{ marginTop: 6 }}>
            <NoteEditor
              initial={annotation ?? ''}
              onSave={text => onSaveAnnotation?.(text)}
              onCancel={() => onCancelAnnotate?.()}
            />
          </div>
        ) : annotation ? (
          <div
            onClick={onStartAnnotate ? () => onStartAnnotate() : undefined}
            title="Click to edit your note on this event"
            style={{
              marginTop: 6,
              padding: '4px 8px',
              borderLeft: '2px solid var(--accent)',
              background: 'rgba(168,85,247,0.06)',
              color: '#fff', fontSize: 10.5, lineHeight: 1.5,
              wordBreak: 'break-word',
              cursor: onStartAnnotate ? 'pointer' : 'default',
            }}>
            <span style={{
              color: 'var(--accent)', fontSize: 9, fontWeight: 700,
              letterSpacing: 0.4, marginRight: 6, textTransform: 'uppercase',
            }}>analyst</span>
            {annotation}
          </div>
        ) : null}
      </td>
      {/* Category tag */}
      <td style={{
        padding: '6px 10px', verticalAlign: 'top',
        textAlign: 'right', whiteSpace: 'nowrap',
      }}>
        <span style={{
          color: accent, fontSize: 9.5, fontWeight: 600,
          letterSpacing: 0.4, textTransform: 'uppercase',
          padding: '1px 6px', borderRadius: 2,
          border: `1px solid ${accent}`,
          background: event.colour ? `${event.colour}1A` : 'transparent',
        }}>
          {CATEGORY_LABEL[event.category]}
        </span>
      </td>
      {/* Action column — explicit per-event buttons. Row is no longer
          clickable as a whole; each affordance is its own button. */}
      <td style={{
        padding: '6px 14px 6px 4px', verticalAlign: 'top',
        textAlign: 'right', whiteSpace: 'nowrap',
      }}>
        <div style={{ display: 'inline-flex', gap: 4 }}>
          {/* Jump to event in Hunt tab — only for auto events that
              have a derivable targeted query (not notes). */}
          {!isNote && onJump && (
            <button
              onClick={onJump}
              title="Open this event in the Hunt tab"
              style={iconBtnStyle}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}>
              hunt ↗
            </button>
          )}
          {/* Edit event — give the analyst control over both the title
              and the detail line for an auto-pulled event. Hidden for
              notes (their text IS the title and is edited inline). */}
          {!isNote && !isEditingEvent && onStartEditEvent && (
            <button
              onClick={onStartEditEvent}
              title={(titleOverride || detailOverride)
                ? 'Edit the analyst title / detail for this event'
                : 'Rewrite the title and detail in your own words'}
              style={iconBtnStyle}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}>
              {(titleOverride || detailOverride) ? '✎ edit' : '+ edit'}
            </button>
          )}
          {/* Add / edit analyst annotation — applies to ANY event,
              including notes (lets the analyst add context to their
              own notes too). Hidden when the editor is already open. */}
          {!isAnnotating && onStartAnnotate && (
            <button
              onClick={onStartAnnotate}
              title={annotation ? 'Edit your note on this event' : 'Add a note / context to this event'}
              style={iconBtnStyle}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}>
              {annotation ? '✎ note' : '+ note'}
            </button>
          )}
          {/* Hide / restore for auto events, delete for notes. */}
          <button
            onClick={() => {
              if (isNote) onDeleteNote?.()
              else (hidden ? onUnhide : onHide)()
            }}
            title={
              isNote ? 'Delete this note'
              : hidden ? 'Restore this event'
              : 'Hide this event from the timeline'
            }
            style={iconBtnStyle}
            onMouseEnter={e => {
              const c = (isNote || !hidden) ? 'var(--red)' : 'var(--accent)'
              e.currentTarget.style.color = c
              e.currentTarget.style.borderColor = c
            }}
            onMouseLeave={e => {
              e.currentTarget.style.color = 'var(--text-muted)'
              e.currentTarget.style.borderColor = 'var(--border)'
            }}>
            {isNote ? '×' : (hidden ? '↺' : '×')}
          </button>
        </div>
      </td>
    </tr>
    </>
  )
}

const iconBtnStyle: React.CSSProperties = {
  background: 'transparent', border: '1px solid var(--border)',
  borderRadius: 2, color: 'var(--text-muted)', cursor: 'pointer',
  fontFamily: 'var(--font-mono)', fontSize: 10.5,
  padding: '1px 6px', lineHeight: 1.4,
  transition: 'border-color 100ms, color 100ms',
}

// Combined editor for a timeline event's title + detail + icon. Each
// field can be overridden independently; an empty string in any field
// clears that override and falls back to the auto-generated value.
// ↺ reset clears all three at once. Common-icon quick-pick chips
// underneath the icon input let the analyst pick a recognisable
// symbol without juggling an emoji keyboard.
function EventEditor({
  initialTitle, initialDetail, initialIcon,
  originalTitle, originalDetail, originalIcon,
  onSave, onCancel,
}: {
  initialTitle:    string
  initialDetail:   string
  initialIcon:     string
  originalTitle:   string
  originalDetail:  string
  originalIcon:    string
  onSave:          (title: string, detail: string, icon: string) => void
  onCancel:        () => void
}) {
  const [title,  setTitle]  = useState(initialTitle)
  const [detail, setDetail] = useState(initialDetail)
  const [icon,   setIcon]   = useState(initialIcon)
  function commit() {
    const t = title.trim()
    const d = detail.trim()
    const i = icon.trim()
    // Save empty or "matches the auto value" → clears that override.
    onSave(
      t === originalTitle ? '' : t,
      d === originalDetail ? '' : d,
      i === originalIcon ? '' : i,
    )
  }
  // Quick-pick palette covering the common attack / IR vocabulary —
  // explosion / lock / shield / smoking-gun / phone / keyboard / globe
  // / fire / skull / clipboard. Click a chip to swap the icon.
  const QUICK = ['💣', '🔓', '🛡', '🚩', '⚠', '🔑', '📞', '⌨', '🌐', '🔥', '💀', '📋', '🕵', '📨']
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <input
        autoFocus
        value={title}
        onChange={e => setTitle(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); commit() }
          else if (e.key === 'Escape') { e.preventDefault(); onCancel() }
        }}
        placeholder="Title (e.g. Initial PowerShell payload)"
        style={{
          width: '100%',
          background: 'var(--bg-app)', color: '#fff',
          border: '1px solid var(--accent)', borderRadius: 3,
          fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1.45,
          padding: '6px 8px', outline: 'none', boxSizing: 'border-box',
        }}
      />
      <textarea
        value={detail}
        onChange={e => setDetail(e.target.value)}
        onKeyDown={e => {
          if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); commit() }
          else if (e.key === 'Escape') { e.preventDefault(); onCancel() }
        }}
        placeholder="Detail (rewrite the command line / hash / network info in plain English)"
        style={{
          width: '100%', minHeight: 56, resize: 'vertical',
          background: 'var(--bg-app)', color: '#fff',
          border: '1px solid var(--accent)', borderRadius: 3,
          fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.5,
          padding: '6px 8px', outline: 'none', boxSizing: 'border-box',
        }}
      />
      {/* Icon row — input on the left, quick-pick chips beside it. */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>icon</span>
        <input
          value={icon}
          onChange={e => setIcon(e.target.value)}
          placeholder={originalIcon}
          maxLength={4}
          style={{
            width: 50, textAlign: 'center',
            background: 'var(--bg-app)', color: '#fff',
            border: '1px solid var(--border)', borderRadius: 3,
            fontFamily: 'var(--font-mono)', fontSize: 16, lineHeight: 1.4,
            padding: '4px 6px', outline: 'none', boxSizing: 'border-box',
          }}
        />
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {QUICK.map(q => (
            <button
              key={q}
              onClick={() => setIcon(q)}
              title={`Use ${q}`}
              style={{
                background: icon === q ? 'rgba(168,85,247,0.22)' : 'transparent',
                border: `1px solid ${icon === q ? 'var(--accent)' : 'var(--border)'}`,
                borderRadius: 3, cursor: 'pointer',
                fontSize: 14, lineHeight: 1, width: 26, height: 24,
                padding: 0,
              }}>{q}</button>
          ))}
        </div>
      </div>
      <div style={{ color: 'var(--text-muted)', fontSize: 9.5, lineHeight: 1.5 }}>
        <div>
          <span>original title:</span>{' '}
          {originalTitle.length > 120 ? originalTitle.slice(0, 120) + '…' : originalTitle}
        </div>
        {originalDetail && (
          <div>
            <span>original detail:</span>{' '}
            {originalDetail.length > 220 ? originalDetail.slice(0, 220) + '…' : originalDetail}
          </div>
        )}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10.5 }}>
        <span style={{ flex: 1 }} />
        <button
          onClick={() => onSave('', '', '')}
          title="Restore the auto-generated title, detail AND icon"
          style={{
            background: 'transparent', color: 'var(--text-muted)',
            border: '1px solid var(--border)', borderRadius: 3, cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5,
            padding: '3px 8px',
          }}>↺ reset</button>
        <button
          onClick={commit}
          style={{
            background: 'var(--accent)', color: '#fff',
            border: 'none', borderRadius: 3, cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5, fontWeight: 600,
            padding: '3px 10px',
          }}>save</button>
        <button
          onClick={onCancel}
          style={{
            background: 'transparent', color: 'var(--text-muted)',
            border: '1px solid var(--border)', borderRadius: 3, cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5,
            padding: '3px 8px',
          }}>cancel</button>
      </div>
    </div>
  )
}

// Inline editor used for note text. Optional initialTsMs enables a
// datetime-local input so the analyst can pin the note to a specific
// moment in the chronology without dragging. When the picker is
// shown, save commits both the text and the parsed timestamp.
// Optional initialIcon adds an icon row identical to the EventEditor's
// — empty / matching the auto 📝 means no override.
function NoteEditor({ initial, initialTsMs, initialIcon, onSave, onCancel }: {
  initial:      string
  initialTsMs?: number
  initialIcon?: string
  onSave:       (text: string, tsMs?: number, icon?: string) => void
  onCancel:     () => void
}) {
  const [value, setValue] = useState(initial)
  const [tsMs, setTsMs] = useState<number | undefined>(initialTsMs)
  const [icon, setIcon] = useState(initialIcon ?? '')
  const [pickerOpen, setPickerOpen] = useState(false)
  const pickerAnchorRef = useRef<HTMLButtonElement | null>(null)
  function fmtChip(ms: number): string {
    const d = new Date(ms)
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`
  }
  function commit() {
    // Empty icon string + the default 📝 both mean "no override". The
    // caller is responsible for treating this as a clear-override.
    onSave(value.trim(), tsMs, initialIcon !== undefined ? icon.trim() : undefined)
  }
  const showIconRow = initialIcon !== undefined
  const QUICK = ['📝', '💣', '🔓', '🛡', '🚩', '⚠', '🔑', '📞', '⌨', '🌐', '🔥', '💀', '📋', '🕵', '📨']
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {showIconRow && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>icon</span>
          <input
            value={icon}
            onChange={e => setIcon(e.target.value)}
            placeholder="📝"
            maxLength={4}
            style={{
              width: 50, textAlign: 'center',
              background: 'var(--bg-app)', color: '#fff',
              border: '1px solid var(--border)', borderRadius: 3,
              fontFamily: 'var(--font-mono)', fontSize: 16, lineHeight: 1.4,
              padding: '4px 6px', outline: 'none', boxSizing: 'border-box',
            }}
          />
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {QUICK.map(q => (
              <button
                key={q}
                onClick={() => setIcon(q)}
                title={`Use ${q}`}
                style={{
                  background: icon === q ? 'rgba(168,85,247,0.22)' : 'transparent',
                  border: `1px solid ${icon === q ? 'var(--accent)' : 'var(--border)'}`,
                  borderRadius: 3, cursor: 'pointer',
                  fontSize: 14, lineHeight: 1, width: 26, height: 24,
                  padding: 0,
                }}>{q}</button>
            ))}
          </div>
        </div>
      )}
      <textarea
        autoFocus
        value={value}
        onChange={e => setValue(e.target.value)}
        onKeyDown={e => {
          if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
            e.preventDefault()
            commit()
          } else if (e.key === 'Escape') {
            e.preventDefault()
            onCancel()
          }
        }}
        placeholder="Note text — e.g. 'USB drive removed from desk by Bob (witnessed)'"
        style={{
          width: '100%', minHeight: 48, resize: 'vertical',
          background: 'var(--bg-app)', color: '#fff',
          border: '1px solid var(--accent)', borderRadius: 3,
          fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.45,
          padding: '6px 8px', outline: 'none', boxSizing: 'border-box',
        }}
      />
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10.5, flexWrap: 'wrap' }}>
        {/* Only standalone notes (those that carry their own
            timestamp) get the date+time picker. Annotations on
            existing events inherit the event's time. */}
        {typeof initialTsMs === 'number' && (
          <>
            <span style={{ color: '#fff' }}>when</span>
            <button
              ref={pickerAnchorRef}
              onClick={() => setPickerOpen(o => !o)}
              title="Pick the date and time for this note"
              style={{
                background: 'var(--bg-app)', color: '#fff',
                border: '1px solid var(--border)', borderRadius: 3,
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)', fontSize: 10.5,
                padding: '3px 8px',
                transition: 'border-color 100ms',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)' }}>
              📅 {tsMs ? fmtChip(tsMs) : 'pick date / time'}
            </button>
            <span style={{ color: 'var(--text-muted)', fontSize: 9.5 }}>local time</span>
          </>
        )}
        <span style={{ flex: 1 }} />
        <button
          onClick={commit}
          style={{
            background: 'var(--accent)', color: '#fff',
            border: 'none', borderRadius: 3, cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5, fontWeight: 600,
            padding: '3px 10px',
          }}>save</button>
        <button
          onClick={onCancel}
          style={{
            background: 'transparent', color: 'var(--text-muted)',
            border: '1px solid var(--border)', borderRadius: 3, cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5,
            padding: '3px 8px',
          }}>cancel</button>
      </div>
      {/* Portal'd RangePicker in single mode — same look as the Hunt
          tab's custom-range picker so the analyst sees a familiar
          calendar UI. */}
      {pickerOpen && (() => {
        const rect = pickerAnchorRef.current?.getBoundingClientRect()
        const POP_W = 320
        const top  = (rect?.bottom ?? 50) + 6
        let left   = rect?.left ?? 12
        if (left + POP_W > window.innerWidth - 12) {
          left = Math.max(12, window.innerWidth - POP_W - 12)
        }
        return createPortal(
          <>
            <div
              onClick={() => setPickerOpen(false)}
              style={{ position: 'fixed', inset: 0, zIndex: 9998 }}
            />
            <div style={{ position: 'fixed', top, left, zIndex: 9999 }}>
              <RangePicker
                mode="single"
                initialStart={typeof tsMs === 'number' ? new Date(tsMs).toISOString() : undefined}
                onApply={(iso) => {
                  setTsMs(new Date(iso).getTime())
                  setPickerOpen(false)
                }}
                onCancel={() => setPickerOpen(false)}
              />
            </div>
          </>,
          document.body,
        )
      })()}
    </div>
  )
}
