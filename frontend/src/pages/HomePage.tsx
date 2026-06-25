import React, { useState, useEffect, useMemo, useRef } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { logout } from '../api/auth'
import { getCredentialStatus } from '../api/credentials'
import { fetchDeviceInfo, fetchNetworkAdapters, fetchHostIncidents, lookupDevice } from '../api/investigate'
import type { DeviceLookupMatch } from '../api/investigate'
import { runAnalysis, type AnalyseScope } from '../api/analyse'
import type { User, ProcessNodeData, InvestigateResponse, Investigation, DeviceInfoData, FlagStatus, AnalysisResult, NetworkAdapter, HostIncident } from '../types'
import ProcessTree from '../components/ProcessTree'
import TelemetryPanel from '../components/TelemetryPanel'
import FindingsPanel from '../components/FindingsPanel'
import IocListPanel from '../components/IocListPanel'
import HuntTab from '../components/HuntTab'
import RangePicker from '../components/RangePicker'
import ProcessTreeTable from '../components/ProcessTreeTable'

type ViewMode = 'flow' | 'table'
const VIEW_MODE_KEY = 'sudotrace.treeViewMode'

function loadViewMode(): ViewMode {
  try {
    const v = localStorage.getItem(VIEW_MODE_KEY)
    return v === 'table' ? 'table' : 'flow'
  } catch { return 'flow' }
}
function saveViewMode(v: ViewMode) {
  try { localStorage.setItem(VIEW_MODE_KEY, v) } catch { /* ignore */ }
}
import { useIocList, clearIocs, removeIoc } from '../store/iocStore'
import type { IocEntry } from '../store/iocStore'
import { useHuntFlags, clearHuntFlags, setHuntFlag } from '../store/huntFlagStore'
import {
  useAnalysisHistory, recordAnalysis, removeAnalysisEntry, clearAnalysisHistory,
  type AnalysisHistoryEntry,
} from '../store/analysisHistoryStore'
import {
  setInvTreeData, setInvHostIncidents, setInvHostname, clearInvestigation,
  setInvFlaggedNodes, setInvFlaggedEvents, setInvFlaggedIncidents,
  useInvTreeData, useInvHostIncidents,
  useInvFlaggedNodes, useInvFlaggedEvents, useInvFlaggedIncidents,
  useTimelineNotes, useHiddenTimelineIds,
} from '../store/investigationStore'
import { buildTimeline } from '../utils/timelineBuilder'
import TimelineTab from '../components/TimelineTab'
import type { HuntJumpRequest } from '../components/HuntTab'
import { fmtDateTime } from '../utils/dateFormat'
import DegradationBanner from '../components/DegradationBanner'
import { setDegraded, clearDegraded, clearAllDegraded, friendlyError } from '../store/degradationStore'
import { exportInvestigationToFile, importInvestigationFromFile } from '../utils/investigationFile'
import { parseBecCaseFile, exportBecCaseToFile } from '../utils/becCaseFile'
import BecView from '../components/BecView'
import { getBecCase, deleteBecCase, putBecCase } from '../api/bec'

// BEC case identity held at the page level. Identifies the account, an optional
// suspected origin IP, and the sign-in window. The analyst-authored state
// (selections, checklist) auto-saves from BecView; on reload we restore it via
// `becRestore` (see the mount effect below).
interface BecCase { account: string; ip: string; timeWindow: string; offline?: boolean }

const TIME_WINDOWS = [
  { value: '±30m',   label: '±30 minutes' },
  { value: '±1h',    label: '±1 hour' },
  { value: '±2h',    label: '±2 hours' },
  { value: '±12h',   label: '±12 hours' },
  { value: '±24h',   label: '±24 hours' },
  { value: 'last7d',  label: 'Last 7 days' },
  { value: 'last30d', label: 'Last 30 days' },
  { value: 'custom',  label: 'Custom range…' },
]

// Cost estimator constants — Haiku 4.5 pricing per token. Kept here as the
// frontend's local copy so the analyse-bar can render a live preview before
// the call is made. If the backend price table changes, update this too.
const HAIKU_INPUT_PER_TOKEN  = 0.80 / 1_000_000
const HAIKU_OUTPUT_PER_TOKEN = 4.00 / 1_000_000
// Empirical fudge: the system prompt + scope_block + tree-formatter overhead
// adds ~4k tokens beyond the raw JSON payload, and each flagged incident
// renders a structured block (HARD RULES + per-alert detail + MITRE) that
// adds ~800 more tokens. JSON tokenises a touch denser than English
// (~3.5 chars/token vs 4). Calibrated against two real runs:
//   13k est vs 12.6k actual (+3 %)
//   7.1k est vs  7.4k actual (-4 %) with the per-incident bump applied.
const PROMPT_OVERHEAD_TOKENS       = 4000
const PROMPT_PER_INCIDENT_TOKENS   = 800
const CHARS_PER_TOKEN              = 3.5
// Typical analyse output — both calibration runs landed at ~2.3k.
const TYPICAL_OUTPUT_TOKENS        = 2400

interface CostEstimate {
  inputTokens: number
  outputTokens: number
  cost: number
}

function estimatePayloadCost(payload: unknown): CostEstimate {
  const json = JSON.stringify(payload) || ''
  // Pull a few fields off the payload to scale the overhead — flagged
  // incidents render a hefty structured block in the prompt that the raw
  // JSON byte count doesn't reflect.
  const p = (payload || {}) as { flagged_incidents?: unknown[] }
  const incidentCount = Array.isArray(p.flagged_incidents) ? p.flagged_incidents.length : 0
  const overhead = PROMPT_OVERHEAD_TOKENS + incidentCount * PROMPT_PER_INCIDENT_TOKENS
  const inputTokens  = Math.round(json.length / CHARS_PER_TOKEN) + overhead
  const outputTokens = TYPICAL_OUTPUT_TOKENS
  const cost = inputTokens * HAIKU_INPUT_PER_TOKEN + outputTokens * HAIKU_OUTPUT_PER_TOKEN
  return { inputTokens, outputTokens, cost }
}

function fmtTokens(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(n >= 10_000 ? 0 : 1)}k`
  return String(n)
}

function fmtCost(c: number): string {
  if (c < 0.01) return '<$0.01'
  if (c < 1)    return `$${c.toFixed(3)}`
  return `$${c.toFixed(2)}`
}

// Wide-window warning text. Long windows can pull a huge number of processes
// which slows investigation load and inflates the prompt. The select handlers
// check needsWideWindowConfirm(v) and, if true, route the value through a
// ConfirmDialog before applying.
function needsWideWindowConfirm(value: string): boolean {
  return value === 'last7d' || value === 'last30d'
}
function wideWindowMessage(value: string): string {
  if (value === 'last7d')
    return 'Last 7 days can return a very large number of processes and may be slow to load. Continue?'
  if (value === 'last30d')
    return 'Last 30 days can return an enormous number of processes and may be very slow. Continue?'
  return ''
}

// In-app confirm dialog — replaces window.confirm so the warning matches
// the rest of the app's visual style instead of using the browser default.
function ConfirmDialog({
  open, message, confirmLabel = 'Continue', cancelLabel = 'Cancel',
  onConfirm, onCancel,
}: {
  open: boolean
  message: string
  confirmLabel?: string
  cancelLabel?: string
  onConfirm: () => void
  onCancel: () => void
}) {
  useEffect(() => {
    if (!open) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onCancel()
      if (e.key === 'Enter')  onConfirm()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, onCancel, onConfirm])

  if (!open) return null
  return createPortal(
    <>
      <div onClick={onCancel} style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 10000,
      }} />
      <div role="dialog" aria-modal="true" style={{
        position: 'fixed', top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)', zIndex: 10001,
        background: 'var(--bg-panel)', border: '1px solid var(--border)',
        borderRadius: 8, padding: '18px 22px',
        minWidth: 320, maxWidth: 480,
        boxShadow: '0 12px 40px rgba(0,0,0,0.55)',
        fontFamily: 'var(--font-mono)',
      }}>
        <div style={{
          color: 'var(--text)', fontSize: 12.5, lineHeight: 1.55, marginBottom: 18,
        }}>{message}</div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button onClick={onCancel} style={{
            background: 'transparent', border: '1px solid var(--border)',
            color: 'var(--text-muted)', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: 0.4,
            padding: '6px 14px', borderRadius: 4, outline: 'none',
          }}>{cancelLabel}</button>
          <button onClick={onConfirm} autoFocus style={{
            background: 'var(--accent)', border: 'none', color: '#fff',
            cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 11,
            letterSpacing: 0.4, padding: '6px 16px', borderRadius: 4,
            fontWeight: 600, outline: 'none',
          }}>{confirmLabel}</button>
        </div>
      </div>
    </>,
    document.body,
  )
}

// Format a custom range ("custom:<startISO>..<endISO>") as a short
// human-readable string in DD/MM HH:MM form ("10/05 15:30 → 17:00").
function formatCustomWindow(raw: string): string {
  if (!raw.startsWith('custom:')) return raw
  const parts = raw.slice('custom:'.length).split('..')
  if (parts.length !== 2) return raw
  const fmt = (iso: string) => {
    const m = iso.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/)
    if (m) return `${m[3]}/${m[2]} ${m[4]}:${m[5]}`
    return iso
  }
  return `${fmt(parts[0])} → ${fmt(parts[1])}`
}

// AppBar window control — a select for presets and an inline popover for
// custom ranges. The select's effective value is "custom" whenever the live
// rawTimeWindow is a custom: string, so the dropdown still shows a labelled
// option rather than something raw and ugly.
function WindowControl({ rawTimeWindow, onChange }: {
  rawTimeWindow: string
  onChange: ((tw: string) => void) | null
}) {
  const isCustom = rawTimeWindow.startsWith('custom:')
  const [open, setOpen] = useState(false)
  // Holds the wide-window value (last7d / last30d) the analyst is trying to
  // apply but hasn't confirmed yet. Drives the ConfirmDialog below.
  const [pendingWide, setPendingWide] = useState<string | null>(null)
  // Anchor used to position the portal'd RangePicker below the select.
  const anchorRef = useRef<HTMLDivElement | null>(null)

  return (
    <div ref={anchorRef} style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
      <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>window</span>
      <select
        value={isCustom ? 'custom' : rawTimeWindow}
        onChange={e => {
          const v = e.target.value
          if (v === 'custom') {
            setOpen(true)
          } else if (needsWideWindowConfirm(v)) {
            setPendingWide(v)
          } else {
            onChange?.(v)
          }
        }}
        onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.background = 'rgba(168,85,247,0.15)'; e.currentTarget.style.color = 'var(--accent)' }}
        onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'var(--bg-elevated)'; e.currentTarget.style.color = 'var(--text)' }}
        style={{
          background: 'var(--bg-elevated)', border: '1px solid var(--border)',
          borderRadius: 3, color: 'var(--text)', cursor: 'pointer',
          fontFamily: 'var(--font-mono)', fontSize: 10.5, padding: '1px 4px',
          outline: 'none',
          transition: 'border-color 100ms, background 100ms, color 100ms',
        }}>
        {TIME_WINDOWS.map(tw => (
          <option key={tw.value} value={tw.value}>{tw.label}</option>
        ))}
      </select>
      {isCustom && (
        <span
          onClick={() => setOpen(true)}
          title="Edit custom range"
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--accent)' }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)' }}
          style={{
            color: 'var(--text-muted)', fontSize: 10.5, marginLeft: 4,
            cursor: 'pointer', transition: 'color 100ms',
          }}>
          {formatCustomWindow(rawTimeWindow)}
        </span>
      )}
      {open && (() => {
        const rect = anchorRef.current?.getBoundingClientRect()
        const PICKER_W = 320
        const top = (rect?.bottom ?? 50) + 6
        let left = rect?.left ?? 12
        if (left + PICKER_W > window.innerWidth - 12) {
          left = Math.max(12, window.innerWidth - PICKER_W - 12)
        }
        return createPortal(
          <>
            {/* Backdrop swallows outside clicks */}
            <div
              onClick={() => setOpen(false)}
              style={{ position: 'fixed', inset: 0, zIndex: 9998 }}
            />
            <div style={{ position: 'fixed', top, left, zIndex: 9999 }}>
              <RangePicker
                initialStart={isCustom ? rawTimeWindow.slice('custom:'.length).split('..')[0] : undefined}
                initialEnd={isCustom ? rawTimeWindow.slice('custom:'.length).split('..')[1] : undefined}
                onApply={(s, e) => { setOpen(false); onChange?.(`custom:${s}..${e}`) }}
                onCancel={() => setOpen(false)}
              />
            </div>
          </>,
          document.body,
        )
      })()}
      <ConfirmDialog
        open={!!pendingWide}
        message={pendingWide ? wideWindowMessage(pendingWide) : ''}
        onConfirm={() => { const v = pendingWide!; setPendingWide(null); onChange?.(v) }}
        onCancel={() => setPendingWide(null)}
      />
    </div>
  )
}

interface Props {
  user: User
  onLogout: () => void
  investigation: Investigation | null
  onInvestigationChange: (inv: Investigation | null) => void
  investigationData: InvestigateResponse | null
  onInvestigationDataChange: (d: InvestigateResponse | null) => void
}

type InvTab = 'analysis' | 'iocs' | 'hunt' | 'timeline' | 'ai'

// ── Flagged Processes manager — modal popup launched from the TreeToolbar
//    "N flagged processes" link. Lists every flagged node with controls to
//    cycle its flag or remove it entirely. ──────────────────────────────────
const FLAGGED_POPUP_CYCLE: FlagStatus[] = [null, 'benign', 'suspicious', 'malicious']
const FLAGGED_POPUP_COLORS: Record<NonNullable<FlagStatus>, string> = {
  malicious:   '#FF5E5B',
  suspicious:  '#F0B340',
  investigate: '#7AA8FF',
  benign:      '#7DD3A0',
}

function FlaggedProcessesPopup({ flags, nodes, onSetFlag, onExamine, onClose }: {
  flags: Map<string, FlagStatus>
  nodes: Record<string, ProcessNodeData>
  onSetFlag: (key: string, flag: FlagStatus) => void
  onExamine?: (key: string) => void
  onClose: () => void
}) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  // Snapshot the order of currently-flagged node keys when the popup opens.
  // We keep using this stable list for rendering so:
  //   1. Cycling a flag (even down to null) doesn't make the row disappear.
  //   2. Changing severity doesn't re-sort the list mid-edit.
  // Items only leave the list when the analyst explicitly clicks × on a row.
  const sevRank: Record<NonNullable<FlagStatus>, number> = { malicious: 0, suspicious: 1, investigate: 2, benign: 3 }
  const [snapshot, setSnapshot] = useState<string[]>(() => {
    return Array.from(flags.entries())
      .map(([key, flag]) => ({ key, flag, node: nodes[key] }))
      .filter(it => !!it.node)
      .sort((a, b) => {
        const aR = a.flag ? sevRank[a.flag] : 99
        const bR = b.flag ? sevRank[b.flag] : 99
        if (aR !== bR) return aR - bR
        return (a.node.name || '').localeCompare(b.node.name || '')
      })
      .map(it => it.key)
  })

  const items = snapshot
    .map(key => ({ key, flag: flags.get(key) ?? null, node: nodes[key] }))
    .filter(it => !!it.node)

  function cycle(key: string, cur: FlagStatus) {
    const idx = FLAGGED_POPUP_CYCLE.indexOf(cur)
    const nextFlag = FLAGGED_POPUP_CYCLE[(idx + 1) % FLAGGED_POPUP_CYCLE.length]
    onSetFlag(key, nextFlag)
  }

  function removeFromList(key: string) {
    setSnapshot(prev => prev.filter(k => k !== key))
    onSetFlag(key, null)
  }

  return createPortal(
    <>
      {/* Backdrop — click to dismiss */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 9998,
          background: 'rgba(0,0,0,0.55)',
        }} />
      {/* Dialog */}
      <div style={{
        position: 'fixed', top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)',
        zIndex: 9999,
        width: 'min(620px, 92vw)', maxHeight: '80vh',
        display: 'flex', flexDirection: 'column',
        background: 'var(--bg-panel)', border: '1px solid var(--border)',
        borderRadius: 8, boxShadow: '0 8px 40px rgba(0,0,0,0.6)',
        fontFamily: 'var(--font-mono)', color: 'var(--text)',
      }}>
        {/* Header */}
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontWeight: 600 }}>
            <span style={{ color: 'var(--accent)' }}>▌</span>
            Flagged Process{items.length === 1 ? '' : 'es'}
            <span style={{ color: 'var(--text-muted)', fontWeight: 500 }}>({items.length})</span>
          </div>
          <span onClick={onClose}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--text)' }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)' }}
            style={{
              color: 'var(--text-muted)', fontSize: 18, lineHeight: 1,
              cursor: 'pointer', padding: '0 6px', userSelect: 'none',
              transition: 'color 100ms',
            }}>×</span>
        </div>

        {/* List */}
        <div style={{ overflow: 'auto', padding: '6px 0' }}>
          {items.length === 0 ? (
            <div style={{ padding: '16px 18px', color: 'var(--text-muted)', fontSize: 11 }}>
              No flagged processes.
            </div>
          ) : items.map(it => {
            const color = it.flag ? FLAGGED_POPUP_COLORS[it.flag] : 'var(--text-muted)'
            return (
              <div key={it.key} style={{
                display: 'grid',
                gridTemplateColumns: 'minmax(0, 1fr) auto auto',
                gap: 10, alignItems: 'center',
                padding: '8px 16px',
                borderBottom: '1px solid var(--border-soft)',
              }}>
                <div style={{ minWidth: 0 }}>
                  <div
                    onClick={onExamine ? () => onExamine(it.key) : undefined}
                    onMouseEnter={onExamine ? e => { e.currentTarget.style.textDecorationColor = color } : undefined}
                    onMouseLeave={onExamine ? e => { e.currentTarget.style.textDecorationColor = `${color}66` } : undefined}
                    title={onExamine ? 'Click to examine — opens this process in the Process Telemetry tab' : undefined}
                    style={{
                      color, fontSize: 12, fontWeight: 600,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      cursor: onExamine ? 'pointer' : 'default',
                      textDecoration: onExamine ? 'underline' : 'none',
                      textDecorationStyle: 'dotted',
                      textDecorationColor: `${color}66`,
                      transition: 'text-decoration-color 100ms',
                    }}>{it.node.name}</div>
                  <div style={{
                    color: 'var(--text-muted)', fontSize: 10, marginTop: 2,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>pid {it.node.pid} · {it.node.user || '—'}</div>
                </div>
                <button
                  onClick={() => cycle(it.key, it.flag)}
                  onMouseDown={e => e.preventDefault()}
                  title={it.flag ? `Currently ${it.flag} — click to cycle` : 'Click to flag'}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)' }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = it.flag ? color : 'var(--border)' }}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 5,
                    background: it.flag ? `${color}1f` : 'transparent',
                    border: `1px solid ${it.flag ? color : 'var(--border)'}`,
                    color: it.flag ? color : 'var(--text-muted)',
                    fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                    padding: '3px 8px', borderRadius: 3,
                    cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
                    transition: 'border-color 100ms, background 100ms',
                  }}>
                  ⚑ {it.flag ? it.flag.toUpperCase() : 'NONE'}
                </button>
                <button
                  onClick={() => removeFromList(it.key)}
                  title="Remove from list (and clear flag)"
                  onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--red)'; e.currentTarget.style.color = 'var(--red)' }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
                  style={{
                    background: 'transparent', border: '1px solid var(--border)',
                    color: 'var(--text-muted)', cursor: 'pointer',
                    fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
                    padding: '2px 8px', borderRadius: 3, lineHeight: 1,
                    transition: 'border-color 100ms, color 100ms',
                  }}>×</button>
              </div>
            )
          })}
        </div>

        {/* Footer */}
        <div style={{
          padding: '8px 14px', borderTop: '1px solid var(--border)',
          color: 'var(--text-muted)', fontSize: 10, flexShrink: 0,
        }}>
          Click ⚑ to cycle flag · Click × to remove · Esc / click outside to close
        </div>
      </div>
    </>,
    document.body,
  )
}

// ── Flagged Events manager — sibling to FlaggedProcessesPopup but listing
//    telemetry-row flags. rowFlags is keyed by `${node_key}:${tab}:${rowIdx}`. ─
type EventTab = 'network' | 'files' | 'registry' | 'dlls' | 'scripts'
const EVENT_TAB_LABELS: Record<EventTab, string> = {
  network: 'net', files: 'files', registry: 'reg', dlls: 'dlls', scripts: 'scripts',
}

// Split key safely — node_key can be a long ID, the last two `:` segments are
// tab and rowIdx.
function parseRowFlagKey(key: string): { nodeKey: string; tab: EventTab; rowIdx: number } | null {
  const lastColon = key.lastIndexOf(':')
  if (lastColon <= 0) return null
  const secondLastColon = key.lastIndexOf(':', lastColon - 1)
  if (secondLastColon <= 0) return null
  const nodeKey = key.slice(0, secondLastColon)
  const tab    = key.slice(secondLastColon + 1, lastColon) as EventTab
  const rowIdx = parseInt(key.slice(lastColon + 1), 10)
  if (isNaN(rowIdx)) return null
  if (!EVENT_TAB_LABELS[tab]) return null
  return { nodeKey, tab, rowIdx }
}

function FlaggedEventsPopup({ rowFlags, nodes, onSetFlag, onExamine, onClose }: {
  rowFlags: Map<string, FlagStatus>
  nodes: Record<string, ProcessNodeData>
  onSetFlag: (key: string, flag: FlagStatus) => void
  onExamine?: (nodeKey: string, tab: EventTab) => void
  onClose: () => void
}) {
  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  const sevRank: Record<NonNullable<FlagStatus>, number> = { malicious: 0, suspicious: 1, investigate: 2, benign: 3 }

  // Snapshot the ordered set of currently-flagged event keys at mount time so
  // cycling to "none" doesn't make the row vanish and changing severity
  // doesn't reorder the list. Same UX rule as FlaggedProcessesPopup.
  const [snapshot, setSnapshot] = useState<string[]>(() => {
    return Array.from(rowFlags.entries())
      .map(([key, flag]) => {
        const parsed = parseRowFlagKey(key)
        return parsed ? { key, flag, parsed, node: nodes[parsed.nodeKey] } : null
      })
      .filter((x): x is { key: string; flag: FlagStatus; parsed: NonNullable<ReturnType<typeof parseRowFlagKey>>; node: ProcessNodeData } => !!x && !!x.node)
      .sort((a, b) => {
        const aR = a.flag ? sevRank[a.flag] : 99
        const bR = b.flag ? sevRank[b.flag] : 99
        if (aR !== bR) return aR - bR
        const nameCmp = (a.node.name || '').localeCompare(b.node.name || '')
        if (nameCmp !== 0) return nameCmp
        if (a.parsed.tab !== b.parsed.tab) return a.parsed.tab.localeCompare(b.parsed.tab)
        return a.parsed.rowIdx - b.parsed.rowIdx
      })
      .map(it => it.key)
  })

  const items = snapshot.map(key => {
    const parsed = parseRowFlagKey(key)
    if (!parsed) return null
    return {
      key,
      flag: rowFlags.get(key) ?? null,
      parsed,
      node: nodes[parsed.nodeKey],
    }
  }).filter((x): x is { key: string; flag: FlagStatus; parsed: NonNullable<ReturnType<typeof parseRowFlagKey>>; node: ProcessNodeData } => !!x && !!x.node)

  function cycle(key: string, cur: FlagStatus) {
    const idx = FLAGGED_POPUP_CYCLE.indexOf(cur)
    const nextFlag = FLAGGED_POPUP_CYCLE[(idx + 1) % FLAGGED_POPUP_CYCLE.length]
    onSetFlag(key, nextFlag)
  }

  function removeFromList(key: string) {
    setSnapshot(prev => prev.filter(k => k !== key))
    onSetFlag(key, null)
  }

  return createPortal(
    <>
      <div onClick={onClose} style={{
        position: 'fixed', inset: 0, zIndex: 9998, background: 'rgba(0,0,0,0.55)',
      }} />
      <div style={{
        position: 'fixed', top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)', zIndex: 9999,
        width: 'min(680px, 92vw)', maxHeight: '80vh',
        display: 'flex', flexDirection: 'column',
        background: 'var(--bg-panel)', border: '1px solid var(--border)',
        borderRadius: 8, boxShadow: '0 8px 40px rgba(0,0,0,0.6)',
        fontFamily: 'var(--font-mono)', color: 'var(--text)',
      }}>
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontWeight: 600 }}>
            <span style={{ color: 'var(--accent)' }}>▌</span>
            Flagged Event{items.length === 1 ? '' : 's'}
            <span style={{ color: 'var(--text-muted)', fontWeight: 500 }}>({items.length})</span>
          </div>
          <span onClick={onClose}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--text)' }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)' }}
            style={{
              color: 'var(--text-muted)', fontSize: 18, lineHeight: 1,
              cursor: 'pointer', padding: '0 6px', userSelect: 'none',
              transition: 'color 100ms',
            }}>×</span>
        </div>

        <div style={{ overflow: 'auto', padding: '6px 0' }}>
          {items.length === 0 ? (
            <div style={{ padding: '16px 18px', color: 'var(--text-muted)', fontSize: 11 }}>
              No flagged events.
            </div>
          ) : items.map(it => {
            const color = it.flag ? FLAGGED_POPUP_COLORS[it.flag] : 'var(--text-muted)'
            return (
              <div key={it.key} style={{
                display: 'grid',
                gridTemplateColumns: 'minmax(0, 1fr) auto auto',
                gap: 10, alignItems: 'center',
                padding: '8px 16px',
                borderBottom: '1px solid var(--border-soft)',
              }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                    <span style={{
                      fontSize: 9, padding: '1px 6px', borderRadius: 2, fontWeight: 700,
                      background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                      color: 'var(--text-muted)', letterSpacing: 0.5, textTransform: 'uppercase',
                      flexShrink: 0,
                    }}>{EVENT_TAB_LABELS[it.parsed.tab]}</span>
                    <span
                      onClick={onExamine ? () => onExamine(it.parsed.nodeKey, it.parsed.tab) : undefined}
                      onMouseEnter={onExamine ? e => { e.currentTarget.style.textDecorationColor = color } : undefined}
                      onMouseLeave={onExamine ? e => { e.currentTarget.style.textDecorationColor = `${color}66` } : undefined}
                      title={onExamine ? `Click to open this event in the ${EVENT_TAB_LABELS[it.parsed.tab]} tab` : undefined}
                      style={{
                        color, fontSize: 12, fontWeight: 600,
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        cursor: onExamine ? 'pointer' : 'default',
                        textDecoration: onExamine ? 'underline' : 'none',
                        textDecorationStyle: 'dotted',
                        textDecorationColor: `${color}66`,
                        transition: 'text-decoration-color 100ms',
                      }}>{it.node.name}</span>
                  </div>
                  <div style={{
                    color: 'var(--text-muted)', fontSize: 10, marginTop: 2,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>pid {it.node.pid} · event #{it.parsed.rowIdx + 1}</div>
                </div>
                <button
                  onClick={() => cycle(it.key, it.flag)}
                  onMouseDown={e => e.preventDefault()}
                  title={it.flag ? `Currently ${it.flag} — click to cycle` : 'Click to flag'}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)' }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = it.flag ? color : 'var(--border)' }}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 5,
                    background: it.flag ? `${color}1f` : 'transparent',
                    border: `1px solid ${it.flag ? color : 'var(--border)'}`,
                    color: it.flag ? color : 'var(--text-muted)',
                    fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                    padding: '3px 8px', borderRadius: 3,
                    cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
                    transition: 'border-color 100ms, background 100ms',
                  }}>
                  ⚑ {it.flag ? it.flag.toUpperCase() : 'NONE'}
                </button>
                <button
                  onClick={() => removeFromList(it.key)}
                  title="Remove from list (and clear flag)"
                  onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--red)'; e.currentTarget.style.color = 'var(--red)' }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
                  style={{
                    background: 'transparent', border: '1px solid var(--border)',
                    color: 'var(--text-muted)', cursor: 'pointer',
                    fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
                    padding: '2px 8px', borderRadius: 3, lineHeight: 1,
                    transition: 'border-color 100ms, color 100ms',
                  }}>×</button>
              </div>
            )
          })}
        </div>

        <div style={{
          padding: '8px 14px', borderTop: '1px solid var(--border)',
          color: 'var(--text-muted)', fontSize: 10, flexShrink: 0,
        }}>
          Click event name to examine · ⚑ to cycle · × to remove · Esc / click outside to close
        </div>
      </div>
    </>,
    document.body,
  )
}

// ── Host Details view — wraps Info / Network Adapters / Incidents
//    sub-tabs. Alerts have been folded into Incidents (each incident
//    expandable card already lists its alerts on this host). ─────────────
type HostSubTab = 'info' | 'network' | 'incidents'

function HostDetailView({
  hostname, deviceInfo,
  cachedAdapters, onAdaptersLoaded,
  cachedIncidents, onIncidentsLoaded,
  incidentFlags, onIncidentFlag,
}: {
  hostname: string
  deviceInfo: DeviceInfoData | null
  cachedAdapters: NetworkAdapter[] | null
  onAdaptersLoaded: (a: NetworkAdapter[]) => void
  cachedIncidents: HostIncident[] | null
  onIncidentsLoaded: (i: HostIncident[]) => void
  incidentFlags: Map<string, FlagStatus>
  onIncidentFlag: (incidentId: string, flag: FlagStatus) => void
}) {
  const [subTab, setSubTab] = useState<HostSubTab>('info')

  const subTabs: { id: HostSubTab; label: string }[] = [
    { id: 'info',      label: 'Info' },
    { id: 'network',   label: 'Network Adapters' },
    { id: 'incidents', label: 'Incidents' },
  ]

  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column',
      background: 'var(--bg-panel)',
      minHeight: 0,
    }}>
      {/* Sub-tab strip */}
      <div style={{
        display: 'flex', borderBottom: '1px solid var(--border)',
        background: 'var(--bg-elevated)', flexShrink: 0,
      }}>
        {subTabs.map(t => {
          const active = t.id === subTab
          return (
            <button
              key={t.id}
              onClick={() => setSubTab(t.id)}
              style={{
                background: 'transparent',
                border: 'none',
                borderBottom: active ? '2px solid var(--accent)' : '2px solid transparent',
                color: active ? 'var(--accent)' : 'var(--text-muted)',
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)',
                fontSize: 10.5,
                fontWeight: active ? 600 : 400,
                padding: '7px 14px',
                letterSpacing: 0.4,
                textTransform: 'uppercase',
                outline: 'none',
              }}>
              {t.label}
            </button>
          )
        })}
      </div>
      {subTab === 'info' ? (
        <HostInfoView hostname={hostname} deviceInfo={deviceInfo} />
      ) : subTab === 'network' ? (
        <NetworkAdaptersView
          hostname={hostname}
          cached={cachedAdapters}
          onLoaded={onAdaptersLoaded}
        />
      ) : (
        <IncidentsView
          hostname={hostname}
          cached={cachedIncidents}
          onLoaded={onIncidentsLoaded}
          incidentFlags={incidentFlags}
          onIncidentFlag={onIncidentFlag}
        />
      )}
    </div>
  )
}

// ── Info sub-tab — DeviceInfo snapshot. ──────────────────────────────────
function HostInfoView({ hostname, deviceInfo }: {
  hostname: string
  deviceInfo: DeviceInfoData | null
}) {
  // Local fallback fetch — if the parent hasn't received deviceInfo yet (or
  // it returned empty), pull it ourselves when the analyst opens the tab.
  const [localInfo, setLocalInfo] = useState<DeviceInfoData | null>(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    if (deviceInfo) return  // parent already has it
    if (!hostname) return
    setLoading(true)
    setErr(null)
    fetchDeviceInfo(hostname)
      .then(info => {
        if (info && info.ok) setLocalInfo(info)
        else setErr(friendlyError(info?.error || 'No DeviceInfo rows returned for this hostname.'))
      })
      .catch(e => setErr(friendlyError(e)))
      .finally(() => setLoading(false))
  }, [hostname, deviceInfo])

  const d = deviceInfo ?? localInfo

  function fmtBool(v: boolean | null | undefined): string {
    if (v === true) return 'yes'
    if (v === false) return 'no'
    return '—'
  }
  function fmtTime(iso: string | undefined): string {
    return fmtDateTime(iso)
  }
  function fmtVal(v: string | undefined | null): string {
    if (v === null || v === undefined || v === '') return '—'
    return String(v)
  }
  function exposureColor(level: string | undefined): string {
    if (!level) return 'var(--text-muted)'
    const l = level.toLowerCase()
    if (l.includes('high')) return 'var(--red)'
    if (l.includes('medium')) return 'var(--amber)'
    if (l.includes('low')) return 'var(--green)'
    return 'var(--text)'
  }
  function sensorColor(state: string | undefined): string {
    if (!state) return 'var(--text-muted)'
    if (state === 'Active') return 'var(--green)'
    if (state.toLowerCase().includes('inactive')) return 'var(--red)'
    return 'var(--amber)'
  }

  // Two-column grid: each entry is { label, value, valueColor? }
  const rows: { label: string; value: React.ReactNode; color?: string }[] = [
    { label: 'hostname',         value: fmtVal(d?.device_name || hostname), color: 'var(--accent)' },
    { label: 'device id',        value: fmtVal(d?.device_id) },
    { label: 'category',         value: fmtVal(d?.device_category) + (d?.device_type ? ` · ${d.device_type}` : '') },
    { label: 'os',               value: fmtVal(d?.os_platform) + (d?.os_architecture ? ` (${d.os_architecture})` : '') },
    { label: 'os version',       value: fmtVal(d?.os_version_info || d?.os_version) },
    { label: 'os build',         value: fmtVal(d?.os_build) },
    { label: 'mde client',       value: fmtVal(d?.client_version) },
    { label: 'public ip',        value: fmtVal(d?.public_ip), color: 'var(--accent)' },
    { label: 'exposure level',   value: fmtVal(d?.exposure_level), color: exposureColor(d?.exposure_level) },
    { label: 'onboarding',       value: fmtVal(d?.onboarding_status) },
    { label: 'sensor health',    value: fmtVal(d?.sensor_health), color: sensorColor(d?.sensor_health) },
    { label: 'isolated',         value: fmtBool(d?.is_isolated), color: d?.is_isolated ? 'var(--red)' : 'var(--text)' },
    { label: 'av status',        value: fmtVal(d?.av_status) },
    { label: 'machine group',    value: fmtVal(d?.machine_group) },
    { label: 'join type',        value: fmtVal(d?.join_type || (d?.is_azure_ad_joined ? 'AAD Joined' : '')) },
    { label: 'azure ad joined',  value: fmtBool(d?.is_azure_ad_joined) },
    { label: 'logged-on users',  value: fmtVal(d?.logged_on_users) },
    { label: 'last seen',        value: fmtTime(d?.last_seen) },
  ]

  return (
    <div style={{
      flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '14px 16px',
      fontFamily: 'var(--font-mono)', fontSize: 11,
      background: 'var(--bg-panel)',
      minHeight: 0,
    }}>
      <div style={{ color: 'var(--text)', fontWeight: 600, fontSize: 12, marginBottom: 12 }}>
        <span style={{ color: 'var(--accent)' }}>▌</span> host details
      </div>
      {loading && !d ? (
        <div style={{ color: 'var(--accent)', fontSize: 11 }}>Loading device info…</div>
      ) : err && !d ? (
        <div style={{ color: 'var(--red)', fontSize: 11, lineHeight: 1.5 }}>
          ✗ {err}
        </div>
      ) : !d ? (
        <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>No DeviceInfo for {hostname}.</div>
      ) : (
        <div style={{
          display: 'grid', gridTemplateColumns: '130px 1fr',
          rowGap: 6, columnGap: 14,
          fontSize: 11, lineHeight: 1.5,
        }}>
          {rows.map(r => (
            <React.Fragment key={r.label}>
              <span style={{ color: 'var(--text-muted)' }}>{r.label}</span>
              <span style={{
                color: r.color ?? 'var(--text)',
                wordBreak: 'break-all',
              }}>{r.value}</span>
            </React.Fragment>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Network Adapters sub-tab — DeviceNetworkInfo snapshot per adapter.
//    The parent owns the cache so the data survives tab switches and is only
//    fetched once per investigation. ────────────────────────────────────────
function NetworkAdaptersView({ hostname, cached, onLoaded }: {
  hostname: string
  cached: NetworkAdapter[] | null
  onLoaded: (a: NetworkAdapter[]) => void
}) {
  const [adapters, setAdapters] = useState<NetworkAdapter[] | null>(cached)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    if (cached !== null) {
      setAdapters(cached)
      return
    }
    if (!hostname) return
    setLoading(true)
    setErr(null)
    fetchNetworkAdapters(hostname)
      .then(res => {
        if (res.ok) {
          const list = res.adapters || []
          setAdapters(list)
          onLoaded(list)
        } else {
          setErr(friendlyError(res.error || 'Network adapter query failed.'))
        }
      })
      .catch(e => setErr(friendlyError(e)))
      .finally(() => setLoading(false))
  }, [hostname, cached, onLoaded])

  function statusColor(s: string): string {
    const v = (s || '').toLowerCase()
    if (v === 'up') return 'var(--green)'
    if (v === 'down' || v === 'disabled') return 'var(--red)'
    return 'var(--amber)'
  }

  return (
    <div style={{
      flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '14px 16px',
      fontFamily: 'var(--font-mono)', fontSize: 11,
      background: 'var(--bg-panel)',
      minHeight: 0,
    }}>
      <div style={{ color: 'var(--text)', fontWeight: 600, fontSize: 12, marginBottom: 12 }}>
        <span style={{ color: 'var(--accent)' }}>▌</span> network adapters
      </div>
      {loading && adapters === null ? (
        <div style={{ color: 'var(--accent)', fontSize: 11 }}>Loading network adapters…</div>
      ) : err ? (
        <div style={{ color: 'var(--red)', fontSize: 11, lineHeight: 1.5 }}>✗ {err}</div>
      ) : !adapters || adapters.length === 0 ? (
        <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
          No network adapter records for {hostname}.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {adapters.map((a, idx) => (
            <div key={`${a.name}-${idx}`} style={{
              border: '1px solid var(--border)', borderRadius: 4,
              background: 'var(--bg-elevated)', padding: '10px 12px',
            }}>
              <div style={{
                display: 'flex', alignItems: 'baseline', gap: 8,
                marginBottom: 8, paddingBottom: 6,
                borderBottom: '1px solid var(--border)',
              }}>
                <span style={{ color: 'var(--accent)', fontWeight: 600, fontSize: 12 }}>
                  {a.name || '(unnamed adapter)'}
                </span>
                {a.type && (
                  <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>
                    · {a.type}
                  </span>
                )}
                <span style={{ flex: 1 }} />
                <span style={{
                  color: statusColor(a.status), fontSize: 10.5,
                  fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5,
                }}>
                  {a.status || '—'}
                </span>
              </div>
              <div style={{
                display: 'grid', gridTemplateColumns: '120px 1fr',
                rowGap: 5, columnGap: 12,
                fontSize: 11, lineHeight: 1.5,
              }}>
                <span style={{ color: 'var(--text-muted)' }}>mac</span>
                <span style={{ wordBreak: 'break-all' }}>{a.mac || '—'}</span>

                <span style={{ color: 'var(--text-muted)' }}>ip addresses</span>
                <span style={{ wordBreak: 'break-all' }}>
                  {a.ip_addresses.length === 0 ? '—' : a.ip_addresses.map((ip, i) => (
                    <span key={i} style={{ display: 'block' }}>
                      {ip.ip}{ip.subnet_prefix != null ? `/${ip.subnet_prefix}` : ''}
                      {ip.address_type ? (
                        <span style={{ color: 'var(--text-muted)' }}> · {ip.address_type}</span>
                      ) : null}
                    </span>
                  ))}
                </span>

                <span style={{ color: 'var(--text-muted)' }}>gateways</span>
                <span style={{ wordBreak: 'break-all' }}>
                  {a.default_gateways.length === 0 ? '—' : a.default_gateways.join(', ')}
                </span>

                <span style={{ color: 'var(--text-muted)' }}>dns</span>
                <span style={{ wordBreak: 'break-all' }}>
                  {a.dns_addresses.length === 0 ? '—' : a.dns_addresses.join(', ')}
                </span>

                <span style={{ color: 'var(--text-muted)' }}>networks</span>
                <span style={{ wordBreak: 'break-all' }}>
                  {a.connected_networks.length === 0 ? '—' : a.connected_networks.join(', ')}
                </span>

                <span style={{ color: 'var(--text-muted)' }}>dhcp</span>
                <span>
                  v4: {a.ipv4_dhcp || '—'}
                  {a.ipv6_dhcp ? `  ·  v6: ${a.ipv6_dhcp}` : ''}
                </span>

                {a.tunnel_type && (
                  <>
                    <span style={{ color: 'var(--text-muted)' }}>tunnel</span>
                    <span>{a.tunnel_type}</span>
                  </>
                )}

                <span style={{ color: 'var(--text-muted)' }}>last seen</span>
                <span style={{ color: 'var(--text-muted)' }}>
                  {fmtDateTime(a.last_seen)}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}


// ── Incidents sub-tab — Graph Security incidents this host appeared in,
//    last 30 days. Each card is one incident with severity / status /
//    classification / determination, link out to the Defender portal, and
//    the number of alerts in that incident tied to this host. ────────────
function IncidentsView({ hostname, cached, onLoaded, incidentFlags, onIncidentFlag }: {
  hostname: string
  cached: HostIncident[] | null
  onLoaded: (i: HostIncident[]) => void
  incidentFlags: Map<string, FlagStatus>
  onIncidentFlag: (incidentId: string, flag: FlagStatus) => void
}) {
  const [incidents, setIncidents] = useState<HostIncident[] | null>(cached)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  function toggleExpand(id: string) {
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  useEffect(() => {
    if (cached !== null) { setIncidents(cached); return }
    if (!hostname) return
    setLoading(true)
    setErr(null)
    fetchHostIncidents(hostname)
      .then(res => {
        if (res.ok) {
          const list = res.incidents || []
          setIncidents(list)
          onLoaded(list)
        } else {
          setErr(friendlyError(res.error || 'Incidents query failed.'))
        }
      })
      .catch(e => setErr(friendlyError(e)))
      .finally(() => setLoading(false))
  }, [hostname, cached, onLoaded])

  function sevColor(s: string): string {
    const v = (s || '').toLowerCase()
    if (v === 'high' || v === 'critical')   return 'var(--red)'
    if (v === 'medium')                     return 'var(--amber)'
    if (v === 'low')                        return 'var(--green)'
    return 'var(--text-muted)'
  }
  function statusColor(s: string): string {
    const v = (s || '').toLowerCase()
    if (v === 'active' || v === 'inprogress') return 'var(--amber)'
    if (v === 'resolved')                     return 'var(--green)'
    if (v === 'redirected')                   return 'var(--text-muted)'
    return 'var(--text-muted)'
  }
  function classColor(c: string): string {
    const v = (c || '').toLowerCase()
    if (v === 'truepositive')              return 'var(--red)'
    if (v === 'falsepositive')             return 'var(--green)'
    if (v === 'informationalexpectedactivity') return 'var(--text-muted)'
    return 'var(--text-muted)'
  }
  function cycleIncidentFlag(current: FlagStatus): FlagStatus {
    const order: FlagStatus[] = [null, 'benign', 'suspicious', 'malicious']
    const idx = order.indexOf(current)
    return order[(idx + 1) % order.length]
  }

  return (
    <div style={{
      flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '14px 16px',
      fontFamily: 'var(--font-mono)', fontSize: 11,
      background: 'var(--bg-panel)', minHeight: 0,
    }}>
      <div style={{
        color: 'var(--text)', fontWeight: 600, fontSize: 12,
        marginBottom: 12, display: 'flex', alignItems: 'baseline', gap: 8,
      }}>
        <span style={{ color: 'var(--accent)' }}>▌</span> incidents
        <span style={{ color: 'var(--text-muted)', fontSize: 10.5, fontWeight: 400 }}>
          last 30 days{incidents ? ` · ${incidents.length}` : ''}
        </span>
      </div>
      {loading && incidents === null ? (
        <div style={{ color: 'var(--accent)', fontSize: 11 }}>Loading incidents…</div>
      ) : err ? (
        <div style={{ color: 'var(--red)', fontSize: 11, lineHeight: 1.5 }}>✗ {err}</div>
      ) : !incidents || incidents.length === 0 ? (
        <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>
          No incidents involving {hostname} in the last 30 days.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {incidents.map(inc => {
            const isOpen = expanded.has(inc.id)
            const flag = incidentFlags.get(inc.id) ?? null
            const flagColor = flag ? FLAGGED_POPUP_COLORS[flag] : null
            return (
            <div key={inc.id} style={{
              border: '1px solid var(--border)',
              borderLeft: flagColor ? `3px solid ${flagColor}` : '1px solid var(--border)',
              borderRadius: 4,
              background: flagColor
                ? `linear-gradient(${flagColor}1F, ${flagColor}1F), var(--bg-elevated)`
                : 'var(--bg-elevated)',
              padding: '10px 12px',
            }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6,
                paddingBottom: 6, borderBottom: '1px solid var(--border)',
              }}>
                <button
                  onClick={() => onIncidentFlag(inc.id, cycleIncidentFlag(flag))}
                  title={flag ? `Flagged: ${flag} — click to cycle` : 'Click to flag this incident'}
                  style={{
                    background: 'transparent',
                    border: `1px solid ${flagColor ?? 'var(--border)'}`,
                    color: flagColor ?? 'var(--text-muted)',
                    borderRadius: 4, cursor: 'pointer',
                    fontFamily: 'var(--font-mono)', fontSize: 16, lineHeight: 1,
                    padding: '5px 10px', outline: 'none',
                    flexShrink: 0, userSelect: 'none',
                  }}
                  onMouseDown={e => e.preventDefault()}>
                  ⚑
                </button>
                <span style={{ color: 'var(--accent)', fontWeight: 600, fontSize: 12 }}>
                  {inc.display_name || `Incident ${inc.id}`}
                </span>
                <span style={{ flex: 1 }} />
                <span style={{
                  color: sevColor(inc.severity), fontSize: 10.5,
                  fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5,
                }}>
                  {inc.severity || '—'}
                </span>
              </div>
              <div style={{
                display: 'grid', gridTemplateColumns: '140px 1fr',
                rowGap: 5, columnGap: 12,
                fontSize: 11, lineHeight: 1.5,
              }}>
                <span style={{ color: 'var(--text-muted)' }}>incident id</span>
                <span style={{ color: 'var(--text-muted)', wordBreak: 'break-all' }}>{inc.id}</span>

                <span style={{ color: 'var(--text-muted)' }}>created</span>
                <span>{fmtDateTime(inc.created)}</span>

                <span style={{ color: 'var(--text-muted)' }}>last update</span>
                <span>{fmtDateTime(inc.last_update)}</span>

                <span style={{ color: 'var(--text-muted)' }}>status</span>
                <span style={{ color: statusColor(inc.status), fontWeight: 600 }}>
                  {inc.status || '—'}
                </span>

                <span style={{ color: 'var(--text-muted)' }}>classification</span>
                <span style={{ color: classColor(inc.classification), fontWeight: 600 }}>
                  {inc.classification || '—'}
                </span>

                <span style={{ color: 'var(--text-muted)' }}>determination</span>
                <span>{inc.determination || '—'}</span>

                <span style={{ color: 'var(--text-muted)' }}>assigned to</span>
                <span>{inc.assigned_to || '—'}</span>

                <span style={{ color: 'var(--text-muted)' }}>alerts on host</span>
                <span>{inc.host_alert_count}</span>

                <span style={{ color: 'var(--text-muted)' }}>tags</span>
                <span style={{ wordBreak: 'break-all' }}>
                  {[...(inc.custom_tags || []), ...(inc.system_tags || [])].join(', ') || '—'}
                </span>

                <span style={{ color: 'var(--text-muted)' }}>comments</span>
                <span>{inc.comments_count}</span>

                {inc.incident_web_url && (
                  <>
                    <span style={{ color: 'var(--text-muted)' }}>portal</span>
                    <a href={inc.incident_web_url} target="_blank" rel="noreferrer"
                       style={{ color: 'var(--accent)', wordBreak: 'break-all' }}>
                      open in Defender ↗
                    </a>
                  </>
                )}
              </div>

              {/* Expandable detail block — host alerts, comments, description. */}
              <div style={{ marginTop: 8 }}>
                <button
                  onClick={() => toggleExpand(inc.id)}
                  style={{
                    background: 'transparent', border: 'none',
                    color: 'var(--text-muted)', cursor: 'pointer',
                    fontFamily: 'var(--font-mono)', fontSize: 10.5,
                    padding: 0, outline: 'none',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.color = 'var(--accent)' }}
                  onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)' }}>
                  {isOpen ? '▾' : '▸'} details
                </button>
                {isOpen && (
                  <div style={{
                    marginTop: 8, paddingTop: 8,
                    borderTop: '1px dashed var(--border)',
                    display: 'flex', flexDirection: 'column', gap: 10,
                    fontSize: 11, lineHeight: 1.5,
                  }}>
                    {(inc.host_earliest_seen || inc.host_latest_seen) && (
                      <div style={{
                        display: 'grid', gridTemplateColumns: '140px 1fr',
                        rowGap: 4, columnGap: 12,
                      }}>
                        <span style={{ color: 'var(--text-muted)' }}>first activity</span>
                        <span>{fmtDateTime(inc.host_earliest_seen)}</span>
                        <span style={{ color: 'var(--text-muted)' }}>last activity</span>
                        <span>{fmtDateTime(inc.host_latest_seen)}</span>
                        {inc.redirect_incident_id && (
                          <>
                            <span style={{ color: 'var(--text-muted)' }}>merged into</span>
                            <span style={{ color: 'var(--amber)' }}>
                              {inc.redirect_incident_id}
                            </span>
                          </>
                        )}
                      </div>
                    )}

                    {inc.description && (
                      <div>
                        <div style={{
                          color: 'var(--text-muted)', textTransform: 'uppercase',
                          letterSpacing: 0.4, fontSize: 10, marginBottom: 3,
                        }}>description</div>
                        <div style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                          {inc.description}
                        </div>
                      </div>
                    )}

                    {inc.host_alerts && inc.host_alerts.length > 0 && (
                      <div>
                        <div style={{
                          color: 'var(--text-muted)', textTransform: 'uppercase',
                          letterSpacing: 0.4, fontSize: 10, marginBottom: 5,
                        }}>alerts on this host ({inc.host_alerts.length})</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          {inc.host_alerts.map(a => (
                            <div key={a.id} style={{
                              border: '1px solid var(--border)', borderRadius: 3,
                              background: 'var(--bg-panel)', padding: '6px 8px',
                            }}>
                              <div style={{
                                display: 'flex', alignItems: 'baseline', gap: 6, marginBottom: 3,
                              }}>
                                <span style={{ color: 'var(--text)', fontWeight: 600 }}>
                                  {a.title || '(untitled alert)'}
                                </span>
                                <span style={{ flex: 1 }} />
                                <span style={{
                                  color: sevColor(a.severity), fontSize: 10,
                                  fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.4,
                                }}>{a.severity || '—'}</span>
                              </div>
                              <div style={{
                                display: 'grid', gridTemplateColumns: '120px 1fr',
                                rowGap: 3, columnGap: 10, fontSize: 10.5,
                              }}>
                                <span style={{ color: 'var(--text-muted)' }}>status</span>
                                <span>{a.status || '—'}</span>
                                <span style={{ color: 'var(--text-muted)' }}>category</span>
                                <span>{a.category || '—'}</span>
                                {a.threat_display_name && (
                                  <>
                                    <span style={{ color: 'var(--text-muted)' }}>threat</span>
                                    <span>
                                      {a.threat_display_name}
                                      {a.threat_family ? ` (${a.threat_family})` : ''}
                                    </span>
                                  </>
                                )}
                                <span style={{ color: 'var(--text-muted)' }}>detection</span>
                                <span>{a.detection_source || '—'}{a.service_source ? ` · ${a.service_source}` : ''}</span>
                                {a.mitre_techniques.length > 0 && (
                                  <>
                                    <span style={{ color: 'var(--text-muted)' }}>mitre</span>
                                    <span>{a.mitre_techniques.join(', ')}</span>
                                  </>
                                )}
                                <span style={{ color: 'var(--text-muted)' }}>first activity</span>
                                <span>{fmtDateTime(a.first_activity)}</span>
                                <span style={{ color: 'var(--text-muted)' }}>last activity</span>
                                <span>{fmtDateTime(a.last_activity)}</span>
                                <span style={{ color: 'var(--text-muted)' }}>alert id</span>
                                <span style={{ color: 'var(--text-muted)', wordBreak: 'break-all' }}>{a.id}</span>
                                {a.alert_web_url && (
                                  <>
                                    <span style={{ color: 'var(--text-muted)' }}>portal</span>
                                    <a href={a.alert_web_url} target="_blank" rel="noreferrer"
                                       style={{ color: 'var(--accent)', wordBreak: 'break-all' }}>
                                      open in Defender ↗
                                    </a>
                                  </>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {inc.comments && inc.comments.length > 0 && (
                      <div>
                        <div style={{
                          color: 'var(--text-muted)', textTransform: 'uppercase',
                          letterSpacing: 0.4, fontSize: 10, marginBottom: 5,
                        }}>comments ({inc.comments.length})</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                          {inc.comments.map((c, i) => (
                            <div key={i} style={{
                              border: '1px solid var(--border)', borderRadius: 3,
                              background: 'var(--bg-panel)', padding: '5px 8px',
                            }}>
                              <div style={{
                                color: 'var(--text-muted)', fontSize: 10, marginBottom: 2,
                              }}>
                                {c.created_by || 'unknown'} ·{' '}
                                {c.created_at ? fmtDateTime(c.created_at) : '?'}
                              </div>
                              <div style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                                {c.body || '—'}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── App Bar (merged nav + device strip) ──────────────────────────────────
function AppBar({ user, investigation, procCount = 0, onLogout, onSettings, onHome, onTimeWindowChange, onFocalPidClick, onChangePid, onLoadInvestigation, becActive, onSaveBec, onLoadBec }: {
  user: User
  investigation: Investigation | null
  procCount?: number
  onLogout: () => void
  onSettings: () => void
  onHome: () => void
  onTimeWindowChange: ((tw: string) => void) | null
  onFocalPidClick: ((pid: number) => void) | null
  // Triggered when the analyst commits a new focal PID via the inline
  // edit popover on the AppBar PID chip. Re-pivots the investigation
  // to the new PID, which reloads the tree and clears the AI panel.
  onChangePid: ((pid: number) => void) | null
  // Fired by the load-from-file flow with the persisted investigation
  // metadata (or null if the file carried only authored state).
  onLoadInvestigation: ((inv: Investigation | null) => void) | null
  // BEC mode: when a case is open, Save/Load operate on the BEC case file
  // instead of the endpoint investigation.
  becActive: boolean
  onSaveBec: () => void
  onLoadBec: (c: import('../api/bec').BecCaseState) => void
}) {
  const iocList = useIocList()
  const [confirmNew, setConfirmNew] = useState(false)
  const [pidEditOpen, setPidEditOpen] = useState(false)
  const [pidEditValue, setPidEditValue] = useState('')
  const [pidEditError, setPidEditError] = useState<string | null>(null)
  const pidAnchorRef = useRef<HTMLSpanElement | null>(null)
  const loadInputRef = useRef<HTMLInputElement | null>(null)
  const [loadMsg, setLoadMsg] = useState<string | null>(null)

  async function handleFileChosen(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''  // reset so picking the same file twice still fires onChange
    if (!file) return
    // First: is it a BEC case file? If so, route it to the BEC loader.
    const bec = await parseBecCaseFile(file)
    if (bec.ok) {
      if ((becActive || !!investigation) && !window.confirm(
        'Load this BEC case? It will replace the current case / investigation.'
      )) return
      onLoadBec(bec.case)
      setLoadMsg('✓ BEC case loaded')
      setTimeout(() => setLoadMsg(null), 4000)
      return
    }
    // Otherwise treat it as an endpoint investigation file.
    // Warn before clobbering current work. Anything an analyst has built up
    // (IOCs / flags / notes / overrides / history) is about to be replaced
    // wholesale by the file contents.
    const haveState = !!investigation || iocList.length > 0
    if (haveState && !window.confirm(
      'Loading this file will replace your current investigation, IOCs, flags, timeline notes and AI analysis history. Continue?'
    )) return
    const res = await importInvestigationFromFile(file)
    if (!res.ok) {
      setLoadMsg(`✗ ${res.error}`)
      setTimeout(() => setLoadMsg(null), 5000)
      return
    }
    onLoadInvestigation?.(res.investigation ?? null)
    setLoadMsg(res.investigation ? '✓ Investigation loaded' : '✓ Saved data restored — start a new investigation to use it')
    setTimeout(() => setLoadMsg(null), 4000)
  }

  function handleNewInv() {
    if (investigation) {
      setConfirmNew(true)
    } else {
      onHome()
    }
  }

  function confirmNewInv() {
    clearIocs()
    clearHuntFlags()
    clearInvestigation()
    clearAnalysisHistory()
    clearAllDegraded()
    setConfirmNew(false)
    onHome()
  }

  const divider = () => (
    <div style={{ width: 1, height: 14, background: 'var(--border)', flexShrink: 0 }} />
  )
  const cell = (label: string, value: string, color?: string) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
      <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>{label}</span>
      <span style={{ color: color ?? 'var(--text)', fontSize: 10.5 }}>{value}</span>
    </div>
  )

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10, padding: '0 14px',
      background: 'var(--bg-app)', borderBottom: '1px solid var(--border)',
      height: 42, flexShrink: 0, fontFamily: 'var(--font-mono)', fontSize: 11,
      overflowX: 'auto',
    }}>
      {/* Logo — horizontal sudotrace banner, pre-cropped at the source
          (5073x694). Rendered at fixed height with natural aspect ratio. */}
      <img
        src="/sudotrace-logo-horizontal.png"
        alt="SudoTrace"
        title="Start a new investigation"
        onClick={handleNewInv}
        style={{
          height: 26, width: 'auto', flexShrink: 0,
          cursor: 'pointer', borderRadius: 3, display: 'block',
          // Soft fade on the rim: transparent at the very edges, fully
          // opaque through the middle band. Same gradient masked on both
          // axes so the logo blends into the AppBar instead of showing a
          // hard rectangle. Both `mask-image` and the webkit-prefixed
          // form are set for cross-browser support.
          WebkitMaskImage:
            'linear-gradient(to right, transparent 0%, #000 6%, #000 94%, transparent 100%), ' +
            'linear-gradient(to bottom, transparent 0%, #000 10%, #000 90%, transparent 100%)',
          WebkitMaskComposite: 'source-in',
          maskImage:
            'linear-gradient(to right, transparent 0%, #000 6%, #000 94%, transparent 100%), ' +
            'linear-gradient(to bottom, transparent 0%, #000 10%, #000 90%, transparent 100%)',
          maskComposite: 'intersect',
        }}
      />

      {investigation && (
        <>
          {divider()}
          <span style={{ color: 'var(--text)', fontSize: 10.5, flexShrink: 0 }}>{investigation.id}</span>
          <span style={{ color: 'var(--text-muted)', flexShrink: 0, fontSize: 10.5 }}>
            scope: <span style={{ color: 'var(--text)' }}>1 device · {procCount} process{procCount === 1 ? '' : 'es'} · {iocList.length} ioc</span>
          </span>
          {divider()}
          {investigation.hostname && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
              <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>host</span>
              <span style={{ color: 'var(--accent)', fontSize: 10.5 }}>{investigation.hostname}</span>
            </div>
          )}
          {investigation.mode === 'host-pid' && investigation.pid && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
              <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>pid</span>
              <span
                ref={pidAnchorRef}
                onClick={() => {
                  setPidEditValue(investigation.pid ?? '')
                  setPidEditError(null)
                  setPidEditOpen(true)
                }}
                onMouseEnter={e => { e.currentTarget.style.textDecorationColor = 'var(--accent)' }}
                onMouseLeave={e => { e.currentTarget.style.textDecorationColor = 'rgba(168,85,247,0.4)' }}
                title="Click to pivot the investigation to a different PID, or jump the tree to this one"
                style={{
                  color: 'var(--accent)', fontSize: 10.5,
                  cursor: 'pointer',
                  textDecoration: 'underline',
                  textDecorationStyle: 'dotted',
                  textDecorationColor: 'rgba(168,85,247,0.4)',
                  transition: 'text-decoration-color 100ms',
                }}>{investigation.pid}</span>
            </div>
          )}
          {investigation.mode === 'alert-id' && investigation.alertId && cell('alert', investigation.alertId, 'var(--accent)')}
          <WindowControl
            rawTimeWindow={investigation.rawTimeWindow}
            onChange={onTimeWindowChange}
          />
        </>
      )}

      <div style={{ flex: 1 }} />

      {/* New investigation button / confirmation */}
      {confirmNew ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <span style={{ color: 'var(--amber)', fontSize: 10.5, flexShrink: 0 }}>
            This will erase everything from the current investigation (flagged items, IOCs, hunt history, AI analyses). Start over?
          </span>
          <button onClick={confirmNewInv} style={{
            background: 'rgba(255,94,91,0.12)', border: '1px solid rgba(255,94,91,0.35)',
            borderRadius: 3, color: '#FF5E5B', cursor: 'pointer', fontSize: 10.5,
            padding: '2px 9px', fontFamily: 'var(--font-mono)', flexShrink: 0,
          }}>confirm</button>
          <button onClick={() => setConfirmNew(false)}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.background = 'rgba(168,85,247,0.15)' }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.background = 'transparent' }}
            style={{
              background: 'transparent', border: '1px solid var(--border)',
              borderRadius: 3, color: 'var(--text-muted)', cursor: 'pointer', fontSize: 10.5,
              padding: '2px 9px', fontFamily: 'var(--font-mono)', flexShrink: 0,
              transition: 'border-color 100ms, color 100ms, background 100ms',
            }}>cancel</button>
        </div>
      ) : investigation ? (
        <button onClick={handleNewInv}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.background = 'rgba(168,85,247,0.15)' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.background = 'transparent' }}
          style={{
            background: 'transparent', border: '1px solid var(--border)',
            borderRadius: 3, color: 'var(--text-muted)', cursor: 'pointer', fontSize: 10.5,
            padding: '2px 9px', fontFamily: 'var(--font-mono)', flexShrink: 0, letterSpacing: 0.2,
            transition: 'border-color 100ms, color 100ms, background 100ms',
          }}>+ New Investigation</button>
      ) : null}

      {/* Right actions */}
      {divider()}
      {/* Save / Load — analyst-driven backup of the current investigation.
          Reuses the same snapshot shape as the auto-save endpoint, so an
          exported file can be re-imported into a fresh session. */}
      <button
        onClick={() => becActive ? onSaveBec() : exportInvestigationToFile(investigation)}
        title={becActive
          ? 'Download the current BEC case (account, selections, checklist, notes, captured IPs) as a JSON file'
          : 'Download the current investigation (IOCs, flags, notes, overrides, AI history) as a JSON file'}
        onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.background = 'rgba(168,85,247,0.15)' }}
        onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.background = 'transparent' }}
        style={{
          background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
          color: 'var(--text-muted)', cursor: 'pointer', fontSize: 10.5,
          padding: '3px 9px', fontFamily: 'var(--font-mono)', flexShrink: 0,
          transition: 'border-color 100ms, color 100ms, background 100ms',
        }}>↓ save</button>
      <button
        onClick={() => loadInputRef.current?.click()}
        title="Load a previously saved investigation file (replaces current state)"
        onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.background = 'rgba(168,85,247,0.15)' }}
        onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.background = 'transparent' }}
        style={{
          background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
          color: 'var(--text-muted)', cursor: 'pointer', fontSize: 10.5,
          padding: '3px 9px', fontFamily: 'var(--font-mono)', flexShrink: 0,
          transition: 'border-color 100ms, color 100ms, background 100ms',
        }}>↑ load</button>
      <input
        ref={loadInputRef}
        type="file"
        accept="application/json,.json"
        onChange={handleFileChosen}
        style={{ display: 'none' }}
      />
      {loadMsg && (
        <span title={loadMsg} style={{
          color: loadMsg.startsWith('✗') ? 'var(--red)' : 'var(--green)',
          fontSize: 10.5, fontFamily: 'var(--font-mono)',
          maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          flexShrink: 0,
        }}>{loadMsg}</span>
      )}
      {divider()}
      <button onClick={onSettings}
        onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.background = 'rgba(168,85,247,0.15)' }}
        onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.background = 'transparent' }}
        style={{
          background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
          color: 'var(--text-muted)', cursor: 'pointer', fontSize: 10.5,
          padding: '3px 9px', fontFamily: 'var(--font-mono)', flexShrink: 0,
          transition: 'border-color 100ms, color 100ms, background 100ms',
        }}>settings</button>
      {divider()}
      <span style={{ color: 'var(--text-muted)', fontSize: 10.5, flexShrink: 0 }}>{user.username}</span>
      <button onClick={onLogout}
        onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.background = 'rgba(168,85,247,0.15)' }}
        onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.background = 'transparent' }}
        style={{
          background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
          color: 'var(--text-muted)', cursor: 'pointer', fontSize: 10.5,
          padding: '3px 9px', fontFamily: 'var(--font-mono)', flexShrink: 0,
          transition: 'border-color 100ms, color 100ms, background 100ms',
        }}>sign out</button>

      {/* PID-edit popover — opens when the analyst clicks the PID chip
          in the AppBar. Lets them pivot the investigation to a new PID
          mid-flight without going back through the Welcome screen.
          Anchored to the chip via getBoundingClientRect. */}
      {pidEditOpen && investigation && (() => {
        const rect = pidAnchorRef.current?.getBoundingClientRect()
        const POP_W = 280
        const top  = (rect?.bottom ?? 50) + 6
        let left   = rect?.left ?? 12
        if (left + POP_W > window.innerWidth - 12) {
          left = Math.max(12, window.innerWidth - POP_W - 12)
        }
        function commit() {
          const n = parseInt(pidEditValue, 10)
          if (!pidEditValue || isNaN(n) || pidEditValue.replace(/\D/g, '') !== pidEditValue || pidEditValue.length > 7 || n === 0 || n === 4) {
            setPidEditError('PID must be a number 1–9999999. PIDs 0 and 4 are reserved.')
            return
          }
          setPidEditOpen(false)
          if (onChangePid) onChangePid(n)
        }
        function focusCurrent() {
          const n = parseInt(investigation!.pid ?? '', 10)
          if (!isNaN(n) && onFocalPidClick) onFocalPidClick(n)
          setPidEditOpen(false)
        }
        return createPortal(
          <>
            <div
              onClick={() => setPidEditOpen(false)}
              style={{ position: 'fixed', inset: 0, zIndex: 9998 }}
            />
            <div style={{
              position: 'fixed', top, left, zIndex: 9999, width: POP_W,
              background: 'var(--bg-panel)', border: '1px solid var(--border)',
              borderRadius: 6, boxShadow: '0 6px 24px rgba(0,0,0,0.55)',
              fontFamily: 'var(--font-mono)', fontSize: 11,
              padding: '12px 14px',
            }}>
              <div style={{ color: 'var(--text-muted)', fontSize: 10, marginBottom: 6, letterSpacing: 0.4, textTransform: 'uppercase' }}>
                pivot investigation
              </div>
              <input
                value={pidEditValue}
                onChange={e => {
                  setPidEditValue(e.target.value.replace(/\D/g, ''))
                  setPidEditError(null)
                }}
                onKeyDown={e => {
                  if (e.key === 'Enter') { e.preventDefault(); commit() }
                  else if (e.key === 'Escape') { setPidEditOpen(false) }
                }}
                placeholder="new PID"
                autoFocus
                inputMode="numeric"
                style={{
                  background: 'var(--bg-app)', border: '1px solid var(--border)',
                  borderRadius: 4, color: 'var(--text)', outline: 'none',
                  fontFamily: 'var(--font-mono)', fontSize: 12,
                  padding: '6px 10px', width: '100%', boxSizing: 'border-box',
                }}
              />
              {pidEditError && (
                <div style={{ color: 'var(--red)', fontSize: 10, marginTop: 6 }}>
                  {pidEditError}
                </div>
              )}
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6, marginTop: 10,
              }}>
                <button
                  onClick={commit}
                  disabled={!pidEditValue || pidEditValue === investigation.pid}
                  style={{
                    background: (!pidEditValue || pidEditValue === investigation.pid) ? 'var(--bg-elevated)' : 'var(--accent)',
                    color: (!pidEditValue || pidEditValue === investigation.pid) ? 'var(--text-muted)' : '#fff',
                    border: 'none', padding: '5px 12px', borderRadius: 3,
                    cursor: (!pidEditValue || pidEditValue === investigation.pid) ? 'default' : 'pointer',
                    fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
                    letterSpacing: 0.3,
                  }}>pivot ▸</button>
                <span style={{ flex: 1 }} />
                <button
                  onClick={focusCurrent}
                  title="Jump the process tree to the current PID without pivoting"
                  style={{
                    background: 'transparent', border: '1px solid var(--border)',
                    borderRadius: 3, color: 'var(--text-muted)', cursor: 'pointer',
                    fontFamily: 'var(--font-mono)', fontSize: 10.5, padding: '4px 9px',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}>
                  focus tree
                </button>
                <button
                  onClick={() => setPidEditOpen(false)}
                  style={{
                    background: 'transparent', border: '1px solid var(--border)',
                    borderRadius: 3, color: 'var(--text-muted)', cursor: 'pointer',
                    fontFamily: 'var(--font-mono)', fontSize: 10.5, padding: '4px 9px',
                  }}>cancel</button>
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: 9.5, marginTop: 8, lineHeight: 1.5 }}>
                Pivoting reloads the tree for the new PID. Your IOC list, hunt history, flagged hunt events, and past AI analyses are all preserved — click any history entry to re-open it without re-spending tokens.
              </div>
            </div>
          </>,
          document.body,
        )
      })()}
    </div>
  )
}

// ── Tab Strip ────────────────────────────────────────────────────────────
const TAB_DEFS: { id: InvTab; label: string }[] = [
  { id: 'analysis', label: 'analysis' },
  { id: 'iocs', label: 'iocs' },
  { id: 'hunt', label: 'hunt' },
  { id: 'timeline', label: 'timeline' },
  { id: 'ai', label: 'AI analysis' },
]

function TabStrip({ active, onChange }: { active: InvTab; onChange: (t: InvTab) => void }) {
  const iocList = useIocList()
  // Live timeline-event count for the tab badge so the analyst sees how
  // much evidence is collected at a glance. Mirrors the same data
  // sources TimelineTab uses — auto events from flags / incidents /
  // alerts plus analyst-authored notes. Hidden events are excluded so
  // the badge matches what the analyst actually sees on the tab; notes
  // can only be deleted, not hidden, so they always count.
  const tlTree         = useInvTreeData()
  const tlIncidents    = useInvHostIncidents()
  const tlFlaggedNodes = useInvFlaggedNodes()
  const tlFlaggedEvts  = useInvFlaggedEvents()
  const tlFlaggedIncs  = useInvFlaggedIncidents()
  const tlHuntFlags    = useHuntFlags()
  const tlNotes        = useTimelineNotes()
  const tlHidden       = useHiddenTimelineIds()
  const timelineCount = useMemo(() => {
    const auto = buildTimeline(tlTree, tlIncidents, tlFlaggedNodes, tlFlaggedEvts, tlFlaggedIncs, tlHuntFlags)
    const visibleAuto = auto.reduce((n, e) => n + (tlHidden.has(e.id) ? 0 : 1), 0)
    return visibleAuto + tlNotes.length
  }, [tlTree, tlIncidents, tlFlaggedNodes, tlFlaggedEvts, tlFlaggedIncs, tlHuntFlags, tlNotes, tlHidden])
  return (
    <div style={{
      display: 'flex', padding: '0 14px',
      background: 'var(--bg-app)', borderBottom: '1px solid var(--border)',
      fontFamily: 'var(--font-mono)', fontSize: 12, flexShrink: 0,
    }}>
      {TAB_DEFS.map(t => {
        const on = t.id === active
        return (
          <div key={t.id} onClick={() => onChange(t.id)}
            onMouseEnter={e => { if (!on) e.currentTarget.style.color = 'var(--accent)' }}
            onMouseLeave={e => { if (!on) e.currentTarget.style.color = 'var(--text-muted)' }}
            style={{
              padding: '9px 14px', cursor: 'pointer',
              color: on ? 'var(--text)' : 'var(--text-muted)',
              borderBottom: `2px solid ${on ? 'var(--accent)' : 'transparent'}`,
              display: 'flex', alignItems: 'center', gap: 6,
              transition: 'color 120ms, border-color 120ms',
            }}>
            <span style={{ color: on ? 'var(--accent)' : 'transparent' }}>▸</span>
            <span>{t.label}</span>
            {t.id === 'iocs' && iocList.length > 0 && (
              <span style={{
                fontSize: 9, padding: '1px 5px', borderRadius: 2, fontWeight: 700,
                background: 'rgba(255,94,91,0.15)', color: '#FF5E5B',
              }}>{iocList.length}</span>
            )}
            {t.id === 'timeline' && timelineCount > 0 && (
              <span style={{
                fontSize: 9, padding: '1px 5px', borderRadius: 2, fontWeight: 700,
                background: 'rgba(168,85,247,0.18)', color: 'var(--accent)',
              }}>{timelineCount}</span>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ── Tree Toolbar ─────────────────────────────────────────────────────────
function TreeToolbar({ procCount = 0, flaggedCount = 0, eventFlagCount = 0, huntFlagCount = 0, onExpandAll, onCollapseAll, viewMode, onViewModeChange, onFlaggedClick, onFlaggedEventsClick, onHuntFlagClick }: {
  procCount?: number; flaggedCount?: number; eventFlagCount?: number; huntFlagCount?: number
  onExpandAll?: () => void; onCollapseAll?: () => void
  viewMode?: ViewMode; onViewModeChange?: (m: ViewMode) => void
  onFlaggedClick?: () => void
  onFlaggedEventsClick?: () => void
  onHuntFlagClick?: () => void
}) {
  const btn = (label: string, active?: boolean, onClick?: () => void) => (
    <span onClick={onClick}
      onMouseEnter={onClick ? (e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.background = 'rgba(168,85,247,0.15)' }) : undefined}
      onMouseLeave={onClick ? (e => { e.currentTarget.style.borderColor = active ? 'var(--border)' : 'transparent'; e.currentTarget.style.color = active ? 'var(--text)' : 'var(--text-muted)'; e.currentTarget.style.background = active ? 'var(--bg-elevated)' : 'transparent' }) : undefined}
      style={{
        padding: '3px 8px', borderRadius: 2, cursor: onClick ? 'pointer' : 'default', fontSize: 10.5, letterSpacing: 0.3,
        color: active ? 'var(--text)' : 'var(--text-muted)',
        background: active ? 'var(--bg-elevated)' : 'transparent',
        border: `1px solid ${active ? 'var(--border)' : 'transparent'}`,
        transition: 'border-color 100ms, color 100ms, background 100ms',
      }}>{label}</span>
  )
  const flagLegend = [
    { label: 'benign',     color: 'var(--green)'  },
    { label: 'suspicious', color: 'var(--amber)' },
    { label: 'malicious',  color: 'var(--red)'   },
  ]
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px',
      background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)',
      fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0,
    }}>
      <span style={{ color: 'var(--text-muted)', marginRight: 6 }}>view</span>
      <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 2, overflow: 'hidden', marginRight: 4 }}>
        {(['flow', 'table'] as ViewMode[]).map(v => {
          const on = viewMode === v
          return (
            <span key={v}
              onClick={() => { if (!on) onViewModeChange?.(v) }}
              onMouseEnter={e => { if (!on) e.currentTarget.style.color = 'var(--accent)' }}
              onMouseLeave={e => { if (!on) e.currentTarget.style.color = 'var(--text-muted)' }}
              title={v === 'flow' ? 'Graph view — visual lineage, slower with many processes' : 'Table view — flat row list, faster with many processes'}
              style={{
                padding: '3px 9px', cursor: on ? 'default' : 'pointer',
                fontSize: 10.5, letterSpacing: 0.3,
                color: on ? 'var(--text)' : 'var(--text-muted)',
                background: on ? 'var(--bg-elevated)' : 'transparent',
                transition: 'color 100ms, background 100ms',
                userSelect: 'none',
              }}>{v === 'flow' ? '⌘ graph' : '☰ table'}</span>
          )
        })}
      </div>
      {btn('expand all', false, onExpandAll)}
      {btn('collapse all', false, onCollapseAll)}
      <div style={{ width: 1, height: 14, background: 'var(--border)', margin: '0 4px' }} />
      <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>
        {procCount} procs
        {flaggedCount > 0 && (
          <> · <span
            onClick={onFlaggedClick}
            onMouseEnter={e => { e.currentTarget.style.textDecorationColor = 'var(--red)' }}
            onMouseLeave={e => { e.currentTarget.style.textDecorationColor = 'rgba(255,94,91,0.4)' }}
            title="Click to manage flagged processes"
            style={{
              color: 'var(--red)', fontWeight: 600,
              cursor: onFlaggedClick ? 'pointer' : 'default',
              textDecoration: onFlaggedClick ? 'underline' : 'none',
              textDecorationStyle: 'dotted',
              textDecorationColor: 'rgba(255,94,91,0.4)',
              transition: 'text-decoration-color 100ms',
            }}>{flaggedCount} flagged process{flaggedCount === 1 ? '' : 'es'}</span></>
        )}
        {eventFlagCount > 0 && (
          <> · <span
            onClick={onFlaggedEventsClick}
            onMouseEnter={e => { e.currentTarget.style.textDecorationColor = 'var(--amber)' }}
            onMouseLeave={e => { e.currentTarget.style.textDecorationColor = 'rgba(240,179,64,0.4)' }}
            title="Click to manage flagged events"
            style={{
              color: 'var(--amber)', fontWeight: 600,
              cursor: onFlaggedEventsClick ? 'pointer' : 'default',
              textDecoration: onFlaggedEventsClick ? 'underline' : 'none',
              textDecorationStyle: 'dotted',
              textDecorationColor: 'rgba(240,179,64,0.4)',
              transition: 'text-decoration-color 100ms',
            }}>{eventFlagCount} flagged event{eventFlagCount === 1 ? '' : 's'}</span></>
        )}
        {huntFlagCount > 0 && (
          <> · <span
            onClick={onHuntFlagClick}
            onMouseEnter={e => { e.currentTarget.style.textDecorationColor = 'var(--amber)' }}
            onMouseLeave={e => { e.currentTarget.style.textDecorationColor = 'rgba(240,179,64,0.4)' }}
            title="Click to jump to the Hunt tab"
            style={{
              color: 'var(--amber)', fontWeight: 600,
              cursor: onHuntFlagClick ? 'pointer' : 'default',
              textDecoration: onHuntFlagClick ? 'underline' : 'none',
              textDecorationStyle: 'dotted',
              textDecorationColor: 'rgba(240,179,64,0.4)',
              transition: 'text-decoration-color 100ms',
            }}>{huntFlagCount} hunt flagged</span></>
        )}
      </span>
      <div style={{ flex: 1 }} />
      <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>legend:</span>
      {flagLegend.map(f => (
        <span key={f.label} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: 'var(--text-muted)' }}>
          <span style={{ width: 8, height: 8, borderRadius: 2, background: f.color, display: 'inline-block' }} />
          {f.label}
        </span>
      ))}
    </div>
  )
}

// ── Analyse Bar ──────────────────────────────────────────────────────────
function AnalyseBar({
  flaggedCount, eventFlagCount = 0, alertFlagCount = 0,
  focusedEstimate, wideEstimate,
  loading, error, onAnalyse, onClearAll,
}: {
  flaggedCount: number
  eventFlagCount?: number
  alertFlagCount?: number
  focusedEstimate?: CostEstimate | null
  wideEstimate?: CostEstimate | null
  loading?: boolean
  error?: string | null
  onAnalyse?: (scope: AnalyseScope) => void
  // Wipe every flag + dismiss any displayed output. Shown as a red
  // button on the right of this bar so the analyst always has a
  // one-click reset path no matter what's currently in the AI pane.
  onClearAll?: () => void
}) {
  const ready = (flaggedCount + eventFlagCount + alertFlagCount) > 0 && !loading
  // Bar button is purely a "dismiss the currently-displayed AI output"
  // affordance — does NOT touch flags. The parent passes onClearAll
  // only when there's actually something to clear (an output is loaded).
  const canClear = !!onClearAll
  void wideEstimate  // retained on the prop interface but no longer rendered

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', gap: 0,
      background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)',
      fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0,
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, padding: '7px 14px', flexWrap: 'wrap', rowGap: 8, justifyContent: 'flex-start' }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: 2 }}>
          <button
            disabled={!ready}
            onClick={ready ? () => onAnalyse?.('focused') : undefined}
            title="Sends only the flagged processes (and their lineage) to the AI — fastest, cheapest"
            style={{
              background: ready ? 'var(--accent)' : 'var(--bg-elevated)',
              color: ready ? '#fff' : 'var(--text-muted)',
              border: 'none', padding: '4px 12px', borderRadius: 2,
              cursor: ready ? 'pointer' : 'default',
              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600, letterSpacing: 0.4,
              transition: 'background 150ms, color 150ms',
              whiteSpace: 'nowrap',
            }}>AI Analyse Flagged Entities ▸</button>
          {focusedEstimate && (
            <span title={`Est. ${focusedEstimate.inputTokens.toLocaleString()} input + ${focusedEstimate.outputTokens.toLocaleString()} output tokens · Haiku 4.5 pricing`}
              style={{ color: 'var(--text-muted)', fontSize: 9.5, letterSpacing: 0.3 }}>
              est {fmtCost(focusedEstimate.cost)} · {fmtTokens(focusedEstimate.inputTokens)} in
            </span>
          )}
        </div>
        {/* Spacer pushes the reset button to the far right of the bar. */}
        <div style={{ flex: 1 }} />
        {canClear && (
          <button
            onClick={onClearAll}
            title="Dismiss the displayed AI analysis. Flagged items are kept so you can re-run without re-flagging."
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,94,91,0.10)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}
            style={{
              background: 'transparent',
              color: 'var(--red)',
              border: '1px solid var(--red)',
              borderRadius: 3,
              cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
              letterSpacing: 0.3, padding: '4px 12px',
              alignSelf: 'flex-start',
              whiteSpace: 'nowrap',
            }}>⌫ clear</button>
        )}
      </div>
      {error && (
        <div style={{
          padding: '5px 14px 6px',
          background: 'rgba(255,94,91,0.07)',
          borderTop: '1px solid rgba(255,94,91,0.2)',
          color: 'var(--red)', fontSize: 10.5, lineHeight: 1.4,
        }}>{error}</div>
      )}
    </div>
  )
}


// ── Right Tab Strip (top-level inside the right panel) ─────────────────────

type RightTabId = 'telemetry' | 'host'

function RightTabStrip({ active, onChange, analysisResult, analysisLoading }: {
  active: RightTabId
  onChange: (t: RightTabId) => void
  analysisResult: AnalysisResult | null
  analysisLoading: boolean
}) {
  // AI Analysis used to live here as a sub-tab; it's now its own
  // top-level tab. The right pane is split between host and telemetry
  // sub-views only.
  void analysisResult; void analysisLoading
  const tabs: { id: RightTabId; label: string }[] = [
    { id: 'host',      label: 'Host Details' },
    { id: 'telemetry', label: 'Process Telemetry' },
  ]
  return (
    <div style={{
      display: 'flex', background: 'var(--bg-app)',
      borderBottom: '1px solid var(--border)',
      fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0,
    }}>
      {tabs.map(t => {
        const on = t.id === active
        return (
          <div key={t.id} onClick={() => onChange(t.id)}
            onMouseEnter={e => { if (!on) e.currentTarget.style.color = 'var(--accent)' }}
            onMouseLeave={e => { if (!on) e.currentTarget.style.color = 'var(--text-muted)' }}
            style={{
              flex: 1, padding: '7px 14px', cursor: 'pointer', whiteSpace: 'nowrap',
              color: on ? 'var(--text)' : 'var(--text-muted)',
              borderBottom: `2px solid ${on ? 'var(--accent)' : 'transparent'}`,
              transition: 'color 120ms, border-color 120ms',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              fontWeight: on ? 600 : 400,
            }}>
            <span>{t.label}</span>
          </div>
        )
      })}
    </div>
  )
}

// ── Analysis Tab ─────────────────────────────────────────────────────────
// ── Flagged Entities Preview ────────────────────────────────────────────
// Shown in the AI tab when no analysis result is loaded yet — gives the
// analyst a clear, itemised view of exactly what will be sent to Claude
// when they click "AI Analyse Flagged Entities". Renders nothing-flagged
// state when empty, otherwise four sections (processes / events /
// incidents / hunt events) with per-item chips.
function FlaggedEntitiesPreview({
  treeData, flagsRef, flaggedCount,
  rowFlags, rowFlagData,
  incidentFlags, hostIncidents,
  huntFlags,
  analystIocs,
  history,
  onRemoveProcess, onRemoveEvent, onRemoveIncident, onRemoveHunt, onRemoveIoc,
  onRestoreHistory, onRemoveHistory,
}: {
  treeData: InvestigateResponse | null
  flagsRef: React.MutableRefObject<Map<string, FlagStatus>>
  flaggedCount: number
  rowFlags: Map<string, FlagStatus>
  rowFlagData: Map<string, Record<string, unknown>>
  incidentFlags: Map<string, FlagStatus>
  hostIncidents: HostIncident[] | null
  huntFlags: import('../store/huntFlagStore').HuntFlagEntry[]
  analystIocs: IocEntry[]
  history: AnalysisHistoryEntry[]
  onRemoveProcess:  (nodeKey: string) => void
  onRemoveEvent:    (key: string) => void
  onRemoveIncident: (incidentId: string) => void
  onRemoveHunt:     (row: Record<string, unknown>) => void
  onRemoveIoc:      (ioc: string) => void
  onRestoreHistory: (entry: AnalysisHistoryEntry) => void
  onRemoveHistory:  (id: string) => void
}) {
  const FLAG_COLOURS: Record<NonNullable<FlagStatus>, string> = {
    malicious:   '#FF5E5B',
    suspicious:  '#F0B340',
    benign:      '#7DD3A0',
    investigate: '#7AA8FF',
  }
  const SEVERITY_COLOUR: Record<string, string> = {
    critical: '#FF5E5B', high: '#FF5E5B',
    medium: '#F0B340',
    low: '#7AA8FF',
    none: '#7DD3A0',
  }
  // flaggedCount is the parent's process-flag count — depend on it so
  // this component re-renders when the analyst toggles flags via the
  // ref-based update path (flagsRef itself doesn't trigger React).
  void flaggedCount

  const flaggedProcesses = treeData
    ? Array.from(flagsRef.current.entries())
        .filter(([, f]) => f !== null)
        .map(([k, f]) => ({ key: k, flag: f as NonNullable<FlagStatus>, node: treeData.nodes[k] }))
        .filter(p => p.node)
    : []
  const flaggedEvents = Array.from(rowFlags.entries())
    .filter(([, f]) => f !== null)
    .map(([k, f]) => {
      const parts = k.split(':')
      const tab = parts[parts.length - 2] ?? '?'
      return { key: k, flag: f as NonNullable<FlagStatus>, tab, row: rowFlagData.get(k) ?? {} }
    })
  const incidentById = new Map((hostIncidents ?? []).map(i => [i.id, i]))
  const flaggedIncidents = Array.from(incidentFlags.entries())
    .filter(([, f]) => f !== null)
    .map(([id, f]) => ({ id, flag: f as NonNullable<FlagStatus>, incident: incidentById.get(id) }))
  // Hunt store only contains evidence-worthy flags (suspicious / malicious);
  // benign is purely a visual marker, so it's already excluded.
  const flaggedHunt = huntFlags

  const totalCount = flaggedProcesses.length + flaggedEvents.length +
                     flaggedIncidents.length + flaggedHunt.length +
                     analystIocs.length

  function fmtAgo(ms: number): string {
    const d = Date.now() - ms
    if (d < 60_000)     return 'just now'
    if (d < 3_600_000)  return `${Math.floor(d / 60_000)}m ago`
    if (d < 86_400_000) return `${Math.floor(d / 3_600_000)}h ago`
    return `${Math.floor(d / 86_400_000)}d ago`
  }
  const fmtMoney = (n?: number) => n != null ? `$${n.toFixed(4)}` : ''
  const renderHistory = () => {
    if (history.length === 0) return null
    return (
      <div style={{ marginBottom: 16 }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6,
        }}>
          <span style={{ color: 'var(--accent)', fontSize: 11, fontWeight: 600, letterSpacing: 0.4 }}>
            past analyses · {history.length}
          </span>
          <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
            click to re-open · already paid for
          </span>
        </div>
        {history.map(h => (
          <div key={h.id}
            onClick={() => onRestoreHistory(h)}
            title="Re-open this analysis without re-spending tokens"
            style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '6px 10px', marginBottom: 4,
              background: 'var(--bg-app)',
              border: '1px solid var(--border)',
              borderRadius: 4, cursor: 'pointer',
              fontSize: 11, transition: 'border-color 100ms, background 100ms',
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.background = 'rgba(168,85,247,0.06)' }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'var(--bg-app)' }}>
            <span style={{
              color: SEVERITY_COLOUR[h.result.severity] ?? 'var(--text-muted)',
              fontSize: 9.5, fontWeight: 700,
              padding: '1px 6px', borderRadius: 2,
              border: `1px solid ${SEVERITY_COLOUR[h.result.severity] ?? 'var(--text-muted)'}`,
              textTransform: 'uppercase', flexShrink: 0,
            }}>{h.result.severity}</span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ color: 'var(--text)' }}>
                {h.summary} <span style={{ color: 'var(--text-muted)' }}>· {h.scope}</span>
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: 10, marginTop: 1 }}>
                {fmtAgo(h.ranAt)}
                {h.inputTokens != null && <> · {h.inputTokens.toLocaleString()} in / {h.outputTokens?.toLocaleString() ?? '?'} out</>}
                {h.costUsd != null && <> · {fmtMoney(h.costUsd)}</>}
                {h.durationMs != null && <> · {(h.durationMs / 1000).toFixed(1)}s</>}
              </div>
            </div>
            <button
              onClick={(e) => { e.stopPropagation(); onRemoveHistory(h.id) }}
              title="Forget this past analysis"
              style={{
                background: 'transparent', border: '1px solid var(--border)',
                borderRadius: 2, color: 'var(--text-muted)', cursor: 'pointer',
                fontFamily: 'var(--font-mono)', fontSize: 11,
                padding: '0 6px', flexShrink: 0,
              }}
              onMouseEnter={e => { e.currentTarget.style.color = 'var(--red)'; e.currentTarget.style.borderColor = 'var(--red)' }}
              onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}>
              ×
            </button>
          </div>
        ))}
      </div>
    )
  }

  if (totalCount === 0) {
    return (
      <div style={{
        flex: 1, overflow: 'auto', padding: '24px 18px',
        fontFamily: 'var(--font-mono)',
      }}>
        {renderHistory()}
        <div style={{ color: 'var(--accent)', marginBottom: 8, fontSize: 12 }}>▌ no AI analysis yet</div>
        <div style={{ color: 'var(--text-muted)', lineHeight: 1.7, fontSize: 11.5 }}>
          flag processes in the tree, telemetry events, incidents, or hunt
          results — then click{' '}
          <span style={{ color: 'var(--text)' }}>AI Analyse Flagged Entities ▸</span>{' '}
          to run claude analysis. flagged items will be listed here so you can
          see exactly what's being sent.
        </div>
      </div>
    )
  }

  const chip = (flag: NonNullable<FlagStatus>) => (
    <span style={{
      color: FLAG_COLOURS[flag], fontSize: 9.5, fontWeight: 700,
      letterSpacing: 0.4, padding: '2px 6px',
      border: `1px solid ${FLAG_COLOURS[flag]}`, borderRadius: 2,
      textTransform: 'uppercase', flexShrink: 0,
      background: `${FLAG_COLOURS[flag]}1A`,
    }}>{flag}</span>
  )
  const removeBtn = (onClick: () => void, label: string) => (
    <button
      onClick={onClick}
      title={label}
      style={{
        background: 'transparent', border: '1px solid var(--border)',
        borderRadius: 2, color: 'var(--text-muted)', cursor: 'pointer',
        fontFamily: 'var(--font-mono)', fontSize: 11,
        padding: '0 6px', lineHeight: 1.4, flexShrink: 0,
      }}
      onMouseEnter={e => { e.currentTarget.style.color = 'var(--red)'; e.currentTarget.style.borderColor = 'var(--red)' }}
      onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}>
      ×
    </button>
  )
  const itemRowStyle: React.CSSProperties = {
    display: 'flex', alignItems: 'flex-start', gap: 10,
    padding: '6px 0', borderBottom: '1px solid var(--border-soft)',
    fontSize: 11, lineHeight: 1.5,
  }

  // Section header with a per-category "clear" affordance — lets the
  // analyst wipe an entire section without clicking every × in turn.
  const sectionHeader = (label: string, count: number, onClear: () => void) => (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10,
      margin: '14px 0 6px',
    }}>
      <span style={{
        color: 'var(--accent)', fontSize: 11, fontWeight: 600,
        letterSpacing: 0.4,
      }}>{label} · {count}</span>
      <span
        onClick={onClear}
        title={`Remove all ${label}`}
        style={{
          color: 'var(--text-muted)', fontSize: 10, cursor: 'pointer',
          padding: '0 4px', borderRadius: 2,
          textDecoration: 'underline', textDecorationStyle: 'dotted',
          textDecorationColor: 'rgba(255,255,255,0.2)',
        }}
        onMouseEnter={e => { e.currentTarget.style.color = 'var(--red)'; e.currentTarget.style.textDecorationColor = 'var(--red)' }}
        onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.textDecorationColor = 'rgba(255,255,255,0.2)' }}>
        clear
      </span>
    </div>
  )

  function clearAllFlagged() {
    for (const p of flaggedProcesses)  onRemoveProcess(p.key)
    for (const e of flaggedEvents)     onRemoveEvent(e.key)
    for (const i of flaggedIncidents)  onRemoveIncident(i.id)
    for (const h of flaggedHunt)       onRemoveHunt(h.row)
    for (const i of analystIocs)       onRemoveIoc(i.ioc)
  }

  // Verdict-coloured chip for IOC rows. Uses the same palette as the
  // IOCs tab so the analyst sees a consistent malicious/suspicious/
  // clean/unknown signal whether they're on the AI preview or the
  // IOC list itself.
  const IOC_VERDICT_COLOURS: Record<string, string> = {
    malicious:  '#FF5E5B',
    suspicious: '#F0B340',
    clean:      '#7DD3A0',
    unknown:    '#888',
  }
  const verdictChip = (verdict: string) => {
    const c = IOC_VERDICT_COLOURS[verdict] ?? '#888'
    return (
      <span style={{
        color: c, fontSize: 9.5, fontWeight: 700,
        letterSpacing: 0.4, padding: '2px 6px',
        border: `1px solid ${c}`, borderRadius: 2,
        textTransform: 'uppercase', flexShrink: 0,
        background: `${c}1A`,
      }}>{verdict}</span>
    )
  }

  return (
    <div style={{
      flex: 1, overflow: 'auto', padding: '18px',
      fontFamily: 'var(--font-mono)',
    }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4,
      }}>
        <div style={{ color: 'var(--accent)', fontSize: 12 }}>▌ flagged for AI analysis</div>
        <span style={{ flex: 1 }} />
        <span
          onClick={clearAllFlagged}
          title="Remove every flagged item across all categories"
          style={{
            color: 'var(--text-muted)', fontSize: 10.5, cursor: 'pointer',
            padding: '2px 8px', borderRadius: 3,
            border: '1px solid var(--border)',
          }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--red)'; e.currentTarget.style.borderColor = 'var(--red)' }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}>
          clear all
        </span>
      </div>
      <div style={{ color: 'var(--text-muted)', fontSize: 10.5, marginBottom: 10 }}>
        {totalCount} item{totalCount === 1 ? '' : 's'} will be sent to claude on the next analyse.
        benign flags are visual-only and aren't included.
      </div>
      {renderHistory()}

      {flaggedProcesses.length > 0 && (
        <>
          {sectionHeader('processes', flaggedProcesses.length,
            () => flaggedProcesses.forEach(p => onRemoveProcess(p.key)))}
          {flaggedProcesses.map(p => (
            <div key={p.key} style={itemRowStyle}>
              {chip(p.flag)}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ color: 'var(--text)', wordBreak: 'break-all' }}>
                  {p.node.name || '(unknown)'} <span style={{ color: 'var(--text-muted)' }}>· pid {p.node.pid}</span>
                </div>
                {p.node.cmdline && (
                  <div style={{ color: 'var(--text-muted)', fontSize: 10, marginTop: 2, wordBreak: 'break-all' }}>
                    {p.node.cmdline.length > 140 ? p.node.cmdline.slice(0, 140) + '…' : p.node.cmdline}
                  </div>
                )}
              </div>
              {removeBtn(() => onRemoveProcess(p.key), 'Remove process flag')}
            </div>
          ))}
        </>
      )}

      {flaggedEvents.length > 0 && (
        <>
          {sectionHeader('telemetry events', flaggedEvents.length,
            () => flaggedEvents.forEach(e => onRemoveEvent(e.key)))}
          {flaggedEvents.map(e => {
            const r = e.row
            const action = String(r.ActionType ?? '')
            const file   = String(r.FileName ?? r.InitiatingProcessFileName ?? '')
            const remote = r.RemoteIP ? `${r.RemoteIP}${r.RemotePort ? ':' + r.RemotePort : ''}` : ''
            const url    = String(r.RemoteUrl ?? '')
            const key    = String(r.RegistryKey ?? '')
            const summary = [action, file, remote, url, key].filter(Boolean).join(' · ')
            return (
              <div key={e.key} style={itemRowStyle}>
                {chip(e.flag)}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: 'var(--text)', wordBreak: 'break-all' }}>
                    [{e.tab}] {summary || '(empty row)'}
                  </div>
                </div>
                {removeBtn(() => onRemoveEvent(e.key), 'Remove event flag')}
              </div>
            )
          })}
        </>
      )}

      {flaggedIncidents.length > 0 && (
        <>
          {sectionHeader('incidents', flaggedIncidents.length,
            () => flaggedIncidents.forEach(i => onRemoveIncident(i.id)))}
          {flaggedIncidents.map(i => (
            <div key={i.id} style={itemRowStyle}>
              {chip(i.flag)}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ color: 'var(--text)', wordBreak: 'break-all' }}>
                  {i.incident?.display_name ?? `incident ${i.id}`}
                </div>
                {i.incident && (
                  <div style={{ color: 'var(--text-muted)', fontSize: 10, marginTop: 2 }}>
                    {[i.incident.severity, i.incident.status, i.incident.classification].filter(Boolean).join(' · ')}
                  </div>
                )}
              </div>
              {removeBtn(() => onRemoveIncident(i.id), 'Remove incident flag')}
            </div>
          ))}
        </>
      )}

      {flaggedHunt.length > 0 && (
        <>
          {sectionHeader('hunt events', flaggedHunt.length,
            () => flaggedHunt.forEach(h => onRemoveHunt(h.row)))}
          {flaggedHunt.map(h => {
            const r = h.row
            const ts = String(r.Timestamp ?? '').slice(0, 19).replace('T', ' ')
            const action = String(r.ActionType ?? '')
            const file   = String(r.FileName ?? r.InitiatingProcessFileName ?? '')
            const remote = r.RemoteIP ? `${r.RemoteIP}${r.RemotePort ? ':' + r.RemotePort : ''}` : ''
            const url    = String(r.RemoteUrl ?? '')
            const summary = [action, file, remote, url].filter(Boolean).join(' · ')
            return (
              <div key={h.key} style={itemRowStyle}>
                {chip(h.flag)}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: 'var(--text)', wordBreak: 'break-all' }}>
                    {summary || '(empty row)'}
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: 10, marginTop: 2 }}>
                    {ts}
                  </div>
                </div>
                {removeBtn(() => onRemoveHunt(h.row), 'Remove hunt-event flag')}
              </div>
            )
          })}
        </>
      )}

      {analystIocs.length > 0 && (
        <>
          {sectionHeader('iocs', analystIocs.length,
            () => analystIocs.forEach(i => onRemoveIoc(i.ioc)))}
          {analystIocs.map(i => {
            const hits = (i.malicious ?? 0) + (i.suspicious ?? 0)
            const detailParts = [
              i.total ? `vt ${hits}/${i.total}` : '',
              i.country ?? '',
              i.as_owner ? `AS ${i.as_owner}` : '',
              i.name ?? '',
            ].filter(Boolean)
            return (
              <div key={i.ioc} style={itemRowStyle}>
                {verdictChip(i.verdict)}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: 'var(--text)', wordBreak: 'break-all' }}>
                    [{i.iocType}] {i.ioc}
                  </div>
                  {detailParts.length > 0 && (
                    <div style={{ color: 'var(--text-muted)', fontSize: 10, marginTop: 2 }}>
                      {detailParts.join(' · ')}
                    </div>
                  )}
                </div>
                {removeBtn(() => onRemoveIoc(i.ioc), 'Remove IOC from the list')}
              </div>
            )
          })}
        </>
      )}
    </div>
  )
}

function AnalysisTab({ inv, deviceInfo, onReset, onPivot, onHostnameResolved, cachedData, onDataCached, focalPidClickRef, showHostTabRef, onShowHuntTab, aiOnly = false }: {
  inv: Investigation
  deviceInfo: DeviceInfoData | null
  onReset: () => void
  onPivot: (pid: number, timestamp: string | null) => void
  onHostnameResolved: (hostname: string, pid: number) => void
  cachedData: InvestigateResponse | null
  onDataCached: (d: InvestigateResponse | null) => void
  focalPidClickRef: React.MutableRefObject<((pid: number) => void) | null>
  showHostTabRef:   React.MutableRefObject<(() => void) | null>
  onShowHuntTab?:   () => void
  // When true, the analysis tab renders only the AI panel (no tree on the
  // left, no right sub-tab strip). Used by the top-level 'AI analysis'
  // tab so the same component instance can serve both the embedded and
  // standalone surfaces without duplicating state.
  aiOnly?:          boolean
}) {
  const [selectedNode, setSelectedNode] = useState<ProcessNodeData | null>(null)
  const [treeData, setTreeData] = useState<InvestigateResponse | null>(cachedData)
  const [rightWidth, setRightWidth] = useState(640)
  const [rightCollapsed, setRightCollapsed] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [flaggedCount, setFlaggedCount] = useState(0)
  // Mirror of the tree's flags Map at the AnalysisTab level so the right-panel
  // Process Telemetry header can colour itself based on the selected node's flag.
  const [processFlags, setProcessFlags] = useState<Map<string, FlagStatus>>(new Map())
  // Telemetry row flags lifted here so they survive switching right-panel tabs.
  const [rowFlags, setRowFlags] = useState<Map<string, FlagStatus>>(new Map())
  // Parallel cache of the actual row data for every flagged telemetry row,
  // keyed identically to rowFlags. Lets the AI analyse call ship the full row
  // payload even when the TelemetryPanel is unmounted (analyst is on AI tab).
  const [rowFlagData, setRowFlagData] = useState<Map<string, Record<string, unknown>>>(() => new Map())
  function handleRowFlagSet(key: string, flag: FlagStatus, row: Record<string, unknown> | null) {
    setRowFlagData(prev => {
      const next = new Map(prev)
      if (flag === null || !row) next.delete(key)
      else next.set(key, row)
      return next
    })
  }
  const eventFlagCount = useMemo(() => {
    let count = 0
    for (const f of rowFlags.values()) {
      if (f === 'malicious' || f === 'suspicious') count++
    }
    return count
  }, [rowFlags])

  // Hunt-tab flagged events live in a module-level store so the analyst
  // can mark events from a hunt query and have them feed straight into
  // the AI Analyse payload here.
  const huntFlags = useHuntFlags()
  // IOC list — already enriched with VT verdicts and Microsoft / Internal
  // tagging by the time we get here. Folded into the analyse payload so
  // Claude treats analyst-confirmed indicators as ground truth.
  const analystIocs = useIocList()
  // Past completed analyses for this investigation — lets the analyst
  // dismiss an output and recall it later without burning tokens again.
  const analysisHistoryEntries = useAnalysisHistory()
  const huntFlagCount = useMemo(() => {
    let count = 0
    for (const e of huntFlags) {
      if (e.flag === 'malicious' || e.flag === 'suspicious') count++
    }
    return count
  }, [huntFlags])
  const [searchTerm, setSearchTerm] = useState('')
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null)
  const [analysisLoading, setAnalysisLoading] = useState(false)
  const [analysisError, setAnalysisError] = useState<string | null>(null)
  const [rightTab, setRightTab] = useState<RightTabId>('host')
  const [viewMode, setViewMode] = useState<ViewMode>(() => loadViewMode())
  // Cached network-adapter snapshot. Lives at this level so it survives both
  // sub-tab switches inside Host Details and right-panel tab switches —
  // fetched once per investigation. Reset when hostname changes (below).
  const [networkAdapters, setNetworkAdapters] = useState<NetworkAdapter[] | null>(null)
  const [hostIncidents, setHostIncidents] = useState<HostIncident[] | null>(null)
  const [incidentFlags, setIncidentFlags] = useState<Map<string, FlagStatus>>(() => new Map())

  // Mirror investigation data into the module-level store so cross-tab
  // consumers (TimelineTab, future Report tab) can read it without
  // having to lift state up to InvestigationShell. AnalysisTab remains
  // the owner of the loading lifecycle.
  useEffect(() => { setInvTreeData(treeData) }, [treeData])
  useEffect(() => { setInvHostIncidents(hostIncidents) }, [hostIncidents])
  useEffect(() => { setInvHostname(inv.hostname) }, [inv.hostname])
  // Mirror flag state into the store too, so TimelineTab can surface
  // analyst-flagged items as their own category. Process flags live in
  // a ref; we re-snapshot them whenever flaggedCount bumps.
  useEffect(() => {
    setInvFlaggedNodes(
      Array.from(flagsRef.current.entries())
        .filter(([, f]) => f !== null)
        .map(([node_key, f]) => ({ node_key, flag: f as NonNullable<FlagStatus> }))
    )
  }, [flaggedCount])
  useEffect(() => {
    setInvFlaggedEvents(
      Array.from(rowFlags.entries())
        .filter(([, f]) => f !== null)
        .map(([key, f]) => ({
          key,
          flag: f as NonNullable<FlagStatus>,
          row: rowFlagData.get(key) ?? {},
          tab: key.split(':').slice(-2)[0] ?? '?',
        }))
    )
  }, [rowFlags, rowFlagData])
  useEffect(() => {
    setInvFlaggedIncidents(
      Array.from(incidentFlags.entries())
        .filter(([, f]) => f !== null)
        .map(([incident_id, f]) => ({ incident_id, flag: f as NonNullable<FlagStatus> }))
    )
  }, [incidentFlags])
  useEffect(() => {
    setNetworkAdapters(null)
    setHostIncidents(null)
    setIncidentFlags(new Map())
  }, [inv.hostname])

  // Pre-fetch every Host Details data source on investigation arrival so
  // every sub-tab is ready instantly when the analyst clicks in. Each
  // fetcher only runs if its cache slot is still null. Failures feed the
  // degradation banner — the investigation itself stays usable.
  useEffect(() => {
    if (!inv.hostname) return
    const host = inv.hostname
    const loadAdapters = () => {
      fetchNetworkAdapters(host)
        .then(res => {
          if (res.ok) {
            setNetworkAdapters(res.adapters || [])
            clearDegraded('network-adapters')
          } else {
            setDegraded({
              source: 'network-adapters', label: 'network adapters',
              message: friendlyError(res.error || 'No adapter data returned.'),
              retry: loadAdapters,
            })
          }
        })
        .catch(e => setDegraded({
          source: 'network-adapters', label: 'network adapters',
          message: friendlyError(String(e)),
          retry: loadAdapters,
        }))
    }
    const loadIncidents = () => {
      fetchHostIncidents(host)
        .then(res => {
          if (res.ok) {
            setHostIncidents(res.incidents || [])
            clearDegraded('host-incidents')
          } else {
            setDegraded({
              source: 'host-incidents', label: 'host incidents',
              message: friendlyError(res.error || 'No incident data returned.'),
              retry: loadIncidents,
            })
          }
        })
        .catch(e => setDegraded({
          source: 'host-incidents', label: 'host incidents',
          message: friendlyError(String(e)),
          retry: loadIncidents,
        }))
    }
    if (networkAdapters === null) loadAdapters()
    if (hostIncidents   === null) loadIncidents()
  // We deliberately only fire when hostname changes; cache values are checked
  // inside so a manual reset triggers refetch via the reset effect above.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inv.hostname])

  const setIncidentFlag = (incidentId: string, flag: FlagStatus) => {
    setIncidentFlags(prev => {
      const next = new Map(prev)
      if (flag === null) next.delete(incidentId)
      else next.set(incidentId, flag)
      return next
    })
  }

  // (AI analysis is now a top-level tab, no longer a right-pane sub-tab,
  // so the old auto-switch-to-AI effects on analysisLoading / analysisResult
  // have been removed.)

  // When the analyst clicks a process in the tree from any non-telemetry tab,
  // jump to Process Telemetry so they see the events for that process. PID-link
  // clicks inside the AI panel set the skip flag and stay on the AI tab.
  useEffect(() => {
    if (skipTabSwitchRef.current) {
      skipTabSwitchRef.current = false
      return
    }
    if (selectedNode) {
      setRightTab(prev => prev === 'telemetry' ? prev : 'telemetry')
    }
  }, [selectedNode])

  const collapseAllRef  = useRef<(() => void) | null>(null)
  const expandAllRef    = useRef<(() => void) | null>(null)
  const matchNavPrevRef = useRef<(() => void) | null>(null)
  const matchNavNextRef = useRef<(() => void) | null>(null)
  const flagsRef        = useRef<Map<string, FlagStatus>>(new Map())
  const prefetchTelemetryRef = useRef<((nodes: ProcessNodeData[]) => void) | null>(null)
  const revealNodeRef        = useRef<((nodeKey: string) => void) | null>(null)
  const skipTabSwitchRef     = useRef(false)
  // Shared between the graph and table views so switching preserves which
  // nodes the analyst has expanded / which are visible. Reset when the
  // investigation's cached data is cleared (new investigation / time-window).
  const visibleKeysRef  = useRef<Set<string>>(new Set())
  const expandedKeysRef = useRef<Set<string>>(new Set())
  // The currently-mounted view (graph or table) writes its flag-cycle handler
  // into this ref so TelemetryPanel can flag the selected process directly.
  const flagSetterRef   = useRef<((nodeKey: string) => void) | null>(null)
  // Direct flag setter (used by the "manage flagged" popup to delete or
  // change flags without cycling).
  const flagSetExplicitRef = useRef<((nodeKey: string, flag: FlagStatus) => void) | null>(null)
  const [showFlaggedPopup, setShowFlaggedPopup] = useState(false)
  const [showFlaggedEventsPopup, setShowFlaggedEventsPopup] = useState(false)
  // Lets the manage-flagged-events popup land the analyst on the right
  // sub-tab inside Process Telemetry after they click "examine".
  const telemetryActiveTabRef = useRef<((tab: 'process' | 'network' | 'files' | 'registry' | 'dlls' | 'scripts') => void) | null>(null)

  // When the parent clears the cache (time window change), reset local state too
  useEffect(() => {
    if (!cachedData) {
      setTreeData(null)
      setSelectedNode(null)
      setFlaggedCount(0)
      setRowFlags(new Map())
      setRowFlagData(new Map())
      setAnalysisResult(null)
      setAnalysisError(null)
      // Drop view-shared state so the next investigation starts fresh
      visibleKeysRef.current  = new Set()
      expandedKeysRef.current = new Set()
    }
  }, [cachedData])

  const procCount = treeData ? Object.keys(treeData.nodes).length : 0
  const focalPid = inv.pid ? parseInt(inv.pid, 10) : 0

  function handleDataLoaded(d: InvestigateResponse | null) {
    setTreeData(d)
    onDataCached(d)
  }

  const lastScopeRef = useRef<AnalyseScope>('focused')

  function handlePidClick(pid: number) {
    if (!treeData) return
    // Multiple instances of the same PID can exist in a tree (PID reuse across
    // process lifetimes). Prefer one that's flagged or focal, else the most
    // recent by timestamp, else any match.
    const matches = Object.values(treeData.nodes).filter(n => n.pid === pid)
    if (matches.length === 0) return
    const flagged = matches.find(n => flagsRef.current.get(n.node_key))
    const focal   = matches.find(n => n.is_focal)
    const newest  = [...matches].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))[0]
    const target  = flagged ?? focal ?? newest
    skipTabSwitchRef.current = true  // stay on the AI tab; don't jump to telemetry
    revealNodeRef.current?.(target.node_key)
  }

  // Latest-handler ref so the AppBar's focal-pid click hits the current
  // handlePidClick closure (which depends on the current treeData).
  const handlePidClickRef = useRef(handlePidClick)
  handlePidClickRef.current = handlePidClick

  useEffect(() => {
    focalPidClickRef.current = (pid: number) => handlePidClickRef.current(pid)
    return () => { focalPidClickRef.current = null }
  }, [focalPidClickRef])

  useEffect(() => {
    showHostTabRef.current = () => setRightTab('host')
    return () => { showHostTabRef.current = null }
  }, [showHostTabRef])

  // Build the analyse payload for a given scope. Used by both handleAnalyse
  // (the actual request) and the live cost-estimator below. Keeping a single
  // builder ensures the preview cost matches what's actually sent.
  function buildAnalysePayload(scope: AnalyseScope): import('../api/analyse').AnalysePayload | null {
    if (!treeData) return null

    const flaggedNodes = Array.from(flagsRef.current.entries())
      .filter(([, f]) => f !== null)
      .map(([node_key, flag]) => ({ node_key, flag: flag as string }))

    // Focused-mode prune: anchor = flagged processes + flagged-event parents +
    // focal fallback. Keep anchor + immediate parent + immediate children only.
    let nodesToSend = treeData.nodes
    if (scope === 'focused') {
      const anchorKeys = new Set<string>()
      for (const f of flaggedNodes) anchorKeys.add(f.node_key)
      for (const k of rowFlags.keys()) {
        const parts = k.split(':')
        const nk = parts.slice(0, -2).join(':')
        if (nk) anchorKeys.add(nk)
      }
      if (anchorKeys.size === 0) {
        for (const [k, n] of Object.entries(treeData.nodes)) {
          if (n.is_focal) { anchorKeys.add(k); break }
        }
      }
      if (anchorKeys.size === 0 && treeData.ancestry_chain.length > 0) {
        const last = treeData.ancestry_chain[treeData.ancestry_chain.length - 1]
        if (treeData.nodes[last]) anchorKeys.add(last)
      }
      if (anchorKeys.size > 0) {
        const keep = new Set<string>()
        for (const ak of anchorKeys) {
          const node = treeData.nodes[ak]
          if (!node) continue
          keep.add(ak)
          const parentKey = node.parent_node_key
          if (parentKey && treeData.nodes[parentKey]) keep.add(parentKey)
          for (const ck of (node.child_node_keys || [])) {
            if (treeData.nodes[ck]) keep.add(ck)
          }
        }
        nodesToSend = {}
        for (const k of keep) {
          const original = treeData.nodes[k]
          nodesToSend[k] = {
            ...original,
            child_node_keys: (original.child_node_keys || []).filter(ck => keep.has(ck)),
          }
        }
      }
    }

    const flaggedEvents = Array.from(rowFlags.entries())
      .filter(([, f]) => f !== null)
      .map(([key, flag]) => {
        const parts = key.split(':')
        const node_key = parts.slice(0, -2).join(':')
        const tab = parts[parts.length - 2]
        const row_idx = parseInt(parts[parts.length - 1], 10)
        return {
          node_key, tab,
          row_idx: isNaN(row_idx) ? -1 : row_idx,
          flag: flag as string,
          row: rowFlagData.get(key) ?? {},
        }
      })
    // Append hunt-tab flagged events. Hunt rows aren't bound to a tree
    // node, so we synthesise a node_key and tag tab='hunt' — the backend
    // claude prompt renders these with a hunt-specific summary.
    huntFlags.forEach((e, i) => {
      flaggedEvents.push({
        node_key: `hunt:${i}`,
        tab: 'hunt',
        row_idx: i,
        flag: e.flag as string,
        row: e.row,
      })
    })

    const incidentById = new Map((hostIncidents ?? []).map(i => [i.id, i]))
    const flaggedIncidentsPayload = Array.from(incidentFlags.entries())
      .filter(([, f]) => f !== null)
      .map(([incident_id, flag]) => {
        const i = incidentById.get(incident_id)
        return {
          incident_id,
          display_name:      i?.display_name ?? '',
          severity:          i?.severity ?? '',
          status:            i?.status ?? '',
          classification:    i?.classification ?? '',
          determination:     i?.determination ?? '',
          description:       i?.description ?? '',
          assigned_to:       i?.assigned_to ?? '',
          created:           i?.created ?? '',
          last_update:       i?.last_update ?? '',
          host_earliest_seen: i?.host_earliest_seen ?? '',
          host_latest_seen:   i?.host_latest_seen ?? '',
          host_alerts: (i?.host_alerts ?? []).map(a => ({
            id: a.id, title: a.title, severity: a.severity, status: a.status,
            category: a.category, detection_source: a.detection_source,
            mitre_techniques: a.mitre_techniques,
            threat_display_name: a.threat_display_name, threat_family: a.threat_family,
            first_activity: a.first_activity, last_activity: a.last_activity,
          })),
          comments: (i?.comments ?? []).map(c => ({
            body: c.body, created_by: c.created_by, created_at: c.created_at,
          })),
          flag: flag as string,
        }
      })

    return {
      investigation_id: inv.id,
      hostname: inv.hostname,
      focal_pid: focalPid,
      focal_time_iso: inv.focalTimeIso,
      time_window: inv.rawTimeWindow,
      flagged_nodes: flaggedNodes,
      all_nodes: nodesToSend,
      ancestry_chain: treeData.ancestry_chain,
      device_info: deviceInfo,
      scope,
      flagged_events: flaggedEvents,
      flagged_incidents: flaggedIncidentsPayload,
      flagged_iocs: analystIocs.map(e => ({
        ioc: e.ioc,
        ioc_type: e.iocType,
        verdict: e.verdict,
        name:       e.name       ?? null,
        country:    e.country    ?? null,
        as_owner:   e.as_owner   ?? null,
        asn:        e.asn,
        total:      e.total,
        malicious:  e.malicious,
        suspicious: e.suspicious,
        link:       e.link,
      })),
    }
  }

  // Live cost estimates for both scopes. Recomputes whenever the inputs that
  // shape the payload change — flag counts, incident cache, row-flag data, etc.
  const focusedEstimate = useMemo<CostEstimate | null>(() => {
    const p = buildAnalysePayload('focused')
    return p ? estimatePayloadCost(p) : null
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [treeData, flaggedCount, rowFlags, rowFlagData, incidentFlags, hostIncidents, deviceInfo, inv.id, inv.hostname, inv.focalTimeIso, inv.rawTimeWindow, focalPid, huntFlags, analystIocs])
  const wideEstimate = useMemo<CostEstimate | null>(() => {
    const p = buildAnalysePayload('wide')
    return p ? estimatePayloadCost(p) : null
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [treeData, flaggedCount, rowFlags, rowFlagData, incidentFlags, hostIncidents, deviceInfo, inv.id, inv.hostname, inv.focalTimeIso, inv.rawTimeWindow, focalPid, huntFlags, analystIocs])

  async function handleAnalyse(scope: AnalyseScope) {
    if (!treeData) return
    const payload = buildAnalysePayload(scope)
    if (!payload) return
    lastScopeRef.current = scope
    setAnalysisLoading(true)
    setAnalysisError(null)
    setAnalysisResult(null)

    // Pre-warm per-process telemetry cache for every flagged node.
    const flaggedNodeData = payload.flagged_nodes
      .map(f => treeData.nodes[f.node_key])
      .filter((n): n is ProcessNodeData => !!n)
    prefetchTelemetryRef.current?.(flaggedNodeData)

    try {
      const res = await runAnalysis(payload)
      if (!res.ok) {
        setAnalysisError(friendlyError(res.error_message ?? res.error ?? 'Analysis failed.'))
      } else {
        const analysis = res as AnalysisResult
        setAnalysisResult(analysis)
        // Record in history so the analyst can re-open dismissed results
        // without re-spending tokens. Summary is a quick payload-shape
        // recap; token usage / cost come straight from the response.
        const parts: string[] = []
        if (payload.flagged_nodes.length)     parts.push(`${payload.flagged_nodes.length} proc${payload.flagged_nodes.length === 1 ? '' : 's'}`)
        if (payload.flagged_events.length)    parts.push(`${payload.flagged_events.length} event${payload.flagged_events.length === 1 ? '' : 's'}`)
        if (payload.flagged_incidents.length) parts.push(`${payload.flagged_incidents.length} incident${payload.flagged_incidents.length === 1 ? '' : 's'}`)
        if (payload.flagged_iocs.length)      parts.push(`${payload.flagged_iocs.length} IOC${payload.flagged_iocs.length === 1 ? '' : 's'}`)
        recordAnalysis({
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          ranAt: Date.now(),
          scope,
          summary: parts.join(' · ') || `${scope} analysis`,
          inputTokens:  analysis.token_usage?.input_tokens,
          outputTokens: analysis.token_usage?.output_tokens,
          costUsd:      analysis.token_usage?.cost_usd,
          durationMs:   analysis.token_usage?.duration_ms,
          result:       analysis,
        })
      }
    } catch (e) {
      setAnalysisError(friendlyError(e))
    } finally {
      setAnalysisLoading(false)
    }
  }

  function startDrag(e: React.MouseEvent) {
    e.preventDefault()
    setDragging(true)
    const startX = e.clientX
    const startWidth = rightCollapsed ? 0 : rightWidth

    function onMove(ev: MouseEvent) {
      const newWidth = startWidth + (startX - ev.clientX)
      if (newWidth < 80) {
        setRightCollapsed(true)
        setRightWidth(640)
      } else {
        setRightCollapsed(false)
        setRightWidth(Math.min(window.innerWidth - 220, newWidth))
      }
    }
    function onUp() {
      setDragging(false)
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }


  return (
    <div style={{ flex: 1, display: 'flex', minHeight: 0, minWidth: 0 }}>
      {/* Left: tree — hidden when the AI analysis tab is showing this
          component as the standalone top-level surface. */}
      <div style={{
        flex: 1, flexDirection: 'column', minWidth: 0,
        display: aiOnly ? 'none' : 'flex',
      }}>
        <TreeToolbar
          procCount={procCount}
          flaggedCount={flaggedCount}
          eventFlagCount={eventFlagCount}
          huntFlagCount={huntFlags.length}
          onExpandAll={() => expandAllRef.current?.()}
          onCollapseAll={() => collapseAllRef.current?.()}
          viewMode={viewMode}
          onViewModeChange={v => { setViewMode(v); saveViewMode(v) }}
          onFlaggedClick={() => setShowFlaggedPopup(true)}
          onFlaggedEventsClick={() => setShowFlaggedEventsPopup(true)}
          onHuntFlagClick={onShowHuntTab}
        />
        {/* overflow:hidden here is what actually prevents the table's
            internal 1500-px fit-content grid from propagating its
            min-content size up the flex chain. minWidth:0 alone wasn't
            enough on its own with deeply-nested fit-content/grid
            children. */}
        <div style={{ flex: 1, minHeight: 0, minWidth: 0, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          {viewMode === 'flow' ? (
            <ProcessTree
              hostname={inv.hostname}
              focalPid={focalPid}
              focalTimeIso={inv.focalTimeIso}
              rawTimeWindow={inv.rawTimeWindow}
              alertId={inv.mode === 'alert-id' ? inv.alertId : null}
              onSelect={setSelectedNode}
              onDataLoaded={handleDataLoaded}
              onReset={onReset}
              initialData={cachedData}
              collapseAllRef={collapseAllRef}
              expandAllRef={expandAllRef}
              matchNavPrevRef={matchNavPrevRef}
              matchNavNextRef={matchNavNextRef}
              searchTerm={searchTerm}
              onSearchChange={setSearchTerm}
              onFlagsChange={setFlaggedCount}
              onFlagsMapChange={setProcessFlags}
              flagSetterRef={flagSetterRef}
              flagSetExplicitRef={flagSetExplicitRef}
              flagsRef={flagsRef}
              revealNodeRef={revealNodeRef}
              visibleKeysRef={visibleKeysRef}
              expandedKeysRef={expandedKeysRef}
              onPivot={onPivot}
              onHostnameResolved={onHostnameResolved}
            />
          ) : (
            <ProcessTreeTable
              hostname={inv.hostname}
              focalPid={focalPid}
              focalTimeIso={inv.focalTimeIso}
              rawTimeWindow={inv.rawTimeWindow}
              alertId={inv.mode === 'alert-id' ? inv.alertId : null}
              onSelect={setSelectedNode}
              onDataLoaded={handleDataLoaded}
              onReset={onReset}
              initialData={cachedData}
              collapseAllRef={collapseAllRef}
              expandAllRef={expandAllRef}
              matchNavPrevRef={matchNavPrevRef}
              matchNavNextRef={matchNavNextRef}
              searchTerm={searchTerm}
              onSearchChange={setSearchTerm}
              onFlagsChange={setFlaggedCount}
              onFlagsMapChange={setProcessFlags}
              flagSetterRef={flagSetterRef}
              flagSetExplicitRef={flagSetExplicitRef}
              flagsRef={flagsRef}
              revealNodeRef={revealNodeRef}
              visibleKeysRef={visibleKeysRef}
              expandedKeysRef={expandedKeysRef}
              onPivot={onPivot}
              onHostnameResolved={onHostnameResolved}
            />
          )}
        </div>
      </div>

      {/* Resize handle — wider 22px transparent hit target, 5px visible
          coloured line, and an explicit click-to-toggle chevron balloon
          in the middle for analysts who don't want to drag precisely.
          Drag = resize, single click on chevron = expand/collapse,
          double-click anywhere on the handle = same toggle. */}
      <div
        onMouseDown={startDrag}
        onDoubleClick={() => setRightCollapsed(c => !c)}
        title="Drag to resize · click chevron to toggle"
        style={{
          width: 22, flexShrink: 0, cursor: 'col-resize', userSelect: 'none',
          display: aiOnly ? 'none' : 'flex',
          alignItems: 'stretch', justifyContent: 'center',
          background: 'transparent', position: 'relative',
        }}
        onMouseEnter={e => {
          const line = e.currentTarget.children[0] as HTMLElement | undefined
          if (line) line.style.background = 'var(--accent)'
        }}
        onMouseLeave={e => {
          const line = e.currentTarget.children[0] as HTMLElement | undefined
          if (line) line.style.background = 'var(--border)'
        }}
      >
        {/* The actual coloured line — uninterrupted full height */}
        <div style={{
          width: 5, flexShrink: 0,
          background: 'var(--border)',
          transition: 'background 150ms',
        }} />
        {/* Click-to-toggle chevron. stopPropagation on mousedown so the
            drag handler ignores it; the click just flips collapsed. */}
        <button
          onMouseDown={e => e.stopPropagation()}
          onClick={e => { e.stopPropagation(); setRightCollapsed(c => !c) }}
          title={rightCollapsed ? 'Expand right panel' : 'Collapse right panel'}
          style={{
            position: 'absolute',
            top: '50%', left: '50%',
            transform: 'translate(-50%, -50%)',
            width: 20, height: 40,
            background: 'var(--bg-elevated)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1,
            padding: 0,
            transition: 'border-color 150ms, color 150ms',
          }}
          onMouseEnter={e => {
            e.currentTarget.style.borderColor = 'var(--accent)'
            e.currentTarget.style.color = 'var(--accent)'
          }}
          onMouseLeave={e => {
            e.currentTarget.style.borderColor = 'var(--border)'
            e.currentTarget.style.color = 'var(--text-muted)'
          }}>
          {rightCollapsed ? '‹' : '›'}
        </button>
        {/* (legacy grip dots removed — chevron above is the affordance now) */}
        <div style={{ display: 'none' }}>{[0, 1, 2].map(i => (
            <span key={i} />
          ))}
        </div>
      </div>

      {/* Right: analyse bar + findings/telemetry. In aiOnly mode this
          panel becomes the full content of the standalone 'AI analysis'
          top-level tab, so it stretches to fill the width and the right
          sub-tab strip is hidden (rightTab is forced to 'ai' below). */}
      <div style={{
        width: aiOnly ? 'auto' : (rightCollapsed ? 0 : rightWidth),
        flex: aiOnly ? 1 : undefined,
        overflow: 'hidden',
        display: 'flex', flexDirection: 'column',
        alignSelf: 'stretch',
        flexShrink: 0,
        transition: dragging ? 'none' : 'width 150ms',
      }}>
        {!aiOnly && (
          <RightTabStrip
            active={rightTab}
            onChange={setRightTab}
            analysisResult={analysisResult}
            analysisLoading={analysisLoading}
          />
        )}
        <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
          {aiOnly ? (
            <>
              <AnalyseBar
                flaggedCount={flaggedCount}
                eventFlagCount={eventFlagCount + huntFlagCount + analystIocs.length}
                alertFlagCount={Array.from(incidentFlags.values()).filter(f => f !== null).length}
                focusedEstimate={focusedEstimate}
                wideEstimate={wideEstimate}
                loading={analysisLoading}
                error={analysisError}
                onAnalyse={handleAnalyse}
                onClearAll={analysisResult ? () => setAnalysisResult(null) : undefined}
              />
              <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
                {analysisLoading ? (
                  <div style={{
                    flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
                    flexDirection: 'column', gap: 12,
                    color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11,
                  }}>
                    <div style={{
                      width: 18, height: 18, borderRadius: '50%',
                      border: '2px solid var(--border)',
                      borderTopColor: 'var(--accent)',
                      animation: 'spin 0.8s linear infinite',
                    }} />
                    <span>running analysis</span>
                  </div>
                ) : analysisResult ? (
                  <FindingsPanel
                    result={analysisResult}
                    onBack={() => setAnalysisResult(null)}
                    onReanalyse={() => { setAnalysisResult(null); handleAnalyse(lastScopeRef.current) }}
                    onPidClick={handlePidClick}
                  />
                ) : (
                  <FlaggedEntitiesPreview
                    treeData={treeData}
                    flagsRef={flagsRef}
                    flaggedCount={flaggedCount}
                    rowFlags={rowFlags}
                    rowFlagData={rowFlagData}
                    incidentFlags={incidentFlags}
                    hostIncidents={hostIncidents}
                    huntFlags={huntFlags}
                    analystIocs={analystIocs}
                    history={analysisHistoryEntries}
                    onRestoreHistory={(entry) => setAnalysisResult(entry.result)}
                    onRemoveHistory={(id) => removeAnalysisEntry(id)}
                    onRemoveProcess={(nk) => {
                      flagsRef.current.delete(nk)
                      let count = 0
                      for (const f of flagsRef.current.values()) if (f) count++
                      setFlaggedCount(count)
                    }}
                    onRemoveEvent={(k) => {
                      setRowFlags(prev => {
                        const n = new Map(prev)
                        n.delete(k)
                        return n
                      })
                      handleRowFlagSet(k, null, null)
                    }}
                    onRemoveIncident={(id) => setIncidentFlag(id, null)}
                    onRemoveHunt={(row) => setHuntFlag(row, null)}
                    onRemoveIoc={(ioc) => removeIoc(ioc)}
                  />
                )}
              </div>
            </>
          ) : rightTab === 'host' ? (
            <HostDetailView
              hostname={inv.hostname}
              deviceInfo={deviceInfo}
              cachedAdapters={networkAdapters}
              onAdaptersLoaded={setNetworkAdapters}
              cachedIncidents={hostIncidents}
              onIncidentsLoaded={setHostIncidents}
              incidentFlags={incidentFlags}
              onIncidentFlag={setIncidentFlag}
            />
          ) : (
            <TelemetryPanel
              node={selectedNode}
              inv={inv}
              prefetchRef={prefetchTelemetryRef}
              rowFlags={rowFlags}
              setRowFlags={setRowFlags}
              onRowFlagSet={handleRowFlagSet}
              searchTerm={searchTerm}
              processFlags={processFlags}
              onCycleProcessFlag={key => flagSetterRef.current?.(key)}
              activeTabSetterRef={telemetryActiveTabRef}
            />
          )}
        </div>
      </div>

      {/* Manage-flagged popup — opened from the TreeToolbar's "N flagged
          processes" link. Lists every flag with cycle / delete controls. */}
      {showFlaggedPopup && (
        <FlaggedProcessesPopup
          flags={processFlags}
          nodes={treeData?.nodes ?? {}}
          onSetFlag={(key, flag) => flagSetExplicitRef.current?.(key, flag)}
          onExamine={key => {
            revealNodeRef.current?.(key)  // reveal + select + centre/scroll
            setRightTab('telemetry')      // open Process Telemetry
            setShowFlaggedPopup(false)    // dismiss the popup
          }}
          onClose={() => setShowFlaggedPopup(false)}
        />
      )}

      {/* Manage-flagged-events popup — opened from "N flagged events". */}
      {showFlaggedEventsPopup && (
        <FlaggedEventsPopup
          rowFlags={rowFlags}
          nodes={treeData?.nodes ?? {}}
          onSetFlag={(key, flag) => {
            setRowFlags(prev => {
              const next = new Map(prev)
              if (flag === null) next.delete(key)
              else next.set(key, flag)
              return next
            })
          }}
          onExamine={(nodeKey, tab) => {
            revealNodeRef.current?.(nodeKey)
            setRightTab('telemetry')
            // Wait a tick so TelemetryPanel is mounted before we switch its sub-tab.
            requestAnimationFrame(() => telemetryActiveTabRef.current?.(tab))
            setShowFlaggedEventsPopup(false)
          }}
          onClose={() => setShowFlaggedEventsPopup(false)}
        />
      )}
    </div>
  )
}

// ── Investigation Shell ──────────────────────────────────────────────────
function InvestigationShell({ inv, deviceInfo, onReset, onPivot, onHostnameResolved, cachedData, onDataCached, focalPidClickRef, showHostTabRef }: {
  inv: Investigation
  deviceInfo: DeviceInfoData | null
  onReset: () => void
  onPivot: (pid: number, timestamp: string | null) => void
  onHostnameResolved: (hostname: string, pid: number) => void
  cachedData: InvestigateResponse | null
  onDataCached: (d: InvestigateResponse | null) => void
  focalPidClickRef: React.MutableRefObject<((pid: number) => void) | null>
  showHostTabRef:   React.MutableRefObject<(() => void) | null>
}) {
  const [tab, setTab] = useState<InvTab>('analysis')
  // Cross-tab jump: TimelineTab fires a HuntJumpRequest when the analyst
  // clicks an event row; we set it here, flip to the Hunt tab, and the
  // Hunt tab consumes the request and runs the targeted query.
  const [pendingHuntRequest, setPendingHuntRequest] = useState<HuntJumpRequest | null>(null)
  function jumpToHunt(req: HuntJumpRequest) {
    setPendingHuntRequest(req)
    setTab('hunt')
  }

  return (
    <>
      <TabStrip active={tab} onChange={setTab} />
      {/* Tab content. HuntTab stays mounted across tab switches so the
          analyst's KQL, results, expanded rows, and flag state survive when
          they pop over to Analysis and back — running a hunt should not be
          throwaway work. The rest are mount/unmount as before. */}
      {/* AnalysisTab is kept mounted across switches between the
          'analysis' and 'ai' top-level tabs so state (tree, flags,
          analysis result) survives. aiOnly switches the layout to a
          standalone AI-panel view for the 'ai' tab. */}
      <div style={{
        display: (tab === 'analysis' || tab === 'ai') ? 'flex' : 'none',
        flex: 1, minHeight: 0,
      }}>
        <AnalysisTab inv={inv} deviceInfo={deviceInfo} onReset={onReset} onPivot={onPivot} onHostnameResolved={onHostnameResolved} cachedData={cachedData} onDataCached={onDataCached} focalPidClickRef={focalPidClickRef} showHostTabRef={showHostTabRef} onShowHuntTab={() => setTab('hunt')} aiOnly={tab === 'ai'} />
      </div>
      {tab === 'iocs' && <IocListPanel onHunt={jumpToHunt} />}
      <div style={{
        display: tab === 'hunt' ? 'flex' : 'none',
        flex: 1, flexDirection: 'column', minHeight: 0,
      }}>
        <HuntTab
          hostname={inv.hostname}
          pendingRequest={pendingHuntRequest}
          onRequestConsumed={() => setPendingHuntRequest(null)}
        />
      </div>
      {tab === 'timeline' && <TimelineTab onNavigate={jumpToHunt} />}
    </>
  )
}

// ── Welcome Screen ───────────────────────────────────────────────────────
function WelcomeScreen({ onStart, onStartBec }: {
  onStart: (inv: Investigation) => void
  onStartBec: (account: string, ip: string, timeWindow: string, offline: boolean) => void
}) {
  // Investigation type (§1): endpoint trace vs account-compromise (BEC).
  const [invType, setInvType] = useState<'endpoint' | 'bec'>('endpoint')
  // BEC form state.
  const [becAccount, setBecAccount] = useState('')
  const [becIp, setBecIp] = useState('')
  const [becWindow, setBecWindow] = useState('last24h')
  // Live (Graph API) vs offline (manual / copy-paste hunting) mode.
  const [becGraph, setBecGraph] = useState(true)
  // Custom absolute range (ISO-8601 UTC strings) when becWindow === 'custom',
  // chosen via the shared RangePicker calendar.
  const [becCustomStart, setBecCustomStart] = useState('')
  const [becCustomEnd, setBecCustomEnd] = useState('')
  const [becRangeOpen, setBecRangeOpen] = useState(false)

  // Resolve the lookback the case opens with: a preset, or a custom:<iso>..<iso>
  // range the backend's parse_time_window understands.
  function becEffectiveWindow(): string {
    if (becWindow !== 'custom') return becWindow
    if (becCustomStart && becCustomEnd) {
      const s = new Date(becCustomStart), e = new Date(becCustomEnd)
      if (!isNaN(s.getTime()) && !isNaN(e.getTime()) && s < e) {
        return `custom:${becCustomStart}..${becCustomEnd}`
      }
    }
    return 'last7d'
  }
  const becCustomInvalid = becWindow === 'custom' && (
    !becCustomStart || !becCustomEnd || new Date(becCustomStart) >= new Date(becCustomEnd)
  )
  // Two flows here: the analyst can search by hostname OR by device ID
  // ('auto' infers from the shape of the input). Looking up first lets
  // us disambiguate when one hostname maps to multiple devices (common
  // in AAD-joined fleets with re-imaged or renamed machines).
  const [query, setQuery] = useState('')
  const [searchKind, setSearchKind] = useState<'auto' | 'hostname' | 'device_id'>('auto')
  const [hostname, setHostname] = useState('')      // resolved canonical hostname
  const [lookupMatches, setLookupMatches] = useState<DeviceLookupMatch[] | null>(null)
  const [lookupLoading, setLookupLoading] = useState(false)
  const [pid, setPid] = useState('14340')
  const [timeWindow, setTimeWindow] = useState('±24h')
  const [pendingWide, setPendingWide] = useState<string | null>(null)
  const [customRange, setCustomRange] = useState<{ startIso: string; endIso: string } | null>(null)
  const [pickerOpen, setPickerOpen] = useState(false)
  const [error, setError] = useState('')

  async function runLookup() {
    setError('')
    setLookupMatches(null)
    const raw = query.trim()
    if (!raw) {
      setError('Enter a hostname or device ID to search.')
      return
    }
    setLookupLoading(true)
    try {
      const res = await lookupDevice(raw, searchKind)
      if (!res.ok) {
        setError(friendlyError(res.error || 'Lookup failed.'))
        return
      }
      if (res.matches.length === 0) {
        setError(`No devices found matching "${raw}".`)
        return
      }
      if (res.matches.length === 1) {
        // Single match — accept silently, no disambiguation needed.
        setHostname(res.matches[0].device_name)
        setLookupMatches(res.matches)  // remember so the analyst can see what we picked
      } else {
        // Multiple matches — surface the picker.
        setLookupMatches(res.matches)
      }
    } catch (e) {
      setError(friendlyError(e))
    } finally {
      setLookupLoading(false)
    }
  }

  function selectMatch(m: DeviceLookupMatch) {
    setHostname(m.device_name)
    setLookupMatches([m])
    setError('')
  }

  async function handleStart(e: React.FormEvent) {
    e.preventDefault()
    setError('')

    // PID + time window validation first — fast and independent of the
    // lookup, no point round-tripping to Graph if the form is invalid.
    const pidNum = parseInt(pid, 10)
    if (!pid || isNaN(pidNum) || pid.replace(/\D/g, '') !== pid || pid.length > 7 || pidNum === 0 || pidNum === 4) {
      setError('PID must be a number 1–9999999. PIDs 0 and 4 are system reserved.')
      return
    }
    let rawTimeWindow = timeWindow
    if (timeWindow === 'custom') {
      if (!customRange) {
        setError('Pick a custom range using the calendar below.')
        return
      }
      rawTimeWindow = `custom:${customRange.startIso}..${customRange.endIso}`
    }

    // Auto-lookup: if the analyst hasn't resolved a hostname yet (no
    // prior click on the lookup button), do it transparently here. Saves
    // them a click in the common case; the explicit lookup button still
    // exists for ambiguous searches where they want to see all matches
    // before committing.
    let resolved = hostname
    if (!resolved) {
      const raw = query.trim()
      if (!raw) {
        setError('Enter a hostname or device ID.')
        return
      }
      setLookupLoading(true)
      try {
        const res = await lookupDevice(raw, searchKind)
        if (!res.ok) {
          setError(friendlyError(res.error || 'Lookup failed.'))
          return
        }
        if (res.matches.length === 0) {
          setError(`No devices found matching "${raw}".`)
          return
        }
        if (res.matches.length > 1) {
          // Ambiguous — surface the picker and let the analyst pick.
          // They'll then click Start again to commit.
          setLookupMatches(res.matches)
          setError(`Multiple devices match "${raw}" — pick one to continue.`)
          return
        }
        // Single match: accept silently and use it for this Start.
        resolved = res.matches[0].device_name
        setHostname(resolved)
        setLookupMatches(res.matches)
      } catch (err) {
        setError(friendlyError(err))
        return
      } finally {
        setLookupLoading(false)
      }
    }

    const stripped = resolved.trim().split('.')[0]
    if (!stripped || !/^[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}$/.test(stripped)) {
      setError('Resolved hostname is invalid. Try a different search.')
      return
    }

    const now = new Date()
    const startedAt = now.toISOString().slice(11, 19) + ' UTC'
    const id = `INV-${now.toISOString().slice(0, 10).replace(/-/g, '')}-${Math.random().toString(36).slice(2, 8)}`

    clearIocs()
    clearHuntFlags()
    clearInvestigation()
    clearAnalysisHistory()
    clearAllDegraded()
    onStart({ id, hostname: stripped, pid, alertId: null, mode: 'host-pid', timeWindow, rawTimeWindow, focalTimeIso: null, startedAt })
  }

  const inputStyle: React.CSSProperties = {
    background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4,
    color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 13,
    padding: '9px 12px', outline: 'none', width: '100%',
  }
  const labelStyle: React.CSSProperties = {
    color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 10.5,
    letterSpacing: 0.5, marginBottom: 5, textTransform: 'uppercase', display: 'block',
  }

  return (
    <div style={{
      flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24,
      backgroundColor: 'var(--bg-app)',
      backgroundImage: 'linear-gradient(rgba(8,8,12,0.62), rgba(8,8,12,0.62)), url(/tree-bg.png)',
      backgroundSize: 'cover',
      backgroundPosition: 'center',
    }}>
      <div style={{
        background: 'var(--bg-panel)', border: '1px solid var(--border)',
        borderRadius: 8, padding: '32px 36px', width: '100%', maxWidth: 460,
      }}>
        <div style={{ fontFamily: 'var(--font-mono)', marginBottom: 24, textAlign: 'center' }}>
          {/* Same stacked sudotrace logo used on the login screen, with the
              same 165% zoom centre-crop to clip the gradient padding. */}
          <div role="img" aria-label="SudoTrace" style={{
            display: 'block',
            width: '100%',
            maxWidth: 320,
            aspectRatio: '5 / 2',
            margin: '0 auto 6px',
            backgroundImage: 'url(/sudotrace-logo.png)',
            backgroundSize: '165% auto',
            backgroundPosition: 'center center',
            backgroundRepeat: 'no-repeat',
            borderRadius: 6,
            // Gentle edge softening — narrower than the AppBar's
            // horizontal-logo fade because the stacked logo is much
            // larger and a wide band makes the text feel cut off.
            WebkitMaskImage:
              'linear-gradient(to right, transparent 0%, #000 2%, #000 98%, transparent 100%), ' +
              'linear-gradient(to bottom, transparent 0%, #000 3%, #000 97%, transparent 100%)',
            WebkitMaskComposite: 'source-in',
            maskImage:
              'linear-gradient(to right, transparent 0%, #000 2%, #000 98%, transparent 100%), ' +
              'linear-gradient(to bottom, transparent 0%, #000 3%, #000 97%, transparent 100%)',
            maskComposite: 'intersect',
          }} />
          <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 5 }}>
            MDE investigation workbench
          </div>
        </div>

        {/* Investigation type selector (§1) */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 18 }}>
          {([['endpoint', 'Endpoint trace', 'Device + PID'], ['bec', 'Account compromise', 'BEC / identity']] as const).map(([t, title, sub]) => {
            const on = invType === t
            return (
              <button type="button" key={t} onClick={() => setInvType(t)}
                style={{
                  flex: 1, textAlign: 'left', cursor: 'pointer',
                  background: on ? 'rgba(168,85,247,0.12)' : 'var(--bg-card)',
                  border: `1px solid ${on ? 'var(--accent)' : 'var(--border)'}`,
                  borderRadius: 6, padding: '10px 12px', fontFamily: 'var(--font-mono)',
                }}>
                <div style={{ color: on ? 'var(--accent)' : 'var(--text)', fontSize: 12, fontWeight: 600 }}>{title}</div>
                <div style={{ color: 'var(--text-muted)', fontSize: 9.5, marginTop: 2 }}>{sub}</div>
              </button>
            )
          })}
        </div>

        {invType === 'bec' && (
          <form
            onSubmit={e => { e.preventDefault(); if (becAccount.trim() && !becCustomInvalid) onStartBec(becAccount.trim(), becIp.trim(), becEffectiveWindow(), !becGraph) }}
            style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div>
              <label style={labelStyle}>Account (UPN or object id)</label>
              <input style={inputStyle} autoFocus placeholder="user@domain.com"
                value={becAccount} onChange={e => setBecAccount(e.target.value)} />
            </div>
            <div>
              <label style={labelStyle}>Suspected origin IP <span style={{ textTransform: 'none', letterSpacing: 0 }}>(optional)</span></label>
              <input style={inputStyle} placeholder="45.135.x.x"
                value={becIp} onChange={e => setBecIp(e.target.value)} />
            </div>
            <div>
              <label style={labelStyle}>Sign-in lookback</label>
              <select style={inputStyle} value={becWindow} onChange={e => setBecWindow(e.target.value)}>
                <option value="last24h">Last 24 hours</option>
                <option value="last7d">Last 7 days</option>
                <option value="last30d">Last 30 days</option>
                <option value="custom">Custom range…</option>
              </select>
              {becWindow === 'custom' && (
                <button type="button" onClick={() => setBecRangeOpen(true)}
                  style={{
                    ...inputStyle, marginTop: 8, textAlign: 'left', cursor: 'pointer',
                    color: becCustomStart && becCustomEnd ? 'var(--text)' : 'var(--text-muted)',
                  }}>
                  {becCustomStart && becCustomEnd
                    ? `${formatCustomWindow(`custom:${becCustomStart}..${becCustomEnd}`)}`
                    : 'Select date range…'}
                </button>
              )}
              {becWindow === 'custom' && becCustomInvalid && (
                <div style={{ color: 'var(--amber)', fontSize: 9.5, marginTop: 4 }}>
                  Pick a start and end on the calendar. Sign-in logs retain ~30 days.
                </div>
              )}
              {becRangeOpen && createPortal(
                <>
                  <div onClick={() => setBecRangeOpen(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 10000 }} />
                  <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', zIndex: 10001 }}>
                    <RangePicker
                      initialStart={becCustomStart || undefined}
                      initialEnd={becCustomEnd || undefined}
                      onApply={(s, e) => { setBecCustomStart(s); setBecCustomEnd(e); setBecRangeOpen(false) }}
                      onCancel={() => setBecRangeOpen(false)}
                    />
                  </div>
                </>,
                document.body,
              )}
            </div>
            <div>
              <label style={labelStyle}>Data mode</label>
              <div style={{ display: 'flex', gap: 6 }}>
                {([['live', 'Live (Graph API)'], ['offline', 'Offline (manual)']] as const).map(([k, lbl]) => {
                  const on = (k === 'live') === becGraph
                  return (
                    <button key={k} type="button" onClick={() => setBecGraph(k === 'live')}
                      style={{
                        flex: 1, background: on ? 'rgba(168,85,247,0.15)' : 'var(--bg-elevated)',
                        border: `1px solid ${on ? 'var(--accent)' : 'var(--border)'}`,
                        color: on ? 'var(--accent)' : 'var(--text-muted)', cursor: 'pointer',
                        fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600, padding: '7px', borderRadius: 4,
                      }}>{lbl}</button>
                  )
                })}
              </div>
            </div>
            <button type="submit" disabled={!becAccount.trim() || becCustomInvalid}
              style={{
                background: becAccount.trim() && !becCustomInvalid ? 'var(--accent)' : 'var(--bg-elevated)',
                color: becAccount.trim() && !becCustomInvalid ? '#fff' : 'var(--text-muted)', border: 'none', borderRadius: 4,
                cursor: becAccount.trim() && !becCustomInvalid ? 'pointer' : 'default', fontFamily: 'var(--font-mono)',
                fontSize: 12, fontWeight: 600, padding: '10px', letterSpacing: 0.3,
              }}>
              Open case ▸
            </button>
            <div style={{ color: 'var(--text-muted)', fontSize: 10, lineHeight: 1.5 }}>
              {becGraph
                ? <>Opens the investigation checklist and, when Graph is reachable, pulls Entra sign-ins, scope hunts and enrichment (needs AuditLog.Read.All + Entra ID P1/P2).</>
                : <><span style={{ color: 'var(--amber)' }}>Offline mode</span> — no Graph calls. You get the checklist plus copy-paste hunting queries (Advanced Hunting / audit log) to run by hand.</>}
            </div>
          </form>
        )}

        {invType === 'endpoint' && (
        <form onSubmit={handleStart} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label style={labelStyle}>Device</label>
            {/* Search-kind toggle: auto / hostname / device id. 'auto'
                infers from input shape (40-char hex → device id). */}
            <div style={{ display: 'flex', gap: 4, marginBottom: 6, fontSize: 10 }}>
              {(['auto', 'hostname', 'device_id'] as const).map(k => {
                const on = searchKind === k
                const label = k === 'auto' ? 'auto-detect' : k === 'hostname' ? 'hostname' : 'device id'
                return (
                  <span key={k}
                    onClick={() => { setSearchKind(k); setError('') }}
                    style={{
                      padding: '2px 8px', borderRadius: 3, cursor: 'pointer',
                      userSelect: 'none',
                      color: on ? 'var(--text)' : 'var(--text-muted)',
                      background: on ? 'var(--bg-elevated)' : 'transparent',
                      border: `1px solid ${on ? 'var(--border)' : 'transparent'}`,
                    }}>{label}</span>
                )
              })}
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <input
                style={{ ...inputStyle, flex: 1 }}
                placeholder={
                  searchKind === 'device_id'
                    ? '40-char DeviceId (hex)'
                    : searchKind === 'hostname'
                      ? 'WS-FIN-04  (partial match OK)'
                      : 'hostname or DeviceId'
                }
                value={query}
                onChange={e => { setQuery(e.target.value); setError(''); setHostname(''); setLookupMatches(null) }}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); runLookup() } }}
                autoFocus />
              <button type="button" onClick={runLookup} disabled={lookupLoading || !query.trim()}
                onMouseEnter={e => { if (!lookupLoading && query.trim()) { e.currentTarget.style.background = 'rgba(168,85,247,0.20)' } }}
                onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}
                style={{
                  background: 'transparent',
                  border: '1px solid var(--accent)', borderRadius: 4,
                  color: lookupLoading || !query.trim() ? 'var(--text-muted)' : 'var(--accent)',
                  cursor: lookupLoading || !query.trim() ? 'default' : 'pointer',
                  fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
                  padding: '0 14px', whiteSpace: 'nowrap',
                }}>
                {lookupLoading ? 'searching…' : 'search ▸'}
              </button>
            </div>
            {/* Single-match auto-selected: show what we picked. */}
            {hostname && lookupMatches?.length === 1 && (
              <div style={{
                marginTop: 8, padding: '6px 10px',
                background: 'rgba(125,211,160,0.08)',
                border: '1px solid rgba(125,211,160,0.3)',
                borderRadius: 4, fontSize: 10.5,
                color: 'var(--text)',
              }}>
                <span style={{ color: '#7DD3A0', fontWeight: 600 }}>✓ matched</span>{' '}
                <span style={{ color: 'var(--text)' }}>{lookupMatches[0].device_name}</span>{' · '}
                <span style={{ color: 'var(--text-muted)' }}>{lookupMatches[0].os_platform} {lookupMatches[0].os_version}</span>
                {lookupMatches[0].device_id && (
                  <div style={{ color: 'var(--text-muted)', fontSize: 9.5, marginTop: 2, wordBreak: 'break-all' }}>
                    {lookupMatches[0].device_id}
                  </div>
                )}
              </div>
            )}
            {/* Disambiguation list when the query matched multiple devices. */}
            {lookupMatches && lookupMatches.length > 1 && (
              <div style={{
                marginTop: 8,
                border: '1px solid var(--border)', borderRadius: 4,
                background: 'var(--bg-app)',
                maxHeight: 260, overflowY: 'auto',
              }}>
                <div style={{
                  padding: '6px 10px', fontSize: 10,
                  color: 'var(--amber)',
                  borderBottom: '1px solid var(--border-soft)',
                  background: 'rgba(240,179,64,0.06)',
                }}>
                  {lookupMatches.length} matches — pick one
                </div>
                {lookupMatches.map(m => {
                  const isSelected = hostname === m.device_name
                  return (
                    <div key={m.device_id}
                      onClick={() => selectMatch(m)}
                      onMouseEnter={e => { e.currentTarget.style.background = 'rgba(168,85,247,0.08)' }}
                      onMouseLeave={e => { e.currentTarget.style.background = isSelected ? 'rgba(168,85,247,0.10)' : 'transparent' }}
                      style={{
                        padding: '8px 10px',
                        borderBottom: '1px solid var(--border-soft)',
                        cursor: 'pointer', fontSize: 10.5,
                        background: isSelected ? 'rgba(168,85,247,0.10)' : 'transparent',
                      }}>
                      <div style={{ color: 'var(--text)', fontWeight: 600 }}>
                        {m.device_name || '(unnamed)'}
                        {isSelected && <span style={{ color: 'var(--accent)', marginLeft: 6, fontSize: 10 }}>✓ selected</span>}
                      </div>
                      <div style={{ color: 'var(--text-muted)', fontSize: 10, marginTop: 2 }}>
                        {[m.os_platform, m.os_version, m.machine_group, m.public_ip].filter(Boolean).join(' · ')}
                      </div>
                      <div style={{ color: 'var(--text-muted)', fontSize: 9.5, marginTop: 2, wordBreak: 'break-all' }}>
                        {m.device_id}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
          <div>
            <label style={labelStyle}>Process ID (PID)</label>
            <input style={inputStyle} placeholder="e.g. 8156" inputMode="numeric"
              value={pid} onChange={e => { setPid(e.target.value.replace(/\D/g, '')); setError('') }} />
          </div>

          {/* Time window */}
          <div>
            <label style={labelStyle}>Time Window</label>
            <select value={timeWindow} onChange={e => {
                const v = e.target.value
                if (needsWideWindowConfirm(v)) {
                  setPendingWide(v)
                  return
                }
                setTimeWindow(v); setError('')
                if (v === 'custom') setPickerOpen(true)
              }}
              style={{ ...inputStyle, cursor: 'pointer' }}>
              {TIME_WINDOWS.map(tw => (
                <option key={tw.value} value={tw.value}>{tw.label}</option>
              ))}
            </select>
            {timeWindow === 'custom' && (
              <div style={{ marginTop: 8 }}>
                {customRange ? (
                  <span
                    onClick={() => setPickerOpen(true)}
                    title="Edit custom range"
                    style={{
                      display: 'inline-block', color: 'var(--text)', cursor: 'pointer',
                      fontSize: 11, padding: '4px 8px',
                      border: '1px dashed var(--border)', borderRadius: 4,
                    }}>
                    {formatCustomWindow(`custom:${customRange.startIso}..${customRange.endIso}`)} (edit)
                  </span>
                ) : (
                  <span
                    onClick={() => setPickerOpen(true)}
                    style={{
                      display: 'inline-block', color: 'var(--amber)', cursor: 'pointer',
                      fontSize: 11, padding: '4px 8px',
                      border: '1px dashed rgba(240,179,64,0.5)', borderRadius: 4,
                    }}>
                    ⚠ pick a range
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Custom range picker — centered modal overlay so it doesn't push
              the form below the viewport (the inline form was clipping the
              Apply button on shorter screens). */}
          {pickerOpen && createPortal(
            <>
              <div
                onClick={() => setPickerOpen(false)}
                style={{
                  position: 'fixed', inset: 0, zIndex: 9998,
                  background: 'rgba(0,0,0,0.45)',
                }}
              />
              <div style={{
                position: 'fixed', top: '50%', left: '50%',
                transform: 'translate(-50%, -50%)', zIndex: 9999,
              }}>
                <RangePicker
                  initialStart={customRange?.startIso}
                  initialEnd={customRange?.endIso}
                  onApply={(startIso, endIso) => {
                    setCustomRange({ startIso, endIso })
                    setError('')
                    setPickerOpen(false)
                  }}
                  onCancel={() => {
                    setPickerOpen(false)
                    if (!customRange) setTimeWindow('±24h')
                  }}
                />
              </div>
            </>,
            document.body,
          )}

          {error && (
            <div style={{
              background: 'rgba(255,94,91,0.1)', border: '1px solid rgba(255,94,91,0.3)',
              borderRadius: 4, color: 'var(--red)', fontFamily: 'var(--font-mono)',
              fontSize: 11, padding: '8px 12px',
            }}>{error}</div>
          )}

          <button type="submit" style={{
            background: 'var(--accent)', border: 'none', borderRadius: 4,
            color: '#fff', cursor: 'pointer', fontFamily: 'var(--font-mono)',
            fontSize: 12, fontWeight: 600, letterSpacing: 0.5, marginTop: 4, padding: '11px',
          }}>
            INVESTIGATE ▸
          </button>
        </form>
        )}
      </div>
      <ConfirmDialog
        open={!!pendingWide}
        message={pendingWide ? wideWindowMessage(pendingWide) : ''}
        onConfirm={() => { const v = pendingWide!; setPendingWide(null); setTimeWindow(v); setError('') }}
        onCancel={() => setPendingWide(null)}
      />
    </div>
  )
}

// ── Home Page ────────────────────────────────────────────────────────────
export default function HomePage({ user, onLogout, investigation, onInvestigationChange, investigationData, onInvestigationDataChange }: Props) {
  const navigate = useNavigate()
  const [credsMissing, setCredsMissing] = useState(false)
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfoData | null>(null)
  // BEC case (account-compromise flow). `becRestore` carries the saved
  // analyst-authored state into BecView on resume; null for a fresh case.
  const [becCase, setBecCase] = useState<BecCase | null>(null)
  const [becRestore, setBecRestore] = useState<{
    selected: string[]; checked: string[]; notes: Record<string, string>
    timeline_custom?: import('../api/bec').BecTimelineCustom[]; timeline_hidden?: string[]; manual_ips?: string[]
  } | null>(null)
  // Bumped when a BEC case is loaded from file so BecView remounts and re-seeds
  // its internal state from the new `restore` snapshot.
  const [becLoadNonce, setBecLoadNonce] = useState(0)
  // Cross-component callback: AppBar's PID click → AnalysisTab's handlePidClick.
  // AnalysisTab updates this ref so the AppBar (a sibling in the tree) can
  // trigger a reveal without lifting all of AnalysisTab's state up here.
  const focalPidClickRef = useRef<((pid: number) => void) | null>(null)
  // Sibling-bridge callback: AppBar hostname click → AnalysisTab.setRightTab('host').
  const showHostTabRef   = useRef<(() => void) | null>(null)

  useEffect(() => {
    getCredentialStatus().then(({ configured }) => setCredsMissing(!configured))
  }, [])

  // On first mount, resume a saved BEC case if one exists and nothing else is
  // already open (an active endpoint investigation takes precedence). Runs once.
  useEffect(() => {
    let cancelled = false
    getBecCase().then(({ case: saved }) => {
      // An active endpoint investigation (mount-time value) takes precedence.
      if (cancelled || !saved || investigation) return
      setBecRestore({
        selected: saved.selected ?? [],
        checked:  saved.checked ?? [],
        notes:    saved.notes ?? {},
        timeline_custom: saved.timeline_custom ?? [],
        timeline_hidden: saved.timeline_hidden ?? [],
        manual_ips: saved.manual_ips ?? [],
      })
      setBecCase({ account: saved.account, ip: saved.ip, timeWindow: saved.time_window, offline: saved.offline })
    })
    return () => { cancelled = true }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!investigation?.hostname) { setDeviceInfo(null); return }
    const host = investigation.hostname
    const loadDeviceInfo = () => {
      fetchDeviceInfo(host)
        .then(info => {
          if (info.ok) {
            setDeviceInfo(info)
            clearDegraded('device-info')
          } else {
            setDegraded({
              source: 'device-info', label: 'device info',
              message: friendlyError(info.error || 'DeviceInfo returned no rows.'),
              retry: loadDeviceInfo,
            })
          }
        })
        .catch(e => setDegraded({
          source: 'device-info', label: 'device info',
          message: friendlyError(String(e)),
          retry: loadDeviceInfo,
        }))
    }
    loadDeviceInfo()
  }, [investigation?.hostname])

  async function handleLogout() {
    await logout()
    onLogout()
  }

  const handleTimeWindowChange = investigation
    ? (tw: string) => {
        onInvestigationChange({ ...investigation, timeWindow: tw, rawTimeWindow: tw })
        onInvestigationDataChange(null)
      }
    : null

  return (
    <div style={{
      height: '100vh', display: 'flex', flexDirection: 'column',
      background: `
        radial-gradient(ellipse 80% 60% at 8% 95%, rgba(56,108,219,0.08) 0%, transparent 55%),
        radial-gradient(ellipse 70% 55% at 92% 5%,  rgba(45,90,200,0.06)  0%, transparent 55%),
        radial-gradient(ellipse 90% 70% at 95% 95%, rgba(168,90,212,0.06) 0%, transparent 50%),
        var(--bg-app)
      `,
      color: 'var(--text)',
    }}>
      <AppBar
        user={user}
        investigation={investigation}
        procCount={investigationData ? Object.keys(investigationData.nodes).length : 0}
        onLogout={handleLogout}
        onSettings={() => navigate('/settings')}
        onHome={() => onInvestigationChange(null)}
        onTimeWindowChange={handleTimeWindowChange}
        onFocalPidClick={pid => focalPidClickRef.current?.(pid)}
        onChangePid={investigation ? pid => {
          // Mirror the existing onPivot flow used elsewhere: stamp a
          // new investigation id, set the new PID, and drop cached
          // tree data so AnalysisTab refetches.
          const now = new Date()
          onInvestigationChange({
            ...investigation,
            id: `INV-${now.toISOString().slice(0, 10).replace(/-/g, '')}-${Math.random().toString(36).slice(2, 8)}`,
            pid: String(pid),
            focalTimeIso: null,
            startedAt: now.toISOString().slice(11, 19) + ' UTC',
            mode: 'host-pid',
          })
          onInvestigationDataChange(null)
        } : null}
        onLoadInvestigation={(inv) => {
          // File import already pushed the analyst-authored state into
          // the stores; we only need to update the investigation
          // metadata here and drop the cached tree so AnalysisTab
          // refetches against the freshly-restored context.
          onInvestigationChange(inv)
          onInvestigationDataChange(null)
        }}
        becActive={!!becCase}
        onSaveBec={async () => {
          // The case auto-saves server-side; fetch the freshest copy and download it.
          const { case: saved } = await getBecCase()
          if (saved) exportBecCaseToFile(saved)
        }}
        onLoadBec={async (c) => {
          await putBecCase(c)   // persist as the active case
          setBecRestore({
            selected: c.selected ?? [], checked: c.checked ?? [], notes: c.notes ?? {},
            timeline_custom: c.timeline_custom ?? [], timeline_hidden: c.timeline_hidden ?? [],
            manual_ips: c.manual_ips ?? [],
          })
          setBecCase({ account: c.account, ip: c.ip, timeWindow: c.time_window, offline: c.offline })
          setBecLoadNonce(n => n + 1)   // force BecView to remount + re-seed
        }}
      />

      {credsMissing && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10, padding: '7px 14px',
          background: 'rgba(240,179,64,0.07)', borderBottom: '1px solid rgba(240,179,64,0.18)',
          color: 'var(--amber)', fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0,
        }}>
          <span>⚠</span>
          <span>MDE credentials not configured — investigations will fail until set up.</span>
          <button onClick={() => navigate('/settings')} style={{
            background: 'transparent', border: 'none', color: 'var(--accent)',
            cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600, padding: 0,
          }}>settings →</button>
        </div>
      )}

      <DegradationBanner />

      {becCase
        ? <BecView
            key={`${becCase.account}-${becLoadNonce}`}
            account={becCase.account}
            ip={becCase.ip}
            timeWindow={becCase.timeWindow}
            offline={becCase.offline}
            restore={becRestore}
            onReset={() => { setBecCase(null); setBecRestore(null); deleteBecCase() }}
          />
        : investigation
        ? <InvestigationShell
            inv={investigation}
            deviceInfo={deviceInfo}
            onReset={() => onInvestigationChange(null)}
            onHostnameResolved={(hostname, pid) => {
              onInvestigationChange({
                ...investigation,
                hostname,
                pid: pid ? String(pid) : investigation.pid,
                mode: 'host-pid',
              })
            }}
            onPivot={(pid, timestamp) => {
              const now = new Date()
              onInvestigationChange({
                ...investigation,
                id: `INV-${now.toISOString().slice(0, 10).replace(/-/g, '')}-${Math.random().toString(36).slice(2, 8)}`,
                pid: String(pid),
                focalTimeIso: timestamp,
                startedAt: now.toISOString().slice(11, 19) + ' UTC',
                mode: 'host-pid',
              })
              onInvestigationDataChange(null)
            }}
            cachedData={investigationData}
            onDataCached={onInvestigationDataChange}
            focalPidClickRef={focalPidClickRef}
            showHostTabRef={showHostTabRef}
          />
        : <WelcomeScreen
            onStart={onInvestigationChange}
            onStartBec={(account, ip, timeWindow, offline) => { setBecRestore(null); setBecCase({ account, ip, timeWindow, offline }) }}
          />
      }
    </div>
  )
}
