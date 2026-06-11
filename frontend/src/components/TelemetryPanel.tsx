import React, { useState, useEffect, useCallback, useRef } from 'react'
import type { ProcessNodeData, Investigation, FlagStatus } from '../types'
import { fetchTelemetry } from '../api/investigate'
import { VtButton } from './VtButton'
import { AddToIocButton } from './AddToIocButton'
import { fmtDateTime } from '../utils/dateFormat'
import { friendlyError } from '../utils/errors'

// Mirror of the process-tree flag cycle. Keep in sync if the canonical
// constants in ProcessNode/ProcessTreeTable ever change. Same glyph, same
// colours so a flagged telemetry row reads identically to a flagged process.
const ROW_FLAG_CYCLE: FlagStatus[] = [null, 'benign', 'suspicious', 'malicious']
const ROW_FLAG_COLORS: Record<NonNullable<FlagStatus>, string> = {
  malicious:   '#FF5E5B',
  suspicious:  '#F0B340',
  investigate: '#7AA8FF',
  benign:      '#7DD3A0',
}

type TelTab = 'process' | 'network' | 'files' | 'registry' | 'dlls' | 'scripts'

const TEL_TABS: { id: TelTab; label: string }[] = [
  { id: 'process',  label: 'proc'    },
  { id: 'network',  label: 'net'     },
  { id: 'files',    label: 'files'   },
  { id: 'registry', label: 'reg'     },
  { id: 'dlls',     label: 'dlls'    },
  { id: 'scripts',  label: 'scripts' },
]

interface ColDef {
  key: string
  label: string
  shrink?: boolean
  wide?: boolean
  // `cmdline` gets an "+ IOC" toggle instead of the VT lookup button —
  // VirusTotal doesn't index command lines, so the only useful action
  // is pinning the value to the IOC list for hunt pivots.
  isIoc?: 'hash' | 'ip' | 'domain' | 'cmdline'
  iocExtract?: (raw: string) => string | null
  renderVal?: (row: Record<string, unknown>) => string
}

function extractDomain(raw: string): string | null {
  if (!raw) return null
  try {
    const url = new URL(raw.includes('://') ? raw : `https://${raw}`)
    const host = url.hostname
    // Skip bare IPs — already handled by RemoteIP column
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return null
    return host || null
  } catch {
    // Not a URL — accept bare domain-looking strings
    if (/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(raw) && !/^\d+(\.\d+)+$/.test(raw)) return raw
    return null
  }
}

const COLS: Record<string, ColDef[]> = {
  network: [
    { key: 'Timestamp',  label: 'time',   shrink: true },
    { key: 'ActionType', label: 'action', shrink: true },
    { key: 'RemoteIP',   label: 'remote', isIoc: 'ip'  },
    { key: 'RemotePort', label: 'port',   shrink: true },
    { key: 'RemoteUrl',  label: 'url',    wide: true, isIoc: 'domain', iocExtract: extractDomain },
    { key: 'LocalPort',  label: 'lport',  shrink: true },
    { key: 'Protocol',   label: 'proto',  shrink: true },
  ],
  files: [
    { key: 'Timestamp',  label: 'time',   shrink: true },
    { key: 'ActionType', label: 'action', shrink: true },
    { key: 'FileName',   label: 'file'                 },
    { key: 'FolderPath', label: 'path',   wide: true   },
    { key: 'SHA256',     label: 'sha256', wide: true, isIoc: 'hash' },
    { key: 'MD5',        label: 'md5',    wide: true, isIoc: 'hash' },
  ],
  registry: [
    { key: 'Timestamp',  label: 'time',   shrink: true },
    { key: 'ActionType', label: 'action', shrink: true },
    {
      key: 'RegistryKey', label: 'key', wide: true,
      renderVal: row => String(row['RegistryKey'] || row['PreviousRegistryKey'] || '—'),
    },
    {
      key: 'RegistryValueName', label: 'value',
      renderVal: row => String(row['RegistryValueName'] || row['PreviousRegistryValueName'] || '—'),
    },
    {
      key: 'RegistryValueData', label: 'data', wide: true,
      renderVal: row => String(row['RegistryValueData'] || row['PreviousRegistryValueData'] || '—'),
    },
  ],
  dlls: [
    { key: 'Timestamp',  label: 'time', shrink: true },
    { key: 'FileName',   label: 'dll' },
    { key: 'FolderPath', label: 'path',   wide: true },
    { key: 'SHA256',     label: 'sha256', wide: true, isIoc: 'hash' },
    { key: 'MD5',        label: 'md5',    wide: true, isIoc: 'hash' },
    { key: 'InitiatingProcessFileName', label: 'loaded by' },
  ],
  scripts: [
    { key: 'Timestamp',           label: 'time',   shrink: true },
    { key: 'ActionType',          label: 'action', shrink: true },
    { key: 'FileName',            label: 'file'                  },
    { key: 'ProcessCommandLine',  label: 'cmdline',     wide: true, isIoc: 'cmdline' },
    {
      key: 'AdditionalFields',    label: 'extra',       wide: true,
      // AdditionalFields often comes back as a JSON-stringified object — pretty
      // it up enough to be skimmable without exploding it across multiple lines.
      renderVal: row => {
        const v = row['AdditionalFields']
        if (v === null || v === undefined || v === '') return '—'
        if (typeof v === 'string') return v
        try { return JSON.stringify(v) } catch { return String(v) }
      },
    },
  ],
}

function fmtTs(ts: unknown): string {
  if (!ts) return '—'
  try {
    const d = new Date(String(ts))
    const mm  = String(d.getUTCMonth() + 1).padStart(2, '0')
    const dd  = String(d.getUTCDate()).padStart(2, '0')
    const hh  = String(d.getUTCHours()).padStart(2, '0')
    const min = String(d.getUTCMinutes()).padStart(2, '0')
    return `${mm}-${dd} ${hh}:${min}`
  } catch {
    return String(ts).slice(0, 16)
  }
}

function TelTable({ rows, cols, getFlag, onCycleFlag, zoom = 1, searchTerm }: {
  rows: Record<string, unknown>[]
  cols: ColDef[]
  getFlag: (rowIdx: number) => FlagStatus
  onCycleFlag: (rowIdx: number) => void
  zoom?: number
  searchTerm?: string
}) {
  const [colWidths, setColWidths] = useState<number[]>(() =>
    cols.map(c => c.shrink ? 90 : c.wide ? 210 : 140)
  )
  const FLAG_COL_WIDTH    = 32   // leading flag column — fixed, not resizable
  const EXPAND_COL_WIDTH  = 26   // leading expand-chevron column — fixed
  // Per-row expansion state — Set of row indices whose detail block is open.
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set())
  const toggleRow = (i: number) => setExpandedRows(prev => {
    const next = new Set(prev)
    if (next.has(i)) next.delete(i); else next.add(i)
    return next
  })

  function handleThMouseMove(e: React.MouseEvent<HTMLTableCellElement>) {
    const rect = e.currentTarget.getBoundingClientRect()
    const nearEdge = e.clientX >= rect.right - 6
    e.currentTarget.style.cursor = nearEdge ? 'col-resize' : 'default'
    e.currentTarget.style.borderRight = nearEdge
      ? '2px solid var(--accent)'
      : '2px solid var(--border)'
  }

  function handleThMouseLeave(e: React.MouseEvent<HTMLTableCellElement>) {
    e.currentTarget.style.cursor = 'default'
    e.currentTarget.style.borderRight = '2px solid var(--border)'
  }

  function handleThMouseDown(idx: number, e: React.MouseEvent<HTMLTableCellElement>) {
    const rect = e.currentTarget.getBoundingClientRect()
    if (e.clientX < rect.right - 6) return
    e.preventDefault()
    const startX = e.clientX
    const startW = colWidths[idx]
    function onMove(ev: MouseEvent) {
      setColWidths(prev => {
        const next = [...prev]
        next[idx] = Math.max(40, startW + (ev.clientX - startX))
        return next
      })
    }
    function onUp() {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  if (rows.length === 0) {
    return (
      <div style={{ padding: '16px 14px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
        no events in time window
      </div>
    )
  }

  return (
    <div style={{ overflow: 'auto', flex: 1 }}>
      <table style={{ borderCollapse: 'collapse', tableLayout: 'fixed', fontFamily: 'var(--font-mono)', fontSize: 10.5 * zoom }}>
        <thead>
          <tr style={{ background: 'var(--bg-elevated)' }}>
            {/* Leading expand column — fixed width, not resizable */}
            <th style={{
              width: EXPAND_COL_WIDTH,
              padding: '5px 4px',
              borderBottom: '1px solid var(--border)',
              borderRight: '1px solid var(--border-soft)',
              position: 'sticky', top: 0, background: 'var(--bg-elevated)',
              userSelect: 'none',
            }} />
            {/* Leading flag column — fixed width, not resizable */}
            <th style={{
              width: FLAG_COL_WIDTH,
              textAlign: 'center', padding: '5px 4px',
              color: 'var(--text-muted)', fontWeight: 600,
              fontSize: 9, letterSpacing: 0.5, textTransform: 'uppercase',
              borderBottom: '1px solid var(--border)',
              borderRight: '2px solid var(--border)',
              whiteSpace: 'nowrap',
              position: 'sticky', top: 0, background: 'var(--bg-elevated)',
              userSelect: 'none',
            }}>flag</th>
            {cols.map((c, i) => (
              <th key={c.key}
                onMouseMove={handleThMouseMove}
                onMouseLeave={handleThMouseLeave}
                onMouseDown={e => handleThMouseDown(i, e)}
                style={{
                  textAlign: 'left', padding: '5px 8px',
                  color: 'var(--text-muted)', fontWeight: 600,
                  fontSize: 9, letterSpacing: 0.5, textTransform: 'uppercase',
                  borderBottom: '1px solid var(--border)',
                  borderRight: '2px solid var(--border)',
                  whiteSpace: 'nowrap',
                  width: colWidths[i],
                  position: 'sticky', top: 0, background: 'var(--bg-elevated)',
                  userSelect: 'none',
                }}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => {
            const rowFlag = getFlag(i)
            const rowFlagColor = rowFlag ? ROW_FLAG_COLORS[rowFlag] : 'var(--text-muted)'
            const isExpanded = expandedRows.has(i)
            const rowBg = rowFlag
              ? `${rowFlagColor}14`
              : (i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)')
            return (
              <React.Fragment key={i}>
              <tr style={{
                borderBottom: '1px solid var(--border-soft)',
                background: rowBg,
              }}>
                {/* Leading expand chevron */}
                <td
                  onClick={e => { e.stopPropagation(); toggleRow(i) }}
                  title={isExpanded ? 'Collapse details' : 'Expand details'}
                  style={{
                    width: EXPAND_COL_WIDTH,
                    padding: '4px 4px', textAlign: 'center', verticalAlign: 'middle',
                    cursor: 'pointer', userSelect: 'none',
                    borderRight: '1px solid var(--border-soft)',
                    color: 'var(--accent)', fontWeight: 700, fontSize: 14,
                    lineHeight: 1,
                  }}
                  onMouseEnter={e => { e.currentTarget.style.background = 'rgba(168,85,247,0.18)' }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}
                >{isExpanded ? '▾' : '▸'}</td>
                {/* Leading flag cell — click to cycle through flag states */}
                <td
                  onClick={e => { e.stopPropagation(); onCycleFlag(i) }}
                  title={rowFlag ? `${rowFlag} (click to change)` : 'Click to flag this event'}
                  style={{
                    width: FLAG_COL_WIDTH,
                    padding: '4px 4px', textAlign: 'center', verticalAlign: 'middle',
                    cursor: 'pointer', userSelect: 'none',
                    borderRight: '1px solid var(--border-soft)',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.04)' }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}
                >
                  <span style={{
                    fontSize: 14, lineHeight: 1,
                    color: rowFlagColor,
                    transition: 'color 100ms',
                  }}>⚑</span>
                </td>
                {cols.map(c => {
                  const raw = row[c.key]
                  const val = c.renderVal ? c.renderVal(row)
                    : c.key === 'Timestamp' ? fmtTs(raw)
                    : (raw == null ? '—' : String(raw))
                  const highlightedVal = highlightMatches(val, searchTerm)
                  return (
                    <td key={c.key}
                      title={raw == null ? '' : String(raw)}
                      style={{
                        padding: '4px 8px', color: 'var(--text)', verticalAlign: 'top',
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                      }}>
                      {c.isIoc && raw ? (() => {
                        const iocVal = c.iocExtract ? c.iocExtract(String(raw)) : String(raw)
                        return (
                          <div style={{ display: 'flex', alignItems: 'center', gap: 4, overflow: 'hidden' }}>
                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', minWidth: 0 }}>{highlightedVal}</span>
                            {iocVal && (c.isIoc === 'cmdline'
                              ? <AddToIocButton ioc={iocVal} iocType="cmdline" compact />
                              : <VtButton ioc={iocVal} iocType={c.isIoc} />
                            )}
                          </div>
                        )
                      })() : highlightedVal}
                    </td>
                  )
                })}
              </tr>
              {isExpanded && (
                <tr style={{
                  borderBottom: '1px solid var(--border-soft)',
                  background: rowBg,
                }}>
                  <td colSpan={cols.length + 2} style={{
                    padding: '8px 14px 12px 38px',
                    background: 'rgba(255,255,255,0.02)',
                  }}>
                    <div style={{
                      display: 'grid', gridTemplateColumns: '130px 1fr',
                      rowGap: 6, columnGap: 14,
                      fontSize: 11 * zoom, lineHeight: 1.45,
                      fontFamily: 'var(--font-mono)',
                    }}>
                      {cols.map(c => {
                        const raw = row[c.key]
                        const val = c.renderVal ? c.renderVal(row)
                          : c.key === 'Timestamp' ? fmtTs(raw)
                          : (raw == null ? '—' : String(raw))
                        // VT lookup gets the extracted IOC value (e.g. domain
                        // from a full URL), same logic as the inline cell render.
                        const iocVal = c.isIoc && raw
                          ? (c.iocExtract ? c.iocExtract(String(raw)) : String(raw))
                          : null
                        return (
                          <React.Fragment key={c.key}>
                            <span style={{ color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: 9.5 * zoom, letterSpacing: 0.5 }}>
                              {c.label}
                            </span>
                            <span style={{
                              color: 'var(--text)', wordBreak: 'break-all',
                              whiteSpace: 'pre-wrap',
                              display: 'flex', flexWrap: 'wrap',
                              alignItems: 'center', gap: 6,
                            }}>
                              <span style={{ wordBreak: 'break-all' }}>
                                {highlightMatches(val, searchTerm)}
                              </span>
                              {iocVal && c.isIoc && (c.isIoc === 'cmdline'
                                ? <AddToIocButton ioc={iocVal} iocType="cmdline" />
                                : <VtButton ioc={iocVal} iocType={c.isIoc} />
                              )}
                            </span>
                          </React.Fragment>
                        )
                      })}
                    </div>
                  </td>
                </tr>
              )}
              </React.Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// Identical layout to the SHA1 block we used to render — label on top,
// monospace value + VT lookup chip below. Carries the right hashType
// so the VT lookup talks to the right endpoint and so any "+ IOC" add
// from the popover records the algorithm correctly.
function HashField({ label, value, hashType, searchTerm }: {
  label: string
  value: string
  hashType: 'sha1' | 'sha256' | 'md5'
  searchTerm?: string
}) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{
        color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
        fontSize: 9.5, letterSpacing: 0.5, textTransform: 'uppercase', marginBottom: 3,
      }}>{label}</div>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
        <div style={{
          color: value ? 'var(--text)' : 'var(--text-muted)',
          fontFamily: 'var(--font-mono)', fontSize: 11,
          wordBreak: 'break-all', lineHeight: 1.5, flex: 1,
        }}>{value ? highlightMatches(value, searchTerm) : '—'}</div>
        {value && <VtButton ioc={value} iocType="hash" hashType={hashType} />}
      </div>
    </div>
  )
}

function ProcessDetails({ node, searchTerm }: { node: ProcessNodeData; searchTerm?: string }) {
  const field = (label: string, value: string, muted = false) => (
    <div style={{ marginBottom: 10 }}>
      <div style={{
        color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
        fontSize: 9.5, letterSpacing: 0.5, textTransform: 'uppercase', marginBottom: 3,
      }}>{label}</div>
      <div style={{
        color: muted ? 'var(--text-muted)' : 'var(--text)',
        fontFamily: 'var(--font-mono)', fontSize: 11,
        wordBreak: 'break-all', lineHeight: 1.5,
      }}>{value ? highlightMatches(value, searchTerm) : '—'}</div>
    </div>
  )
  const time = fmtDateTime(node.timestamp)
  return (
    <div style={{ flexGrow: 1, flexShrink: 1, flexBasis: 0, minHeight: 0, overflow: 'auto', padding: '14px 16px', background: 'var(--bg-panel)' }}>
      {field('Process ID', String(node.pid))}
      {field('User', node.user)}
      {field('Timestamp', time)}
      {/* Command Line gets an inline "+ IOC" button so the analyst can
          pin a process invocation as evidence and pivot from the IOCs
          tab to hunt for every other host that ran the same cmdline. */}
      <div style={{ marginBottom: 10 }}>
        <div style={{
          color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
          fontSize: 9.5, letterSpacing: 0.5, textTransform: 'uppercase', marginBottom: 3,
        }}>Command Line</div>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
          <div style={{
            color: node.cmdline ? 'var(--text)' : 'var(--text-muted)',
            fontFamily: 'var(--font-mono)', fontSize: 11,
            wordBreak: 'break-all', lineHeight: 1.5, flex: 1,
          }}>{node.cmdline ? highlightMatches(node.cmdline, searchTerm) : '—'}</div>
          {node.cmdline && <AddToIocButton ioc={node.cmdline} iocType="cmdline" />}
        </div>
      </div>
      {field('Image Path', node.folder)}
      <HashField label="SHA256" value={node.sha256} hashType="sha256" searchTerm={searchTerm} />
      <HashField label="MD5"    value={node.md5}    hashType="md5"    searchTerm={searchTerm} />
      {node.child_node_keys.length > 0 &&
        field('Children', `${node.child_node_keys.length} child process${node.child_node_keys.length !== 1 ? 'es' : ''}`)}
    </div>
  )
}

interface Props {
  node: ProcessNodeData | null
  inv: Investigation
  prefetchRef?: React.MutableRefObject<((nodes: ProcessNodeData[]) => void) | null>
  // Row-level event flags lifted to the parent so they survive switching to
  // other right-panel tabs (AI Analysis / Host Details) and back. Keyed by
  // `${node_key}:${tab}:${rowIdx}`.
  rowFlags: Map<string, FlagStatus>
  setRowFlags: React.Dispatch<React.SetStateAction<Map<string, FlagStatus>>>
  // Called when a row's flag is set/cleared with the resolved row data, so the
  // parent can keep a parallel cache of flagged rows and feed them to the AI
  // analysis payload even when this panel is unmounted.
  onRowFlagSet?: (key: string, flag: FlagStatus, row: Record<string, unknown> | null) => void
  // The live tree-search term — highlighted inside event cells so analysts
  // can see which fields the search matched in the telemetry too.
  searchTerm?: string
  // Map of process flags from the tree so the node header in this panel
  // reflects the analyst's flag for the currently-selected process.
  processFlags?: Map<string, FlagStatus>
  // Called with the selected node's node_key to cycle its flag — wired to
  // whichever tree view (graph or table) is currently mounted.
  onCycleProcessFlag?: (nodeKey: string) => void
  // Lets the parent force which sub-tab (proc/net/files/reg/dlls/scripts) is
  // active — used by the "manage flagged events" popup to land the analyst
  // on the right tab when they click an event to examine it.
  activeTabSetterRef?: React.MutableRefObject<((tab: 'process' | 'network' | 'files' | 'registry' | 'dlls' | 'scripts') => void) | null>
}

// Wrap occurrences of `term` (case-insensitive) inside `text` with a <mark>.
// Returns the raw text untouched when term is empty/absent so we avoid
// allocating React nodes for every cell on every render.
function highlightMatches(text: string, term: string | undefined): React.ReactNode {
  if (!term) return text
  const lowerTerm = term.toLowerCase()
  // Require 2+ chars so a single typed letter doesn't blanket-highlight the
  // panel (matches the tree-table search threshold).
  if (lowerTerm.length < 2) return text
  const lowerText = text.toLowerCase()
  if (!lowerText.includes(lowerTerm)) return text

  const parts: React.ReactNode[] = []
  let i = 0
  let key = 0
  while (i < text.length) {
    const idx = lowerText.indexOf(lowerTerm, i)
    if (idx === -1) { parts.push(text.slice(i)); break }
    if (idx > i) parts.push(text.slice(i, idx))
    parts.push(
      <mark key={key++} style={{
        background: '#FFEB3B',
        color: '#000',
        fontWeight: 700,
        padding: '0 2px', borderRadius: 2,
      }}>{text.slice(idx, idx + term.length)}</mark>
    )
    i = idx + term.length
  }
  return parts
}

export default function TelemetryPanel({ node, inv, prefetchRef, rowFlags, setRowFlags, onRowFlagSet, searchTerm, processFlags, onCycleProcessFlag, activeTabSetterRef }: Props) {
  const [activeTab, setActiveTab] = useState<TelTab>('process')
  // Text-size zoom for telemetry-row content. 0.85–1.6× of base sizes.
  const [textZoom, setTextZoom] = useState(1.0)
  const textZoomMin = 0.85, textZoomMax = 1.6
  const cacheRef = useRef<Map<string, Record<string, unknown>[]>>(new Map())
  const tabStateRef = useRef<Map<string, { loading: boolean; error: string | null }>>(new Map())
  const [version, setVersion] = useState(0)
  const bump = useCallback(() => setVersion(v => v + 1), [])
  const flagKey = useCallback(
    (nk: string, tab: TelTab, idx: number) => `${nk}:${tab}:${idx}`,
    [],
  )

  useEffect(() => {
    setActiveTab('process')
  }, [node?.node_key])

  const fetchAndCache = useCallback(async (n: ProcessNodeData, tab: TelTab) => {
    if (tab === 'process') return
    const key = `${n.node_key}:${tab}`
    if (cacheRef.current.has(key)) return
    if (tabStateRef.current.get(key)?.loading) return

    tabStateRef.current.set(key, { loading: true, error: null })
    bump()
    try {
      const res = await fetchTelemetry({
        hostname: inv.hostname,
        pid: n.pid,
        username: n.user,
        focal_time: n.timestamp || inv.focalTimeIso,
        time_window: inv.rawTimeWindow,
        table: tab,
      })
      if (!res.ok) {
        tabStateRef.current.set(key, { loading: false, error: friendlyError(res.error || 'Request failed.') })
      } else {
        cacheRef.current.set(key, res.rows)
        tabStateRef.current.set(key, { loading: false, error: null })
      }
    } catch (e) {
      tabStateRef.current.set(key, { loading: false, error: friendlyError(e) })
    }
    bump()
  }, [inv, bump])

  const loadTab = useCallback(async (tab: TelTab) => {
    if (!node) return
    return fetchAndCache(node, tab)
  }, [node, fetchAndCache])

  // Keep a stable ref to loadTab so the auto-fetch effect doesn't re-run when loadTab is recreated
  const loadTabRef = useRef(loadTab)
  loadTabRef.current = loadTab

  // Auto-fetch all telemetry tabs whenever the selected node changes
  useEffect(() => {
    if (!node) return
    loadTabRef.current('network')
    loadTabRef.current('files')
    loadTabRef.current('registry')
    loadTabRef.current('dlls')
    loadTabRef.current('scripts')
  }, [node?.node_key])

  // Let the parent flip the active sub-tab (used by the manage-flagged-events
  // popup so clicking an event lands the analyst on the right sub-tab).
  useEffect(() => {
    if (!activeTabSetterRef) return
    activeTabSetterRef.current = (tab: TelTab) => {
      setActiveTab(tab)
      if (tab !== 'process') loadTabRef.current(tab)
    }
    return () => { if (activeTabSetterRef) activeTabSetterRef.current = null }
  }, [activeTabSetterRef])

  // Expose a prefetch callback so the parent can warm the cache for flagged
  // nodes when an AI analysis is kicked off.
  useEffect(() => {
    if (!prefetchRef) return
    prefetchRef.current = (nodes: ProcessNodeData[]) => {
      for (const n of nodes) {
        fetchAndCache(n, 'network')
        fetchAndCache(n, 'files')
        fetchAndCache(n, 'registry')
        fetchAndCache(n, 'dlls')
        fetchAndCache(n, 'scripts')
      }
    }
  }, [fetchAndCache, prefetchRef])

  void version  // satisfies lint; bump() triggers re-renders when tab state or cache updates

  function handleTabChange(tab: TelTab) {
    setActiveTab(tab)
    loadTab(tab)
  }

  if (!node) {
    return (
      <div style={{
        flexGrow: 1, flexShrink: 1, flexBasis: 0, overflow: 'auto', padding: '24px 18px',
        background: 'var(--bg-panel)', fontFamily: 'var(--font-mono)',
      }}>
        <div style={{ color: 'var(--accent)', marginBottom: 8, fontSize: 12 }}>▌ no process selected</div>
        <div style={{ color: 'var(--text-muted)', lineHeight: 1.7, fontSize: 11.5 }}>
          click a node in the tree to inspect it.<br />
          process details, network, file and registry events appear here.
        </div>
      </div>
    )
  }

  const isTelTab = activeTab !== 'process'
  const cacheKey = isTelTab ? `${node.node_key}:${activeTab}` : null
  const rows = cacheKey ? (cacheRef.current.get(cacheKey) ?? null) : null
  const tabState = cacheKey ? (tabStateRef.current.get(cacheKey) ?? null) : null
  const loading = tabState?.loading ?? false
  const error = tabState?.error ?? null
  const cols = isTelTab ? (COLS[activeTab] ?? []) : []

  return (
    <div style={{
      flexGrow: 1, flexShrink: 1, flexBasis: 0, display: 'flex', flexDirection: 'column', minHeight: 0,
      position: 'relative', background: 'var(--bg-panel)',
    }}>
      {/* Flag-coloured tint overlay — sits on top of every inner section so
          the entire panel reads as "this process is flagged" at a glance.
          pointer-events: none lets clicks pass through to the elements below. */}
      {(() => {
        const f = node ? (processFlags?.get(node.node_key) ?? null) : null
        if (!f) return null
        const c = ROW_FLAG_COLORS[f]
        return (
          <div style={{
            position: 'absolute', inset: 0, zIndex: 6,
            pointerEvents: 'none',
            background: `${c}1a`,   // ~10% alpha — visible without washing out text
          }} />
        )
      })()}
      {/* Node header — uses the analyst's flag colour if this process is flagged */}
      {(() => {
        const nodeFlag = processFlags?.get(node.node_key) ?? null
        const flagColor = nodeFlag ? ROW_FLAG_COLORS[nodeFlag] : null
        const headerColor = flagColor ?? 'var(--accent)'
        return (
          <div style={{
            padding: '10px 14px',
            borderBottom: '1px solid var(--border)',
            borderLeft: flagColor ? `3px solid ${flagColor}` : '3px solid transparent',
            background: flagColor ? `${flagColor}14` : 'var(--bg-elevated)',
            flexShrink: 0,
          }}>
            <div style={{
              fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: 15,
              color: headerColor, display: 'flex', alignItems: 'center', gap: 10,
              overflow: 'hidden',
            }}>
              <span>▌</span>
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {node.name}
              </span>
              <span style={{ color: 'var(--text-muted)', fontSize: 11, fontWeight: 500 }}>
                pid {node.pid}
              </span>
              {/* Flag toggle — cycle through none/benign/suspicious/malicious */}
              {onCycleProcessFlag && (
                <button
                  onClick={() => onCycleProcessFlag(node.node_key)}
                  onMouseDown={e => e.preventDefault()}
                  title={nodeFlag ? `Flagged ${nodeFlag} — click to cycle` : 'Click to flag this process'}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)' }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = (nodeFlag ? (flagColor as string) : 'var(--border)') }}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 5,
                    background: nodeFlag ? `${flagColor}1f` : 'transparent',
                    border: `1px solid ${nodeFlag ? flagColor : 'var(--border)'}`,
                    color: nodeFlag ? flagColor! : 'var(--text-muted)',
                    fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
                    padding: '3px 10px', borderRadius: 3,
                    cursor: 'pointer', userSelect: 'none', flexShrink: 0,
                    transition: 'border-color 100ms, background 100ms',
                  }}>
                  <span style={{ fontSize: 13, lineHeight: 1 }}>⚑</span>
                  {nodeFlag ? nodeFlag.toUpperCase() : 'FLAG'}
                </button>
              )}
              {node.is_focal && (
                <span style={{
                  fontSize: 9, padding: '2px 6px', borderRadius: 2, fontWeight: 700, flexShrink: 0,
                  background: 'rgba(94,129,172,0.18)', color: 'var(--accent)',
                }}>FOCAL</span>
              )}
              {node.is_lolbin && (
                <span style={{
                  fontSize: 9, padding: '2px 6px', borderRadius: 2, fontWeight: 700, flexShrink: 0,
                  background: 'rgba(240,179,64,0.12)', color: 'var(--amber)',
                }}>LOLBIN</span>
              )}
            </div>
          </div>
        )
      })()}

      {/* Sub-tab strip */}
      <div style={{
        display: 'flex', background: 'var(--bg-app)', borderBottom: '1px solid var(--border)',
        fontFamily: 'var(--font-mono)', fontSize: 12.5, flexShrink: 0, overflowX: 'auto',
      }}>
        {TEL_TABS.map(t => {
          const on = t.id === activeTab
          const isTelTab = t.id !== 'process'
          const tabKey = isTelTab ? `${node.node_key}:${t.id}` : null
          const tabRows = tabKey ? cacheRef.current.get(tabKey) : undefined
          const tabLoading = tabKey ? (tabStateRef.current.get(tabKey)?.loading ?? false) : false
          const tabError = tabKey ? (tabStateRef.current.get(tabKey)?.error ?? null) : null
          return (
            <div key={t.id} onClick={() => handleTabChange(t.id)}
              style={{
                padding: '8px 14px', cursor: 'pointer', whiteSpace: 'nowrap',
                color: on ? 'var(--text)' : 'var(--text-muted)',
                borderBottom: `2px solid ${on ? 'var(--accent)' : 'transparent'}`,
                transition: 'color 100ms, border-color 100ms',
                display: 'flex', alignItems: 'center', gap: 6,
              }}>
              {t.label}
              {tabLoading && (
                <span style={{ fontSize: 9, color: 'var(--text-muted)', opacity: 0.6 }}>…</span>
              )}
              {!tabLoading && tabError && (
                <span style={{ fontSize: 9, color: 'var(--red)' }}>!</span>
              )}
              {!tabLoading && !tabError && tabRows !== undefined && (
                <span style={{
                  fontSize: 9, padding: '1px 4px', borderRadius: 2, fontWeight: 600,
                  background: tabRows.length > 0 ? 'rgba(94,129,172,0.18)' : 'rgba(255,255,255,0.04)',
                  color: tabRows.length > 0 ? 'var(--accent)' : 'var(--text-muted)',
                }}>
                  {tabRows.length}
                </span>
              )}
            </div>
          )
        })}
      </div>

      {/* Tab content */}
      {activeTab === 'process' && <ProcessDetails node={node} searchTerm={searchTerm} />}

      {activeTab !== 'process' && (
        <div style={{ flexGrow: 1, flexShrink: 1, flexBasis: 0, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          {loading && (
            <div style={{
              padding: '14px', fontFamily: 'var(--font-mono)', fontSize: 11,
              display: 'flex', alignItems: 'center', gap: 8,
            }}>
              <span style={{ color: 'var(--accent)' }}>▌</span>
              <span style={{ color: 'var(--text-muted)' }}>querying {activeTab} events…</span>
            </div>
          )}
          {!loading && error && (
            <div style={{ padding: '14px', color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              ✗ {error}
            </div>
          )}
          {!loading && !error && rows !== null && (
            <TelTable
              key={activeTab}
              rows={rows}
              cols={cols}
              zoom={textZoom}
              searchTerm={searchTerm}
              getFlag={idx => node ? (rowFlags.get(flagKey(node.node_key, activeTab, idx)) ?? null) : null}
              onCycleFlag={idx => {
                if (!node) return
                const k = flagKey(node.node_key, activeTab, idx)
                const cur = rowFlags.get(k) ?? null
                const nextFlag = ROW_FLAG_CYCLE[(ROW_FLAG_CYCLE.indexOf(cur) + 1) % ROW_FLAG_CYCLE.length]
                setRowFlags(prev => {
                  const next = new Map(prev)
                  if (nextFlag === null) next.delete(k)
                  else next.set(k, nextFlag)
                  return next
                })
                if (onRowFlagSet) {
                  const tabRows = cacheRef.current.get(`${node.node_key}:${activeTab}`)
                  const row = tabRows ? tabRows[idx] : null
                  onRowFlagSet(k, nextFlag, row ?? null)
                }
              }}
            />
          )}
        </div>
      )}

      {/* Floating text-size controls — bottom-right of the panel.
          Show on every tab except the (no-data) process detail tab. */}
      {activeTab !== 'process' && (
        <div style={{
          position: 'absolute', bottom: 8, right: 10, zIndex: 4,
          display: 'flex', gap: 0,
          background: 'var(--bg-app)', padding: 2,
          borderRadius: 4, border: '1px solid var(--border-soft)',
          boxShadow: '0 2px 8px rgba(0,0,0,0.35)',
        }}>
          <button
            onClick={() => setTextZoom(z => Math.max(textZoomMin, Math.round((z - 0.1) * 10) / 10))}
            title="Smaller text"
            onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-card)'; e.currentTarget.style.color = 'var(--text)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-elevated)'; e.currentTarget.style.color = 'var(--text-muted)' }}
            style={{
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              borderRight: 'none', borderRadius: '3px 0 0 3px',
              color: 'var(--text-muted)', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600,
              padding: '3px 9px', lineHeight: 1,
              transition: 'background 100ms, color 100ms',
            }}>−</button>
          <button
            onClick={() => setTextZoom(z => Math.min(textZoomMax, Math.round((z + 0.1) * 10) / 10))}
            title="Bigger text"
            onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-card)'; e.currentTarget.style.color = 'var(--text)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-elevated)'; e.currentTarget.style.color = 'var(--text-muted)' }}
            style={{
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              borderRadius: '0 3px 3px 0',
              color: 'var(--text-muted)', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600,
              padding: '3px 9px', lineHeight: 1,
              transition: 'background 100ms, color 100ms',
            }}>+</button>
        </div>
      )}
    </div>
  )
}

