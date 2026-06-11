import { memo, useCallback, useState, useRef, useLayoutEffect } from 'react'
import { createPortal } from 'react-dom'
import { Handle, Position } from '@xyflow/react'
import type { NodeProps } from '@xyflow/react'
import type { FlagStatus, ProcessNodeData } from '../types'
import { NODE_W } from '../utils/treeLayout'

// Wrap occurrences of `term` (case-insensitive, 2+ chars) inside `text` with
// a yellow <mark>. Matches the highlight style used in the table and
// telemetry views so the same word stands out everywhere.
function highlightMatches(text: string | undefined, term: string | undefined): React.ReactNode {
  if (!text) return text ?? ''
  if (!term) return text
  const lowerTerm = term.toLowerCase()
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
        background: '#FFEB3B', color: '#000', fontWeight: 700,
        padding: '0 2px', borderRadius: 2,
      }}>{text.slice(idx, idx + term.length)}</mark>
    )
    i = idx + term.length
  }
  return parts
}

const FLAG_CYCLE: FlagStatus[] = [null, 'benign', 'suspicious', 'malicious']

const FLAG_COLORS: Record<NonNullable<FlagStatus>, string> = {
  malicious:   '#FF5E5B',
  suspicious:  '#F0B340',
  investigate: '#7AA8FF',
  benign:      '#7DD3A0',
}

const FLAG_BG: Record<NonNullable<FlagStatus>, string> = {
  malicious:   'rgba(255,94,91,0.13)',
  suspicious:  'rgba(240,179,64,0.13)',
  investigate: 'rgba(122,168,255,0.10)',
  benign:      'rgba(125,211,160,0.10)',
}

export interface ProcessNodeExtended extends ProcessNodeData {
  flag: FlagStatus
  selected: boolean
  expanded: boolean
  isMatch: boolean
  isDimmed: boolean
  searchTerm?: string
  onSelect: (key: string) => void
  onToggleExpand: (key: string) => void
  onFlag: (key: string, f: FlagStatus) => void
  onPivot: (pid: number, timestamp: string | null) => void
}

function ProcessNodeInner({ data }: NodeProps) {
  const d = data as unknown as ProcessNodeExtended
  const flagColor = d.flag ? FLAG_COLORS[d.flag] : 'var(--border)'
  const borderColor = d.selected ? 'var(--accent)' : flagColor

  const [pivotOpen, setPivotOpen] = useState(false)
  const [anchor, setAnchor]       = useState({ top: 0, left: 0 })
  const [visible, setVisible]     = useState(false)
  const pidRef    = useRef<HTMLSpanElement>(null)
  const popRef    = useRef<HTMLDivElement>(null)

  const handleFlagClick = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    const idx = FLAG_CYCLE.indexOf(d.flag)
    d.onFlag(d.node_key, FLAG_CYCLE[(idx + 1) % FLAG_CYCLE.length])
  }, [d])

  const handleExpandClick = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    d.onToggleExpand(d.node_key)
  }, [d])

  const handlePidClick = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    if (pidRef.current) {
      const r = pidRef.current.getBoundingClientRect()
      setAnchor({ top: r.bottom + 6, left: r.left })
    }
    setVisible(false)
    setPivotOpen(o => !o)
  }, [])

  const handleConfirmPivot = useCallback((e: React.MouseEvent) => {
    e.stopPropagation()
    setPivotOpen(false)
    d.onPivot(d.pid, d.timestamp)
  }, [d])

  // Position popover so it stays inside viewport
  useLayoutEffect(() => {
    if (!pivotOpen || !popRef.current) return
    const pop = popRef.current.getBoundingClientRect()
    const vw = window.innerWidth
    const vh = window.innerHeight
    const GAP = 6
    const PAD = 8
    let top  = anchor.top
    let left = anchor.left
    if (top + pop.height > vh - PAD) top = Math.max(PAD, anchor.top - pop.height - GAP * 2)
    if (left + pop.width  > vw - PAD) left = Math.max(PAD, vw - pop.width - PAD)
    popRef.current.style.top  = `${top}px`
    popRef.current.style.left = `${left}px`
    setVisible(true)
  }, [pivotOpen, anchor])

  // Close on outside click or Esc. Use capture phase for mousedown — React
  // Flow stops propagation inside its canvas (for pan/drag), so a bubble-phase
  // listener never sees clicks on the tree background or other nodes.
  useLayoutEffect(() => {
    if (!pivotOpen) return
    function onDown(e: MouseEvent) {
      const t = e.target as Node
      if (pidRef.current?.contains(t) || popRef.current?.contains(t)) return
      setPivotOpen(false)
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setPivotOpen(false)
    }
    document.addEventListener('mousedown', onDown, true)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown, true)
      document.removeEventListener('keydown', onKey)
    }
  }, [pivotOpen])

  const time = d.timestamp ? d.timestamp.slice(11, 19) : ''

  return (
    <>
      <Handle type="target" position={Position.Top}
        style={{ opacity: 0, pointerEvents: 'none' }} />

      <div
        onClick={() => d.onSelect(d.node_key)}
        style={{
          width: NODE_W,
          background: d.flag ? FLAG_BG[d.flag] : (d.selected ? 'var(--bg-elevated)' : 'var(--bg-card)'),
          border: `1px solid ${d.isMatch ? 'var(--amber)' : borderColor}`,
          borderLeft: `3px solid ${d.isMatch ? 'var(--amber)' : borderColor}`,
          borderRadius: 4,
          display: 'flex',
          flexDirection: 'column',
          gap: 0,
          cursor: 'pointer',
          boxShadow: d.isMatch ? '0 0 0 1px var(--amber)' : (d.selected ? `0 0 0 1px ${borderColor}` : undefined),
          opacity: d.isDimmed ? 0.35 : 1,
          transition: 'border-color 100ms, background 100ms, opacity 100ms',
        }}
      >
        {/* Header row */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '6px 10px 4px',
          borderBottom: '1px solid var(--border-soft)',
        }}>
          {d.is_focal && (
            <span style={{
              fontSize: 9, letterSpacing: 0.5, padding: '1px 5px',
              background: 'rgba(168,85,247,0.15)', color: 'var(--accent)',
              borderRadius: 2, fontFamily: 'var(--font-mono)', fontWeight: 600,
              flexShrink: 0,
            }}>FOCAL</span>
          )}
          {d.is_lolbin && (
            <span style={{
              fontSize: 9, letterSpacing: 0.5, padding: '1px 5px',
              background: 'rgba(240,179,64,0.12)', color: 'var(--amber)',
              borderRadius: 2, fontFamily: 'var(--font-mono)', fontWeight: 600,
              flexShrink: 0,
            }}>LOLBIN</span>
          )}
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 12.5, fontWeight: 600,
            color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            flex: 1,
          }}>{highlightMatches(d.name, d.searchTerm)}</span>
          <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 10, flexShrink: 0 }}>
            {time}
          </span>
        </div>

        {/* Meta row */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '3px 10px',
          fontFamily: 'var(--font-mono)', fontSize: 10,
        }}>
          <span style={{ color: 'var(--text-muted)' }}>pid</span>
          <span
            ref={pidRef}
            onClick={handlePidClick}
            onMouseEnter={e => {
              e.currentTarget.style.color = 'var(--accent)'
              e.currentTarget.style.background = 'rgba(168,85,247,0.15)'
              e.currentTarget.style.borderColor = 'var(--accent)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.color = 'var(--text-muted)'
              e.currentTarget.style.background = 'var(--bg-elevated)'
              e.currentTarget.style.borderColor = 'var(--border)'
            }}
            title="Click to pivot to new investigation"
            style={{
              color: 'var(--text-muted)', cursor: 'pointer',
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border)',
              borderRadius: 2, padding: '1px 5px',
              transition: 'background 100ms, color 100ms, border-color 100ms',
              fontSize: 9, fontWeight: 600, letterSpacing: 0.3,
            }}
          >{highlightMatches(String(d.pid), d.searchTerm)}</span>
          <span style={{ color: 'var(--border)' }}>·</span>
          <span style={{ color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
            {d.user ? highlightMatches(d.user, d.searchTerm) : '—'}
          </span>
          {d.sha1 && (
            <span style={{ color: 'var(--text-muted)', fontSize: 9.5, flexShrink: 0 }}>{highlightMatches(d.sha1.slice(0, 8), d.searchTerm)}</span>
          )}
        </div>

        {/* Cmdline */}
        <div style={{
          padding: '2px 10px 4px',
          fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)',
          overflow: 'hidden',
          display: '-webkit-box',
          WebkitLineClamp: 5,
          WebkitBoxOrient: 'vertical' as const,
          lineHeight: 1.45,
          wordBreak: 'break-all',
        }}>{d.cmdline ? highlightMatches(d.cmdline, d.searchTerm) : '—'}</div>

        {/* Footer row */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '3px 8px 5px',
          borderTop: '1px solid var(--border-soft)',
        }}>
          {/* Flag chip */}
          <button
            onClick={handleFlagClick}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--accent)'
              e.currentTarget.style.background = 'rgba(168,85,247,0.15)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = d.flag ? FLAG_COLORS[d.flag] : 'var(--border)'
              e.currentTarget.style.background = d.flag ? FLAG_BG[d.flag] : 'var(--bg-elevated)'
            }}
            style={{
              background: d.flag ? FLAG_BG[d.flag] : 'var(--bg-elevated)',
              border: `1px solid ${d.flag ? FLAG_COLORS[d.flag] : 'var(--border)'}`,
              borderRadius: 2, padding: '1px 7px',
              fontFamily: 'var(--font-mono)', fontSize: 9, letterSpacing: 0.4,
              color: d.flag ? FLAG_COLORS[d.flag] : 'var(--text-muted)',
              cursor: 'pointer', fontWeight: 600, transition: 'border-color 100ms, background 100ms',
              display: 'inline-flex', alignItems: 'center', gap: 4,
            }}>
            <span style={{ fontSize: 11, lineHeight: 1 }}>⚑</span>
            {d.flag?.toUpperCase() ?? 'FLAG'}
          </button>

          <div style={{ flex: 1 }} />

          {/* Expand/collapse toggle */}
          {d.child_node_keys.length > 0 && (
            <button
              onClick={handleExpandClick}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
              style={{
                background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                borderRadius: 2, padding: '1px 7px',
                fontFamily: 'var(--font-mono)', fontSize: 9,
                color: 'var(--text-muted)', cursor: 'pointer',
                transition: 'border-color 100ms, color 100ms',
              }}>
              {d.expanded ? '▴ collapse' : `▾ ${d.child_node_keys.length} child${d.child_node_keys.length > 1 ? 'ren' : ''}`}
            </button>
          )}
        </div>
      </div>

      <Handle type="source" position={Position.Bottom}
        style={{ opacity: 0, pointerEvents: 'none' }} />

      {/* Pivot confirmation popover */}
      {pivotOpen && createPortal(
        <div
          ref={popRef}
          onClick={e => e.stopPropagation()}
          style={{
            position: 'fixed',
            top: anchor.top,
            left: anchor.left,
            visibility: visible ? 'visible' : 'hidden',
            zIndex: 9999,
            background: 'var(--bg-panel)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            padding: '14px 16px',
            width: 260,
            fontFamily: 'var(--font-mono)',
            fontSize: 11,
            boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
          }}
        >
          <div style={{ color: 'var(--text)', fontWeight: 600, marginBottom: 6 }}>
            Pivot to new investigation
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: 10.5, lineHeight: 1.6, marginBottom: 14 }}>
            Set <span style={{ color: 'var(--accent)' }}>PID {d.pid}</span> ({d.name}) as the focal
            process and start a new investigation?
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={handleConfirmPivot} style={{
              flex: 1,
              background: 'var(--accent)', border: 'none', borderRadius: 3,
              color: '#fff', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 10.5, fontWeight: 600,
              padding: '5px 10px',
            }}>Pivot ↗</button>
            <button onClick={e => { e.stopPropagation(); setPivotOpen(false) }} style={{
              background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
              color: 'var(--text-muted)', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 10.5,
              padding: '5px 10px',
            }}>cancel</button>
          </div>
        </div>,
        document.body
      )}
    </>
  )
}

export const ProcessNodeComponent = memo(ProcessNodeInner)
