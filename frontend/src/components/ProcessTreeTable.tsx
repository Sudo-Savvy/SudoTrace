import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import type { FlagStatus, ProcessNodeData, InvestigateResponse } from '../types'
import { fetchProcessTree } from '../api/investigate'
import { fmtDateTime } from '../utils/dateFormat'

// Wrap occurrences of `term` (case-insensitive) inside `text` with a yellow
// <mark> so search hits stand out within each row's cells. Mirrors the helper
// in TelemetryPanel — duplicated rather than imported to keep the components
// uncoupled.
function highlightMatches(text: string | undefined, term: string | undefined): React.ReactNode {
  if (!text) return text ?? ''
  if (!term) return text
  const lowerTerm = term.toLowerCase()
  // Require at least 2 chars so single-letter typing doesn't flood the view.
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

type ColKey = 'name' | 'pid' | 'user' | 'time' | 'cmdline'

const DEFAULT_COL_WIDTHS: Record<ColKey, number> = {
  // `name` covers the combined leading cell: depth-indent + expand triangle
  // + flag glyph + the process name itself. Wider than just the name text
  // since it has to fit all four pieces.
  name:    340,
  pid:     70,
  user:    140,
  time:    150,
  cmdline: 800,
}
const MIN_COL_WIDTH = 50
const INDENT_PER_LEVEL = 16   // px indent per tree depth in the body

interface Props {
  hostname: string
  focalPid: number
  focalTimeIso: string | null
  rawTimeWindow: string
  alertId?: string | null
  onSelect: (node: ProcessNodeData | null) => void
  onDataLoaded: (data: InvestigateResponse | null) => void
  onReset: () => void
  initialData: InvestigateResponse | null
  collapseAllRef?: React.MutableRefObject<(() => void) | null>
  expandAllRef?: React.MutableRefObject<(() => void) | null>
  matchNavPrevRef?: React.MutableRefObject<(() => void) | null>
  matchNavNextRef?: React.MutableRefObject<(() => void) | null>
  searchTerm?: string
  onSearchChange?: (s: string) => void
  onMatchCount?: (n: number) => void
  onMatchNav?: (current: number, total: number) => void
  onFlagsChange?: (count: number) => void
  onFlagsMapChange?: (flags: Map<string, FlagStatus>) => void
  flagSetterRef?: React.MutableRefObject<((nodeKey: string) => void) | null>
  flagSetExplicitRef?: React.MutableRefObject<((nodeKey: string, flag: FlagStatus) => void) | null>
  flagsRef?: React.MutableRefObject<Map<string, FlagStatus>>
  revealNodeRef?: React.MutableRefObject<((nodeKey: string) => void) | null>
  visibleKeysRef?: React.MutableRefObject<Set<string>>
  expandedKeysRef?: React.MutableRefObject<Set<string>>
  onPivot?: (pid: number, timestamp: string | null) => void
  onHostnameResolved?: (hostname: string, pid: number) => void
}

function initVisibleKeys(res: InvestigateResponse): { visible: Set<string>; expanded: Set<string> } {
  return { visible: new Set<string>(res.ancestry_chain), expanded: new Set<string>() }
}

function AmbiguityPicker({ focalPid, candidates, nodes, onPick }: {
  focalPid: number
  candidates: string[]
  nodes: Record<string, ProcessNodeData>
  onPick: (nodeKey: string) => void
}) {
  return (
    <div style={{
      background: 'var(--bg-panel)', border: '1px solid var(--border)',
      borderRadius: 6, padding: '22px 26px', maxWidth: 480, width: '100%',
      fontFamily: 'var(--font-mono)',
    }}>
      <div style={{ color: 'var(--amber)', fontWeight: 600, fontSize: 11, letterSpacing: 0.5, marginBottom: 6 }}>
        PID_AMBIGUOUS
      </div>
      <div style={{ color: 'var(--text-muted)', fontSize: 11, lineHeight: 1.6, marginBottom: 16 }}>
        PID <span style={{ color: 'var(--text)' }}>{focalPid}</span> matched {candidates.length} process instances
        in this time window. Select the one to investigate:
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {candidates.map(key => {
          const n = nodes[key]
          if (!n) return null
          const ts = fmtDateTime(n.timestamp)
          return (
            <div key={key} onClick={() => onPick(key)}
              style={{
                background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '10px 14px', cursor: 'pointer',
                transition: 'border-color 120ms, background 120ms',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.borderColor = 'var(--accent)'
                e.currentTarget.style.background = 'var(--bg-card)'
              }}
              onMouseLeave={e => {
                e.currentTarget.style.borderColor = 'var(--border)'
                e.currentTarget.style.background = 'var(--bg-elevated)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                <span style={{ color: 'var(--text)', fontWeight: 600, fontSize: 12 }}>{n.name}</span>
                <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>{ts}</span>
              </div>
              <div style={{
                color: 'var(--text-muted)', fontSize: 10, lineHeight: 1.4,
                overflow: 'hidden', display: '-webkit-box',
                WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' as const,
                wordBreak: 'break-all',
              }}>{n.cmdline || '—'}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default function ProcessTreeTable({
  hostname, focalPid, focalTimeIso, rawTimeWindow, alertId,
  onSelect, onDataLoaded, onReset, initialData,
  collapseAllRef, expandAllRef, matchNavPrevRef, matchNavNextRef,
  searchTerm, onSearchChange, onMatchCount, onMatchNav, onFlagsChange, onFlagsMapChange, flagSetterRef, flagSetExplicitRef, flagsRef,
  revealNodeRef, visibleKeysRef, expandedKeysRef,
  onPivot, onHostnameResolved,
}: Props) {
  const [data, setData] = useState<InvestigateResponse | null>(initialData)
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(!initialData)
  const [pinnedNodeKey, setPinnedNodeKey] = useState<string | null>(null)

  // Seed visible/expanded from the shared refs so a switch from the graph
  // view preserves the analyst's expansion. Falls back to ancestry-only.
  const [visibleKeys, setVisibleKeys] = useState<Set<string>>(() => {
    if (visibleKeysRef?.current && visibleKeysRef.current.size > 0) {
      return new Set(visibleKeysRef.current)
    }
    return initialData ? initVisibleKeys(initialData).visible : new Set()
  })
  const [expandedKeys, setExpandedKeys] = useState<Set<string>>(() => {
    if (expandedKeysRef?.current) return new Set(expandedKeysRef.current)
    return initialData ? initVisibleKeys(initialData).expanded : new Set()
  })
  // Seed flags from the shared ref so view-switching from the React Flow tree
  // preserves the analyst's flags.
  const [flags, setFlags] = useState<Map<string, FlagStatus>>(
    () => flagsRef?.current ? new Map(flagsRef.current) : new Map(),
  )
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  // Zoom multiplier for the whole table — affects row font + cell sizes so
  // the analyst can resize click targets without changing browser zoom.
  const [zoom, setZoom] = useState(1.0)
  const zoomMin = 0.85, zoomMax = 1.6
  // Per-column pixel widths (resizable via drag handles on the header).
  const [colWidths, setColWidths] = useState<Record<ColKey, number>>(DEFAULT_COL_WIDTHS)

  const dataRef = useRef(data)
  useEffect(() => { dataRef.current = data }, [data])

  const matchKeysRef = useRef<string[]>([])
  const matchIndexRef = useRef(0)
  const rowRefs = useRef<Map<string, HTMLDivElement | null>>(new Map())
  const scrollRef = useRef<HTMLDivElement | null>(null)

  // ── Fetching ────────────────────────────────────────────────────────────
  function doFetch(nodeKey?: string) {
    setLoading(true)
    setLoadErr(null)
    setData(null)
    setVisibleKeys(new Set())
    setSelectedKey(null)
    setExpandedKeys(new Set())
    onSelect(null)

    fetchProcessTree({
      hostname,
      focal_pid: focalPid,
      focal_time: focalTimeIso,
      time_window: rawTimeWindow,
      ...(alertId ? { alert_id: alertId } : {}),
      ...(nodeKey ? { focal_node_key: nodeKey } : {}),
    })
      .then(res => {
        setData(res)
        onDataLoaded(res)
        if (res.resolved_hostname && onHostnameResolved) {
          onHostnameResolved(res.resolved_hostname, res.resolved_pid ?? 0)
        }
        if (res.nodes) {
          const { visible, expanded } = initVisibleKeys(res)
          setVisibleKeys(visible)
          setExpandedKeys(expanded)
        }
      })
      .catch(e => setLoadErr(String(e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    setPinnedNodeKey(null)
    if (initialData) return
    doFetch()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hostname, focalPid, focalTimeIso, rawTimeWindow])

  useEffect(() => {
    if (!pinnedNodeKey) return
    doFetch(pinnedNodeKey)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pinnedNodeKey])

  // ── Callbacks ───────────────────────────────────────────────────────────
  const handleSelect = useCallback((key: string) => {
    setSelectedKey(prev => {
      const next = prev === key ? null : key
      onSelect(next && data ? (data.nodes[next] ?? null) : null)
      return next
    })
  }, [data, onSelect])

  const handleFlag = useCallback((key: string) => {
    setFlags(prev => {
      const cur = prev.get(key) ?? null
      const idx = FLAG_CYCLE.indexOf(cur)
      const nextFlag = FLAG_CYCLE[(idx + 1) % FLAG_CYCLE.length]
      const next = new Map(prev)
      if (nextFlag === null) next.delete(key)
      else next.set(key, nextFlag)
      return next
    })
  }, [])

  // Direct set (any value including null) — used by the flagged-processes
  // popup to delete or override flags without cycling.
  const setFlagExplicit = useCallback((key: string, f: FlagStatus) => {
    setFlags(prev => {
      const next = new Map(prev)
      if (f === null) next.delete(key)
      else next.set(key, f)
      return next
    })
  }, [])

  const handleToggleExpand = useCallback((key: string) => {
    if (!data) return
    const node = data.nodes[key]
    if (!node) return
    setExpandedKeys(prev => {
      const next = new Set(prev)
      if (next.has(key)) {
        next.delete(key)
        // Collapse: remove all descendants from visible, preserving flagged + their chain
        const allDesc = new Set<string>()
        const queue = [...node.child_node_keys]
        while (queue.length) {
          const k = queue.pop()!
          allDesc.add(k)
          const child = data.nodes[k]
          if (child) queue.push(...child.child_node_keys)
        }
        const toRemove = new Set(allDesc)
        for (const k of allDesc) {
          if (flags.has(k)) {
            toRemove.delete(k)
            let ancestor = data.nodes[k]?.parent_node_key
            while (ancestor && ancestor !== key && allDesc.has(ancestor)) {
              toRemove.delete(ancestor)
              next.add(ancestor)
              ancestor = data.nodes[ancestor]?.parent_node_key ?? null
            }
          }
        }
        for (const r of toRemove) next.delete(r)
        setVisibleKeys(prevV => {
          const nv = new Set(prevV)
          for (const r of toRemove) nv.delete(r)
          return nv
        })
      } else {
        next.add(key)
        setVisibleKeys(prevV => {
          const nv = new Set(prevV)
          for (const ck of node.child_node_keys) nv.add(ck)
          return nv
        })
      }
      return next
    })
  }, [data, flags])

  // Expand all visible nodes (lazy-load every descendant of currently-visible roots)
  const expandAll = useCallback(() => {
    if (!data) return
    const d = data  // capture for closures (TS narrowing doesn't survive)
    const allKeys = new Set<string>()
    const allExpanded = new Set<string>()
    function walk(key: string) {
      if (allKeys.has(key)) return
      const n = d.nodes[key]
      if (!n) return
      allKeys.add(key)
      if (n.child_node_keys.length) allExpanded.add(key)
      for (const ck of n.child_node_keys) walk(ck)
    }
    if (d.ancestry_chain.length > 0) walk(d.ancestry_chain[0])
    setVisibleKeys(allKeys)
    setExpandedKeys(allExpanded)
  }, [data])

  // Collapse all back to the ancestry chain, but keep flagged
  // (malicious/suspicious) nodes visible by re-adding them plus the chain of
  // ancestors that connects each to root. Matches the graph view's behaviour.
  const collapseAll = useCallback(() => {
    if (!data) return
    const d = data
    const newVisible = new Set<string>(d.ancestry_chain)

    for (const [key, flagStatus] of flags) {
      if (flagStatus === 'benign' || !d.nodes[key]) continue
      newVisible.add(key)
      let anc = d.nodes[key]?.parent_node_key
      while (anc && d.nodes[anc]) {
        newVisible.add(anc)
        anc = d.nodes[anc].parent_node_key ?? null
      }
    }

    // Re-expand only the parents whose children are visible.
    const newExpanded = new Set<string>()
    for (const key of newVisible) {
      const parent = d.nodes[key]?.parent_node_key
      if (parent && newVisible.has(parent)) newExpanded.add(parent)
    }

    setVisibleKeys(newVisible)
    setExpandedKeys(newExpanded)
  }, [data, flags])

  // ── Tree ordering ──────────────────────────────────────────────────────
  // Walk the visible tree in pre-order and produce a flat array of (node, depth).
  const orderedRows = useMemo(() => {
    if (!data) return [] as { node: ProcessNodeData; depth: number }[]
    const d = data
    const rows: { node: ProcessNodeData; depth: number }[] = []
    const visited = new Set<string>()

    function walk(key: string, depth: number) {
      if (visited.has(key)) return
      visited.add(key)
      if (!visibleKeys.has(key)) return
      const n = d.nodes[key]
      if (!n) return
      rows.push({ node: n, depth })
      for (const ck of n.child_node_keys) walk(ck, depth + 1)
    }

    if (d.ancestry_chain.length > 0) walk(d.ancestry_chain[0], 0)
    for (const key of visibleKeys) {
      if (!visited.has(key)) walk(key, 0)
    }
    return rows
  }, [data, visibleKeys])

  // ── Search match computation ────────────────────────────────────────────
  const matchKeys = useMemo(() => {
    const term = (searchTerm ?? '').trim().toLowerCase()
    // Match list is empty until the analyst has typed 2+ chars — keeps the
    // first keystroke from highlighting half the tree.
    if (term.length < 2) return [] as string[]
    const out: string[] = []
    for (const { node } of orderedRows) {
      const haystack = [
        node.name, node.cmdline, node.user, node.sha1, String(node.pid), node.folder,
      ].join(' ').toLowerCase()
      if (haystack.includes(term)) out.push(node.node_key)
    }
    return out
  }, [orderedRows, searchTerm])

  // Mirror of matchIndexRef in React state so the in-view search counter
  // ("3 of 11") re-renders when the analyst clicks the nav arrows.
  const [matchCurrent, setMatchCurrent] = useState(0)

  useEffect(() => {
    matchKeysRef.current = matchKeys
    matchIndexRef.current = 0
    setMatchCurrent(0)
    onMatchCount?.(matchKeys.length)
  }, [matchKeys, onMatchCount])

  const navToMatch = useCallback((dir: 'prev' | 'next') => {
    const keys = matchKeysRef.current
    if (!keys.length) return
    matchIndexRef.current = dir === 'next'
      ? (matchIndexRef.current + 1) % keys.length
      : (matchIndexRef.current - 1 + keys.length) % keys.length
    setMatchCurrent(matchIndexRef.current)
    const key = keys[matchIndexRef.current]
    setSelectedKey(key)
    onSelect(dataRef.current?.nodes[key] ?? null)
    const el = rowRefs.current.get(key)
    if (el) el.scrollIntoView({ block: 'center', behavior: 'smooth' })
    onMatchNav?.(matchIndexRef.current + 1, keys.length)
  }, [onSelect, onMatchNav])

  // ── Exposed callbacks via refs ──────────────────────────────────────────
  useEffect(() => {
    if (collapseAllRef) collapseAllRef.current = collapseAll
    if (expandAllRef)   expandAllRef.current   = expandAll
  }, [collapseAll, expandAll, collapseAllRef, expandAllRef])

  useEffect(() => {
    if (matchNavPrevRef) matchNavPrevRef.current = () => navToMatch('prev')
    if (matchNavNextRef) matchNavNextRef.current = () => navToMatch('next')
  }, [navToMatch, matchNavPrevRef, matchNavNextRef])

  useEffect(() => {
    if (onFlagsChange) {
      let count = 0
      for (const f of flags.values()) {
        if (f === 'malicious' || f === 'suspicious') count++
      }
      onFlagsChange(count)
    }
    if (onFlagsMapChange) onFlagsMapChange(new Map(flags))
  }, [flags, onFlagsChange, onFlagsMapChange])

  useEffect(() => {
    if (flagsRef) flagsRef.current = flags
  }, [flags, flagsRef])

  useEffect(() => {
    if (flagSetterRef) flagSetterRef.current = handleFlag
    return () => { if (flagSetterRef) flagSetterRef.current = null }
  }, [flagSetterRef, handleFlag])

  useEffect(() => {
    if (flagSetExplicitRef) flagSetExplicitRef.current = setFlagExplicit
    return () => { if (flagSetExplicitRef) flagSetExplicitRef.current = null }
  }, [flagSetExplicitRef, setFlagExplicit])

  useEffect(() => {
    if (visibleKeysRef) visibleKeysRef.current = new Set(visibleKeys)
  }, [visibleKeys, visibleKeysRef])

  useEffect(() => {
    if (expandedKeysRef) expandedKeysRef.current = new Set(expandedKeys)
  }, [expandedKeys, expandedKeysRef])

  // Expose reveal callback — same semantics as ProcessTree.revealNodeRef.
  useEffect(() => {
    if (!revealNodeRef) return
    revealNodeRef.current = (key: string) => {
      const d = dataRef.current
      if (!d || !d.nodes[key]) return
      // Walk ancestors and add them all to visible + expanded
      const chain: string[] = []
      let cur: string | null = key
      const seen = new Set<string>()
      while (cur && !seen.has(cur) && d.nodes[cur]) {
        seen.add(cur)
        chain.push(cur)
        cur = d.nodes[cur].parent_node_key
      }
      setVisibleKeys(prev => {
        const nv = new Set(prev)
        for (const k of chain) nv.add(k)
        return nv
      })
      setExpandedKeys(prev => {
        const ne = new Set(prev)
        for (const k of chain) if (k !== key) ne.add(k)
        return ne
      })
      setSelectedKey(key)
      onSelect(d.nodes[key])
      // Scroll into view after the next render commit
      requestAnimationFrame(() => {
        const el = rowRefs.current.get(key)
        if (el) el.scrollIntoView({ block: 'center', behavior: 'smooth' })
      })
    }
  }, [revealNodeRef, onSelect])

  // ── Pivot popover state (one global popover for the table view) ─────────
  const [pivotFor, setPivotFor] = useState<{ pid: number; timestamp: string | null; anchor: DOMRect } | null>(null)
  useEffect(() => {
    if (!pivotFor) return
    function onDown(e: MouseEvent) {
      const t = e.target as HTMLElement
      if (t.closest('[data-pivot-popover]')) return
      setPivotFor(null)
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setPivotFor(null)
    }
    document.addEventListener('mousedown', onDown, true)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown, true)
      document.removeEventListener('keydown', onKey)
    }
  }, [pivotFor])

  // Shared backdrop — same image as the graph view, applied to every render
  // state so the table-view backdrop is consistent from load through to live
  // data (no flash of plain dark panel during fetch).
  const tableBgStyle: React.CSSProperties = {
    backgroundImage: `linear-gradient(rgba(8,8,12,0.86), rgba(8,8,12,0.86)), url(/tree-bg.png)`,
    backgroundSize: 'cover',
    backgroundPosition: 'center',
  }

  // ── Render ──────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 11, ...tableBgStyle }}>
        ▌ loading process tree…
      </div>
    )
  }

  if (loadErr) {
    return (
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)', padding: 24, ...tableBgStyle }}>
        <div>✗ failed to load tree</div>
        <div style={{ color: 'var(--text-muted)', maxWidth: 480, textAlign: 'center', lineHeight: 1.5 }}>{loadErr}</div>
        <button onClick={onReset} style={{
          marginTop: 6, background: 'transparent', border: '1px solid var(--border)',
          color: 'var(--text-muted)', cursor: 'pointer',
          fontFamily: 'var(--font-mono)', fontSize: 10.5, padding: '5px 12px', borderRadius: 3,
        }}>← back</button>
      </div>
    )
  }

  if (data && (data.pid_candidates?.length ?? 0) > 1 && !pinnedNodeKey) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24, ...tableBgStyle }}>
        <AmbiguityPicker
          focalPid={focalPid}
          candidates={data.pid_candidates}
          nodes={data.nodes}
          onPick={setPinnedNodeKey}
        />
      </div>
    )
  }

  if (!data || orderedRows.length === 0) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11, ...tableBgStyle }}>
        no processes to show
      </div>
    )
  }

  // Layout math — all dimensions scale with `zoom`.
  const baseFont   = 12
  const baseSubFont = 11
  const baseRowPadY = 6
  const baseRowPadX = 12
  const triangleW = 28   // fixed click target — does not scale with zoom
  const flagW     = 28
  const fontSize    = baseFont    * zoom
  const subFontSize = baseSubFont * zoom
  const rowPadY     = baseRowPadY * zoom
  const rowPadX     = baseRowPadX * zoom
  const gridTemplate = `${colWidths.name}px ${colWidths.pid}px ${colWidths.user}px ${colWidths.time}px ${colWidths.cmdline}px`

  function startColResize(col: ColKey, e: React.MouseEvent) {
    e.preventDefault()
    e.stopPropagation()
    const startX = e.clientX
    const startW = colWidths[col]
    function onMove(ev: MouseEvent) {
      const newW = Math.max(MIN_COL_WIDTH, startW + (ev.clientX - startX))
      setColWidths(prev => ({ ...prev, [col]: newW }))
    }
    function onUp() {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  function focusFocal() {
    const d = dataRef.current
    if (!d || d.ancestry_chain.length === 0) return
    const focalKey = d.ancestry_chain[d.ancestry_chain.length - 1]
    if (!focalKey) return
    // Make sure focal is in visibleKeys (its chain too — should be by default)
    setVisibleKeys(prev => {
      const nv = new Set(prev)
      for (const k of d.ancestry_chain) nv.add(k)
      return nv
    })
    setSelectedKey(focalKey)
    onSelect(d.nodes[focalKey] ?? null)
    requestAnimationFrame(() => {
      const el = rowRefs.current.get(focalKey)
      if (el) el.scrollIntoView({ block: 'center', behavior: 'smooth' })
    })
  }

  function ResizeHandle({ col }: { col: ColKey }) {
    return (
      <div
        onMouseDown={e => startColResize(col, e)}
        onClick={e => e.stopPropagation()}
        title="Drag to resize column"
        style={{
          position: 'absolute', right: 0, top: 0, bottom: 0,
          width: 6, cursor: 'col-resize',
          background: 'transparent',
          transition: 'background 100ms',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = 'var(--accent)')}
        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
      />
    )
  }

  const headerCellStyle: React.CSSProperties = {
    position: 'relative',
    padding: '0 8px',
    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
  }

  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, minWidth: 0,
      position: 'relative',
      ...tableBgStyle,
    }}>
      {/* Single scroll container holding both header and rows, so they scroll
          horizontally together while the header stays pinned at the top.    */}
      <div
        ref={scrollRef}
        onClick={e => {
          // Click in empty space (not on a row) clears selection.
          if (e.target === e.currentTarget) {
            setSelectedKey(null)
            onSelect(null)
          }
        }}
        // minWidth:0 is crucial — without it, the table's fit-content
        // width acts as a min-content constraint on the flex parent and
        // prevents the surrounding left pane from shrinking when the
        // analyst drags the right panel wider. Bug was table-view-only
        // because the graph view has no fit-content child.
        style={{ flex: 1, overflow: 'auto', minHeight: 0, minWidth: 0 }}
      >
        {/* Header row */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: gridTemplate,
          gap: 0,
          padding: `${rowPadY}px ${rowPadX}px`,
          background: 'var(--bg-panel)',
          borderBottom: '1px solid var(--border)',
          fontFamily: 'var(--font-mono)', fontSize: subFontSize * 0.85, letterSpacing: 0.5,
          color: 'var(--text-muted)', textTransform: 'uppercase',
          position: 'sticky', top: 0, zIndex: 2,
          width: 'fit-content', minWidth: '100%',
        }}>
          <div style={{
            ...headerCellStyle,
            // Match the leading body cells' inner padding so the "process"
            // label sits roughly over where root-level names appear.
            paddingLeft: triangleW + flagW + 8,
          }}>process<ResizeHandle col="name" /></div>
          <div style={headerCellStyle}>pid<ResizeHandle col="pid" /></div>
          <div style={headerCellStyle}>user<ResizeHandle col="user" /></div>
          <div style={headerCellStyle}>time (UTC)<ResizeHandle col="time" /></div>
          <div style={headerCellStyle}>command line<ResizeHandle col="cmdline" /></div>
        </div>

        {/* Body rows */}
        {orderedRows.map(({ node, depth }) => {
          const isSelected = selectedKey === node.node_key
          const flag = flags.get(node.node_key) ?? null
          const flagColor = flag ? FLAG_COLORS[flag] : 'transparent'
          const isMatch = matchKeys.includes(node.node_key)
          const matchIdx = matchKeys.indexOf(node.node_key)
          const isCurrentMatch = matchIdx === matchIndexRef.current && isMatch
          const hasChildren = node.child_node_keys.length > 0
          const isExpanded = expandedKeys.has(node.node_key)
          const ts = fmtDateTime(node.timestamp, false)

          // Build a background-image gradient that draws vertical guide lines
          // at each ancestor depth. Each line sits exactly under where the
          // ancestor's expand-chevron renders — i.e. at the centre of that
          // ancestor's triangle cell — so the line visually starts at the
          // tip of the parent's purple arrow.
          const indentBg = depth > 0
            ? `linear-gradient(to right, ${
                Array.from({ length: depth }).flatMap((_, i) => {
                  const x = rowPadX + i * INDENT_PER_LEVEL + Math.floor(triangleW / 2)
                  return [
                    `transparent ${x}px`,
                    `rgba(255,255,255,0.10) ${x}px`,
                    `rgba(255,255,255,0.10) ${x + 1}px`,
                    `transparent ${x + 1}px`,
                  ]
                }).join(', ')
              })`
            : undefined

          return (
            <div
              key={node.node_key}
              ref={el => { rowRefs.current.set(node.node_key, el) }}
              onClick={() => handleSelect(node.node_key)}
              style={{
                display: 'grid',
                gridTemplateColumns: gridTemplate,
                gap: 0,
                padding: `${rowPadY}px ${rowPadX}px`,
                fontFamily: 'var(--font-mono)', fontSize,
                color: 'var(--text)',
                cursor: 'pointer',
                backgroundColor: isCurrentMatch
                  ? 'rgba(240,179,64,0.12)'
                  : isMatch
                  ? 'rgba(240,179,64,0.05)'
                  : flag
                  ? `${flagColor}1f`   // ~12% alpha — lighter than the text colour
                  : 'transparent',
                backgroundImage: indentBg,
                borderLeft: `3px solid ${isCurrentMatch ? 'var(--amber)' : (flag ? flagColor : 'transparent')}`,
                // Selected state: purple outline around the whole row — no
                // fill tint. Inset box-shadow keeps the layout stable.
                boxShadow: isSelected ? 'inset 0 0 0 1px var(--accent)' : undefined,
                alignItems: 'center',
                width: 'fit-content', minWidth: '100%',
                position: 'relative',
              }}
              onMouseEnter={e => { e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.04)' }}
              onMouseLeave={e => {
                if (isCurrentMatch) e.currentTarget.style.backgroundColor = 'rgba(240,179,64,0.12)'
                else if (isMatch) e.currentTarget.style.backgroundColor = 'rgba(240,179,64,0.05)'
                else if (flag) e.currentTarget.style.backgroundColor = `${flagColor}1f`
                else e.currentTarget.style.backgroundColor = 'transparent'
              }}
            >
              {/* Combined leading cell — indent + triangle + flag + name.
                  Outer flex (no overflow) holds the indent segments so their
                  negative-margin extension through row padding doesn't get
                  clipped. Inner flex holds the rest with overflow:hidden so
                  long names ellipsis cleanly. */}
              <span style={{
                display: 'flex', alignItems: 'stretch',
                minWidth: 0,
              }}>
                {/* Indent spacers — one per depth level. The actual vertical
                    guide lines are drawn by the row's backgroundImage gradient
                    above, so these are now plain flex spacers. */}
                {Array.from({ length: depth }).map((_, i) => (
                  <span key={i} style={{
                    width: INDENT_PER_LEVEL,
                    flexShrink: 0,
                  }} />
                ))}
                <span style={{
                  display: 'flex', alignItems: 'center', gap: 4,
                  overflow: 'hidden', minWidth: 0, flex: 1,
                }}>
                <span
                  onClick={e => { e.stopPropagation(); if (hasChildren) handleToggleExpand(node.node_key) }}
                  title={hasChildren ? (isExpanded ? 'Collapse children' : 'Expand children') : ''}
                  style={{
                    color: hasChildren ? 'var(--accent)' : 'transparent',
                    fontSize: 22,
                    lineHeight: '20px',
                    fontWeight: 700,
                    display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                    userSelect: 'none',
                    cursor: hasChildren ? 'pointer' : 'default',
                    borderRadius: 3,
                    transition: 'background 100ms',
                    width: triangleW, height: 20, flexShrink: 0,
                  }}
                  onMouseEnter={e => { if (hasChildren) e.currentTarget.style.background = 'rgba(168,85,247,0.18)' }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}>
                  {hasChildren ? (isExpanded ? '▾' : '▸') : ''}
                </span>

                <span
                  onClick={e => { e.stopPropagation(); handleFlag(node.node_key) }}
                  onMouseDown={e => e.preventDefault()}  // suppress double-click text selection
                  title={flag ? `${flag} (click to change)` : 'click to flag'}
                  style={{
                    display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                    cursor: 'pointer', userSelect: 'none',
                    borderRadius: 3,
                    transition: 'background 100ms',
                    width: flagW, height: 20, flexShrink: 0,
                  }}
                  onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.05)' }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}>
                  <span style={{
                    fontSize: 20, lineHeight: '20px',
                    color: flag ? flagColor : 'var(--text-muted)',
                    display: 'inline-block',
                    transition: 'color 100ms',
                  }}>⚑</span>
                </span>

                <span style={{
                  color: flag ? flagColor : 'var(--text)',
                  fontWeight: node.is_focal ? 700 : 500,
                  fontSize: 13,
                  lineHeight: '20px',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  minWidth: 0,
                }}>{highlightMatches(node.name, searchTerm)}</span>
                {node.is_focal && (
                  <span style={{
                    fontSize: 9, padding: '1px 5px', borderRadius: 2, fontWeight: 700, flexShrink: 0,
                    background: 'rgba(168,85,247,0.15)', color: 'var(--accent)',
                  }}>FOCAL</span>
                )}
                {node.is_lolbin && (
                  <span style={{
                    fontSize: 9, padding: '1px 5px', borderRadius: 2, fontWeight: 700, flexShrink: 0,
                    background: 'rgba(240,179,64,0.12)', color: 'var(--amber)',
                  }}>LOLBin</span>
                )}
                </span>{/* end inner overflow-hidden content group */}
              </span>{/* end outer leading cell */}

              {/* PID — clickable to open pivot popover */}
              <span
                onClick={e => {
                  e.stopPropagation()
                  const r = (e.currentTarget as HTMLElement).getBoundingClientRect()
                  setPivotFor({ pid: node.pid, timestamp: node.timestamp, anchor: r })
                }}
                title="Click to pivot to a new investigation"
                style={{
                  color: 'var(--accent)', cursor: 'pointer',
                  textDecoration: 'underline', textDecorationStyle: 'dotted',
                  textDecorationColor: 'rgba(168,85,247,0.4)',
                  padding: '0 8px',
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                {highlightMatches(String(node.pid), searchTerm)}
              </span>

              {/* User */}
              <span style={{
                color: 'var(--text-muted)',
                padding: '0 8px',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}>{node.user ? highlightMatches(node.user, searchTerm) : '—'}</span>

              {/* Time */}
              <span style={{
                color: 'var(--text-muted)', fontSize: subFontSize,
                padding: '0 8px',
                whiteSpace: 'nowrap',
              }}>{highlightMatches(ts, searchTerm)}</span>

              {/* Cmdline */}
              <span style={{
                color: 'var(--text-muted)', fontSize: subFontSize,
                padding: '0 8px',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                fontFamily: 'var(--font-mono)',
              }} title={node.cmdline || ''}>
                {node.cmdline ? highlightMatches(node.cmdline, searchTerm) : '—'}
              </span>
            </div>
          )
        })}
      </div>

      {/* Floating bottom-right controls — search + match nav + zoom + focus */}
      <div style={{
        position: 'absolute', bottom: 12, right: 12, zIndex: 5,
        display: 'flex', gap: 8, alignItems: 'center',
        background: 'var(--bg-app)', padding: '4px 6px',
        borderRadius: 4, border: '1px solid var(--border-soft)',
        boxShadow: '0 2px 12px rgba(0,0,0,0.35)',
      }}>
        {/* Search input — only render if AnalysisTab opts in via onSearchChange */}
        {onSearchChange && (
          <>
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <input
                type="text"
                placeholder="search processes…"
                value={searchTerm ?? ''}
                onChange={e => onSearchChange(e.target.value)}
                onFocus={e => { e.currentTarget.style.borderColor = 'var(--accent)' }}
                onBlur={e => { e.currentTarget.style.borderColor = (searchTerm ? 'var(--accent)' : 'var(--border)') }}
                style={{
                  background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                  borderRadius: 3, color: 'var(--text)', fontFamily: 'var(--font-mono)',
                  fontSize: 11, padding: '3px 22px 3px 8px', outline: 'none', width: 170,
                  transition: 'border-color 100ms',
                }}
              />
              {searchTerm && (
                <span
                  onClick={() => onSearchChange('')}
                  title="Clear search"
                  onMouseEnter={e => { e.currentTarget.style.color = 'var(--text)' }}
                  onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)' }}
                  style={{
                    position: 'absolute', right: 5, cursor: 'pointer',
                    color: 'var(--text-muted)', fontSize: 13, lineHeight: 1,
                    transition: 'color 100ms', userSelect: 'none',
                    padding: '2px 3px',
                  }}>×</span>
              )}
            </div>
            {searchTerm && (
              <>
                <div style={{ display: 'flex', gap: 0 }}>
                  <button
                    onClick={() => navToMatch('prev')}
                    disabled={!matchKeys.length}
                    title="Previous match"
                    style={{
                      background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                      borderRadius: '3px 0 0 3px', borderRight: 'none',
                      color: 'var(--text-muted)', cursor: matchKeys.length ? 'pointer' : 'default',
                      fontFamily: 'var(--font-mono)', fontSize: 10, padding: '2px 6px',
                      opacity: matchKeys.length ? 1 : 0.4,
                    }}>▴</button>
                  <button
                    onClick={() => navToMatch('next')}
                    disabled={!matchKeys.length}
                    title="Next match"
                    style={{
                      background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                      borderRadius: '0 3px 3px 0',
                      color: 'var(--text-muted)', cursor: matchKeys.length ? 'pointer' : 'default',
                      fontFamily: 'var(--font-mono)', fontSize: 10, padding: '2px 6px',
                      opacity: matchKeys.length ? 1 : 0.4,
                    }}>▾</button>
                </div>
                <span style={{
                  color: matchKeys.length > 0 ? 'var(--amber)' : 'var(--text-muted)',
                  fontFamily: 'var(--font-mono)', fontSize: 10.5, whiteSpace: 'nowrap',
                }}>
                  {matchKeys.length > 0 ? `${matchCurrent + 1} of ${matchKeys.length}` : '0 matches'}
                </span>
              </>
            )}
            <div style={{ width: 1, height: 18, background: 'var(--border)', margin: '0 2px' }} />
          </>
        )}

        {[
          { label: '−', onClick: () => setZoom(z => Math.max(zoomMin, Math.round((z - 0.1) * 10) / 10)), title: 'Smaller rows', radius: '3px 0 0 3px' as const, br: 'none' as const },
          { label: '+', onClick: () => setZoom(z => Math.min(zoomMax, Math.round((z + 0.1) * 10) / 10)), title: 'Bigger rows',   radius: '0' as const, br: 'none' as const },
          { label: '⊡ focus', onClick: focusFocal, title: 'Scroll to focal process', radius: '0 3px 3px 0' as const, br: '1px solid var(--border)' as const, wide: true },
        ].map((b, i) => (
          <button key={i} onClick={b.onClick} title={b.title}
            onMouseEnter={e => { e.currentTarget.style.background = 'var(--bg-card)'; e.currentTarget.style.color = 'var(--text)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-elevated)'; e.currentTarget.style.color = 'var(--text-muted)' }}
            style={{
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              borderRight: b.br,
              color: 'var(--text-muted)', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 600,
              padding: b.wide ? '5px 10px' : '5px 10px', lineHeight: 1,
              borderRadius: b.radius,
              transition: 'background 100ms, color 100ms',
            }}>{b.label}</button>
        ))}
      </div>

      {/* Pivot popover */}
      {pivotFor && (
        <div
          data-pivot-popover
          style={{
            position: 'fixed',
            top: pivotFor.anchor.bottom + 6,
            left: Math.min(pivotFor.anchor.left, window.innerWidth - 290),
            zIndex: 9999,
            background: 'var(--bg-panel)', border: '1px solid var(--border)',
            borderRadius: 6, padding: '14px 16px', width: 260,
            fontFamily: 'var(--font-mono)', fontSize: 11,
            boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
          }}
        >
          <div style={{ color: 'var(--text)', fontWeight: 600, marginBottom: 6 }}>
            Pivot to new investigation
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: 10.5, lineHeight: 1.6, marginBottom: 14 }}>
            Set <span style={{ color: 'var(--accent)' }}>PID {pivotFor.pid}</span> as the focal
            process and start a new investigation?
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => {
              onPivot?.(pivotFor.pid, pivotFor.timestamp)
              setPivotFor(null)
            }} style={{
              flex: 1,
              background: 'var(--accent)', border: 'none', borderRadius: 3,
              color: '#fff', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 10.5, fontWeight: 600,
              padding: '5px 10px',
            }}>Pivot ↗</button>
            <button onClick={() => setPivotFor(null)} style={{
              background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
              color: 'var(--text-muted)', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 10.5,
              padding: '5px 10px',
            }}>cancel</button>
          </div>
        </div>
      )}
    </div>
  )
}
