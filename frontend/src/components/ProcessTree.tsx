import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { ReactFlow, Background, BackgroundVariant, Panel, useReactFlow, BaseEdge } from '@xyflow/react'
import type { Node, Edge, EdgeProps } from '@xyflow/react'
import type { FlagStatus, ProcessNodeData, InvestigateResponse } from '../types'
import { fetchProcessTree } from '../api/investigate'
import { fmtDateTime } from '../utils/dateFormat'
import { layoutTree, NODE_W, estimateNodeHeight } from '../utils/treeLayout'
import { ProcessNodeComponent } from './ProcessNode'
import type { ProcessNodeExtended } from './ProcessNode'
import { friendlyError } from '../utils/errors'

// Custom edge: strictly down → horizontal → down. Never routes upward.
function TreeEdge({ sourceX, sourceY, targetX, targetY, style }: EdgeProps) {
  const midY = (sourceY + targetY) / 2
  const path = `M ${sourceX} ${sourceY} L ${sourceX} ${midY} L ${targetX} ${midY} L ${targetX} ${targetY}`
  return <BaseEdge path={path} style={style} />
}

const NODE_TYPES = { processNode: ProcessNodeComponent }
const EDGE_TYPES = { treeEdge: TreeEdge }

function TreeControls({
  focalNodeKey, fitViewTrigger, centerTarget,
  searchTerm, onSearchChange, matchTotal, matchCurrent, onMatchPrev, onMatchNext,
}: {
  focalNodeKey: string | null
  fitViewTrigger: number
  centerTarget: { key: string; seq: number } | null
  searchTerm?: string
  onSearchChange?: (s: string) => void
  matchTotal?: number
  matchCurrent?: number
  onMatchPrev?: () => void
  onMatchNext?: () => void
}) {
  const { getNode, setCenter, fitView, zoomIn, zoomOut } = useReactFlow()

  useEffect(() => {
    if (fitViewTrigger === 0) return
    fitView({ padding: 0.2, duration: 400 })
  }, [fitViewTrigger, fitView])

  useEffect(() => {
    if (!centerTarget) return
    const node = getNode(centerTarget.key)
    if (node) {
      setCenter(
        node.position.x + NODE_W / 2,
        node.position.y + (node.measured?.height ?? 52) / 2,
        { zoom: 1, duration: 300 },
      )
    }
  }, [centerTarget, getNode, setCenter])

  function handleFocus() {
    if (focalNodeKey) {
      const node = getNode(focalNodeKey)
      if (node) {
        setCenter(
          node.position.x + NODE_W / 2,
          node.position.y + (node.measured?.height ?? 52),
          { zoom: 1, duration: 300 },
        )
        return
      }
    }
    fitView({ padding: 0.2, duration: 300 })
  }

  const btnStyle: React.CSSProperties = {
    background: 'var(--bg-elevated)', border: '1px solid var(--border)',
    color: 'var(--text-muted)', cursor: 'pointer',
    fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 600,
    padding: '4px 9px', lineHeight: 1,
    transition: 'background 100ms, color 100ms',
  }
  const onHover = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.currentTarget.style.background = 'var(--bg-card)'
    e.currentTarget.style.color = 'var(--text)'
  }
  const onLeave = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.currentTarget.style.background = 'var(--bg-elevated)'
    e.currentTarget.style.color = 'var(--text-muted)'
  }

  const total = matchTotal ?? 0
  return (
    <Panel position="bottom-right">
      <div style={{
        display: 'flex', gap: 8, alignItems: 'center',
        background: 'var(--bg-app)', padding: '4px 6px',
        borderRadius: 4, border: '1px solid var(--border-soft)',
        boxShadow: '0 2px 12px rgba(0,0,0,0.35)',
      }}>
        {/* Search input (only when the parent opts in by passing onSearchChange) */}
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
                    onClick={onMatchPrev}
                    disabled={!total}
                    title="Previous match"
                    style={{
                      background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                      borderRadius: '3px 0 0 3px', borderRight: 'none',
                      color: 'var(--text-muted)', cursor: total ? 'pointer' : 'default',
                      fontFamily: 'var(--font-mono)', fontSize: 10, padding: '2px 6px',
                      opacity: total ? 1 : 0.4,
                    }}>▴</button>
                  <button
                    onClick={onMatchNext}
                    disabled={!total}
                    title="Next match"
                    style={{
                      background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                      borderRadius: '0 3px 3px 0',
                      color: 'var(--text-muted)', cursor: total ? 'pointer' : 'default',
                      fontFamily: 'var(--font-mono)', fontSize: 10, padding: '2px 6px',
                      opacity: total ? 1 : 0.4,
                    }}>▾</button>
                </div>
                <span style={{
                  color: total > 0 ? 'var(--amber)' : 'var(--text-muted)',
                  fontFamily: 'var(--font-mono)', fontSize: 10.5, whiteSpace: 'nowrap',
                }}>
                  {total > 0 ? `${(matchCurrent ?? 0) + 1} of ${total}` : '0 matches'}
                </span>
              </>
            )}
            <div style={{ width: 1, height: 18, background: 'var(--border)', margin: '0 2px' }} />
          </>
        )}
        <button onClick={() => zoomOut({ duration: 200 })} title="Zoom out"
          onMouseEnter={onHover} onMouseLeave={onLeave}
          style={{ ...btnStyle, padding: '5px 10px', borderRadius: '3px 0 0 3px', borderRight: 'none' }}>−</button>
        <button onClick={() => zoomIn({ duration: 200 })} title="Zoom in"
          onMouseEnter={onHover} onMouseLeave={onLeave}
          style={{ ...btnStyle, padding: '5px 10px', borderRadius: 0, borderRight: 'none' }}>+</button>
        <button onClick={handleFocus} title="Centre on focal process"
          onMouseEnter={onHover} onMouseLeave={onLeave}
          style={{ ...btnStyle, padding: '5px 10px', borderRadius: '0 3px 3px 0', fontSize: 13 }}>⊡ focus</button>
      </div>
    </Panel>
  )
}

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
  onMatchCount?: (n: number) => void
  onMatchNav?: (current: number, total: number) => void
  onSearchChange?: (s: string) => void
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
  // Start with only the ancestry chain (root → focal). Children are rendered
  // on demand when the analyst explicitly expands each node.
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
              <div style={{ color: 'var(--text-muted)', fontSize: 10, marginBottom: 2 }}>
                {n.user || '—'}
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

export default function ProcessTree({
  hostname, focalPid, focalTimeIso, rawTimeWindow, alertId, onSelect, onDataLoaded, onReset, initialData,
  collapseAllRef, expandAllRef, matchNavPrevRef, matchNavNextRef,
  searchTerm, onMatchCount, onMatchNav, onSearchChange, onFlagsChange, onFlagsMapChange, flagSetterRef, flagSetExplicitRef, flagsRef, revealNodeRef,
  visibleKeysRef, expandedKeysRef, onPivot, onHostnameResolved,
}: Props) {
  const [data, setData] = useState<InvestigateResponse | null>(initialData)
  const [loadErr, setLoadErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(!initialData)
  const [pinnedNodeKey, setPinnedNodeKey] = useState<string | null>(null)
  const [fitViewTrigger, setFitViewTrigger] = useState(0)
  const [centerTarget, setCenterTarget] = useState<{ key: string; seq: number } | null>(null)

  // Seed visible/expanded from the shared refs so view-switching from the
  // table view preserves the analyst's expansion. Falls back to ancestry-only.
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
  const [flags, setFlags] = useState<Map<string, FlagStatus>>(
    () => flagsRef?.current ? new Map(flagsRef.current) : new Map(),
  )
  const [selectedKey, setSelectedKey] = useState<string | null>(null)

  function doFetch(nodeKey?: string) {
    setLoading(true)
    setLoadErr(null)
    setData(null)
    setVisibleKeys(new Set())
    setFlags(new Map())
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
        if (res.ok || res.nodes) {
          const { visible, expanded } = initVisibleKeys(res)
          setVisibleKeys(visible)
          setExpandedKeys(expanded)
        }
      })
      .catch(e => setLoadErr(friendlyError(e)))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    // Reset picker selection and re-fetch when primary investigation params change
    setPinnedNodeKey(null)
    if (initialData) return
    doFetch()
  // initialData intentionally excluded — only checked once on mount
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hostname, focalPid, focalTimeIso, rawTimeWindow])

  // Re-fetch when the analyst picks a specific candidate from the ambiguity picker
  useEffect(() => {
    if (!pinnedNodeKey) return
    doFetch(pinnedNodeKey)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pinnedNodeKey])

  const handleSelect = useCallback((key: string) => {
    setSelectedKey(prev => {
      const next = prev === key ? null : key
      onSelect(next && data ? (data.nodes[next] ?? null) : null)
      return next
    })
  }, [data, onSelect])

  const handleFlag = useCallback((key: string, f: FlagStatus) => {
    setFlags(prev => {
      const next = new Map(prev)
      if (f === null) next.delete(key)
      else next.set(key, f)
      return next
    })
  }, [])

  // Cycle the flag for a key — used by the Process Telemetry panel's flag
  // button to flag the currently-selected process without leaving the panel.
  const FLAG_CYCLE_LOCAL: FlagStatus[] = [null, 'benign', 'suspicious', 'malicious']
  const cycleFlag = useCallback((key: string) => {
    setFlags(prev => {
      const cur = prev.get(key) ?? null
      const idx = FLAG_CYCLE_LOCAL.indexOf(cur)
      const nextFlag = FLAG_CYCLE_LOCAL[(idx + 1) % FLAG_CYCLE_LOCAL.length]
      const next = new Map(prev)
      if (nextFlag === null) next.delete(key)
      else next.set(key, nextFlag)
      return next
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (flagSetterRef) flagSetterRef.current = cycleFlag
    return () => { if (flagSetterRef) flagSetterRef.current = null }
  }, [flagSetterRef, cycleFlag])

  useEffect(() => {
    if (flagSetExplicitRef) flagSetExplicitRef.current = handleFlag
    return () => { if (flagSetExplicitRef) flagSetExplicitRef.current = null }
  }, [flagSetExplicitRef, handleFlag])

  const handleToggleExpand = useCallback((key: string) => {
    if (!data) return
    const node = data.nodes[key]
    if (!node) return
    setExpandedKeys(prev => {
      const next = new Set(prev)
      if (next.has(key)) {
        next.delete(key)

        // Collect every descendant of the collapsed node
        const allDesc = new Set<string>()
        const queue = [...node.child_node_keys]
        while (queue.length) {
          const k = queue.pop()!
          allDesc.add(k)
          const child = data.nodes[k]
          if (child) queue.push(...child.child_node_keys)
        }

        // Start by marking everything for removal
        const toRemove = new Set(allDesc)

        // Preserve flagged nodes and their ancestor chains so the tree stays connected
        for (const k of allDesc) {
          if (flags.has(k)) {
            toRemove.delete(k)
            let ancestor = data.nodes[k]?.parent_node_key
            while (ancestor && ancestor !== key && allDesc.has(ancestor)) {
              toRemove.delete(ancestor)
              next.add(ancestor)  // mark intermediate as expanded (has visible children)
              ancestor = data.nodes[ancestor]?.parent_node_key ?? null
            }
          }
        }

        // Remove expandedKeys for anything that is being hidden
        for (const r of toRemove) next.delete(r)

        setVisibleKeys(prevV => {
          const nv = new Set(prevV)
          for (const r of toRemove) nv.delete(r)
          return nv
        })
        setCenterTarget({ key, seq: Date.now() })
      } else {
        // Expand: add direct children
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

  const collapseAll = useCallback(() => {
    if (!data) return

    // Start with only the ancestry chain (root → focal), no children
    const newVisible = new Set<string>(data.ancestry_chain)

    // Keep flagged (suspicious/malicious) nodes and their ancestor chains visible
    for (const [key, flagStatus] of flags) {
      if (flagStatus === 'benign' || !data.nodes[key]) continue
      newVisible.add(key)
      let anc = data.nodes[key]?.parent_node_key
      while (anc && data.nodes[anc]) {
        newVisible.add(anc)
        anc = data.nodes[anc].parent_node_key ?? null
      }
    }

    // A node is "expanded" only if it has at least one visible child
    const newExpanded = new Set<string>()
    for (const key of newVisible) {
      const parent = data.nodes[key]?.parent_node_key
      if (parent && newVisible.has(parent)) newExpanded.add(parent)
    }

    setVisibleKeys(newVisible)
    setExpandedKeys(newExpanded)
    setFitViewTrigger(t => t + 1)
  }, [data, flags])

  const expandAll = useCallback(() => {
    if (!data) return
    const allKeys = new Set(Object.keys(data.nodes))
    const allExpanded = new Set<string>()
    for (const key of allKeys) {
      if ((data.nodes[key]?.child_node_keys.length ?? 0) > 0) allExpanded.add(key)
    }
    setVisibleKeys(allKeys)
    setExpandedKeys(allExpanded)
    setFitViewTrigger(t => t + 1)
  }, [data])

  useEffect(() => {
    if (collapseAllRef) collapseAllRef.current = collapseAll
  }, [collapseAll, collapseAllRef])

  useEffect(() => {
    if (expandAllRef) expandAllRef.current = expandAll
  }, [expandAll, expandAllRef])

  // Refs so navToMatch can read current data/keys without stale closures
  const dataRef       = useRef(data)
  const matchKeysRef  = useRef<string[]>([])
  const matchIndexRef = useRef(0)
  // State mirror of matchIndexRef so the in-view "N of M" counter re-renders
  // when the analyst clicks nav arrows.
  const [matchCurrent, setMatchCurrent] = useState(0)
  // The total match count (mirrored from the matchKeys useMemo below).
  const [matchTotal, setMatchTotal] = useState(0)
  useEffect(() => { dataRef.current = data }, [data])
  useEffect(() => { matchIndexRef.current = 0; setMatchCurrent(0) }, [searchTerm])

  const navToMatch = useCallback((dir: 'prev' | 'next') => {
    const keys = matchKeysRef.current
    if (!keys.length) return
    matchIndexRef.current = dir === 'next'
      ? (matchIndexRef.current + 1) % keys.length
      : (matchIndexRef.current - 1 + keys.length) % keys.length
    setMatchCurrent(matchIndexRef.current)
    const key = keys[matchIndexRef.current]
    setCenterTarget({ key, seq: Date.now() })
    setSelectedKey(key)
    onSelect(dataRef.current?.nodes[key] ?? null)
    onMatchNav?.(matchIndexRef.current + 1, keys.length)
  }, [onSelect, onMatchNav])

  useEffect(() => {
    if (matchNavPrevRef) matchNavPrevRef.current = () => navToMatch('prev')
    if (matchNavNextRef) matchNavNextRef.current = () => navToMatch('next')
  }, [navToMatch, matchNavPrevRef, matchNavNextRef])

  // Expose a "reveal + centre a specific node" callback. Walks up ancestors
  // to make the target visible (in case it sits inside a collapsed branch),
  // marks them expanded, centres the viewport, and selects the node.
  useEffect(() => {
    if (!revealNodeRef) return
    revealNodeRef.current = (key: string) => {
      const d = dataRef.current
      if (!d || !d.nodes[key]) return

      // Collect every ancestor key up to root
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
        // Expand every ancestor (not the target itself unless it has children visible)
        for (const k of chain) if (k !== key) ne.add(k)
        return ne
      })
      setSelectedKey(key)
      setCenterTarget({ key, seq: Date.now() })
      onSelect(d.nodes[key])
    }
  }, [revealNodeRef, onSelect])

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
    if (visibleKeysRef) visibleKeysRef.current = new Set(visibleKeys)
  }, [visibleKeys, visibleKeysRef])

  useEffect(() => {
    if (expandedKeysRef) expandedKeysRef.current = new Set(expandedKeys)
  }, [expandedKeys, expandedKeysRef])

  const { rfNodes, rfEdges } = useMemo(() => {
    if (!data || visibleKeys.size === 0) return { rfNodes: [], rfEdges: [] }

    // Compute search matches across visible nodes — require 2+ chars so a
    // single letter doesn't highlight half the tree.
    const term = searchTerm?.trim().toLowerCase() ?? ''
    const matchKeys = new Set<string>()
    if (term.length >= 2) {
      for (const key of visibleKeys) {
        const n = data.nodes[key]
        if (!n) continue
        if (
          n.name.toLowerCase().includes(term) ||
          n.cmdline.toLowerCase().includes(term) ||
          n.user.toLowerCase().includes(term) ||
          String(n.pid).includes(term)
        ) matchKeys.add(key)
      }
    }
    const hasSearch = term.length > 0

    // Compute per-node heights before layout so vertical spacing is correct
    const heights = new Map<string, number>()
    for (const key of visibleKeys) {
      const node = data.nodes[key]
      if (node) heights.set(key, estimateNodeHeight(node.cmdline))
    }

    const positions = layoutTree(data.nodes, visibleKeys, heights)
    const rfNodes: Node[] = []
    const rfEdges: Edge[] = []
    const seenEdges = new Set<string>()

    for (const key of visibleKeys) {
      const node = data.nodes[key]
      if (!node || !positions.has(key)) continue
      const pos = positions.get(key)!
      const nodeH = heights.get(key)!
      const nodeData: ProcessNodeExtended = {
        ...node,
        flag: flags.get(key) ?? null,
        selected: selectedKey === key,
        expanded: expandedKeys.has(key),
        isMatch: hasSearch && matchKeys.has(key),
        isDimmed: hasSearch && !matchKeys.has(key),
        searchTerm,
        onSelect: handleSelect,
        onToggleExpand: handleToggleExpand,
        onFlag: handleFlag,
        onPivot: onPivot ?? (() => {}),
      }
      rfNodes.push({
        id: key,
        type: 'processNode',
        position: pos,
        data: nodeData as unknown as Record<string, unknown>,
        draggable: false,
        selectable: false,
        style: { background: 'none', border: 'none', padding: 0, width: NODE_W, height: nodeH },
      })

      if (node.parent_node_key && visibleKeys.has(node.parent_node_key)) {
        const edgePair = `${node.parent_node_key}→${key}`
        if (!seenEdges.has(edgePair)) {
          seenEdges.add(edgePair)
          rfEdges.push({
            id: `e_${node.parent_node_key}_${key}`,
            source: node.parent_node_key,
            target: key,
            type: 'treeEdge',
            style: { stroke: 'var(--border)', strokeWidth: 1.5 },
            animated: false,
          })
        }
      }
    }

    // Sort by Y position so ▴/▾ navigate top-to-bottom in the tree
    const sortedMatchKeys = Array.from(matchKeys).sort((a, b) =>
      (positions.get(a)?.y ?? 0) - (positions.get(b)?.y ?? 0)
    )
    matchKeysRef.current = sortedMatchKeys
    // Defer state updates out of the useMemo to avoid setState-in-render.
    queueMicrotask(() => setMatchTotal(sortedMatchKeys.length))
    if (onMatchCount) onMatchCount(sortedMatchKeys.length)
    return { rfNodes, rfEdges }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, visibleKeys, flags, selectedKey, expandedKeys, searchTerm, handleSelect, handleToggleExpand, handleFlag])

  // ── States ───────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={centreStyle}>
        <span style={{ color: 'var(--accent)', fontSize: 18 }}>▌</span>
        <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
          querying graph api…
        </span>
      </div>
    )
  }

  if (loadErr) {
    return (
      <div style={centreStyle}>
        <span style={{ color: 'var(--red)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
          ✗ {loadErr}
        </span>
      </div>
    )
  }

  if (!data) return null

  if (!data.ok && data.error_code === 'PID_AMBIGUOUS') {
    return (
      <div style={centreStyle}>
        <AmbiguityPicker
          focalPid={focalPid}
          candidates={data.pid_candidates}
          nodes={data.nodes as unknown as Record<string, ProcessNodeData>}
          onPick={setPinnedNodeKey}
        />
      </div>
    )
  }

  if (!data.ok && data.error_code !== 'LIMIT_EXCEEDED') {
    return (
      <div style={centreStyle}>
        <ErrorPanel code={data.error_code} msg={data.error_message} onReset={onReset} />
      </div>
    )
  }

  return (
    <div style={{ flex: 1, position: 'relative' }}>
      {data.error_code === 'LIMIT_EXCEEDED' && (
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0, zIndex: 10,
          background: 'rgba(240,179,64,0.07)', borderBottom: '1px solid rgba(240,179,64,0.2)',
          color: 'var(--amber)', fontFamily: 'var(--font-mono)', fontSize: 10.5,
          padding: '5px 12px',
        }}>
          ⚠ {data.error_message}
        </div>
      )}
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={NODE_TYPES}
        edgeTypes={EDGE_TYPES}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.2}
        maxZoom={2}
        zoomOnDoubleClick={false}
        proOptions={{ hideAttribution: true }}
        style={TREE_BG}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        onNodeClick={() => {}}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={24}
          size={1}
          color="var(--border-soft)"
        />
        <TreeControls
          focalNodeKey={data.focal_node_key}
          fitViewTrigger={fitViewTrigger}
          centerTarget={centerTarget}
          searchTerm={searchTerm}
          onSearchChange={onSearchChange}
          matchTotal={matchTotal}
          matchCurrent={matchCurrent}
          onMatchPrev={() => navToMatch('prev')}
          onMatchNext={() => navToMatch('next')}
        />
      </ReactFlow>
    </div>
  )
}

const TREE_BG = {
  backgroundImage: `linear-gradient(rgba(8,8,12,0.86), rgba(8,8,12,0.86)), url(/tree-bg.png)`,
  backgroundSize: 'cover',
  backgroundPosition: 'center',
}

const centreStyle: React.CSSProperties = {
  flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
  flexDirection: 'column', gap: 10, ...TREE_BG,
}

const ERROR_LABELS: Record<string, string> = {
  DEVICE_NOT_FOUND:    'Device not found in the selected time window. Check the hostname and time range.',
  NO_DATA:             'No process events found. Widen the time window or check the device name.',
  PID_NOT_FOUND:       'PID not found in the event data. The process may have started outside the time window.',
  PID_AMBIGUOUS:       'Multiple processes matched this PID. Try narrowing the time window.',
  LIMIT_EXCEEDED:      'Event limit reached — tree may be incomplete.',
  GRAPH_ERROR:         'Microsoft Graph API error.',
  CREDENTIALS_MISSING: 'MDE credentials not configured. Go to Settings.',
  ALERT_NOT_FOUND:     'Alert not found. Use the da637xxx format (Advanced Hunting) or a GUID (Graph Security API / Defender portal).',
}

function ErrorPanel({ code, msg, onReset }: { code: string | null; msg: string | null; onReset: () => void }) {
  const label = (code && ERROR_LABELS[code]) ?? 'An unexpected error occurred.'
  // Raw backend message is shown as supplementary detail. Run it through
  // friendlyError so httpx-flavoured strings ("ReadTimeout", "HTTPStatusError")
  // become analyst-readable. The plain-English code label already gives the
  // high-level reason — this second line just adds specific context.
  const detail = msg ? friendlyError(msg) : null
  return (
    <div style={{
      background: 'var(--bg-panel)', border: '1px solid var(--border)',
      borderRadius: 6, padding: '24px 28px', maxWidth: 420,
      fontFamily: 'var(--font-mono)', textAlign: 'center',
    }}>
      <div style={{ color: 'var(--red)', fontWeight: 600, fontSize: 12, marginBottom: 8 }}>
        {code ?? 'ERROR'}
      </div>
      <div style={{ color: 'var(--text-muted)', fontSize: 11, lineHeight: 1.6 }}>{label}</div>
      {detail && detail !== label && (
        <div style={{ color: 'var(--text-muted)', fontSize: 10, marginTop: 6, opacity: 0.7 }}>{detail}</div>
      )}
      <button onClick={onReset} style={{
        marginTop: 18, background: 'transparent', border: '1px solid var(--border)',
        borderRadius: 3, color: 'var(--accent)', cursor: 'pointer',
        fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
        padding: '6px 16px', letterSpacing: 0.3,
      }}>
        ← new investigation
      </button>
    </div>
  )
}
