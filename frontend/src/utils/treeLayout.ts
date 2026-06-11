import type { ProcessNodeData } from '../types'

export const NODE_W = 360
export const NODE_H = 104   // kept as default/fallback
const GAP_X = 28
const GAP_Y = 40

// Fixed chrome height: header + meta + footer rows (px)
const CHROME_H = 78
// Line height for the cmdline area at 10px mono font
const LINE_H = 14.5
// Approximate chars that fit in one cmdline line (NODE_W - 20px padding, ~6px/char)
const CHARS_PER_LINE = 56
const MAX_LINES = 5
const MIN_LINES = 1

export function estimateNodeHeight(cmdline: string | null | undefined): number {
  const len = cmdline?.length ?? 0
  const lines = len === 0 ? MIN_LINES : Math.ceil(len / CHARS_PER_LINE)
  const clamped = Math.max(MIN_LINES, Math.min(MAX_LINES, lines))
  return Math.round(CHROME_H + clamped * LINE_H + 4)
}

type Pos = { x: number; y: number }

function subtreeWidth(
  key: string,
  visibleChildren: Map<string, string[]>,
  memo: Map<string, number>,
): number {
  if (memo.has(key)) return memo.get(key)!
  const children = visibleChildren.get(key) ?? []
  if (children.length === 0) {
    memo.set(key, NODE_W)
    return NODE_W
  }
  const total =
    children.reduce((sum, c) => sum + subtreeWidth(c, visibleChildren, memo), 0) +
    GAP_X * (children.length - 1)
  const w = Math.max(NODE_W, total)
  memo.set(key, w)
  return w
}

function placeNode(
  key: string,
  cx: number,
  y: number,
  visibleChildren: Map<string, string[]>,
  widthMemo: Map<string, number>,
  heights: Map<string, number>,
  out: Map<string, Pos>,
) {
  out.set(key, { x: cx - NODE_W / 2, y })
  const children = visibleChildren.get(key) ?? []
  if (children.length === 0) return
  const totalW =
    children.reduce((sum, c) => sum + subtreeWidth(c, visibleChildren, widthMemo), 0) +
    GAP_X * (children.length - 1)
  const nodeH = heights.get(key) ?? NODE_H
  let left = cx - totalW / 2
  for (const c of children) {
    const cw = subtreeWidth(c, visibleChildren, widthMemo)
    placeNode(c, left + cw / 2, y + nodeH + GAP_Y, visibleChildren, widthMemo, heights, out)
    left += cw + GAP_X
  }
}

export function layoutTree(
  nodes: Record<string, ProcessNodeData>,
  visibleKeys: Set<string>,
  heights?: Map<string, number>,
): Map<string, Pos> {
  const h = heights ?? new Map<string, number>()

  // Build parent→children map for visible nodes only
  const visibleChildren = new Map<string, string[]>()
  const hasParent = new Set<string>()

  for (const key of visibleKeys) {
    visibleChildren.set(key, [])
  }
  for (const key of visibleKeys) {
    const parent = nodes[key]?.parent_node_key
    if (parent && visibleKeys.has(parent)) {
      visibleChildren.get(parent)!.push(key)
      hasParent.add(key)
    }
  }

  const roots = [...visibleKeys].filter(k => !hasParent.has(k))
  const widthMemo = new Map<string, number>()
  const out = new Map<string, Pos>()

  const totalRootW =
    roots.reduce((sum, r) => sum + subtreeWidth(r, visibleChildren, widthMemo), 0) +
    GAP_X * (roots.length - 1)

  let rx = totalRootW / 2
  for (const r of roots) {
    const rw = subtreeWidth(r, visibleChildren, widthMemo)
    placeNode(r, rx - totalRootW / 2 + rw / 2, 0, visibleChildren, widthMemo, h, out)
    rx += rw + GAP_X
  }

  return out
}
