import { useState, useEffect } from 'react'

export interface IocEntry {
  ioc: string
  // 'hash' / 'ip' / 'domain' get VirusTotal lookups and the existing
  // network / file pivots. 'registry' covers full registry keys, value
  // names or data dumps; 'file_path' covers full filesystem paths. VT
  // doesn't index either, but they still hunt-pivot against the
  // respective MDE tables.
  iocType: 'hash' | 'ip' | 'domain' | 'registry' | 'file_path' | 'cmdline'
  // Specific hash algorithm — recorded so the "hunt for this IOC" pivot
  // queries the right KQL field (SHA1 / SHA256 / MD5). When the entry
  // came from a column whose name carried the algorithm (e.g.
  // `InitiatingProcessSHA1`) we capture it directly. For IOCs added
  // without that context (Claude suggestions, manual paste) the pivot
  // helper falls back to length-based detection.
  hashType?: 'sha1' | 'sha256' | 'md5'
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown'
  name?: string | null
  country?: string | null
  as_owner?: string | null
  asn?: number | null
  total?: number
  malicious?: number
  suspicious?: number
  link?: string
  addedAt: number
}

const _list: IocEntry[] = []
const _listeners = new Set<() => void>()

function _notify() {
  _listeners.forEach(fn => fn())
}

export function addIoc(entry: IocEntry): void {
  if (_list.some(e => e.ioc === entry.ioc)) return
  _list.unshift(entry)
  _notify()
}

export function removeIoc(ioc: string): void {
  const idx = _list.findIndex(e => e.ioc === ioc)
  if (idx >= 0) {
    _list.splice(idx, 1)
    _notify()
  }
}

export function hasIoc(ioc: string): boolean {
  return _list.some(e => e.ioc === ioc)
}

export function clearIocs(): void {
  _list.splice(0, _list.length)
  _notify()
}

export function updateIoc(ioc: string, updates: Partial<IocEntry>): void {
  const idx = _list.findIndex(e => e.ioc === ioc)
  if (idx === -1) return
  _list[idx] = { ..._list[idx], ...updates }
  _notify()
}

export function getIocCount(): number {
  return _list.length
}

// Snapshot for session auto-save.
export function getIocs(): IocEntry[] {
  return _list.slice()
}

// Replace the list wholesale — used by session recovery to restore an
// auto-saved IOC list after login. Dedupes by `ioc` so noisy snapshots
// can't introduce duplicates.
export function hydrateIocs(list: IocEntry[]): void {
  _list.splice(0, _list.length)
  const seen = new Set<string>()
  for (const e of list) {
    if (!e || typeof e.ioc !== 'string' || seen.has(e.ioc)) continue
    seen.add(e.ioc)
    _list.push(e)
  }
  _notify()
}

export function useIocList(): IocEntry[] {
  const [, setV] = useState(0)
  useEffect(() => {
    const bump = () => setV(v => v + 1)
    _listeners.add(bump)
    return () => { _listeners.delete(bump) }
  }, [])
  return _list
}
