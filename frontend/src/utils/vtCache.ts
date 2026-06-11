import type { VtResult } from '../api/vt'

// Module-level VT lookup cache. Shared between VtButton and HuntTab's
// IocAddButton so a verdict captured by one is available to the other:
// previously the IocAddButton in the Hunt-tab expanded row had no way
// to read the cached lookup, so adding to the IOC list after running a
// VT check landed with verdict='unknown' even though the verdict was
// already in memory.

const _cache = new Map<string, VtResult>()

export function getCachedVt(ioc: string): VtResult | null {
  return _cache.get(ioc) ?? null
}

export function setCachedVt(ioc: string, result: VtResult): void {
  _cache.set(ioc, result)
}

// Translate a VT result into the verdict shape the IOC store uses.
// 'unknown' is returned for not-found IOCs so the caller can fall
// through to the default without having to handle null.
export function verdictFromVt(r: VtResult | null): 'malicious' | 'suspicious' | 'clean' | 'unknown' {
  if (!r || !r.found) return 'unknown'
  if ((r.malicious ?? 0) > 0) return 'malicious'
  if ((r.suspicious ?? 0) > 0) return 'suspicious'
  return 'clean'
}
