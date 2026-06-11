export interface VtResult {
  found: boolean
  type: 'hash' | 'ip'
  ioc: string
  malicious?: number
  suspicious?: number
  total?: number
  // hash-specific
  name?: string | null
  vendors?: string[]
  // ip-specific
  country?: string | null
  asn?: number | null
  as_owner?: string | null
  link?: string
}

export async function vtLookup(ioc: string, iocType: 'hash' | 'ip' | 'domain'): Promise<VtResult> {
  const params = new URLSearchParams({ ioc, ioc_type: iocType })
  const res = await fetch(`/api/vt/lookup?${params}`, { credentials: 'include' })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'VT lookup failed.')
  return data
}
