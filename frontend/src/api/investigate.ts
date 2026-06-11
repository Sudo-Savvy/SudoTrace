import type { InvestigateResponse, DeviceInfoData, TelemetryResponse, NetworkAdaptersResponse, HostAlertsResponse, HostIncidentsResponse } from '../types'

const BASE = '/api/investigate'

export interface InvestigateRequest {
  hostname: string
  focal_pid: number
  focal_time: string | null
  time_window: string
  focal_node_key?: string
  alert_id?: string
}

export async function fetchProcessTree(req: InvestigateRequest): Promise<InvestigateResponse> {
  const res = await fetch(`${BASE}/process-tree`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(req),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'Process tree request failed.')
  return data
}

export interface DeviceInfoResponse extends DeviceInfoData {
  ok: boolean
  error: string | null
}

export interface DeviceLookupMatch {
  device_id:         string
  device_name:       string
  os_platform:       string
  os_version:        string
  public_ip:         string
  machine_group:     string
  join_type:         string
  exposure_level:    string
  onboarding_status: string
  last_seen:         string
}

export interface DeviceLookupResponse {
  ok:            boolean
  error:         string | null
  resolved_kind?: 'hostname' | 'device_id'
  matches:       DeviceLookupMatch[]
}

export async function lookupDevice(
  q: string,
  kind: 'auto' | 'hostname' | 'device_id' = 'auto',
): Promise<DeviceLookupResponse> {
  const params = new URLSearchParams({ q, kind })
  const res = await fetch(`${BASE}/lookup?${params}`, { credentials: 'include' })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    return { ok: false, error: data.detail || `Lookup returned HTTP ${res.status}.`, matches: [] }
  }
  return data
}

export async function fetchDeviceInfo(hostname: string): Promise<DeviceInfoResponse> {
  const res = await fetch(`${BASE}/device-info?hostname=${encodeURIComponent(hostname)}`, {
    credentials: 'include',
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'Device info request failed.')
  return data
}

export async function fetchNetworkAdapters(hostname: string): Promise<NetworkAdaptersResponse> {
  const res = await fetch(`${BASE}/network-adapters?hostname=${encodeURIComponent(hostname)}`, {
    credentials: 'include',
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'Network adapters request failed.')
  return data
}

export async function fetchHostAlerts(hostname: string): Promise<HostAlertsResponse> {
  const res = await fetch(`${BASE}/alerts?hostname=${encodeURIComponent(hostname)}`, {
    credentials: 'include',
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'Host alerts request failed.')
  return data
}

export async function fetchHostIncidents(hostname: string): Promise<HostIncidentsResponse> {
  const res = await fetch(`${BASE}/incidents?hostname=${encodeURIComponent(hostname)}`, {
    credentials: 'include',
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'Host incidents request failed.')
  return data
}

export interface TelemetryRequest {
  hostname: string
  pid: number
  username: string
  focal_time: string | null
  time_window: string
  table: string
}

export async function fetchTelemetry(req: TelemetryRequest): Promise<TelemetryResponse> {
  const res = await fetch(`${BASE}/telemetry`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify(req),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(data.detail || 'Telemetry request failed.')
  return data
}
