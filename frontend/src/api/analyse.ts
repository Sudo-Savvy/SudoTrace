import type { AnalysisResult, ProcessNodeData, DeviceInfoData } from '../types'

export type AnalyseScope = 'focused' | 'wide'

export interface FlaggedEventPayload {
  node_key: string
  tab: string
  row_idx: number
  flag: string
  row: Record<string, unknown>
}

export interface FlaggedIncidentAlertPayload {
  id: string
  title: string
  severity: string
  status: string
  category: string
  detection_source: string
  mitre_techniques: string[]
  threat_display_name: string
  threat_family: string
  first_activity: string
  last_activity: string
}

export interface FlaggedIncidentPayload {
  incident_id: string
  display_name: string
  severity: string
  status: string
  classification: string
  determination: string
  description: string
  assigned_to: string
  created: string
  last_update: string
  host_earliest_seen: string
  host_latest_seen: string
  host_alerts: FlaggedIncidentAlertPayload[]
  comments: Array<{ body: string; created_by: string; created_at: string }>
  flag: string
}

export interface AnalystIocPayload {
  ioc:        string
  ioc_type:   'hash' | 'ip' | 'domain' | 'registry' | 'file_path' | 'cmdline'
  verdict:    'malicious' | 'suspicious' | 'clean' | 'unknown'
  name?:      string | null
  country?:   string | null
  as_owner?:  string | null
  asn?:       number | null
  total?:     number
  malicious?: number
  suspicious?:number
  link?:      string
}

export interface AnalysePayload {
  investigation_id: string
  hostname: string
  focal_pid: number
  focal_time_iso: string | null
  time_window: string
  flagged_nodes: Array<{ node_key: string; flag: string }>
  all_nodes: Record<string, ProcessNodeData>
  ancestry_chain: string[]
  device_info: DeviceInfoData | null
  scope: AnalyseScope
  flagged_events: FlaggedEventPayload[]
  flagged_incidents: FlaggedIncidentPayload[]
  flagged_iocs: AnalystIocPayload[]
}

export interface AnalyseResponse extends Partial<AnalysisResult> {
  ok: boolean
  error?: string
  error_message?: string
}

export async function runAnalysis(payload: AnalysePayload): Promise<AnalyseResponse> {
  const res = await fetch('/api/analyse/', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!res.ok) {
    if (res.status === 413) {
      return {
        ok: false,
        error: 'PAYLOAD_TOO_LARGE',
        error_message: 'Investigation is too large to send to the analysis service. Narrow the time window or reduce visible processes, then try again.',
      }
    }
    return {
      ok: false,
      error: `HTTP_${res.status}`,
      error_message: `Analysis service returned HTTP ${res.status}.`,
    }
  }
  return res.json()
}
