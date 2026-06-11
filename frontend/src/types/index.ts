export interface User {
  username: string
  must_change_password: boolean
  key_available: boolean
}

export type FlagStatus = 'malicious' | 'suspicious' | 'investigate' | 'benign' | null  // investigate kept for data compat

export interface ProcessNodeData {
  node_key: string
  pid: number
  name: string
  cmdline: string
  user: string
  timestamp: string
  folder: string
  sha1:   string
  sha256: string
  md5:    string
  parent_node_key: string | null
  child_node_keys: string[]
  is_focal: boolean
  is_lolbin: boolean
}

export type InvMode = 'host-pid' | 'alert-id'

export interface Investigation {
  id: string
  hostname: string
  pid: string | null
  alertId: string | null
  mode: InvMode
  timeWindow: string
  rawTimeWindow: string
  focalTimeIso: string | null
  startedAt: string
}

export interface InvestigateResponse {
  ok: boolean
  error_code: string | null
  error_message: string | null
  nodes: Record<string, ProcessNodeData>
  ancestry_chain: string[]
  focal_node_key: string | null
  pid_candidates: string[]
  clock_skew_seconds: number
  resolved_hostname?: string | null
  resolved_pid?: number | null
}

export interface DeviceInfoData {
  os_platform: string
  os_version: string
  os_build: string
  sensor_health: string
  av_status: string
  last_seen: string
  // Extended fields — populated when the analyst opens the hostname detail
  // popover. All optional because older backend deployments may not return them.
  device_name?: string
  device_id?: string
  os_architecture?: string
  os_version_info?: string
  client_version?: string
  public_ip?: string
  exposure_level?: string
  onboarding_status?: string
  logged_on_users?: string
  is_azure_ad_joined?: boolean | null
  join_type?: string
  device_category?: string
  device_type?: string
  machine_group?: string
  is_isolated?: boolean | null
}

export interface TelemetryResponse {
  ok: boolean
  error: string | null
  rows: Record<string, unknown>[]
}

export interface NetworkAdapterIp {
  ip: string
  subnet_prefix: number | null
  address_type: string
}

export interface NetworkAdapter {
  name: string
  type: string
  status: string
  mac: string
  tunnel_type: string
  ipv4_dhcp: string
  ipv6_dhcp: string
  ip_addresses: NetworkAdapterIp[]
  dns_addresses: string[]
  default_gateways: string[]
  connected_networks: string[]
  last_seen: string
}

export interface NetworkAdaptersResponse {
  ok: boolean
  error: string | null
  adapters: NetworkAdapter[]
}

export interface HostAlert {
  timestamp: string
  alert_id: string
  title: string
  severity: string
  categories: string[]
  service_source: string
  detection_source: string
  last_verdict: string
  remediation_state: string
  additional_fields: Record<string, unknown>
}

export interface HostAlertsResponse {
  ok: boolean
  error: string | null
  alerts: HostAlert[]
}

export interface HostIncidentAlert {
  id: string
  title: string
  severity: string
  status: string
  classification: string
  determination: string
  category: string
  detection_source: string
  service_source: string
  mitre_techniques: string[]
  threat_display_name: string
  threat_family: string
  first_activity: string
  last_activity: string
  alert_web_url: string
}

export interface HostIncidentComment {
  body: string
  created_by: string
  created_at: string
}

export interface HostIncident {
  id: string
  display_name: string
  severity: string
  status: string
  classification: string
  determination: string
  assigned_to: string
  created: string
  last_update: string
  incident_web_url: string
  redirect_incident_id: string
  description: string
  summary: string
  custom_tags: string[]
  system_tags: string[]
  comments: HostIncidentComment[]
  comments_count: number
  host_alert_count: number
  host_alerts: HostIncidentAlert[]
  host_earliest_seen: string
  host_latest_seen: string
}

export interface HostIncidentsResponse {
  ok: boolean
  error: string | null
  incidents: HostIncident[]
}

export type AnalysisSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN'

export interface AnalysisResult {
  severity: AnalysisSeverity
  confidence: number
  narrative: string
  delivery_vector: {
    type: string
    confidence: 'high' | 'medium' | 'low' | 'unknown'
    evidence: string
  }
  root_cause: string
  urgency: {
    level: 'immediate' | 'within_hour' | 'monitor' | 'none'
    reason: string
    active_pids: number[]
  }
  per_process_findings: Array<{
    pid: number
    name: string
    verdict: 'malicious' | 'suspicious' | 'benign' | 'unknown'
    summary: string
    evidence: string[]
  }>
  ioc_suggestions: Array<{
    type: 'ip' | 'domain' | 'hash' | 'file_path' | 'registry_key'
    value: string
    context: string
    confidence: 'high' | 'medium' | 'low'
  }>
  token_usage: {
    input_tokens: number
    output_tokens: number
    cached_tokens: number
    cost_usd: number
    duration_ms: number
  }
}
