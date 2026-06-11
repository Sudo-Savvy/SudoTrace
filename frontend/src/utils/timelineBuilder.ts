import type { InvestigateResponse, HostIncident } from '../types'
import type {
  FlaggedNodeRef, FlaggedEventRef, FlaggedIncidentRef,
} from '../store/investigationStore'
import type { HuntFlagEntry } from '../store/huntFlagStore'

// Public helper: given a timeline event + the loaded investigation
// context, returns a targeted Hunt request that loads exactly the
// event the analyst clicked. The Hunt tab uses Timestamp + DeviceName
// + ProcessId (or ReportId where available) as the discriminator and
// a ±5 minute custom range to satisfy the backend's mandatory
// timeframe clause.

export interface HuntJumpForEvent {
  kql:           string
  timeframe:     string
  customRange:   { startIso: string; endIso: string }
  targetRow?:    Record<string, unknown>
}

function escapeKqlStr(v: string): string {
  return v.replace(/"/g, '')
}

function tightRangeAround(iso: string): { wire: string; iso: { startIso: string; endIso: string } } | null {
  const t = Date.parse(iso)
  if (isNaN(t)) return null
  const startIso = new Date(t - 5 * 60_000).toISOString()
  const endIso   = new Date(t + 5 * 60_000).toISOString()
  return { wire: `custom:${startIso}..${endIso}`, iso: { startIso, endIso } }
}

export function buildHuntRequestForEvent(
  ev: TimelineEvent,
  treeData:  InvestigateResponse | null,
  hostname:  string | null,
  huntFlags: HuntFlagEntry[],
): HuntJumpForEvent | null {
  // Hunt-tab flag: prefer the stored KQL so the analyst lands in the
  // exact same source table, plus row identifiers for the in-result jump.
  if (ev.id.startsWith('flag:hunt:')) {
    const key = ev.id.slice('flag:hunt:'.length)
    const entry = huntFlags.find(h => h.key === key)
    if (!entry) return null
    const tight = tightRangeAround(ev.tsIso)
    if (!tight) return null
    return targetedFromHuntRow(entry.kql, entry.row, tight)
  }

  // Process-flag entries pivot to a targeted DeviceProcessEvents query
  // by Timestamp + ProcessId. (The 'process' category itself no longer
  // appears on the timeline.)
  if (ev.id.startsWith('flag:proc:')) {
    const node = ev.nodeKey ? treeData?.nodes[ev.nodeKey] : null
    if (!node || !hostname) return null
    const tight = tightRangeAround(ev.tsIso)
    if (!tight) return null
    const filters = [
      `DeviceName == "${escapeKqlStr(hostname)}"`,
      `Timestamp == datetime("${escapeKqlStr(ev.tsIso)}")`,
      `ProcessId == ${node.pid}`,
    ]
    return {
      kql: `DeviceProcessEvents\n| where ${filters.join('\n  and ')}\n| take 1`,
      timeframe: tight.wire,
      customRange: tight.iso,
    }
  }

  // Telemetry-event flag — schema-dependent. We know Timestamp +
  // DeviceId (often) + ReportId; the `tab` indicates the table.
  if (ev.id.startsWith('flag:event:')) {
    // Caller-side row data isn't directly attached to the timeline
    // event; the FlaggedEventRef lives in the store. We rebuild the
    // query from the event's identifiers and the tab tag implied by
    // the original key. For now, just bounce to a hostname+timestamp
    // search on DeviceEvents — the analyst sees something near the
    // moment of the flag, even if we can't target exactly.
    if (!hostname) return null
    const tight = tightRangeAround(ev.tsIso)
    if (!tight) return null
    return {
      kql: `DeviceEvents\n| where DeviceName == "${escapeKqlStr(hostname)}"\n  and Timestamp == datetime("${escapeKqlStr(ev.tsIso)}")\n| take 50`,
      timeframe: tight.wire,
      customRange: tight.iso,
    }
  }

  // Alerts → query AlertEvidence on the alert id.
  if (ev.category === 'alert' && ev.alertId) {
    const tight = tightRangeAround(ev.tsIso)
    if (!tight) return null
    return {
      kql: `AlertEvidence\n| where AlertId == "${escapeKqlStr(ev.alertId)}"\n| take 100`,
      timeframe: tight.wire,
      customRange: tight.iso,
    }
  }

  // Incidents themselves don't map to a single hunt-table row, so
  // there's nothing useful to pivot to. Returning null disables the
  // click affordance for those rows.
  return null
}

function targetedFromHuntRow(
  originalKql: string,
  row: Record<string, unknown>,
  tight: { wire: string; iso: { startIso: string; endIso: string } },
): HuntJumpForEvent | null {
  const trimmed = originalKql
    .split('\n')
    .filter(l => {
      const t = l.trim()
      return t.length > 0 && !t.startsWith('//') && !t.startsWith('let ')
    })
    .join('\n')
    .trim()
  const tableMatch = trimmed.match(/^([A-Za-z][A-Za-z0-9_]*)/)
  if (!tableMatch) return null
  const table = tableMatch[1]
  const filters: string[] = []
  const ts = row.Timestamp
  if (typeof ts === 'string' && ts) {
    filters.push(`Timestamp == datetime("${escapeKqlStr(ts)}")`)
  }
  const dev = row.DeviceId
  if (typeof dev === 'string' && dev) {
    filters.push(`DeviceId == "${escapeKqlStr(dev)}"`)
  }
  const rid = row.ReportId
  if (typeof rid === 'number') {
    filters.push(`ReportId == ${rid}`)
  } else if (typeof rid === 'string' && rid) {
    filters.push(`ReportId == "${escapeKqlStr(rid)}"`)
  }
  if (filters.length < 2) return null
  return {
    kql: `${table}\n| where ${filters.join('\n  and ')}\n| take 1`,
    timeframe: tight.wire,
    customRange: tight.iso,
    targetRow: row,
  }
}

// A single row on the timeline. Categories drive the icon + colour
// columns. `tsMs` is parsed once upfront so sort comparisons are cheap.
export type TimelineCategory = 'incident' | 'alert' | 'flag' | 'note'

export interface TimelineEvent {
  id:          string
  tsMs:        number
  tsIso:       string
  category:    TimelineCategory
  icon:        string
  title:       string
  detail:      string
  // Severity-style colour hint when applicable (incidents/alerts use it
  // to pick red/amber/green; process events leave it null).
  colour:      string | null
  // Hooks for follow-up clicks — Timeline tab can use them to pivot
  // back into the tree / incident view.
  pid?:        number
  nodeKey?:    string
  incidentId?: string
  alertId?:    string
}

function parseTs(iso: string | null | undefined): number | null {
  if (!iso) return null
  const t = Date.parse(iso)
  return isNaN(t) ? null : t
}

// Map MDE / Defender severity strings (case-insensitive) to UI colours
// matching the rest of the app's flag palette.
function severityColour(sev: string | null | undefined): string | null {
  const s = (sev ?? '').toLowerCase()
  if (s === 'high')          return '#FF5E5B'
  if (s === 'medium')        return '#F0B340'
  if (s === 'low')           return '#7AA8FF'
  if (s === 'informational') return '#888'
  return null
}

// Pulls the most useful identifying / context fields out of an MDE row,
// shaped per ActionType where we can recognise it, and falling back to
// a generic "all non-empty fields" dump otherwise. Used to build the
// detail line for malicious-flagged hunt / telemetry events on the
// timeline so the analyst sees the substance of WHY they flagged it,
// not just the action type + filename.
function rowContext(row: Record<string, unknown>): string {
  const s = (k: string) => {
    const v = row[k]
    if (v === null || v === undefined || v === '') return ''
    return String(v)
  }
  const pid     = s('ProcessId') || s('InitiatingProcessId')
  const ppid    = s('InitiatingProcessId')
  const folder  = s('FolderPath') || s('InitiatingProcessFolderPath')
  const cmdline = s('ProcessCommandLine') || s('InitiatingProcessCommandLine')
  const account = s('AccountName') || s('InitiatingProcessAccountName')
  const initBy  = s('InitiatingProcessFileName')
  const remoteIp   = s('RemoteIP')
  const remotePort = s('RemotePort')
  const localIp    = s('LocalIP')
  const localPort  = s('LocalPort')
  const protocol   = s('Protocol')
  const url        = s('RemoteUrl') || s('FileOriginUrl')
  const sha1       = s('SHA1') || s('InitiatingProcessSHA1')
  const sha256     = s('SHA256') || s('InitiatingProcessSHA256')
  const md5        = s('MD5') || s('InitiatingProcessMD5')
  const regKey     = s('RegistryKey')
  const regVal     = s('RegistryValueName')
  const regData    = s('RegistryValueData')
  const action     = s('ActionType')
  const parts: string[] = []
  // Process identity
  if (pid)     parts.push(`pid ${pid}`)
  if (folder)  parts.push(folder)
  if (cmdline && cmdline !== folder) {
    // No truncation — the CSS row already wraps long text with
    // `word-break: break-word`, and the analyst now has the edit
    // button if they want to rewrite a noisy cmdline into something
    // shorter.
    parts.push(cmdline)
  }
  if (account) parts.push(`as ${account}`)
  if (initBy && (!cmdline || !cmdline.toLowerCase().includes(initBy.toLowerCase()))) {
    parts.push(`init by ${initBy}${ppid && ppid !== pid ? ` (ppid ${ppid})` : ''}`)
  }
  // Network identity
  if (remoteIp) {
    parts.push(`remote ${remoteIp}${remotePort ? ':' + remotePort : ''}${protocol ? ' ' + protocol : ''}`)
  }
  if (localIp && localIp !== remoteIp) {
    parts.push(`local ${localIp}${localPort ? ':' + localPort : ''}`)
  }
  if (url) parts.push(`url ${url}`)
  // Hashes — short form
  const hash = sha256 || sha1 || md5
  if (hash) parts.push(`${sha256 ? 'sha256' : sha1 ? 'sha1' : 'md5'} ${hash}`)
  // Registry
  if (regKey) {
    const reg = regVal
      ? `${regKey}\\${regVal}${regData ? ' = ' + regData : ''}`
      : regKey
    parts.push(reg)
  }
  if (parts.length === 0) {
    // Generic fallback — dump non-empty, non-noisy fields up to a cap.
    const NOISE = new Set([
      'Timestamp', 'DeviceId', 'DeviceName', 'ReportId', 'AdditionalFields',
      'ActionType',
    ])
    const kept: string[] = []
    for (const [k, v] of Object.entries(row)) {
      if (NOISE.has(k)) continue
      if (v === null || v === undefined || v === '') continue
      const sv = String(v)
      if (!sv.trim() || sv === '0') continue
      kept.push(`${k}=${sv}`)
      if (kept.length >= 8) break
    }
    if (kept.length) parts.push(kept.join(' · '))
  }
  return action && parts.length ? `${action} · ${parts.join(' · ')}` : (action || parts.join(' · '))
}

export function buildTimeline(
  treeData:          InvestigateResponse | null,
  hostIncidents:     HostIncident[] | null,
  flaggedNodes:      FlaggedNodeRef[]     = [],
  flaggedEvents:     FlaggedEventRef[]    = [],
  flaggedIncidents:  FlaggedIncidentRef[] = [],
  huntFlags:         HuntFlagEntry[]      = [],
): TimelineEvent[] {
  const events: TimelineEvent[] = []
  const RED = '#FF5E5B'

  // Process spawns are NOT emitted here — only analyst-flagged
  // processes (suspicious / malicious) make the timeline. The
  // flag-driven entries come from the flaggedNodes loop further down.
  // (Used to dump every tree node; that buried the signal in noise on
  // busy hosts where the tree has thousands of processes.)

  // Incident creation + the alerts attached to each incident. Each
  // alert's first_activity is its on-timeline appearance.
  if (hostIncidents) {
    for (const inc of hostIncidents) {
      const incTs = parseTs(inc.created)
      if (incTs != null) {
        const detailParts = [
          inc.severity ? `severity ${inc.severity}` : '',
          inc.status ? `status ${inc.status}` : '',
          inc.classification ? `class ${inc.classification}` : '',
          inc.assigned_to ? `assigned to ${inc.assigned_to}` : '',
        ].filter(Boolean)
        events.push({
          id:         `inc:${inc.id}`,
          tsMs:       incTs,
          tsIso:      inc.created,
          category:   'incident',
          icon:       '🛡',
          title:      `Incident opened — ${inc.display_name || inc.id}`,
          detail:     detailParts.join(' · '),
          colour:     severityColour(inc.severity),
          incidentId: inc.id,
        })
      }
      for (const a of inc.host_alerts ?? []) {
        const aTs = parseTs(a.first_activity)
        if (aTs == null) continue
        const detailParts = [
          a.severity ? `severity ${a.severity}` : '',
          a.category ? `category ${a.category}` : '',
          a.detection_source ? `source ${a.detection_source}` : '',
          a.threat_display_name ? `threat ${a.threat_display_name}` : '',
          a.mitre_techniques?.length ? `mitre ${a.mitre_techniques.join(', ')}` : '',
        ].filter(Boolean)
        events.push({
          id:         `alert:${a.id}`,
          tsMs:       aTs,
          tsIso:      a.first_activity,
          category:   'alert',
          icon:       '⚠',
          title:      `Alert — ${a.title || a.id}`,
          detail:     detailParts.join(' · '),
          colour:     severityColour(a.severity),
          incidentId: inc.id,
          alertId:    a.id,
        })
      }
    }
  }

  // ── Analyst-flagged items (suspicious + malicious) ─────────────────
  // Each suspicious or malicious flag (processes, telemetry events,
  // incidents, hunt events) lands on the timeline at the source
  // event's timestamp. Benign is deliberately excluded — it's a
  // visual marker only, not evidence-worthy.
  const AMBER = '#F0B340'
  const flagColour = (f: string) => f === 'malicious' ? RED : AMBER
  const flagLabel  = (f: string) => f === 'malicious' ? 'MALICIOUS' : 'SUSPICIOUS'
  const isEvidence = (f: string) => f === 'malicious' || f === 'suspicious'

  for (const f of flaggedNodes) {
    if (!isEvidence(f.flag)) continue
    const node = treeData?.nodes[f.node_key]
    if (!node) continue
    const tsMs = parseTs(node.timestamp)
    if (tsMs == null) continue
    // Rich context for analyst-flagged processes: command line,
    // parent process, account, path, hash. The previous "user + path"
    // was too thin — the analyst needs to recall WHY they flagged it
    // (typically the command line is the smoking gun).
    const parentKey = node.parent_node_key
    const parent = parentKey ? treeData?.nodes[parentKey] : null
    const cmdline = (node.cmdline || '').trim()
    const detailParts: string[] = []
    if (node.user)   detailParts.push(`as ${node.user}`)
    if (node.folder) detailParts.push(`from ${node.folder}`)
    if (cmdline) {
      detailParts.push(`cmd: ${cmdline}`)
    }
    if (parent) {
      detailParts.push(`spawned by ${parent.name || '?'} (pid ${parent.pid})`)
    }
    if (node.sha1) detailParts.push(`sha1 ${String(node.sha1)}`)
    events.push({
      id:       `flag:proc:${f.node_key}`,
      tsMs, tsIso: node.timestamp,
      category: 'flag',
      icon:     '🚩',
      title:    `Flagged ${flagLabel(f.flag)} — ${node.name || '(unknown)'} (pid ${node.pid})`,
      detail:   detailParts.join(' · '),
      colour:   flagColour(f.flag),
      pid:      node.pid,
      nodeKey:  f.node_key,
    })
  }

  for (const f of flaggedEvents) {
    if (!isEvidence(f.flag)) continue
    const r = f.row
    const tsRaw = typeof r.Timestamp === 'string' ? r.Timestamp : null
    const tsMs = parseTs(tsRaw)
    if (tsMs == null || !tsRaw) continue
    const action = String(r.ActionType ?? '')
    const file   = String(r.FileName ?? r.InitiatingProcessFileName ?? '')
    const headline = [action, file].filter(Boolean).join(' · ') || '(event)'
    events.push({
      id:       `flag:event:${f.key}`,
      tsMs, tsIso: tsRaw,
      category: 'flag',
      icon:     '🚩',
      title:    `Flagged ${flagLabel(f.flag)} — [${f.tab}] ${headline}`,
      detail:   rowContext(r),
      colour:   flagColour(f.flag),
    })
  }

  for (const f of flaggedIncidents) {
    if (!isEvidence(f.flag)) continue
    const inc = (hostIncidents ?? []).find(i => i.id === f.incident_id)
    if (!inc) continue
    const tsMs = parseTs(inc.created)
    if (tsMs == null) continue
    events.push({
      id:         `flag:inc:${f.incident_id}`,
      tsMs, tsIso: inc.created,
      category:   'flag',
      icon:       '🚩',
      title:      `Flagged ${flagLabel(f.flag)} — incident ${inc.display_name || f.incident_id}`,
      detail:     [inc.severity ? `severity ${inc.severity}` : '', inc.classification ? `class ${inc.classification}` : ''].filter(Boolean).join(' · '),
      colour:     flagColour(f.flag),
      incidentId: f.incident_id,
    })
  }

  for (const h of huntFlags) {
    if (!isEvidence(h.flag)) continue
    const r = h.row
    const tsRaw = typeof r.Timestamp === 'string' ? r.Timestamp : null
    const tsMs = parseTs(tsRaw)
    if (tsMs == null || !tsRaw) continue
    const action = String(r.ActionType ?? '')
    const file   = String(r.FileName ?? r.InitiatingProcessFileName ?? '')
    const headline = [action, file].filter(Boolean).join(' · ') || '(event)'
    events.push({
      id:       `flag:hunt:${h.key}`,
      tsMs, tsIso: tsRaw,
      category: 'flag',
      icon:     '🚩',
      title:    `Flagged ${flagLabel(h.flag)} — [hunt] ${headline}`,
      detail:   rowContext(r),
      colour:   flagColour(h.flag),
    })
  }

  events.sort((a, b) => a.tsMs - b.tsMs)
  return events
}
