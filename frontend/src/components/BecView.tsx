import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import {
  fetchBecSignins, fetchBecScope, putBecCase, fetchBecEnrich, fetchBecWatch, fetchBecComms,
  type BecSigninsResponse, type BecOrigin, type BecSignin,
  type BecScopeResponse, type BecPersistenceEvent,
  type BecEnrichResponse, type BecRole, type BecWatchResponse,
  type BecCommsResponse,
} from '../api/bec'
import { friendlyError } from '../utils/errors'
import { fmtDateTime } from '../utils/dateFormat'
import BecChecklist from './BecChecklist'
import { VtButton } from './VtButton'
import RangePicker from './RangePicker'
import { buildManualHunts } from '../utils/becManualHunts'

// Finding sub-category → display (persistence + mailbox + exfil).
const PERSIST_CAT: Record<string, { label: string; color: string }> = {
  // persistence
  oauth_grant:    { label: 'OAuth consent grant', color: '#FF5E5B' },
  app_credential: { label: 'App credential added', color: '#FF5E5B' },
  new_app:        { label: 'New app / service principal', color: '#FF5E5B' },
  mfa_method:     { label: 'MFA method change',   color: '#FF5E5B' },
  device:         { label: 'Device registration', color: '#F0B340' },
  new_user:       { label: 'New user created',    color: '#FF5E5B' },
  credential:     { label: 'Credential / SSPR change', color: '#F0B340' },
  group_role:     { label: 'Group / role add',    color: '#F0B340' },
  // defence / policy tampering
  ca_policy:      { label: 'Conditional Access change', color: '#FF5E5B' },
  auth_policy:    { label: 'Auth / MFA policy change',  color: '#FF5E5B' },
  // mailbox manipulation
  inbox_rule:     { label: 'Inbox rule',           color: '#FF5E5B' },
  forwarding:     { label: 'External forwarding',  color: '#FF5E5B' },
  delegation:     { label: 'Mailbox delegation',   color: '#FF5E5B' },
  folder_perm:    { label: 'Folder permission',    color: '#FF5E5B' },
  transport_rule: { label: 'Transport rule',       color: '#FF5E5B' },
  legacy_protocol:{ label: 'Legacy protocol enabled', color: '#FF5E5B' },
  mailbox_config: { label: 'Mailbox config change', color: '#F0B340' },
  // recon / data accessed
  mail_read:      { label: 'Mailbox read',   color: '#F0B340' },
  file_read:      { label: 'File accessed',  color: '#F0B340' },
  search:         { label: 'Search',         color: '#7AA8FF' },
  // exfiltration
  file_download:  { label: 'File download',  color: '#F0B340' },
  file_upload:    { label: 'File upload',    color: '#F0B340' },
  sharing_link:   { label: 'Sharing link',   color: '#FF5E5B' },
  mailbox_export: { label: 'Mailbox export',  color: '#FF5E5B' },
  ediscovery:     { label: 'eDiscovery search', color: '#FF5E5B' },
  // anti-forensics
  mail_delete:    { label: 'Mail deleted',   color: '#FF5E5B' },
  file_delete:    { label: 'File deleted',   color: '#FF5E5B' },
  audit_bypass:   { label: 'Audit disabled', color: '#FF5E5B' },
  // action on objectives
  thread_hijack:  { label: 'Thread hijack',  color: '#FF5E5B' },
  mail_sent:      { label: 'Mail sent',      color: '#F0B340' },
  other:          { label: 'Audit event',    color: '#888' },
}

const CATEGORY_TITLE: Record<string, string> = {
  persistence:  'Persistence',
  defense:      'Defence / policy tampering',
  recon:        'Recon / data accessed',
  mailbox:      'Mailbox manipulation',
  exfil:        'Exfiltration',
  antiforensic: 'Anti-forensics',
  objective:    'Action on objectives',
}

// Plain-English explanation of what each action MEANS, so a row reads as a
// sentence ("the attacker did X, which matters because Y") instead of a label.
const ACTION_EXPLAIN: Record<string, string> = {
  oauth_grant:    'Consented an OAuth app to the account — gives the attacker programmatic access that survives a password reset.',
  app_credential: 'Added a secret or certificate to an app / service principal — stealthy persistence that survives password reset AND MFA changes (the attacker can now authenticate AS that app).',
  new_app:        'Registered a new application / service principal — attacker-controlled identity planted in the tenant for persistence.',
  mfa_method:     'Added a new MFA method to the account — lets the attacker pass MFA on future sign-ins, and can lock the real user out.',
  device:         'Registered or joined a device to the account — a persistence foothold.',
  new_user:       'Created a new user / invited an external account — a backdoor identity separate from the compromised one.',
  credential:     'Changed the account’s credentials or password-reset info.',
  group_role:     'Added the account to a group or directory role — escalates privilege / widens access.',
  ca_policy:      'Changed Conditional Access (policy or trusted location) — typically to weaken or bypass MFA enforcement for the attacker (or everyone).',
  auth_policy:    'Changed authentication-method / MFA / security-defaults policy — weakens the tenant’s own login protections.',
  folder_perm:    'Granted mailbox folder permissions — shared a folder (e.g. the Inbox) with another identity.',
  transport_rule: 'Created or changed an org-wide mail-flow (transport) rule — tenant-level forwarding / BCC / exfiltration, far broader than a single inbox rule.',
  legacy_protocol:'Enabled a legacy mail protocol (IMAP / POP / ActiveSync) — a modern-auth-bypassing channel often used for quiet exfiltration.',
  ediscovery:     'Created an eDiscovery / compliance content search — using the tenant’s own tooling to hunt for sensitive data (invoices, credentials, contacts) across mailboxes and sites.',
  audit_bypass:   'Disabled mailbox or admin auditing — anti-forensics: the attacker is blinding the very logs that record their activity.',
  inbox_rule:     'Created or changed a mailbox inbox rule — usually to hide, move, or auto-forward mail so the user doesn’t notice.',
  forwarding:     'Turned on external mail forwarding — silently copies incoming mail to an outside address.',
  delegation:     'Granted mailbox delegation / Send-As — another identity can now read or send as this mailbox.',
  mailbox_config: 'Changed mailbox configuration.',
  mail_read:      'Opened / read mailbox items — the attacker was reading the user’s email (reconnaissance / data theft).',
  file_read:      'Opened or previewed files in SharePoint / OneDrive — reading the user’s documents (recon / data theft).',
  search:         'Ran a mailbox or SharePoint search — hunting for specific content (invoices, payment details, credentials, contacts).',
  file_download:  'Downloaded files from OneDrive / SharePoint — possible data exfiltration.',
  file_upload:    'Uploaded a file to OneDrive / SharePoint — possible payload staging or planting shared content.',
  sharing_link:   'Created a sharing link — possible data exfiltration / external access.',
  mailbox_export: 'Exported mailbox contents — bulk data theft.',
  mail_delete:    'Deleted mail (incl. hard / soft delete) — covering tracks, e.g. removing the fraud mail from Sent Items.',
  file_delete:    'Deleted files — covering tracks / destruction of evidence.',
  thread_hijack:  'Replied into or forwarded a real email thread out to an external address — the BEC payload itself (fraud / data theft using the user’s trust).',
  mail_sent:      'Sent email from the account, posing as the user.',
}

// BEC Phase-1 surface. The investigation CHECKLIST is the always-available
// core — it renders from the analyst's UPN (+ optional suspected IP) with NO
// Graph connection. The live access-origin triage (Entra sign-ins) is
// non-blocking enrichment: if Graph is unreachable or a permission/licence is
// missing, the table area shows a quiet note and the checklist stays fully
// usable.

// Short label for a custom:<startISO>..<endISO> window (DD/MM HH:MM → HH:MM).
function formatCustomWindow(raw: string): string {
  if (!raw.startsWith('custom:')) return raw
  const [s, e] = raw.slice('custom:'.length).split('..')
  const fmt = (iso: string) => { const m = (iso || '').match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/); return m ? `${m[3]}/${m[2]} ${m[4]}:${m[5]}` : iso }
  return s && e ? `${fmt(s)} → ${fmt(e)}` : 'Custom'
}

const FLAG_META: Record<string, { label: string; color: string; title: string }> = {
  'hosting-asn':       { label: 'HOSTING ASN',   color: '#FF5E5B', title: 'Source is a cloud/hosting/datacenter ASN — not a residential connection' },
  'aitm-token-reuse':  { label: 'AiTM',          color: '#FF5E5B', title: 'Same session token seen from two or more IPs — adversary-in-the-middle / token theft tell' },
  'impossible-travel': { label: 'IMPOSSIBLE TRAVEL', color: '#F0B340', title: 'Two successful sign-ins too far apart in space for the time between them' },
  'legacy-auth':       { label: 'LEGACY AUTH',   color: '#F0B340', title: 'Legacy authentication protocol (no modern-auth / MFA enforcement path)' },
}

// Survives navigation within the SPA session (e.g. Home ↔ Settings) so the
// expensive fetched data — the sign-in triage, the P2 enrichment, and ESPECIALLY
// the scoped attacker activity (the UAL query can take minutes) — isn't thrown
// away and re-fetched every time the analyst leaves the page. Module scope
// outlives the component unmount. Keyed by account; cleared on New investigation.
const becSessionCache: {
  account: string
  respWindow: string                // the lookback the cached resp was fetched for
  resp: BecSigninsResponse | null
  enrich: BecEnrichResponse | null
  scope: BecScopeResponse | null
  notifiedEnabled: boolean | null   // last account state we already alerted on
} = { account: '', respWindow: '', resp: null, enrich: null, scope: null, notifiedEnabled: null }

function becCacheFor(account: string) {
  return becSessionCache.account === account ? becSessionCache : null
}
// The cached sign-ins are only valid for the window they were fetched for.
function becCachedResp(account: string, window: string) {
  return (becSessionCache.account === account && becSessionCache.respWindow === window) ? becSessionCache.resp : null
}
export function clearBecSessionCache() {
  becSessionCache.account = ''
  becSessionCache.respWindow = ''
  becSessionCache.resp = null
  becSessionCache.enrich = null
  becSessionCache.scope = null
  becSessionCache.notifiedEnabled = null
}

// Short Web-Audio chime for the account-state alert. ENABLED (still active /
// dangerous) → two urgent high beeps; DISABLED (contained) → one soft low tone.
function playStateChime(enabled: boolean) {
  try {
    const Ctx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext
    if (!Ctx) return
    const ctx = new Ctx()
    const beep = (freq: number, start: number, dur: number) => {
      const o = ctx.createOscillator(); const g = ctx.createGain()
      o.type = 'sine'; o.frequency.value = freq
      o.connect(g); g.connect(ctx.destination)
      const t = ctx.currentTime + start
      g.gain.setValueAtTime(0.0001, t)
      g.gain.exponentialRampToValueAtTime(0.18, t + 0.01)
      g.gain.exponentialRampToValueAtTime(0.0001, t + dur)
      o.start(t); o.stop(t + dur)
    }
    if (enabled) { beep(880, 0, 0.16); beep(880, 0.22, 0.16) }
    else { beep(523, 0, 0.32) }
    setTimeout(() => ctx.close().catch(() => {}), 1200)
  } catch { /* audio blocked — the visual toast still shows */ }
}

export default function BecView({ account, ip, timeWindow, offline, onReset, restore }: {
  account: string
  ip: string
  timeWindow: string
  offline?: boolean        // deliberate no-Graph mode — checklist + manual hunts only
  onReset: () => void
  // Analyst-authored state restored from a saved case (Milestone C). Triage /
  // findings re-fetch from Graph; only selections + checklist + timeline edits
  // are seeded.
  restore?: {
    selected: string[]; checked: string[]; notes: Record<string, string>
    timeline_custom?: TimelineCustom[]; timeline_hidden?: string[]; manual_ips?: string[]
  } | null
}) {
  // Offline/live is seeded from the prop but owned here so the analyst can flip
  // it in-case (the OFFLINE badge → "switch to Live"), which re-runs the hunts.
  const [offlineMode, setOfflineMode] = useState(!!offline)

  // Sign-in lookback — seeded from the prop, changeable in-case via the triage
  // time selector. Changing it invalidates the cached sign-ins so they re-pull.
  const [win, setWin] = useState(timeWindow)
  const [winPickerOpen, setWinPickerOpen] = useState(false)
  function changeWindow(next: string) {
    if (next === win) return
    setSelected(new Set())        // origins from the old window no longer apply
    setWin(next)                  // cache is window-aware → effect re-fetches
  }
  const [loading, setLoading] = useState(() => !offline && !becCachedResp(account, timeWindow))
  const [resp, setResp] = useState<BecSigninsResponse | null>(() => becCachedResp(account, timeWindow) ?? null)
  const [selected, setSelected] = useState<Set<string>>(
    () => restore ? new Set(restore.selected) : (ip ? new Set([ip]) : new Set()))

  // Checklist state — seeded from a restored case when present, else empty.
  const [checked, setChecked] = useState<Set<string>>(() => new Set(restore?.checked ?? []))
  const [notes, setNotes] = useState<Record<string, string>>(() => restore?.notes ?? {})

  // Editable-timeline state — custom analyst entries + removed (hidden) auto
  // events. Both persist with the case.
  const [timelineCustom, setTimelineCustom] = useState<TimelineCustom[]>(() => restore?.timeline_custom ?? [])
  const [timelineHidden, setTimelineHidden] = useState<Set<string>>(() => new Set(restore?.timeline_hidden ?? []))

  // Analyst-captured IPs (manual mode) — found in query output, persisted.
  const [manualIps, setManualIps] = useState<string[]>(() => restore?.manual_ips ?? [])
  const addManualIp = (ip: string) => setManualIps(prev => prev.includes(ip) ? prev : [...prev, ip])
  const removeManualIp = (ip: string) => setManualIps(prev => prev.filter(i => i !== ip))

  // Add a timeline item, idempotent by id (re-adding the same finding is a no-op).
  function addTimelineItem(c: TimelineCustom) {
    setTimelineCustom(prev => prev.some(x => x.id === c.id) ? prev : [...prev, c])
  }
  function removeTimelineItem(id: string) {
    if (id.startsWith('custom-')) setTimelineCustom(prev => prev.filter(c => c.id !== id))
    else setTimelineHidden(prev => new Set(prev).add(id))
  }
  function restoreTimelineItem(id: string) {
    setTimelineHidden(prev => { const n = new Set(prev); n.delete(id); return n })
  }

  // Debounced auto-save of the case (identity + selections + checklist +
  // timeline edits) so a reload resumes where the analyst left off. The
  // triage/findings tables are deliberately NOT persisted — they re-fetch fresh.
  useEffect(() => {
    const handle = setTimeout(() => {
      putBecCase({
        account, ip, time_window: win, offline: offlineMode,
        selected: Array.from(selected),
        checked: Array.from(checked),
        notes,
        timeline_custom: timelineCustom,
        timeline_hidden: Array.from(timelineHidden),
        manual_ips: manualIps,
      })
    }, 1200)
    return () => clearTimeout(handle)
  }, [account, ip, win, offlineMode, selected, checked, notes, timelineCustom, timelineHidden, manualIps])

  // Scope-attacker-activity state (Milestone B). Seeded from the session cache
  // so it survives Home ↔ Settings navigation.
  const [scoping, setScoping] = useState(false)
  const [scope, setScope] = useState<BecScopeResponse | null>(() => becCacheFor(account)?.scope ?? null)
  const [view, setView] = useState<'triage' | 'findings' | 'timeline' | 'containment' | 'comms'>('triage')

  // Identity Protection + directory-role enrichment (P2). Non-blocking; loads
  // in parallel with the sign-in triage. Also seeded from the session cache.
  const [enrich, setEnrich] = useState<BecEnrichResponse | null>(() => becCacheFor(account)?.enrich ?? null)

  // UI: collapsible checklist sidebar + account-state alert toast + manual-hunt panel.
  const [checklistOpen, setChecklistOpen] = useState(true)
  const [accountToast, setAccountToast] = useState<{ enabled: boolean } | null>(null)
  const [showManual, setShowManual] = useState(!!offline)

  // Flip a case from offline → live in-place: re-enable the Graph fetches and
  // drop the manual panel. (Live → offline is via the mode-select on a new case.)
  function switchToLive() { setOfflineMode(false); setShowManual(false) }

  // Containment watcher (§5) — verifies out-of-band containment holds.
  const [watch, setWatch] = useState<BecWatchResponse | null>(null)
  const [watching, setWatching] = useState(false)

  async function runWatch() {
    setWatching(true)
    try {
      const w = await fetchBecWatch(account)
      setWatch(w)
      if (w.ok && w.invariants) {
        const tick = (id: string) => setChecked(prev => new Set(prev).add(id))
        if (w.invariants.account_disabled) tick('p2-disabled')
        if (w.invariants.sessions_holding) tick('p2-revoked')
        if (w.invariants.held) tick('p2-invariants')
      }
    } finally {
      setWatching(false)
    }
  }

  // Client comms drafting (§7).
  const [comms, setComms] = useState<BecCommsResponse | null>(null)
  const [drafting, setDrafting] = useState(false)

  async function runComms(audience: string) {
    setDrafting(true)
    try {
      const facts = buildCaseFacts({ account, ip, acct, origins, scope, enrich, watch })
      const r = await fetchBecComms(account, audience, facts)
      setComms(r)
    } finally {
      setDrafting(false)
    }
  }

  useEffect(() => {
    if (offlineMode) { setLoading(false); return }   // no-Graph mode — manual hunts only
    // Already cached for THIS window (e.g. nav back from Settings) — don't re-fetch.
    const cached = becCachedResp(account, win)
    if (cached) { setResp(cached); setLoading(false); return }
    let cancelled = false
    setLoading(true)
    fetchBecSignins(account, win)
      .then(r => { if (!cancelled) { setResp(r); becSessionCache.account = account; becSessionCache.respWindow = win; becSessionCache.resp = r } })
      .catch(e => { if (!cancelled) setResp({ ok: false, error_code: 'CLIENT', error_message: friendlyError(e), account: null, origins: [], anomalies: {} }) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [account, win, offlineMode])

  useEffect(() => {
    if (offlineMode) return                    // no-Graph mode
    if (becCacheFor(account)?.enrich) return  // cached — keep it
    let cancelled = false
    fetchBecEnrich(account)
      .then(r => {
        if (cancelled) return
        setEnrich(r)
        becSessionCache.account = account; becSessionCache.enrich = r
        // A risky-user state or any detection is the "Identity Protection risk
        // state" half of the entry-characterisation step — auto-tick it.
        const hasRisk = !!(r.ok && r.risk?.available &&
          ((r.risk.state && r.risk.state.risk_level && r.risk.state.risk_level !== 'none') ||
           r.risk.detections.length))
        if (hasRisk) setChecked(prev => new Set(prev).add('p1-entry'))
      })
      .catch(() => { /* enrichment is best-effort */ })
    return () => { cancelled = true }
  }, [account, offlineMode])

  const origins = resp?.origins ?? []
  const acct = resp?.account
  const graphOk = !!resp?.ok

  // Account-state alert: popup + chime when the enabled/disabled state is first
  // known, and again if it CHANGES (e.g. the attacker re-enables a disabled
  // account, or containment lands). Suppressed on plain navigation (same state
  // is remembered in the session cache).
  useEffect(() => {
    const en = acct?.account_enabled
    if (typeof en !== 'boolean') return
    if (becSessionCache.account === account && becSessionCache.notifiedEnabled === en) return
    becSessionCache.account = account
    becSessionCache.notifiedEnabled = en
    setAccountToast({ enabled: en })
    playStateChime(en)
  }, [acct, account])

  // Auto-dismiss the toast after a while (it's also manually closeable).
  useEffect(() => {
    if (!accountToast) return
    const h = setTimeout(() => setAccountToast(null), 9000)
    return () => clearTimeout(h)
  }, [accountToast])

  function toggle(o: string) {
    setSelected(prev => { const n = new Set(prev); n.has(o) ? n.delete(o) : n.add(o); return n })
  }
  function toggleCheck(id: string) {
    setChecked(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n })
  }
  function setNote(id: string, text: string) {
    setNotes(prev => ({ ...prev, [id]: text }))
  }

  const selectedSessions = useMemo(() => {
    const sids = new Set<string>()
    let first = '', last = ''
    for (const o of origins) {
      if (!selected.has(o.ip)) continue
      o.session_ids.forEach(s => sids.add(s))
      if (o.first_seen && (!first || o.first_seen < first)) first = o.first_seen
      if (o.last_seen && o.last_seen > last) last = o.last_seen
    }
    return { ids: Array.from(sids), first, last }
  }, [origins, selected])

  // Scope attacker activity: hunt from the earliest selected sign-in forward.
  // The UAL categories run an async Graph query that often isn't done within one
  // request — so when they come back "still running" we AUTO-RETRY the same
  // window (the backend resumes the same query) up to a few times, so the
  // analyst doesn't have to keep clicking Scope.
  const scopeRetries = useRef(0)
  // Bumped on every fresh scope so a window change supersedes any pending
  // auto-retry of the previous window.
  const scopeGen = useRef(0)
  // Explicit scope window the analyst picked in the findings header (overrides
  // the auto-derived "earliest selected sign-in → now"). null = auto.
  const [scopeWin, setScopeWin] = useState<string | null>(null)

  // Re-run scope over an explicitly chosen window (preset or custom:..), or
  // 'auto' to go back to the auto-derived "earliest selected sign-in → now".
  function rescope(nextWin: string) {
    const w = nextWin === 'auto' ? null : nextWin
    setScopeWin(w)
    runScope(undefined, w ?? 'auto')
  }

  async function runScope(reuseWin?: string, overrideWin?: string, gen?: number) {
    // A fresh run (not a retry) gets a new generation; retries carry the gen of
    // the run that scheduled them, and bail if a newer run has superseded them.
    const myGen = gen ?? (reuseWin ? scopeGen.current : ++scopeGen.current)
    if (reuseWin && myGen !== scopeGen.current) return   // superseded — drop this retry
    setScoping(true)
    setView('findings')   // switch immediately so the "searches running" indicator is visible during the (slow) fetch
    // Base window: explicit override > previously-chosen > auto-derived from the
    // earliest selected sign-in. Presets resolve to absolute ranges client-side.
    const base = overrideWin ?? scopeWin
    let derived: string
    if (base && base.startsWith('custom:')) {
      derived = base
    } else if (base === 'last24h' || base === 'last7d' || base === 'last30d') {
      const days = base === 'last24h' ? 1 : base === 'last7d' ? 7 : 30
      derived = `custom:${new Date(Date.now() - days * 86_400_000).toISOString()}..${new Date().toISOString()}`
    } else {
      const startMs = selectedSessions.first
        ? new Date(selectedSessions.first).getTime() - 5 * 60_000
        : Date.now() - 7 * 86_400_000
      derived = `custom:${new Date(startMs).toISOString()}..${new Date().toISOString()}`
    }
    // Reuse the exact same window across retries so the UAL query (keyed on the
    // start) resumes instead of starting over.
    const win = reuseWin ?? derived
    if (!reuseWin) scopeRetries.current = 0
    let willRetry = false
    try {
      const r = await fetchBecScope(account, win)
      setScope(r)
      becSessionCache.account = account; becSessionCache.scope = r
      setView('findings')
      if (r.ok) {
        // Auto-tick the checklist items the findings satisfy.
        const tick = (id: string) => setChecked(prev => new Set(prev).add(id))
        tick('p1-sessions')  // §2.4 — resolving a selection to a scope
        const f = r.findings || {}
        if (f.persistence?.available && f.persistence.events.length) tick('p3-persist')
        if (f.recon?.available && f.recon.events.length) tick('p3-recon')
        if (f.mailbox?.available && f.mailbox.events.length) tick('p3-mailbox')
        if (f.exfil?.available && f.exfil.events.length) tick('p3-exfil')
        if (f.antiforensic?.available && f.antiforensic.events.length) tick('p3-antiforensic')
        if (f.objective?.available && f.objective.events.length) tick('p3-objective')

        // Still-running UAL categories → resume automatically. A cold audit-log
        // query (e.g. a freshly re-scoped window) can take a couple of minutes
        // to materialise, so keep resuming at a steady cadence rather than
        // giving up after a few tries.
        const stillRunning = ['mailbox', 'exfil', 'recon', 'antiforensic'].some(k => {
          const c = f[k]
          return c && !c.available && (c.reason || '').toLowerCase().includes('still running')
        })
        if (stillRunning && scopeRetries.current < 20) {
          scopeRetries.current += 1
          willRetry = true
          setTimeout(() => runScope(win, undefined, myGen), 8000)
        } else {
          scopeRetries.current = 0
        }
      }
    } finally {
      // Only clear the spinner if we're not retrying AND a newer run hasn't taken over.
      if (!willRetry && myGen === scopeGen.current) setScoping(false)
    }
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, background: 'var(--bg-app)' }}>
      {/* Header strip */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 16, padding: '10px 16px',
        borderBottom: '1px solid var(--border)', fontFamily: 'var(--font-mono)', flexShrink: 0, flexWrap: 'wrap',
      }}>
        <span style={{ color: 'var(--accent)', fontWeight: 700, fontSize: 12, letterSpacing: 0.4 }}>
          ▌ account compromise
        </span>
        <span style={{ color: 'var(--text)', fontSize: 12 }}>{acct?.display_name || account}</span>
        {acct?.upn && acct.upn !== account && <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{acct.upn}</span>}
        {offlineMode && (
          <button onClick={switchToLive}
            title="Offline mode — no Graph API calls. Click to switch to Live and pull from Graph."
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 10, fontWeight: 700,
              padding: '2px 9px', borderRadius: 3, color: 'var(--amber)', border: '1px solid var(--amber)',
              background: 'rgba(240,179,64,0.10)', cursor: 'pointer', fontFamily: 'var(--font-mono)',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(240,179,64,0.22)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'rgba(240,179,64,0.10)' }}>
            OFFLINE <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>→ switch to Live</span>
          </button>
        )}
        {acct && (() => {
          const enabled = acct.account_enabled
          const c = enabled ? '#7DD3A0' : '#FF5E5B'  // green = enabled, red = disabled
          return (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              fontSize: 10, fontWeight: 700, padding: '1px 8px', borderRadius: 3,
              color: c, border: `1px solid ${c}`, background: `${c}1A`,
            }} title={enabled
              ? 'Account is currently ENABLED'
              : 'Account is currently DISABLED (containment in place)'}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: c, boxShadow: `0 0 4px ${c}` }} />
              {enabled ? 'ENABLED' : 'DISABLED'}
            </span>
          )
        })()}
        {ip && (
          <span style={{ color: 'var(--text-muted)', fontSize: 11 }} title="Suspected origin IP you entered">
            suspected IP <span style={{ color: '#FF5E5B' }}>{ip}</span>
          </span>
        )}
        <span style={{ flex: 1 }} />
        <button onClick={() => { clearBecSessionCache(); onReset() }}
          style={{
            background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
            color: 'var(--text-muted)', cursor: 'pointer', fontFamily: 'var(--font-mono)',
            fontSize: 10.5, fontWeight: 600, padding: '3px 10px',
          }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}>
          + New investigation
        </button>
      </div>

      {/* Identity Protection + privilege strip (P2 enrichment). */}
      <EnrichmentStrip enrich={enrich} />

      {/* Two-column body: triage (main) + checklist (sidebar). */}
      <div style={{ flex: 1, minHeight: 0, display: 'flex' }}>
        {/* Main: live access-origin triage (non-blocking) */}
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', borderRight: '1px solid var(--border)' }}>
          <div style={{ padding: '8px 14px', borderBottom: '1px solid var(--border-soft)', display: 'flex', alignItems: 'center', gap: 14, fontFamily: 'var(--font-mono)' }}>
            <ViewTab active={view === 'triage'}    onClick={() => setView('triage')}    label="access-origin triage" />
            <ViewTab active={view === 'containment'} onClick={() => setView('containment')} label="containment" />
            {scope && <ViewTab active={view === 'findings'} onClick={() => setView('findings')} label="attacker activity" />}
            <ViewTab active={view === 'timeline'}  onClick={() => setView('timeline')}  label="timeline" />
            <span style={{ flex: 1 }} />
            {view === 'triage' && graphOk && <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>{resp?.signin_count} sign-ins · {origins.length} origins</span>}
            {view === 'triage' && !offlineMode && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>window</span>
                <select
                  value={win.startsWith('custom:') ? 'custom' : win}
                  onChange={e => { const v = e.target.value; if (v === 'custom') setWinPickerOpen(true); else changeWindow(v) }}
                  style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 3, color: 'var(--text)', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10, padding: '1px 4px', outline: 'none' }}>
                  <option value="last24h">Last 24 hours</option>
                  <option value="last7d">Last 7 days</option>
                  <option value="last30d">Last 30 days</option>
                  <option value="custom">{win.startsWith('custom:') ? formatCustomWindow(win) : 'Custom range…'}</option>
                </select>
              </span>
            )}
            {view === 'triage' && (
              <button onClick={() => setShowManual(v => !v)} title="Copy-paste hunting queries to run by hand — no Graph API needed"
                style={{
                  background: showManual ? 'rgba(168,85,247,0.15)' : 'transparent',
                  border: `1px solid ${showManual ? 'var(--accent)' : 'var(--border)'}`,
                  color: showManual ? 'var(--accent)' : 'var(--text-muted)', cursor: 'pointer',
                  fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 600, padding: '2px 9px', borderRadius: 3,
                }}>⌗ manual queries</button>
            )}
          </div>

          {view === 'timeline' ? (
            <BecTimeline origins={origins} scope={scope} enrich={enrich} loading={loading}
              window={resp?.window} selected={selected} account={acct?.upn || account}
              custom={timelineCustom} hidden={timelineHidden}
              onAdd={addTimelineItem} onRemove={removeTimelineItem} onRestore={restoreTimelineItem} />
          ) : view === 'containment' ? (
            <ContainmentView watch={watch} watching={watching} onRun={runWatch} />
          ) : view === 'comms' ? (
            <CommsView comms={comms} drafting={drafting} onRun={runComms} />
          ) : view === 'findings' ? (
            <FindingsPanel scope={scope} scoping={scoping} scopeWin={scopeWin} onRescope={rescope} onAddTimelineItem={addTimelineItem} />
          ) : showManual ? (
            <div style={{ flex: 1, overflow: 'auto', padding: '14px 16px' }}>
              <ManualHunts account={account} timeWindow={win} ips={manualIps} onAddIp={addManualIp} onRemoveIp={removeManualIp} />
            </div>
          ) : loading ? (
            <Centered>Pulling sign-in activity from Entra…</Centered>
          ) : !graphOk ? (
            // Non-blocking: live data unavailable — the checklist works offline,
            // and the analyst can run the hunts by hand with the queries below.
            <div style={{ flex: 1, overflow: 'auto', padding: '14px 16px', fontFamily: 'var(--font-mono)' }}>
              <div style={{
                border: '1px solid rgba(240,179,64,0.30)', background: 'rgba(240,179,64,0.07)',
                borderRadius: 6, padding: '10px 12px', fontSize: 11, lineHeight: 1.6, color: 'var(--text)', marginBottom: 16,
              }}>
                <div style={{ color: 'var(--amber)', fontWeight: 700, fontSize: 10.5, letterSpacing: 0.4, textTransform: 'uppercase', marginBottom: 4 }}>
                  ⚠ Live sign-in data unavailable
                </div>
                {friendlyError(resp?.error_message || 'Could not reach Microsoft Graph.')}
                <div style={{ color: 'var(--text-muted)', marginTop: 6 }}>
                  The investigation checklist on the right is fully usable offline. Or run the same hunts by hand — copy the queries below into Advanced Hunting / the audit log, then re-run once Graph is reachable to pull it in automatically.
                </div>
              </div>
              <ManualHunts account={account} timeWindow={win} ips={manualIps} onAddIp={addManualIp} onRemoveIp={removeManualIp} />
            </div>
          ) : origins.length === 0 ? (
            <Centered>No sign-ins for this account in the selected window.</Centered>
          ) : (
            <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
              <div style={{ flex: 1, overflow: 'auto' }}>
                <table style={{ borderCollapse: 'separate', borderSpacing: 0, width: '100%', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                  <thead>
                    <tr>
                      {['', 'flags', 'IP', 'location', 'ASN / org', 'device', 'first → last', 'OK/fail', 'MFA'].map((h, i) => (
                        <th key={i} style={thStyle}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {origins.map(o => (
                      <OriginRow key={o.ip} o={o} selected={selected.has(o.ip)} isEnteredIp={o.ip === ip} onToggle={() => toggle(o.ip)} />
                    ))}
                  </tbody>
                </table>
              </div>
              <div style={{
                flexShrink: 0, borderTop: '1px solid var(--border)', background: 'var(--bg-panel)',
                padding: '8px 16px', fontFamily: 'var(--font-mono)', fontSize: 11,
                display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap',
              }}>
                <span style={{ color: 'var(--accent)', fontWeight: 600 }}>selected: {selected.size}</span>
                {selected.size > 0 ? (
                  <>
                    <span style={{ color: 'var(--text-muted)' }}>→ {selectedSessions.ids.length} session id{selectedSessions.ids.length === 1 ? '' : 's'}</span>
                    {selectedSessions.first && <span style={{ color: 'var(--text-muted)' }}>from {fmtDateTime(selectedSessions.first)}</span>}
                    <span style={{ flex: 1 }} />
                    <button
                      onClick={() => runScope()}
                      disabled={scoping}
                      title="Hunt what the attacker did from this origin onward (persistence, mailbox, exfil)"
                      style={{
                        background: 'var(--accent)', color: '#fff', border: 'none', borderRadius: 3,
                        cursor: scoping ? 'default' : 'pointer', fontFamily: 'var(--font-mono)',
                        fontSize: 11, fontWeight: 600, padding: '4px 12px', letterSpacing: 0.3,
                        opacity: scoping ? 0.6 : 1,
                      }}>
                      {scoping ? 'scoping…' : 'Scope attacker activity ▸'}
                    </button>
                  </>
                ) : (
                  <span style={{ color: 'var(--text-muted)' }}>tick the attacker's origin row(s) to resolve them to sessions, then scope their activity.</span>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Collapse/expand strip for the checklist sidebar. */}
        <div onClick={() => setChecklistOpen(o => !o)}
          title={checklistOpen ? 'Collapse the investigation checklist' : 'Show the investigation checklist'}
          style={{ width: 34, flexShrink: 0, cursor: 'pointer', borderLeft: '1px solid var(--border)', background: 'var(--bg-elevated)', display: 'flex', alignItems: checklistOpen ? 'center' : 'flex-start', justifyContent: 'center', paddingTop: checklistOpen ? 0 : 14 }}
          onMouseEnter={e => { e.currentTarget.style.background = 'rgba(168,85,247,0.15)' }}
          onMouseLeave={e => { e.currentTarget.style.background = 'var(--bg-elevated)' }}>
          {checklistOpen
            ? <span style={{ color: 'var(--accent)', fontSize: 22, fontWeight: 700, lineHeight: 1 }}>›</span>
            : <span style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)', color: 'var(--accent)', fontSize: 12, fontWeight: 700, letterSpacing: 0.5 }}>‹ investigation checklist</span>}
        </div>

        {/* Sidebar: the always-available checklist (collapsible). */}
        {checklistOpen && (
          <div style={{ width: 400, flexShrink: 0, overflow: 'auto', padding: '12px 14px', background: 'var(--bg-app)' }}>
            <BecChecklist checked={checked} onToggle={toggleCheck} notes={notes} onNote={setNote} />
          </div>
        )}
      </div>

      {/* Custom sign-in window picker (triage time selector). */}
      {winPickerOpen && createPortal(
        <>
          <div onClick={() => setWinPickerOpen(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 10000 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', zIndex: 10001 }}>
            <RangePicker
              initialStart={win.startsWith('custom:') ? win.slice('custom:'.length).split('..')[0] : undefined}
              initialEnd={win.startsWith('custom:') ? win.slice('custom:'.length).split('..')[1] : undefined}
              onApply={(s, e) => { setWinPickerOpen(false); changeWindow(`custom:${s}..${e}`) }}
              onCancel={() => setWinPickerOpen(false)} />
          </div>
        </>,
        document.body,
      )}

      {/* Account-state alert toast (with chime). */}
      {accountToast && createPortal(
        <div style={{
          position: 'fixed', top: 18, left: '50%', transform: 'translateX(-50%)', zIndex: 10050,
          minWidth: 340, maxWidth: 520, display: 'flex', alignItems: 'center', gap: 12,
          padding: '12px 16px', borderRadius: 8, fontFamily: 'var(--font-mono)',
          background: 'var(--bg-panel)',
          border: `1px solid ${accountToast.enabled ? '#FF5E5B' : '#7DD3A0'}`,
          boxShadow: `0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px ${accountToast.enabled ? '#FF5E5B33' : '#7DD3A033'}`,
        }}>
          <span style={{ width: 12, height: 12, borderRadius: '50%', flexShrink: 0,
            background: accountToast.enabled ? '#FF5E5B' : '#7DD3A0',
            boxShadow: `0 0 8px ${accountToast.enabled ? '#FF5E5B' : '#7DD3A0'}` }} />
          <div style={{ flex: 1 }}>
            <div style={{ color: accountToast.enabled ? '#FF5E5B' : '#7DD3A0', fontWeight: 700, fontSize: 12.5, letterSpacing: 0.3 }}>
              {accountToast.enabled ? '⚠ ACCOUNT IS ENABLED' : '✓ ACCOUNT IS DISABLED'}
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: 10.5, marginTop: 2 }}>
              {acct?.display_name || account}
              {accountToast.enabled
                ? ' — still active and able to sign in. Containment is NOT in place.'
                : ' — sign-in is blocked. Containment is in place.'}
            </div>
          </div>
          <button onClick={() => setAccountToast(null)}
            style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16, lineHeight: 1, padding: '0 2px', flexShrink: 0 }}>×</button>
        </div>,
        document.body,
      )}
    </div>
  )
}

// Map an Entra deviceDetail.trustType to a short chip label + colour. A
// registered/joined/compliant device is a trust signal (the real user's
// device); attacker logins are typically from an unmanaged device.
function trustChips(o: BecOrigin): { label: string; color: string; title: string }[] {
  const chips: { label: string; color: string; title: string }[] = []
  for (const t of o.device_trust) {
    const v = t.toLowerCase()
    if (v.includes('hybrid')) chips.push({ label: 'HYBRID JOINED', color: '#7DD3A0', title: `Hybrid Azure AD joined device (${t})` })
    else if (v.includes('joined') || v === 'azuread') chips.push({ label: 'AAD JOINED', color: '#7DD3A0', title: `Entra (Azure AD) joined device (${t})` })
    else if (v.includes('registered') || v.includes('workplace')) chips.push({ label: 'AAD REGISTERED', color: '#7AA8FF', title: `Entra (Azure AD) registered device (${t})` })
    else if (v.includes('serverad') || v.includes('server ad')) chips.push({ label: 'ON-PREM AD', color: '#7AA8FF', title: `On-premises AD domain-joined device (${t})` })
    else chips.push({ label: t.toUpperCase(), color: '#7AA8FF', title: t })
  }
  if (o.device_compliant) chips.push({ label: 'COMPLIANT', color: '#7DD3A0', title: 'Device marked compliant by Intune / MDM' })
  else if (o.device_managed) chips.push({ label: 'MANAGED', color: '#7AA8FF', title: 'Device is managed (Intune / MDM enrolled)' })
  return chips
}

function OriginRow({ o, selected, isEnteredIp, onToggle }: { o: BecOrigin; selected: boolean; isEnteredIp: boolean; onToggle: () => void }) {
  const [open, setOpen] = useState(false)
  const mfaSummary = Object.entries(o.mfa).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}×${v}`).join(', ')
  const chips = trustChips(o)
  const rowBg = selected ? 'rgba(168,85,247,0.10)' : (isEnteredIp ? 'rgba(255,94,91,0.08)' : (o.flags.length ? 'rgba(255,94,91,0.04)' : 'transparent'))
  return (
    <>
      <tr style={{ borderBottom: open ? 'none' : '1px solid var(--border-soft)', background: rowBg }}>
        <td style={tdStyle}><input type="checkbox" checked={selected} onChange={onToggle} style={{ cursor: 'pointer' }} /></td>
        <td style={tdStyle}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
            {o.flags.length === 0 && <span style={{ color: 'var(--text-muted)' }}>—</span>}
            {o.flags.map(f => {
              const m = FLAG_META[f] ?? { label: f, color: 'var(--text-muted)', title: f }
              return <span key={f} title={m.title} style={{ fontSize: 8.5, fontWeight: 700, letterSpacing: 0.3, padding: '1px 4px', borderRadius: 2, color: m.color, border: `1px solid ${m.color}`, background: `${m.color}1A`, whiteSpace: 'nowrap' }}>{m.label}</span>
            })}
          </div>
        </td>
        <td style={{ ...tdStyle, color: 'var(--text)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span onClick={() => setOpen(v => !v)} title={open ? 'Hide sign-in detail' : 'Show the exact sign-ins behind this row'}
              style={{ cursor: 'pointer', color: 'var(--text-muted)', userSelect: 'none' }}>{open ? '▾' : '▸'}</span>
            <span onClick={() => setOpen(v => !v)} style={{ cursor: 'pointer' }}>{o.ip}</span>
            {isEnteredIp && <span title="The suspected IP you entered" style={{ color: '#FF5E5B' }}>◂</span>}
          </div>
          {o.ip && o.ip !== '(unknown)' && (
            <div style={{ marginTop: 4 }}><VtButton ioc={o.ip} iocType="ip" lookupOnly /></div>
          )}
        </td>
        <td style={tdStyle}>{[o.city, o.country].filter(Boolean).join(', ') || '—'}</td>
        <td style={tdStyle}>{o.asn != null ? <span style={{ color: o.is_hosting_asn ? '#FF5E5B' : 'var(--text)' }}>AS{o.asn}{o.asn_org ? ` ${o.asn_org}` : ''}</span> : '—'}</td>
        <td style={{ ...tdStyle, maxWidth: 220, whiteSpace: 'normal', wordBreak: 'break-word' }}>
          {o.devices.join(' · ') || '—'}
          {chips.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 3 }}>
              {chips.map((c, i) => (
                <span key={i} title={c.title} style={{ fontSize: 8, fontWeight: 700, letterSpacing: 0.3, padding: '1px 4px', borderRadius: 2, color: c.color, border: `1px solid ${c.color}`, background: `${c.color}1A`, whiteSpace: 'nowrap' }}>{c.label}</span>
              ))}
            </div>
          )}
        </td>
        <td style={tdStyle}>{o.first_seen ? `${fmtDateTime(o.first_seen, false)} → ${fmtDateTime(o.last_seen, false)}` : '—'}</td>
        <td style={tdStyle}><span style={{ color: '#7DD3A0' }}>{o.success}</span>{' / '}<span style={{ color: o.failure ? '#FF5E5B' : 'var(--text-muted)' }}>{o.failure}</span></td>
        <td style={{ ...tdStyle, maxWidth: 200, whiteSpace: 'normal', wordBreak: 'break-word' }}>{mfaSummary || '—'}</td>
      </tr>
      {open && (
        <tr style={{ background: rowBg, borderBottom: '1px solid var(--border-soft)' }}>
          <td style={{ padding: 0 }} />
          <td colSpan={8} style={{ padding: '2px 10px 10px' }}>
            <SigninDetail signins={o.signins} />
          </td>
        </tr>
      )}
    </>
  )
}

// Per-sign-in detail revealed when an access-origin row is expanded — the exact
// events Entra returned behind the aggregate (status, MFA, app, CA, risk, …).
function SigninDetail({ signins }: { signins: BecSignin[] }) {
  if (!signins || signins.length === 0) {
    return <div style={{ color: 'var(--text-muted)', fontSize: 10 }}>No per-sign-in detail returned.</div>
  }
  const dim: React.CSSProperties = { color: 'var(--text-muted)' }
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 5, background: 'var(--bg-app)', overflow: 'hidden' }}>
      <div style={{ padding: '4px 10px', borderBottom: '1px solid var(--border-soft)', color: 'var(--text-muted)', fontSize: 9, letterSpacing: 0.3, textTransform: 'uppercase' }}>
        {signins.length} sign-in{signins.length === 1 ? '' : 's'} from this IP {signins.length >= 100 ? '(latest 100)' : ''}
      </div>
      <div style={{ maxHeight: 280, overflow: 'auto' }}>
        {signins.map((s, i) => (
          <div key={i} style={{ padding: '6px 10px', borderBottom: i === signins.length - 1 ? 'none' : '1px solid var(--border-soft)', fontSize: 10, lineHeight: 1.5 }}>
            <div>
              <span style={{ color: 'var(--text)' }}>{fmtDateTime(s.timestamp)}</span>
              {' · '}
              {s.success
                ? <span style={{ color: '#7DD3A0' }}>✓ success</span>
                : <span style={{ color: '#FF5E5B' }}>✗ {s.error_code ?? 'fail'}{s.failure_reason ? ` ${s.failure_reason}` : ''}</span>}
              {' · '}<span style={dim}>MFA:</span> {s.mfa}
              {s.ca_status ? <> · <span style={dim}>CA:</span> {s.ca_status}</> : null}
              {s.risk_state && s.risk_state.toLowerCase() !== 'none' ? <> · <span style={dim}>risk:</span> <span style={{ color: '#F0B340' }}>{s.risk_state}{s.risk_level && s.risk_level !== 'none' ? ` (${s.risk_level})` : ''}</span></> : null}
            </div>
            <div style={dim}>
              {s.app ? <>app {s.app}</> : null}
              {s.resource ? <> → {s.resource}</> : null}
              {s.client_app ? <> · client {s.client_app}</> : null}
              {s.device ? <> · {s.device}</> : null}
              {s.trust_type ? <> ({s.trust_type})</> : null}
            </div>
            {(s.session_id || s.user_agent) && (
              <div style={{ ...dim, fontSize: 9, wordBreak: 'break-all', marginTop: 1 }}>
                {s.session_id ? <>session {s.session_id}</> : null}
                {s.user_agent ? <>{s.session_id ? ' · ' : ''}{s.user_agent}</> : null}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function ViewTab({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button onClick={onClick} style={{
      background: 'transparent', border: 'none', cursor: 'pointer', padding: 0,
      fontFamily: 'var(--font-mono)', fontSize: 11.5,
      fontWeight: active ? 600 : 400,
      color: active ? 'var(--accent)' : 'var(--text-muted)',
    }}>
      {active ? '▌ ' : ''}{label}
    </button>
  )
}

// ── BEC timeline ─────────────────────────────────────────────────────────────
// Merges sign-in origins, Identity Protection detections, and the scoped
// attacker-activity findings onto one chronological track so the analyst sees
// the compromise unfold in order. Pure client-side merge of already-fetched
// data; sign-ins + risk show even before Scope is run.
interface TimelineEvent {
  id: string
  ts: string
  kind: string
  color: string
  label: string
  sub: string
  ip?: string        // source IP, for "selected origins only" filtering
  custom?: boolean
}

// Analyst-curated timeline entry (persisted in the case): a free-text note, or
// an attacker-activity finding the analyst explicitly added from the findings
// tab. `kind`/`color` carry the finding's category styling when present.
export interface TimelineCustom {
  id: string
  ts: string     // ISO 8601
  label: string
  sub: string
  kind?: string
  color?: string
}

// Reusable "add a custom timeline item" form — used on both the Timeline tab
// and the Attacker-activity tab so the analyst can annotate from either.
function AddTimelineItemForm({ onAdd, onClose }: { onAdd: (c: TimelineCustom) => void; onClose: () => void }) {
  const [when, setWhen] = useState('')       // ISO 8601, chosen via RangePicker
  const [pickWhen, setPickWhen] = useState(false)
  const [label, setLabel] = useState('')
  const [sub, setSub] = useState('')
  const inputStyle: React.CSSProperties = {
    background: 'var(--bg-app)', border: '1px solid var(--border)', borderRadius: 3,
    color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '4px 8px', outline: 'none',
  }
  function submit() {
    if (!label.trim()) return
    onAdd({ id: `custom-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`, ts: when || new Date().toISOString(), label: label.trim(), sub: sub.trim() })
    onClose()
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 14, padding: '10px 12px', border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-panel)' }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <button type="button" onClick={() => setPickWhen(true)} style={{ ...inputStyle, cursor: 'pointer', color: when ? 'var(--text)' : 'var(--text-muted)' }} title="Pick the date & time on the calendar">
          {when ? fmtDateTime(when) : 'pick date & time (now)'}
        </button>
        <input autoFocus placeholder="what happened (e.g. Notified user by phone)" value={label} onChange={e => setLabel(e.target.value)} style={{ ...inputStyle, flex: 1, minWidth: 220 }} onKeyDown={e => { if (e.key === 'Enter') submit() }} />
      </div>
      <input placeholder="detail (optional)" value={sub} onChange={e => setSub(e.target.value)} style={inputStyle} onKeyDown={e => { if (e.key === 'Enter') submit() }} />
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
        <button onClick={onClose} style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-muted)', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10.5, padding: '4px 12px', borderRadius: 3 }}>cancel</button>
        <button onClick={submit} style={{ background: 'var(--accent)', color: '#fff', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10.5, fontWeight: 600, padding: '4px 14px', borderRadius: 3 }}>add to timeline</button>
      </div>
      {pickWhen && createPortal(
        <>
          <div onClick={() => setPickWhen(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 10000 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', zIndex: 10001 }}>
            <RangePicker mode="single" initialStart={when || undefined}
              onApply={(iso) => { setWhen(iso); setPickWhen(false) }}
              onCancel={() => setPickWhen(false)} />
          </div>
        </>,
        document.body,
      )}
    </div>
  )
}

// Auto timeline events = sign-ins + Identity Protection risk detections (origin-
// level context). Attacker-activity FINDINGS are NOT auto-added — the analyst
// curates which ones go on the timeline from the Attacker-activity tab.
function buildBecTimeline(
  origins: BecOrigin[],
  enrich: BecEnrichResponse | null,
): TimelineEvent[] {
  const ev: TimelineEvent[] = []

  for (const o of origins) {
    const anomalous = o.flags.length > 0
    ev.push({
      id: `signin:${o.ip}:${o.first_seen}`,
      ts: o.first_seen,
      kind: 'signin',
      color: anomalous ? '#FF5E5B' : 'var(--text-muted)',
      label: `Sign-in activity · ${o.ip}`,
      ip: o.ip,
      sub: [
        [o.city, o.country].filter(Boolean).join(', '),
        `${o.success} ok / ${o.failure} fail`,
        o.flags.join(', '),
      ].filter(Boolean).join(' · '),
    })
  }

  const detections = (enrich?.ok && enrich.risk?.available) ? enrich.risk.detections : []
  for (const d of detections) {
    ev.push({
      id: `risk:${d.id || d.detected + d.ip}`,
      ts: d.detected,
      kind: 'risk',
      color: riskColor(d.risk_level),
      label: `Risk detection · ${d.risk_event_type || 'unknown'} (${d.risk_level || '—'})`,
      ip: d.ip,
      sub: [d.location || d.ip, d.risk_state, d.detail].filter(Boolean).join(' · '),
    })
  }

  return ev
}

// Category colours, shared by the findings chips and the timeline entries the
// analyst adds from them.
const FINDING_CAT_COLOR: Record<string, string> = {
  persistence: '#FF5E5B', defense: '#FF5E5B', recon: '#F0B340', mailbox: '#FF5E5B',
  exfil: '#F0B340', antiforensic: '#FF5E5B', objective: '#F0B340',
}

// Build a persisted timeline entry from a selected attacker-activity finding.
function findingToTimelineItem(cat: string, e: BecPersistenceEvent): TimelineCustom {
  return {
    id: `find:${cat}:${e.id || e.timestamp + e.activity}`,
    ts: e.timestamp,
    label: `${CATEGORY_TITLE[cat] || cat} · ${e.activity}`,
    sub: [
      e.detail,
      e.target && `target ${e.target}`,
      e.initiated_by_ip && `from ${e.initiated_by_ip}`,
      e.result,
    ].filter(Boolean).join(' · '),
    kind: cat,
    color: FINDING_CAT_COLOR[cat] || 'var(--accent)',
  }
}

function BecTimeline({ origins, scope, enrich, loading, window, selected, account, custom, hidden, onAdd, onRemove, onRestore }: {
  origins: BecOrigin[]
  scope: BecScopeResponse | null
  enrich: BecEnrichResponse | null
  loading: boolean
  window?: { start: string; end: string }   // the case's selected lookback — bounds auto events
  selected: Set<string>                      // ticked attacker origins (IPs)
  account: string
  custom: TimelineCustom[]
  hidden: Set<string>
  onAdd: (c: TimelineCustom) => void
  onRemove: (id: string) => void          // hide an auto event / delete a custom one
  onRestore: (id: string) => void         // un-hide a removed auto event
}) {
  const auto = useMemo(() => buildBecTimeline(origins, enrich), [origins, enrich])

  // Bound auto events (esp. all-time Identity Protection detections) to the
  // selected lookback so a 24h case doesn't drag in months of old risk events.
  const ws = window ? new Date(window.start).getTime() : -Infinity
  const we = window ? new Date(window.end).getTime() : Infinity
  const inWindow = (iso: string) => {
    const t = new Date(iso).getTime()
    return isNaN(t) || (t >= ws && t <= we)
  }

  // "Attacker origins only" — when origins are ticked in triage, default to
  // showing ONLY events attributable to those IPs (events from the legit user's
  // safe IPs are excluded). Events with no IP are kept (can't attribute).
  const [attackerOnly, setAttackerOnly] = useState(true)
  const filterByIp = attackerOnly && selected.size > 0
  const fromAttacker = (e: TimelineEvent) => !filterByIp || !e.ip || selected.has(e.ip)
  const excludedCount = filterByIp ? auto.filter(e => !hidden.has(e.id) && inWindow(e.ts) && !fromAttacker(e)).length : 0

  const customEvents: TimelineEvent[] = custom.map(c => ({
    id: c.id, ts: c.ts, kind: c.kind || 'custom', color: c.color || 'var(--accent)', label: c.label, sub: c.sub, custom: true,
  }))

  // Custom (analyst-added) items are always shown; auto events respect the
  // window and the attacker-origin filter.
  const visible = [...auto.filter(e => !hidden.has(e.id) && inWindow(e.ts) && fromAttacker(e)), ...customEvents]
    .filter(e => e.ts)
    .sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0))

  const removedAuto = auto.filter(e => hidden.has(e.id))

  // Add-item form toggle (the form itself is the shared AddTimelineItemForm).
  const [showAdd, setShowAdd] = useState(false)

  function exportCsv() {
    const esc = (v: string) => `"${(v || '').replace(/"/g, '""')}"`
    const header = ['timestamp_utc', 'category', 'event', 'detail', 'source_ip']
    const rows = visible.map(e => [
      e.ts, e.kind, e.label, e.sub, e.ip || '',
    ].map(esc).join(','))
    const csv = [header.map(esc).join(','), ...rows].join('\r\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-')
    a.href = url
    a.download = `bec-timeline-${(account || 'case').replace(/[^a-zA-Z0-9._-]/g, '_')}-${stamp}.csv`
    document.body.appendChild(a); a.click(); a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const btnStyle = (on: boolean): React.CSSProperties => ({
    background: on ? 'rgba(168,85,247,0.15)' : 'transparent',
    border: `1px solid ${on ? 'var(--accent)' : 'var(--border)'}`,
    color: on ? 'var(--accent)' : 'var(--text-muted)', cursor: 'pointer',
    fontFamily: 'var(--font-mono)', fontSize: 10.5, fontWeight: 600, padding: '3px 10px', borderRadius: 3,
  })

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '14px 18px', fontFamily: 'var(--font-mono)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
        {!scope && (
          <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
            Showing sign-ins and risk detections. Run <span style={{ color: 'var(--accent)' }}>Scope</span> to fold in attacker activity.
          </span>
        )}
        <span style={{ flex: 1 }} />
        {selected.size > 0 && (
          <button onClick={() => setAttackerOnly(v => !v)} style={btnStyle(attackerOnly)}
            title="Show only events from the ticked attacker origins — excludes the legitimate user's safe IPs">
            {attackerOnly ? '✓ attacker origins only' : 'attacker origins only'}
          </button>
        )}
        <button onClick={exportCsv} style={btnStyle(false)} title="Export the visible timeline as CSV">⤓ export CSV</button>
        <button onClick={() => setShowAdd(s => !s)} style={btnStyle(showAdd)}>+ add item</button>
      </div>

      {filterByIp && excludedCount > 0 && (
        <div style={{ color: 'var(--text-muted)', fontSize: 9.5, marginBottom: 10 }}>
          Excluding {excludedCount} event{excludedCount === 1 ? '' : 's'} from non-selected (safe) origins — toggle “attacker origins only” to show them.
        </div>
      )}

      {showAdd && <AddTimelineItemForm onAdd={onAdd} onClose={() => setShowAdd(false)} />}

      {loading && visible.length === 0 ? (
        <Centered>Building timeline…</Centered>
      ) : visible.length === 0 ? (
        <Centered>No timeline events yet — sign-ins, risk detections and scoped activity will appear here, plus anything you add.</Centered>
      ) : (
        <div style={{ position: 'relative', paddingLeft: 4 }}>
          {visible.map((e, i) => (
            <div key={e.id} style={{ display: 'flex', gap: 12, position: 'relative', borderRadius: 4, transition: 'background 90ms', margin: '0 -8px', padding: '0 8px' }}
              onMouseEnter={ev => { ev.currentTarget.style.background = 'rgba(168,85,247,0.08)'; const x = ev.currentTarget.querySelector('[data-rm]') as HTMLElement | null; if (x) x.style.opacity = '1' }}
              onMouseLeave={ev => { ev.currentTarget.style.background = 'transparent'; const x = ev.currentTarget.querySelector('[data-rm]') as HTMLElement | null; if (x) x.style.opacity = '0' }}>
              <div style={{ flexShrink: 0, width: 132, textAlign: 'right', color: 'var(--text-muted)', fontSize: 10, paddingTop: 1 }}>
                {fmtDateTime(e.ts)}
              </div>
              <div style={{ flexShrink: 0, position: 'relative', width: 12, display: 'flex', justifyContent: 'center' }}>
                {i < visible.length - 1 && (
                  <div style={{ position: 'absolute', top: 8, bottom: -8, width: 1, background: 'var(--border)' }} />
                )}
                <div style={{ width: 9, height: 9, borderRadius: e.custom ? 2 : '50%', background: e.color, marginTop: 3, zIndex: 1, boxShadow: `0 0 4px ${e.color}` }} />
              </div>
              <div style={{ flex: 1, minWidth: 0, paddingBottom: 14, display: 'flex', gap: 8 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: 'var(--text)', fontSize: 11.5 }}>
                    {e.custom && e.kind === 'custom' && <span style={{ color: 'var(--accent)', fontSize: 8.5, fontWeight: 700, border: '1px solid var(--accent)', borderRadius: 2, padding: '0 4px', marginRight: 6 }}>NOTE</span>}
                    {e.label}
                  </div>
                  {e.sub && <div style={{ color: 'var(--text-muted)', fontSize: 10, marginTop: 1, wordBreak: 'break-word' }}>{e.sub}</div>}
                </div>
                <span data-rm onClick={() => onRemove(e.id)} title={e.custom ? 'Delete this note' : 'Remove from timeline'}
                  style={{ opacity: 0, transition: 'opacity 100ms', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 13, lineHeight: 1, flexShrink: 0, padding: '0 2px' }}
                  onMouseEnter={ev => { ev.currentTarget.style.color = '#FF5E5B' }}
                  onMouseLeave={ev => { ev.currentTarget.style.color = 'var(--text-muted)' }}>×</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {removedAuto.length > 0 && (
        <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--border-soft)' }}>
          <div style={{ color: 'var(--text-muted)', fontSize: 9.5, marginBottom: 6 }}>removed ({removedAuto.length}) — click to restore</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {removedAuto.map(e => (
              <span key={e.id} onClick={() => onRestore(e.id)} title={`${fmtDateTime(e.ts)} · ${e.label}`} style={{
                cursor: 'pointer', fontSize: 9.5, color: 'var(--text-muted)', border: '1px solid var(--border)',
                borderRadius: 2, padding: '2px 7px', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              }}>↩ {e.label}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function riskColor(level: string | null | undefined): string {
  switch ((level || '').toLowerCase()) {
    case 'high':   return '#FF5E5B'
    case 'medium': return '#F0B340'
    case 'low':    return '#7AA8FF'
    default:       return 'var(--text-muted)'
  }
}

// Identity Protection risk + directory-privilege strip. Renders quietly: a thin
// band under the header. Each half degrades independently (P2 / permission).
function EnrichmentStrip({ enrich }: { enrich: BecEnrichResponse | null }) {
  if (!enrich) return null  // still loading — stay invisible

  const risk = enrich.ok ? enrich.risk : null
  const roles = enrich.ok ? enrich.roles : null
  const allRoles: BecRole[] = roles?.available ? [...roles.active, ...roles.eligible] : []
  const privileged = allRoles.length > 0

  const seg: React.CSSProperties = { display: 'flex', alignItems: 'center', gap: 8, whiteSpace: 'nowrap' }
  const label: React.CSSProperties = { color: 'var(--text-muted)', fontSize: 9.5, letterSpacing: 0.4, textTransform: 'uppercase' }

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap',
      padding: '6px 16px', borderBottom: '1px solid var(--border-soft)',
      background: 'var(--bg-panel)', fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0,
    }}>
      {/* Identity Protection */}
      <div style={seg}>
        <span style={label}>identity protection</span>
        {!risk ? (
          <span style={{ color: 'var(--text-muted)' }}>{enrich.error_message ? friendlyError(enrich.error_message) : '—'}</span>
        ) : !risk.available ? (
          <span style={{ color: '#888', fontSize: 9.5, border: '1px solid var(--border)', borderRadius: 2, padding: '1px 5px' }} title={risk.reason}>needs permission</span>
        ) : (
          <>
            {(() => {
              const lvl = risk.state?.risk_level
              const c = riskColor(lvl)
              const isRisk = lvl && lvl.toLowerCase() !== 'none'
              return (
                <span style={{
                  fontSize: 9, fontWeight: 700, letterSpacing: 0.3, padding: '1px 6px', borderRadius: 2,
                  color: isRisk ? c : 'var(--text-muted)', border: `1px solid ${isRisk ? c : 'var(--border)'}`,
                  background: isRisk ? `${c}1A` : 'transparent',
                }}>
                  {isRisk ? `${(lvl as string).toUpperCase()} RISK` : 'no risk'}
                </span>
              )
            })()}
            {risk.state?.risk_state && <span style={{ color: 'var(--text-muted)' }}>{risk.state.risk_state}</span>}
            {risk.detections.length > 0 && (
              <span style={{ color: '#FF5E5B' }} title={risk.detections.slice(0, 6).map(d => `${d.risk_event_type} · ${d.risk_level} · ${d.location || d.ip}`).join('\n')}>
                {risk.detections.length} detection{risk.detections.length === 1 ? '' : 's'}
              </span>
            )}
          </>
        )}
      </div>

      <span style={{ color: 'var(--border)' }}>│</span>

      {/* Directory privilege */}
      <div style={seg}>
        <span style={label}>privilege</span>
        {!roles ? (
          <span style={{ color: 'var(--text-muted)' }}>—</span>
        ) : !roles.available ? (
          <span style={{ color: '#888', fontSize: 9.5, border: '1px solid var(--border)', borderRadius: 2, padding: '1px 5px' }} title={roles.reason}>needs permission</span>
        ) : !privileged ? (
          <span style={{ color: 'var(--text-muted)' }}>no directory roles</span>
        ) : (
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ color: '#FF5E5B', fontWeight: 700, fontSize: 9, letterSpacing: 0.3, padding: '1px 6px', borderRadius: 2, border: '1px solid #FF5E5B', background: 'rgba(255,94,91,0.10)' }}>PRIVILEGED</span>
            {allRoles.slice(0, 6).map((r, i) => (
              <span key={i} title={r.assignment_type === 'eligible' ? 'PIM-eligible (can activate)' : 'active assignment'} style={{
                fontSize: 9.5, padding: '1px 6px', borderRadius: 2,
                color: r.assignment_type === 'eligible' ? '#F0B340' : 'var(--text)',
                border: `1px solid ${r.assignment_type === 'eligible' ? '#F0B340' : 'var(--border)'}`,
              }}>
                {r.role_name}{r.assignment_type === 'eligible' ? ' ⏱' : ''}
              </span>
            ))}
            {allRoles.length > 6 && <span style={{ color: 'var(--text-muted)' }}>+{allRoles.length - 6}</span>}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Containment watcher (§5) ─────────────────────────────────────────────────
// Verifies out-of-band containment holds: account disabled + no session
// surviving the token-revocation watermark. Read-only — it verifies.
function ContainmentView({ watch, watching, onRun }: {
  watch: BecWatchResponse | null
  watching: boolean
  onRun: () => void
}) {
  const inv = watch?.ok ? watch.invariants : undefined

  const RunButton = (
    <button onClick={onRun} disabled={watching} style={{
      background: 'var(--accent)', color: '#fff', border: 'none', borderRadius: 3,
      cursor: watching ? 'default' : 'pointer', fontFamily: 'var(--font-mono)',
      fontSize: 11, fontWeight: 600, padding: '5px 14px', letterSpacing: 0.3, opacity: watching ? 0.6 : 1,
    }}>
      {watching ? 're-checking…' : watch ? '↻ Re-check containment' : 'Run containment check'}
    </button>
  )

  if (!watch) {
    return (
      <div style={{ flex: 1, overflow: 'auto', padding: '16px 18px', fontFamily: 'var(--font-mono)' }}>
        <div style={{ color: 'var(--text-muted)', fontSize: 11, lineHeight: 1.7, maxWidth: 560, marginBottom: 16 }}>
          Containment is performed out-of-band (disable the account, revoke its sessions in Entra). This
          check <span style={{ color: 'var(--text)' }}>verifies it holds</span> — it does not execute containment.
          It confirms the account is disabled and that no session survived the token-revocation watermark
          (a successful sign-in after it means the attacker still has working access).
        </div>
        {watching ? <Centered>Checking containment invariants…</Centered> : RunButton}
      </div>
    )
  }

  if (!watch.ok) {
    return (
      <Centered>
        <div style={{ color: 'var(--red)', fontSize: 12, marginBottom: 6 }}>✗ {watch.error_code || 'Error'}</div>
        <div style={{ color: 'var(--text-muted)', fontSize: 11.5, maxWidth: 520, textAlign: 'center', lineHeight: 1.6, marginBottom: 14 }}>
          {friendlyError(watch.error_message || 'Could not check containment.')}
        </div>
        {RunButton}
      </Centered>
    )
  }

  const held = inv?.held
  const bannerColor = held ? '#7DD3A0' : '#FF5E5B'

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '14px 18px', fontFamily: 'var(--font-mono)', display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Overall banner */}
      <div style={{
        border: `1px solid ${bannerColor}`, background: `${bannerColor}14`, borderRadius: 6,
        padding: '10px 14px', display: 'flex', alignItems: 'center', gap: 12,
      }}>
        <span style={{ width: 10, height: 10, borderRadius: '50%', background: bannerColor, boxShadow: `0 0 5px ${bannerColor}` }} />
        <span style={{ color: bannerColor, fontWeight: 700, fontSize: 12.5, letterSpacing: 0.3 }}>
          {held ? 'CONTAINMENT HOLDING' : 'CONTAINMENT NOT VERIFIED'}
        </span>
        <span style={{ flex: 1 }} />
        <span style={{ color: 'var(--text-muted)', fontSize: 9.5 }}>checked {fmtDateTime(watch.checked_at)}</span>
        {RunButton}
      </div>

      {/* Invariant 1: sessions revoked & holding — the action that actually
          evicts a stolen-token attacker, so it leads. */}
      {inv && !inv.sessions_revoked ? (
        <InvariantRow
          ok={false}
          title="Sessions / tokens revoked & holding"
          okText=""
          badText="Sessions have not been revoked — the revocation watermark is still at account creation. Revoke sign-in sessions in Entra (this is what evicts a stolen token), then re-check."
        />
      ) : inv && !inv.sessions_available ? (
        <InvariantRow
          ok={null}
          title="Sessions / tokens revoked & holding"
          okText=""
          badText={inv.sessions_reason || 'Could not verify the session invariant.'}
        />
      ) : (
        <InvariantRow
          ok={!!inv?.sessions_holding}
          title="Sessions / tokens revoked & holding"
          okText={`Revoked ${inv?.sessions_valid_from ? fmtDateTime(inv.sessions_valid_from) : ''} — no successful sign-in since. Holding.`}
          badText={`${inv?.breaches.length} successful sign-in${inv && inv.breaches.length === 1 ? '' : 's'} AFTER revocation — a live session survived. Access is re-established.`}
        >
          {inv && inv.breaches.length > 0 && (
            <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
              {inv.breaches.slice(0, 12).map((b, i) => (
                <div key={i} style={{ color: 'var(--text-muted)', fontSize: 10 }}>
                  <span style={{ color: '#FF5E5B' }}>{b.ip}</span>
                  {(b.city || b.country) ? ` · ${[b.city, b.country].filter(Boolean).join(', ')}` : ''}
                  {` · ${fmtDateTime(b.timestamp)}`}
                </div>
              ))}
            </div>
          )}
        </InvariantRow>
      )}

      {/* Invariant 2: account disabled — blocks re-authentication. */}
      <InvariantRow
        ok={!!inv?.account_disabled}
        title="Account disabled / sign-in blocked"
        okText="Account is disabled — staying disabled is the containment state."
        badText="Account is still ENABLED — it is active and must be disabled."
      />
    </div>
  )
}

function InvariantRow({ ok, title, okText, badText, children }: {
  ok: boolean | null
  title: string
  okText: string
  badText: string
  children?: React.ReactNode
}) {
  const color = ok === null ? '#888' : ok ? '#7DD3A0' : '#FF5E5B'
  const mark = ok === null ? '?' : ok ? '✓' : '✗'
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-panel)', padding: '10px 14px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{
          width: 16, height: 16, borderRadius: '50%', flexShrink: 0, display: 'inline-flex',
          alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: 10, fontWeight: 700,
          background: color,
        }}>{mark}</span>
        <span style={{ color: 'var(--text)', fontSize: 12, fontWeight: 600 }}>{title}</span>
      </div>
      <div style={{ color: ok === false ? '#FF8E8C' : 'var(--text-muted)', fontSize: 10.5, lineHeight: 1.6, marginTop: 5, marginLeft: 24 }}>
        {ok === null ? badText : ok ? okText : badText}
        {children}
      </div>
    </div>
  )
}

// ── Client comms drafting (§7) ───────────────────────────────────────────────
// Assembles the established facts of the case into a plain-text block the AI
// drafts from. Only states what's actually been observed — no speculation.
function buildCaseFacts(d: {
  account: string
  ip: string
  acct: BecSigninsResponse['account'] | undefined
  origins: BecOrigin[]
  scope: BecScopeResponse | null
  enrich: BecEnrichResponse | null
  watch: BecWatchResponse | null
}): string {
  const { account, acct, origins, scope, enrich, watch } = d
  const L: string[] = []
  L.push(`Account: ${acct?.display_name || account} (${acct?.upn || account})`)
  L.push(`Account state: ${acct?.account_enabled === false ? 'DISABLED' : acct?.account_enabled ? 'ENABLED' : 'unknown'}`)

  const anom = origins.filter(o => o.flags.length)
  if (anom.length) {
    L.push(`Suspicious sign-in origins (${anom.length}):`)
    for (const o of anom.slice(0, 6)) {
      L.push(`  - ${o.ip} (${[o.city, o.country].filter(Boolean).join(', ') || 'unknown location'}); flags: ${o.flags.join(', ')}; ${o.success} successful sign-in(s)`)
    }
  } else if (origins.length) {
    L.push(`Sign-in origins observed: ${origins.length} (no anomaly flags raised).`)
  }

  if (enrich?.ok && enrich.risk?.available) {
    const s = enrich.risk.state
    if (s?.risk_level && s.risk_level.toLowerCase() !== 'none') {
      L.push(`Identity Protection: risk level ${s.risk_level}, state ${s.risk_state || '—'}.`)
    }
    if (enrich.risk.detections.length) L.push(`Identity Protection raised ${enrich.risk.detections.length} risk detection(s).`)
  }
  if (enrich?.ok && enrich.roles?.available) {
    const roles = [...enrich.roles.active, ...enrich.roles.eligible]
    if (roles.length) L.push(`Privileged directory roles held by the account: ${roles.map(r => r.role_name).join(', ')}.`)
  }

  if (scope?.ok) {
    const f = scope.findings
    const seg = (cat: string, label: string) => {
      const c = f[cat]
      if (c?.available && c.events.length) L.push(`${label}: ${c.events.length} event(s).`)
    }
    seg('persistence', 'Attacker persistence established (e.g. OAuth consent grants / MFA or credential changes)')
    seg('mailbox', 'Mailbox manipulation (inbox rules / forwarding / delegation)')
    seg('exfil', 'Data-exfiltration indicators')
    seg('objective', 'Mail sent from the account / thread hijack')
    const obj = f['objective']
    if (obj?.available && obj.events.length) {
      for (const e of obj.events.slice(0, 3)) L.push(`  - sent: "${e.activity}" to ${e.target || '(recipient)'}`)
    }
  }

  if (watch?.ok && watch.invariants) {
    const iv = watch.invariants
    const sess = iv.sessions_revoked
      ? (iv.sessions_holding ? 'revoked and holding' : 'revoked but a session survived (access may persist)')
      : 'not yet revoked'
    L.push(`Containment status: account ${iv.account_disabled ? 'disabled' : 'still enabled'}; sessions ${sess}.`)
  }

  return L.join('\n')
}

const COMMS_AUDIENCES: [string, string][] = [
  ['client', 'Client'],
  ['internal', 'Internal SOC'],
  ['affected_user', 'Affected user'],
]

function CommsView({ comms, drafting, onRun }: {
  comms: BecCommsResponse | null
  drafting: boolean
  onRun: (audience: string) => void
}) {
  const [audience, setAudience] = useState('client')
  const [edited, setEdited] = useState('')
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (comms?.ok && comms.draft != null) setEdited(comms.draft)
  }, [comms])

  function copy() {
    navigator.clipboard?.writeText(edited).then(() => {
      setCopied(true); setTimeout(() => setCopied(false), 1500)
    }).catch(() => { /* clipboard blocked — analyst can select manually */ })
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '14px 18px', fontFamily: 'var(--font-mono)', display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ color: 'var(--text-muted)', fontSize: 10.5, lineHeight: 1.6, maxWidth: 620 }}>
        Generates a notification <span style={{ color: 'var(--text)' }}>draft</span> from the established case facts (sign-in origins,
        risk, privilege, attacker activity, containment). AI-assisted — review and edit before sending. Nothing is sent from here.
      </div>

      {/* Audience + generate */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>audience</span>
        {COMMS_AUDIENCES.map(([val, lbl]) => (
          <button key={val} onClick={() => setAudience(val)} style={{
            background: audience === val ? 'rgba(168,85,247,0.15)' : 'transparent',
            border: `1px solid ${audience === val ? 'var(--accent)' : 'var(--border)'}`,
            color: audience === val ? 'var(--accent)' : 'var(--text-muted)',
            cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10.5, fontWeight: 600,
            padding: '3px 10px', borderRadius: 3,
          }}>{lbl}</button>
        ))}
        <span style={{ flex: 1 }} />
        <button onClick={() => onRun(audience)} disabled={drafting} style={{
          background: 'var(--accent)', color: '#fff', border: 'none', borderRadius: 3,
          cursor: drafting ? 'default' : 'pointer', fontFamily: 'var(--font-mono)',
          fontSize: 11, fontWeight: 600, padding: '5px 14px', letterSpacing: 0.3, opacity: drafting ? 0.6 : 1,
        }}>
          {drafting ? 'drafting…' : comms ? '↻ Re-draft' : 'Generate draft'}
        </button>
      </div>

      {drafting ? (
        <Centered>Drafting notification…</Centered>
      ) : comms && !comms.ok ? (
        <div style={{ color: 'var(--red)', fontSize: 11.5, lineHeight: 1.6 }}>
          ✗ {friendlyError(comms.error_message || 'Could not generate the draft.')}
        </div>
      ) : comms && comms.ok ? (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ color: 'var(--amber)', fontSize: 9, fontWeight: 700, letterSpacing: 0.4, border: '1px solid var(--amber)', borderRadius: 2, padding: '1px 6px' }}>DRAFT — REVIEW BEFORE SENDING</span>
            <span style={{ flex: 1 }} />
            {comms.token_usage?.cost_usd != null && (
              <span style={{ color: 'var(--text-muted)', fontSize: 9.5 }}>
                {comms.token_usage.model} · {comms.token_usage.cost_usd < 0.01 ? '<$0.01' : `$${comms.token_usage.cost_usd.toFixed(3)}`}
              </span>
            )}
            <button onClick={copy} style={{
              background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
              color: copied ? '#7DD3A0' : 'var(--text-muted)', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 600, padding: '3px 10px',
            }}>{copied ? '✓ copied' : 'copy'}</button>
          </div>
          <textarea
            value={edited}
            onChange={e => setEdited(e.target.value)}
            spellCheck={false}
            style={{
              flex: 1, minHeight: 320, resize: 'vertical',
              background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: 6,
              color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1.6,
              padding: '12px 14px', outline: 'none',
            }} />
        </>
      ) : null}
    </div>
  )
}

// Copy-paste hunting queries for when Graph API access isn't available — the
// analyst runs the same investigation by hand in Advanced Hunting / the audit
// log. Parameterised with the account UPN and the case window.
function ManualHunts({ account, timeWindow, ips, onAddIp, onRemoveIp }: {
  account: string; timeWindow: string
  ips: string[]; onAddIp: (ip: string) => void; onRemoveIp: (ip: string) => void
}) {
  const sections = useMemo(() => buildManualHunts(account, timeWindow, ips), [account, timeWindow, ips])
  const [copied, setCopied] = useState<string | null>(null)
  const [ipInput, setIpInput] = useState('')
  function copy(id: string, text: string) {
    navigator.clipboard?.writeText(text)
      .then(() => { setCopied(id); setTimeout(() => setCopied(null), 1400) })
      .catch(() => { /* clipboard blocked — analyst can select manually */ })
  }
  const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/
  function addIp() {
    const v = ipInput.trim()
    if (v && IP_RE.test(v) && !ips.includes(v)) { onAddIp(v); setIpInput('') }
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, fontFamily: 'var(--font-mono)' }}>
      <div style={{ color: 'var(--text-muted)', fontSize: 10.5, lineHeight: 1.6 }}>
        No Graph API needed — run these by hand. They’re pre-filled with <span style={{ color: 'var(--text)' }}>{account}</span> and your selected window.
      </div>

      {/* Analyst-captured IPs — add suspicious origins as you find them in the
          output; every query below narrows to them, and you can VT-check each. */}
      <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-panel)', padding: '10px 12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: ips.length ? 8 : 0 }}>
          <span style={{ color: 'var(--accent)', fontSize: 11, fontWeight: 600 }}>Attacker IPs</span>
          <span style={{ color: 'var(--text-muted)', fontSize: 9.5 }}>add as you find them — the queries narrow to these</span>
          <span style={{ flex: 1 }} />
          <input value={ipInput} onChange={e => setIpInput(e.target.value)} placeholder="45.135.x.x"
            onKeyDown={e => { if (e.key === 'Enter') addIp() }}
            style={{ background: 'var(--bg-app)', border: '1px solid var(--border)', borderRadius: 3, color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '4px 8px', width: 150, outline: 'none' }} />
          <button onClick={addIp} style={{ background: 'var(--accent)', color: '#fff', border: 'none', borderRadius: 3, cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10.5, fontWeight: 600, padding: '4px 12px' }}>+ add</button>
        </div>
        {ips.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {ips.map(ip => (
              <div key={ip} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: 'var(--text)', fontSize: 11, width: 130 }}>{ip}</span>
                <VtButton ioc={ip} iocType="ip" lookupOnly />
                <span style={{ flex: 1 }} />
                <span onClick={() => onRemoveIp(ip)} title="Remove" style={{ cursor: 'pointer', color: 'var(--text-muted)', fontSize: 13, padding: '0 4px' }}
                  onMouseEnter={e => { e.currentTarget.style.color = '#FF5E5B' }}
                  onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)' }}>×</span>
              </div>
            ))}
          </div>
        )}
      </div>
      {sections.map((sec, si) => (
        <div key={si}>
          <div style={{ color: 'var(--accent)', fontWeight: 600, fontSize: 11.5 }}>{sec.title}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: 9.5, marginBottom: 7 }}>{sec.where}</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {sec.queries.map((q, qi) => {
              const id = `${si}-${qi}`
              return (
                <div key={qi} style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-panel)', overflow: 'hidden' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', borderBottom: '1px solid var(--border-soft)' }}>
                    <span style={{ flex: 1, minWidth: 0, color: 'var(--text)', fontSize: 10.5 }}>
                      {q.label}{q.note && <span style={{ color: 'var(--text-muted)' }}> · {q.note}</span>}
                    </span>
                    <button onClick={() => copy(id, q.query)} style={{
                      background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
                      color: copied === id ? '#7DD3A0' : 'var(--accent)', cursor: 'pointer',
                      fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 600, padding: '2px 10px', flexShrink: 0,
                    }}>{copied === id ? '✓ copied' : 'copy'}</button>
                  </div>
                  <pre style={{ margin: 0, padding: '8px 10px', fontSize: 10, lineHeight: 1.55, color: 'var(--text)', whiteSpace: 'pre-wrap', wordBreak: 'break-word', background: 'var(--bg-app)' }}>{q.query}</pre>
                </div>
              )
            })}
          </div>
        </div>
      ))}
    </div>
  )
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 12, padding: 24 }}>{children}</div>
  )
}

// Spinning ring for "work in progress". Injects its keyframe once (identical
// @keyframes by the same name are harmless if rendered more than once).
function Spinner({ size = 16, color = '#7AA8FF' }: { size?: number; color?: string }) {
  return (
    <>
      <style>{'@keyframes bec-spin{to{transform:rotate(360deg)}}@keyframes bec-pulse{0%,100%{opacity:1}50%{opacity:0.45}}'}</style>
      <span style={{ display: 'inline-block', width: size, height: size, border: `${Math.max(2, size / 9)}px solid ${color}40`, borderTopColor: color, borderRadius: '50%', animation: 'bec-spin 0.8s linear infinite', flexShrink: 0 }} />
    </>
  )
}

// Prominent "the audit-log searches are still running" banner. The UAL query is
// async + auto-retried, so this stays up (with partial results below) until it
// resolves.
function ScopingBanner() {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 14, padding: '12px 16px', borderRadius: 8,
      border: '1px solid #7AA8FF', background: 'rgba(122,168,255,0.10)',
      boxShadow: '0 0 0 3px rgba(122,168,255,0.10)', animation: 'bec-pulse 1.8s ease-in-out infinite',
    }}>
      <Spinner size={26} />
      <div>
        <div style={{ color: '#7AA8FF', fontWeight: 700, fontSize: 13, letterSpacing: 0.3 }}>SEARCHES STILL RUNNING…</div>
        <div style={{ color: 'var(--text-muted)', fontSize: 10.5, marginTop: 3, lineHeight: 1.5 }}>
          The unified audit log query is running and fetching automatically — this can take a few minutes on a busy tenant. Results appear below as they arrive; you don’t need to click anything.
        </div>
      </div>
    </div>
  )
}

// Attacker-activity findings, by category. Persistence is live; the others
// render a "needs permission" card so the analyst sees the upgrade path.
function FindingsPanel({ scope, scoping, scopeWin, onRescope, onAddTimelineItem }: {
  scope: BecScopeResponse | null; scoping: boolean
  scopeWin: string | null; onRescope: (win: string) => void
  onAddTimelineItem: (c: TimelineCustom) => void
}) {
  // Categories the analyst has toggled off (hidden from the chronological list
  // via the summary chips). Declared before any early return per hooks rules.
  const [hiddenCats, setHiddenCats] = useState<Set<string>>(new Set())
  const toggleCat = (cat: string) =>
    setHiddenCats(prev => { const n = new Set(prev); n.has(cat) ? n.delete(cat) : n.add(cat); return n })
  const [winPickerOpen, setWinPickerOpen] = useState(false)
  const [showAddTl, setShowAddTl] = useState(false)
  // Per-row selection of attacker-activity events to add to the timeline.
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const evKey = (cat: string, e: BecPersistenceEvent) => `${cat}:${e.id || e.timestamp + e.activity}`
  const togglePick = (k: string) =>
    setPicked(prev => { const n = new Set(prev); n.has(k) ? n.delete(k) : n.add(k); return n })

  // Only block on the very first scope; once we have a (partial) result keep it
  // visible while the UAL categories auto-retry in the background.
  if (scoping && !scope) return (
    <Centered>
      <Spinner size={36} />
      <div style={{ color: '#7AA8FF', fontWeight: 700, fontSize: 13, marginTop: 16 }}>SCOPING ATTACKER ACTIVITY…</div>
      <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 6, maxWidth: 460, textAlign: 'center', lineHeight: 1.6 }}>
        Running persistence, mailbox, recon, exfil and objective searches. The audit-log query is async and can take a few minutes — it fetches automatically.
      </div>
    </Centered>
  )
  if (!scope) return <Centered>No scope results.</Centered>
  if (!scope.ok) {
    return (
      <Centered>
        <div style={{ color: 'var(--red)', fontSize: 12, marginBottom: 6 }}>✗ {scope.error_code || 'Error'}</div>
        <div style={{ color: 'var(--text-muted)', fontSize: 11.5, maxWidth: 520, textAlign: 'center', lineHeight: 1.6 }}>
          {friendlyError(scope.error_message || 'Could not scope attacker activity.')}
        </div>
      </Centered>
    )
  }
  const order = ['persistence', 'defense', 'recon', 'mailbox', 'exfil', 'antiforensic', 'objective']
  const cats = order.filter(c => scope.findings[c])

  // Merge every found event across categories into ONE chronological account
  // (oldest first) so it reads as the attack unfolding, rather than jumping
  // around by category. Each row keeps its own sub-category badge.
  const merged: { cat: string; e: BecPersistenceEvent }[] = []
  for (const cat of cats) {
    const c = scope.findings[cat]
    if (c.available) for (const e of c.events) merged.push({ cat, e })
  }
  merged.sort((a, b) => (a.e.timestamp < b.e.timestamp ? -1 : a.e.timestamp > b.e.timestamp ? 1 : 0))
  const visibleMerged = merged.filter(m => !hiddenCats.has(m.cat))

  const gated = cats.filter(c => !scope.findings[c].available)

  function addPickedToTimeline() {
    for (const { cat, e } of merged) {
      if (picked.has(evKey(cat, e))) onAddTimelineItem(findingToTimelineItem(cat, e))
    }
    setPicked(new Set())
  }
  const allPickableKeys = visibleMerged.map(({ cat, e }) => evKey(cat, e))
  const allPicked = allPickableKeys.length > 0 && allPickableKeys.every(k => picked.has(k))

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '12px 16px', fontFamily: 'var(--font-mono)', display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Big "still running" indicator while the async UAL query auto-retries. */}
      {scoping && <ScopingBanner />}

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', color: 'var(--text-muted)', fontSize: 10.5 }}>
        <span>Scoped to {scope.account?.upn} · {scope.window ? `${fmtDateTime(scope.window.start)} → ${fmtDateTime(scope.window.end)}` : ''}</span>
        <span style={{ flex: 1 }} />
        {/* Re-scope over a chosen window (overrides the auto-derived range). */}
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
          <span>scope window</span>
          <select
            value={scopeWin && scopeWin.startsWith('custom:') ? 'custom' : (scopeWin || 'auto')}
            onChange={e => { const v = e.target.value; if (v === 'custom') setWinPickerOpen(true); else onRescope(v) }}
            title="Re-run the attacker-activity hunts over this window"
            style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 3, color: 'var(--text)', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10, padding: '1px 4px', outline: 'none' }}>
            <option value="auto">Auto (from selection)</option>
            <option value="last24h">Last 24 hours</option>
            <option value="last7d">Last 7 days</option>
            <option value="last30d">Last 30 days</option>
            <option value="custom">{scopeWin && scopeWin.startsWith('custom:') ? formatCustomWindow(scopeWin) : 'Custom range…'}</option>
          </select>
        </span>
        {picked.size > 0 && (
          <button onClick={addPickedToTimeline} title="Add the ticked attacker-activity events to the case timeline"
            style={{ background: 'var(--accent)', border: 'none', color: '#fff', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, padding: '2px 10px', borderRadius: 3 }}>
            + add {picked.size} to timeline
          </button>
        )}
        <button onClick={() => setShowAddTl(s => !s)} title="Add a free-text note to the case timeline"
          style={{
            background: showAddTl ? 'rgba(168,85,247,0.15)' : 'transparent',
            border: `1px solid ${showAddTl ? 'var(--accent)' : 'var(--border)'}`,
            color: showAddTl ? 'var(--accent)' : 'var(--text-muted)', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 600, padding: '2px 9px', borderRadius: 3,
          }}>+ add note</button>
      </div>

      {showAddTl && <AddTimelineItemForm onAdd={c => { onAddTimelineItem(c); setShowAddTl(false) }} onClose={() => setShowAddTl(false)} />}

      {winPickerOpen && createPortal(
        <>
          <div onClick={() => setWinPickerOpen(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 10000 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', zIndex: 10001 }}>
            <RangePicker
              initialStart={scope.window?.start}
              initialEnd={scope.window?.end}
              onApply={(s, e) => { setWinPickerOpen(false); onRescope(`custom:${s}..${e}`) }}
              onCancel={() => setWinPickerOpen(false)} />
          </div>
        </>,
        document.body,
      )}

      {/* Per-category summary — counts at a glance; click a chip to hide/show
          that category in the chronological list below. */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {cats.map(cat => {
          const c = scope.findings[cat]
          const r = (c.reason || '').toLowerCase()
          const running = !c.available && r.includes('still running')
          const needsPerm = !c.available && !running && (r.includes('permission') || r.includes('missing') || r.includes('licen') || r.includes('403'))
          let label: string, color: string
          if (c.available) { label = String(c.events.length); color = c.events.length > 0 ? '#FF5E5B' : 'var(--text-muted)' }
          else if (running) { label = 'running…'; color = '#7AA8FF' }
          else if (needsPerm) { label = 'needs permission'; color = '#888' }
          else { label = 'unavailable'; color = '#888' }
          const hidden = hiddenCats.has(cat)
          const hasEvents = c.available && c.events.length > 0
          return (
            <span key={cat} onClick={() => toggleCat(cat)}
              title={hidden ? 'Hidden — click to show in the list' : (hasEvents ? 'Click to hide from the list' : (!c.available ? c.reason : 'Click to hide from the list'))}
              style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 3, cursor: 'pointer', userSelect: 'none',
                border: `1px solid ${color === '#888' ? 'var(--border)' : color}`,
                color, background: hidden ? 'transparent' : (hasEvents ? '#FF5E5B14' : (running ? '#7AA8FF14' : 'transparent')),
                opacity: hidden ? 0.4 : 1, textDecoration: hidden ? 'line-through' : 'none', whiteSpace: 'nowrap',
                animation: running && !hidden ? 'bec-pulse 1.6s ease-in-out infinite' : undefined,
              }}>
              {hidden ? '⊘ ' : ''}{CATEGORY_TITLE[cat] || cat}: {label}
            </span>
          )
        })}
      </div>

      {/* Reasons for any gated category. */}
      {gated.map(cat => (
        <div key={cat} style={{ color: 'var(--text-muted)', fontSize: 10, lineHeight: 1.5 }}>
          <span style={{ color: 'var(--text)' }}>{CATEGORY_TITLE[cat] || cat}</span> — {scope.findings[cat].reason}
        </div>
      ))}

      {/* The chronological account. */}
      {merged.length === 0 ? (
        <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 4 }}>
          No attacker activity found in the scoped window{gated.length ? ' (some categories need permission — see above)' : ''}.
        </div>
      ) : visibleMerged.length === 0 ? (
        <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 4 }}>
          All categories hidden — click a chip above to show its events.
        </div>
      ) : (
        <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-panel)', padding: '4px 12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-muted)', fontSize: 9.5, padding: '6px 0 2px', letterSpacing: 0.3, textTransform: 'uppercase' }}>
            <input type="checkbox" checked={allPicked}
              onChange={() => setPicked(allPicked ? new Set() : new Set(allPickableKeys))}
              title="Select all / none" style={{ cursor: 'pointer' }} />
            what the attacker did · in order — tick events to add to the timeline
            {hiddenCats.size > 0 && <span style={{ textTransform: 'none', letterSpacing: 0, marginLeft: 8 }}>({hiddenCats.size} categor{hiddenCats.size === 1 ? 'y' : 'ies'} hidden)</span>}
          </div>
          {visibleMerged.map(({ cat, e }, i) => (
            <PersistRow key={e.id || i} e={e} last={i === visibleMerged.length - 1}
              picked={picked.has(evKey(cat, e))} onPick={() => togglePick(evKey(cat, e))} />
          ))}
        </div>
      )}
    </div>
  )
}

function PersistRow({ e, last, picked, onPick }: { e: BecPersistenceEvent; last?: boolean; picked?: boolean; onPick?: () => void }) {
  const meta = PERSIST_CAT[e.category] ?? { label: e.category, color: 'var(--text-muted)' }
  const explain = ACTION_EXPLAIN[e.category]
  const extraIps = (e.ip_count ?? 0) > 1 ? ` (+${(e.ip_count ?? 1) - 1} more IP${e.ip_count === 2 ? '' : 's'})` : ''
  const seen = (e.event_count ?? 0) > 1 ? ` · seen ${e.event_count}×` : ''
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 0', borderBottom: last ? 'none' : '1px solid var(--border-soft)' }}>
      {onPick && (
        <input type="checkbox" checked={!!picked} onChange={onPick}
          title="Add this event to the timeline" style={{ cursor: 'pointer', marginTop: 3, flexShrink: 0 }} />
      )}
      {/* Time leads so the list reads chronologically top-to-bottom. */}
      <div style={{ width: 118, flexShrink: 0, textAlign: 'right', color: 'var(--text-muted)', fontSize: 9.5, paddingTop: 2 }}>
        {fmtDateTime(e.timestamp)}
      </div>
      <span style={{
        fontSize: 8.5, fontWeight: 700, letterSpacing: 0.3, padding: '1px 5px', borderRadius: 2,
        color: meta.color, border: `1px solid ${meta.color}`, background: `${meta.color}1A`,
        whiteSpace: 'nowrap', flexShrink: 0, marginTop: 1,
      }}>{meta.label}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        {/* Plain-English explanation leads. */}
        <div style={{ color: 'var(--text)', fontSize: 11, lineHeight: 1.45 }}>{explain || e.activity}</div>
        {/* The concrete value that was set (registered method, rule name, …). */}
        {e.detail && (
          <div style={{ color: 'var(--text)', fontSize: 10.5, marginTop: 3, wordBreak: 'break-word', borderLeft: `2px solid ${meta.color}`, paddingLeft: 6 }}>
            {e.detail}
          </div>
        )}
        {/* The raw audit specifics, muted. Source IP / device lead so the
            analyst can see WHERE the action came from. */}
        <div style={{ color: 'var(--text-muted)', fontSize: 9.5, marginTop: 3 }}>
          {e.activity}
          {e.initiated_by_ip
            ? <> · from <span style={{ color: '#F0B340' }}>{e.initiated_by_ip}</span>{extraIps}</>
            : <> · <span style={{ fontStyle: 'italic' }}>source IP not in audit record</span></>}
          {e.device ? ` · ${e.device}` : ''}
          {e.target ? ` · target ${e.target}` : ''}
          {e.result ? ` · ${e.result}` : ''}
          {seen}
        </div>
      </div>
    </div>
  )
}

const thStyle: React.CSSProperties = {
  textAlign: 'left', padding: '6px 10px', background: 'var(--bg-card)', color: 'var(--text-muted)',
  fontWeight: 600, fontSize: 9.5, letterSpacing: 0.3, textTransform: 'uppercase',
  borderBottom: '1px solid var(--border)', position: 'sticky', top: 0, whiteSpace: 'nowrap',
}
const tdStyle: React.CSSProperties = {
  padding: '5px 10px', verticalAlign: 'top', color: 'var(--text-muted)', whiteSpace: 'nowrap',
}
