import { useState, useEffect } from 'react'
import { changePassword } from '../api/auth'
import { getCredentials, saveCredentials, testGraphConnection, testAnthropicConnection } from '../api/credentials'
import type { Credentials, TestResult } from '../api/credentials'
import type { User } from '../types'
import { friendlyError } from '../utils/errors'
import { TokenUsagePanel, AuditLogPanel } from '../components/UsageAuditPanels'
import { useTimezone, setTimezone, resolveTimezone, TIMEZONE_OPTIONS } from '../utils/timezone'
import { fmtDateTime } from '../utils/dateFormat'

interface Props {
  user: User
  onLogout: () => void
  onHome: () => void
}

function EyeIcon({ visible }: { visible: boolean }) {
  return visible ? (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
      <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
      <line x1="1" y1="1" x2="23" y2="23" />
    </svg>
  ) : (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  )
}

function MaskedField({ id, label, value, onChange, disabled, placeholder }: {
  id: string; label: string; value: string
  onChange: (v: string) => void; disabled?: boolean; placeholder?: string
}) {
  const [visible, setVisible] = useState(false)
  return (
    <div style={s.field}>
      <label style={s.label} htmlFor={id}>{label}</label>
      <div style={s.inputWrap}>
        <input
          id={id} style={s.input}
          type={visible ? 'text' : 'password'}
          value={value} onChange={e => onChange(e.target.value)}
          disabled={disabled} placeholder={placeholder}
          autoComplete="off" spellCheck={false}
        />
        <button type="button" style={s.eyeBtn} onClick={() => setVisible(v => !v)} tabIndex={-1}>
          <EyeIcon visible={visible} />
        </button>
      </div>
    </div>
  )
}

function TestBadge({ result }: { result: { ok: boolean; error?: string } }) {
  return (
    <span style={{ ...s.badge, background: result.ok ? 'rgba(56,161,105,0.15)' : 'rgba(229,62,62,0.12)', color: result.ok ? 'var(--green)' : 'var(--red)', border: `1px solid ${result.ok ? 'rgba(56,161,105,0.3)' : 'rgba(229,62,62,0.3)'}` }}>
      {result.ok ? '✓ Connected' : `✗ ${result.error}`}
    </span>
  )
}

function MDEInstructions() {
  const [open, setOpen] = useState(false)
  return (
    <div style={si.wrap}>
      <button type="button" style={si.toggle} onClick={() => setOpen(o => !o)}>
        {open ? '▾' : '▸'} How to get these credentials
      </button>
      {open && (
        <div style={si.body}>
          <ol style={si.list}>
            <li>Go to <code style={si.code}>portal.azure.com</code> → search <strong>App registrations</strong> → <strong>New registration</strong></li>
            <li>Name it (e.g. <em>SudoTrace</em>), set account type to <strong>Single tenant</strong>, click <strong>Register</strong></li>
            <li>On the Overview page copy:
              <ul style={si.subList}>
                <li><strong>Directory (tenant) ID</strong> → Tenant ID</li>
                <li><strong>Application (client) ID</strong> → Client ID</li>
              </ul>
            </li>
            <li>Go to <strong>Certificates &amp; secrets</strong> → <strong>New client secret</strong> → Add. The table shows two columns — copy the <strong>Value</strong> column (long string), <em>not</em> the Secret ID (GUID). Value is shown once only — if you missed it, delete and recreate.</li>
            <li>Go to <strong>API permissions</strong> → <strong>Add a permission</strong> → <strong>Microsoft Graph</strong> → <strong>Application permissions</strong> and add:
              <ul style={si.subList}>
                <li><code style={si.code}>ThreatHunting.Read.All</code> — runs all KQL queries (process tree, telemetry, alerts table)</li>
                <li><code style={si.code}>SecurityAlert.Read.All</code> — alert resolution for the Alerts sub-tab</li>
                <li><code style={si.code}>SecurityIncident.Read.All</code> — Incidents sub-tab (Graph Security Incidents API)</li>
              </ul>
            </li>
            <li>Click <strong>Grant admin consent for [your tenant]</strong> — required, otherwise Test will return a permission error.</li>
          </ol>
          <p style={si.note}>⚠ The tenant must have Microsoft Defender for Endpoint Plan 2 licences active.</p>
        </div>
      )}
    </div>
  )
}

// Always-visible disclaimer rendered above the Anthropic API key field.
// Placed at the point of decision (enabling AI features) rather than a
// first-login modal, so it stays discoverable later — analysts can
// re-read it before changing keys or onboarding a teammate. Covers the
// four things an analyst should keep in mind about AI-assisted DFIR:
// what gets sent, the verdict-vs-evidence distinction, cost, and where
// the audit trail lives.
function AnthropicDisclaimer() {
  return (
    <div style={{
      border: '1px solid rgba(240,179,64,0.35)',
      background: 'rgba(240,179,64,0.07)',
      borderRadius: 6,
      padding: '12px 14px',
      marginBottom: 12,
      fontFamily: 'var(--font-mono)',
      fontSize: 11.5, lineHeight: 1.6,
      color: 'var(--text)',
    }}>
      <div style={{
        color: 'var(--amber)', fontWeight: 700, fontSize: 10.5,
        letterSpacing: 0.4, textTransform: 'uppercase', marginBottom: 8,
      }}>
        ⚠ Before you enable AI-assisted analysis
      </div>
      <ul style={{ margin: 0, paddingLeft: 18, color: 'var(--text-muted)' }}>
        <li>
          <strong style={{ color: 'var(--text)' }}>Data leaves your environment.</strong>{' '}
          Process trees, command lines, file paths, hashes, IPs, IOCs and
          analyst-confirmed evidence are sent to Anthropic's API.
          Don't enable this on investigations whose contents must not
          leave your tenancy.
        </li>
        <li>
          <strong style={{ color: 'var(--text)' }}>AI findings are a lead, not a verdict.</strong>{' '}
          Treat every AI summary, classification or IOC suggestion as
          analyst-assist material — confirm against the underlying
          telemetry, your incident notes and policy before acting.
          Hallucinations and false confidence happen.
        </li>
        <li>
          <strong style={{ color: 'var(--text)' }}>Costs are real.</strong>{' '}
          Each analysis bills tokens against your Anthropic account.
          Wide-scope or repeated runs add up — watch{' '}
          <strong>Settings → Token usage</strong> if you're cost-sensitive.
        </li>
        <li>
          <strong style={{ color: 'var(--text)' }}>Audit trail.</strong>{' '}
          Every AI call is logged with user, scope, model, tokens and
          cost in <strong>Settings → Audit log</strong>. Investigation
          starts, credential changes and logins are recorded the same way.
        </li>
      </ul>
    </div>
  )
}

function AnthropicInstructions() {
  const [open, setOpen] = useState(false)
  return (
    <div style={si.wrap}>
      <button type="button" style={si.toggle} onClick={() => setOpen(o => !o)}>
        {open ? '▾' : '▸'} How to get your API key
      </button>
      {open && (
        <div style={si.body}>
          <ol style={si.list}>
            <li>Go to <code style={si.code}>console.anthropic.com</code> and sign in</li>
            <li>Go to <strong>Manage</strong> → <strong>API Keys</strong> → <strong>Create Key</strong></li>
            <li>Copy the key — it starts with <code style={si.code}>sk-ant-</code></li>
            <li>Ensure the account has billing configured — the free tier has very limited quota</li>
          </ol>
        </div>
      )}
    </div>
  )
}

const si: Record<string, React.CSSProperties> = {
  wrap: { border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden' },
  toggle: { background: 'var(--bg-card)', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '13px', padding: '10px 14px', textAlign: 'left', width: '100%' },
  body: { background: 'var(--bg-card)', borderTop: '1px solid var(--border)', padding: '14px' },
  list: { color: 'var(--text-muted)', fontSize: '13px', lineHeight: '1.7', paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '2px' },
  subList: { marginTop: '2px', paddingLeft: '16px' },
  code: { background: 'rgba(255,255,255,0.06)', borderRadius: '3px', color: 'var(--text)', fontFamily: 'var(--font-mono)', fontSize: '12px', padding: '1px 5px' },
  note: { background: 'rgba(232,99,10,0.08)', border: '1px solid rgba(232,99,10,0.2)', borderRadius: '5px', color: 'var(--amber)', fontSize: '12px', marginTop: '10px', padding: '7px 10px' },
}

function TimezonePicker() {
  const tz = useTimezone()
  const known = TIMEZONE_OPTIONS.some(o => o.value === tz)
  const [mode, setMode] = useState<'select' | 'custom'>(known ? 'select' : 'custom')
  const [custom, setCustom] = useState(known ? '' : tz)
  const [customError, setCustomError] = useState<string | null>(null)
  const nowIso = new Date().toISOString()
  const resolved = resolveTimezone(tz)

  function applyCustom() {
    const v = custom.trim()
    if (!v) { setCustomError('Enter an IANA timezone name (e.g. Europe/Berlin).'); return }
    try {
      // Round-trip through Intl to validate — invalid names throw.
      new Intl.DateTimeFormat('en-GB', { timeZone: v }).format(new Date())
    } catch {
      setCustomError(`"${v}" is not a recognised IANA timezone.`)
      return
    }
    setCustomError(null)
    setTimezone(v)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <p style={{ color: 'var(--text-muted)', fontSize: 12.5, lineHeight: 1.6, margin: 0 }}>
        Affects every timestamp shown in the UI (timeline, telemetry, hunt results, incidents).
        UTC is the default so timestamps match what you see in the Defender portal.
      </p>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <select
          value={mode === 'custom' ? '__custom' : tz}
          onChange={e => {
            const v = e.target.value
            if (v === '__custom') { setMode('custom'); return }
            setMode('select')
            setCustomError(null)
            setTimezone(v)
          }}
          style={{
            background: 'var(--bg-card)', color: 'var(--text)',
            border: '1px solid var(--border)', borderRadius: 4,
            fontFamily: 'var(--font-mono)', fontSize: 12,
            padding: '7px 10px', minWidth: 280,
          }}>
          {TIMEZONE_OPTIONS.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
          <option value="__custom">Custom IANA name…</option>
        </select>
        {mode === 'custom' && (
          <>
            <input
              value={custom}
              onChange={e => { setCustom(e.target.value); setCustomError(null) }}
              onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); applyCustom() } }}
              placeholder="e.g. Pacific/Auckland"
              style={{
                background: 'var(--bg-card)', color: 'var(--text)',
                border: '1px solid var(--border)', borderRadius: 4,
                fontFamily: 'var(--font-mono)', fontSize: 12,
                padding: '7px 10px', minWidth: 220,
              }}
            />
            <button
              onClick={applyCustom}
              style={{
                background: 'var(--accent)', color: '#fff',
                border: 'none', borderRadius: 4, cursor: 'pointer',
                fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600,
                padding: '7px 14px',
              }}>apply</button>
          </>
        )}
      </div>
      {customError && (
        <div style={{ color: 'var(--red)', fontSize: 11.5 }}>{customError}</div>
      )}
      <div style={{ color: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
        active: <span style={{ color: 'var(--text)' }}>{resolved}</span>
        {' · preview: '}
        <span style={{ color: 'var(--accent)' }}>{fmtDateTime(nowIso)}</span>
      </div>
    </div>
  )
}

export default function SettingsPage({ user, onLogout, onHome }: Props) {
  const [creds, setCreds] = useState<Credentials>({ tenant_id: null, client_id: null, client_secret: null, anthropic_key: null, vt_api_key: null })
  const [credsLoading, setCredsLoading] = useState(true)

  // MDE save state
  const [mdeSaving, setMdeSaving] = useState(false)
  const [mdeError, setMdeError] = useState('')
  const [mdeSaved, setMdeSaved] = useState(false)

  // Anthropic save state
  const [anthropicSaving, setAnthropicSaving] = useState(false)
  const [anthropicError, setAnthropicError] = useState('')
  const [anthropicSaved, setAnthropicSaved] = useState(false)

  // VirusTotal save state
  const [vtSaving, setVtSaving] = useState(false)
  const [vtError, setVtError] = useState('')
  const [vtSaved, setVtSaved] = useState(false)

  // MDE test state
  const [mdeTesting, setMdeTesting] = useState(false)
  const [mdeTestError, setMdeTestError] = useState('')
  const [mdeTestResult, setMdeTestResult] = useState<TestResult | null>(null)

  // Anthropic test state
  const [anthropicTesting, setAnthropicTesting] = useState(false)
  const [anthropicTestError, setAnthropicTestError] = useState('')
  const [anthropicTestResult, setAnthropicTestResult] = useState<TestResult | null>(null)

  // Password state
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [pwError, setPwError] = useState('')
  const [pwSuccess, setPwSuccess] = useState(false)
  const [pwLoading, setPwLoading] = useState(false)

  useEffect(() => {
    getCredentials()
      .then(data => setCreds(data))
      .catch(() => {})
      .finally(() => setCredsLoading(false))
  }, [])

  function setField(field: keyof Credentials, value: string) {
    setCreds(prev => ({ ...prev, [field]: value }))
  }

  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

  async function saveMDE(e: React.FormEvent) {
    e.preventDefault()
    setMdeError(''); setMdeSaved(false)
    if (creds.client_secret && UUID_RE.test(creds.client_secret.trim())) {
      setMdeError('Client Secret looks like a GUID — that is the Secret ID, not the Secret Value. Copy the Value column from Certificates & secrets.')
      return
    }
    setMdeSaving(true)
    try {
      await saveCredentials({ tenant_id: creds.tenant_id, client_id: creds.client_id, client_secret: creds.client_secret })
      setMdeSaved(true)
    } catch (err) {
      setMdeError(friendlyError(err))
    } finally {
      setMdeSaving(false)
    }
  }

  async function saveAnthropic(e: React.FormEvent) {
    e.preventDefault()
    setAnthropicError(''); setAnthropicSaved(false)
    setAnthropicSaving(true)
    try {
      await saveCredentials({ anthropic_key: creds.anthropic_key })
      setAnthropicSaved(true)
    } catch (err) {
      setAnthropicError(friendlyError(err))
    } finally {
      setAnthropicSaving(false)
    }
  }

  async function handleTestMDE() {
    setMdeTestError(''); setMdeTestResult(null); setMdeTesting(true)
    try {
      setMdeTestResult(await testGraphConnection())
    } catch (err) {
      setMdeTestError(friendlyError(err))
    } finally {
      setMdeTesting(false)
    }
  }

  async function handleTestAnthropic() {
    setAnthropicTestError(''); setAnthropicTestResult(null); setAnthropicTesting(true)
    try {
      setAnthropicTestResult(await testAnthropicConnection())
    } catch (err) {
      setAnthropicTestError(friendlyError(err))
    } finally {
      setAnthropicTesting(false)
    }
  }

  async function handlePasswordSubmit(e: React.FormEvent) {
    e.preventDefault()
    setPwError(''); setPwSuccess(false)
    if (next.length < 8) { setPwError('Password must be at least 8 characters.'); return }
    if (next !== confirm) { setPwError('Passwords do not match.'); return }
    setPwLoading(true)
    try {
      await changePassword(current, next)
      setPwSuccess(true)
      setCurrent(''); setNext(''); setConfirm('')
    } catch (err) {
      setPwError(friendlyError(err))
    } finally {
      setPwLoading(false)
    }
  }

  async function saveVT(e: React.FormEvent) {
    e.preventDefault()
    setVtError(''); setVtSaved(false); setVtSaving(true)
    try {
      await saveCredentials({ vt_api_key: creds.vt_api_key })
      setVtSaved(true)
    } catch (err) {
      setVtError(friendlyError(err))
    } finally {
      setVtSaving(false)
    }
  }

  const busy = mdeSaving || anthropicSaving || vtSaving || mdeTesting || anthropicTesting

  return (
    <div style={s.root}>
      <header style={s.header}>
        <img
          src="/sudotrace-logo-horizontal.png"
          alt="SudoTrace"
          title="Back to investigation"
          onClick={onHome}
          style={s.logoImg}
        />
        <div style={s.headerRight}>
          <button style={s.navBtn} onClick={onHome}>← Back</button>
          <span style={s.username}>{user.username}</span>
          <button style={s.navBtn} onClick={onLogout}>Sign out</button>
        </div>
      </header>

      <main style={s.main}>
        <div style={s.content}>
          <h1 style={s.heading}>Settings</h1>

          {credsLoading ? (
            <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Loading…</p>
          ) : (<>

            {/* MDE section */}
            <section style={s.section}>
              <h2 style={s.sectionTitle}>Microsoft Defender for Endpoint</h2>
              <p style={s.sectionDesc}>Azure AD app registration credentials. Stored encrypted — never written to disk in plaintext.</p>
              <form onSubmit={saveMDE} style={s.form}>
                <MDEInstructions />
                <MaskedField id="tenant_id" label="Tenant ID" value={creds.tenant_id ?? ''} onChange={v => { setField('tenant_id', v); setMdeSaved(false) }} disabled={busy} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
                <MaskedField id="client_id" label="Client ID" value={creds.client_id ?? ''} onChange={v => { setField('client_id', v); setMdeSaved(false) }} disabled={busy} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
                <MaskedField id="client_secret" label="Client Secret" value={creds.client_secret ?? ''} onChange={v => { setField('client_secret', v); setMdeSaved(false) }} disabled={busy} placeholder="Client secret value" />
                {mdeError && <p style={s.error}>{mdeError}</p>}
                {mdeSaved && <p style={s.successMsg}>Defender credentials saved.</p>}
                <div style={s.btnRow}>
                  <button type="submit" style={{ ...s.btn, ...(mdeSaving ? s.btnDisabled : {}) }} disabled={busy}>
                    {mdeSaving ? 'Saving…' : 'Save'}
                  </button>
                  <button type="button" style={{ ...s.btnSecondary, ...(mdeTesting ? s.btnDisabled : {}) }} onClick={handleTestMDE} disabled={busy}>
                    {mdeTesting ? 'Testing…' : 'Test connection'}
                  </button>
                </div>
                {mdeTestError && <p style={s.error}>{mdeTestError}</p>}
                {mdeTestResult && <TestBadge result={mdeTestResult} />}
              </form>
            </section>

            {/* Anthropic section */}
            <section style={{ ...s.section, marginTop: '16px' }}>
              <h2 style={s.sectionTitle}>Claude AI (Anthropic)</h2>
              <p style={s.sectionDesc}>Used for all AI analysis. Stored encrypted — never written to disk in plaintext.</p>
              <AnthropicDisclaimer />
              <form onSubmit={saveAnthropic} style={s.form}>
                <AnthropicInstructions />
                <MaskedField id="anthropic_key" label="Anthropic API Key" value={creds.anthropic_key ?? ''} onChange={v => { setField('anthropic_key', v); setAnthropicSaved(false) }} disabled={busy} placeholder="sk-ant-..." />
                {anthropicError && <p style={s.error}>{anthropicError}</p>}
                {anthropicSaved && <p style={s.successMsg}>Anthropic API key saved.</p>}
                <div style={s.btnRow}>
                  <button type="submit" style={{ ...s.btn, ...(anthropicSaving ? s.btnDisabled : {}) }} disabled={busy}>
                    {anthropicSaving ? 'Saving…' : 'Save'}
                  </button>
                  <button type="button" style={{ ...s.btnSecondary, ...(anthropicTesting ? s.btnDisabled : {}) }} onClick={handleTestAnthropic} disabled={busy}>
                    {anthropicTesting ? 'Testing…' : 'Test connection'}
                  </button>
                </div>
                {anthropicTestError && <p style={s.error}>{anthropicTestError}</p>}
                {anthropicTestResult && <TestBadge result={anthropicTestResult} />}
              </form>
            </section>

            {/* VirusTotal section */}
            <section style={{ ...s.section, marginTop: '16px' }}>
              <h2 style={s.sectionTitle}>VirusTotal</h2>
              <p style={s.sectionDesc}>
                Used for IOC lookups on file hashes and IP addresses. Get a free API key at{' '}
                <code style={si.code}>virustotal.com</code>. Stored encrypted — never written to disk in plaintext.
              </p>
              <form onSubmit={saveVT} style={s.form}>
                <MaskedField
                  id="vt_api_key"
                  label="VirusTotal API Key"
                  value={creds.vt_api_key ?? ''}
                  onChange={v => { setField('vt_api_key', v); setVtSaved(false) }}
                  disabled={busy}
                  placeholder="Enter your VirusTotal API key"
                />
                {vtError && <p style={s.error}>{vtError}</p>}
                {vtSaved && <p style={s.successMsg}>VirusTotal API key saved.</p>}
                <div style={s.btnRow}>
                  <button type="submit" style={{ ...s.btn, ...(vtSaving ? s.btnDisabled : {}) }} disabled={busy}>
                    {vtSaving ? 'Saving…' : 'Save'}
                  </button>
                </div>
              </form>
            </section>

          </>)}

          {/* Display timezone — affects every timestamp the analyst sees
              (timeline, telemetry, hunt results, incidents). Default UTC
              keeps things lined up with the Defender portal. */}
          <section style={{ ...s.section, marginTop: '16px' }}>
            <h2 style={s.sectionTitle}>Display timezone</h2>
            <TimezonePicker />
          </section>

          {/* Token Usage (Claude API spend) */}
          <section style={{ ...s.section, marginTop: '16px' }}>
            <h2 style={s.sectionTitle}>Token usage</h2>
            <TokenUsagePanel />
          </section>

          {/* Audit Log */}
          <section style={{ ...s.section, marginTop: '16px' }}>
            <h2 style={s.sectionTitle}>Audit log</h2>
            <AuditLogPanel />
          </section>

          {/* Change password */}
          <section style={{ ...s.section, marginTop: '16px' }}>
            <h2 style={s.sectionTitle}>Change password</h2>
            <p style={s.sectionDesc}>Use a strong password of at least 8 characters.</p>
            <form onSubmit={handlePasswordSubmit} style={s.form}>
              <div style={s.field}>
                <label style={s.label} htmlFor="current">Current password</label>
                <input id="current" style={s.input} type="password" autoComplete="current-password" value={current} onChange={e => setCurrent(e.target.value)} disabled={pwLoading} required />
              </div>
              <div style={s.field}>
                <label style={s.label} htmlFor="new-pw">New password</label>
                <input id="new-pw" style={s.input} type="password" autoComplete="new-password" value={next} onChange={e => setNext(e.target.value)} disabled={pwLoading} required />
              </div>
              <div style={s.field}>
                <label style={s.label} htmlFor="confirm-pw">Confirm new password</label>
                <input id="confirm-pw" style={s.input} type="password" autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} disabled={pwLoading} required />
              </div>
              {pwError && <p style={s.error}>{pwError}</p>}
              {pwSuccess && <p style={s.successMsg}>Password updated successfully.</p>}
              <button style={{ ...s.btn, ...(pwLoading ? s.btnDisabled : {}) }} type="submit" disabled={pwLoading}>
                {pwLoading ? 'Updating…' : 'Update password'}
              </button>
            </form>
          </section>

        </div>
      </main>
    </div>
  )
}

const s: Record<string, React.CSSProperties> = {
  root: { minHeight: '100vh', background: 'var(--bg-app)', display: 'flex', flexDirection: 'column' },
  header: { alignItems: 'center', background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', padding: '0 24px', height: '52px' },
  logoImg: { height: 32, width: 'auto', cursor: 'pointer', display: 'block', borderRadius: 3, flexShrink: 0 },
  headerRight: { alignItems: 'center', display: 'flex', gap: '12px' },
  username: { color: 'var(--text-muted)', fontSize: '13px' },
  navBtn: { background: 'transparent', border: '1px solid var(--border)', borderRadius: '5px', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '13px', padding: '5px 12px' },
  main: { display: 'flex', justifyContent: 'center', padding: '48px 24px' },
  content: { width: '100%', maxWidth: '520px' },
  heading: { color: 'var(--text)', fontSize: '20px', fontWeight: 600, marginBottom: '32px' },
  section: { background: 'var(--bg-panel)', border: '1px solid var(--border)', borderRadius: '10px', padding: '24px' },
  sectionTitle: { color: 'var(--text)', fontSize: '14px', fontWeight: 600, marginBottom: '4px' },
  sectionDesc: { color: 'var(--text-muted)', fontSize: '13px', marginBottom: '16px' },
  form: { display: 'flex', flexDirection: 'column', gap: '14px' },
  field: { display: 'flex', flexDirection: 'column', gap: '6px' },
  label: { color: 'var(--text-muted)', fontSize: '12px', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.05em' },
  inputWrap: { position: 'relative', display: 'flex', alignItems: 'center' },
  input: { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--text)', fontSize: '14px', padding: '9px 36px 9px 12px', outline: 'none', width: '100%' },
  eyeBtn: { position: 'absolute', right: '10px', background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '2px', display: 'flex', alignItems: 'center' },
  error: { background: 'rgba(229,62,62,0.1)', border: '1px solid rgba(229,62,62,0.3)', borderRadius: '6px', color: 'var(--red)', fontSize: '13px', padding: '9px 12px' },
  successMsg: { background: 'rgba(56,161,105,0.1)', border: '1px solid rgba(56,161,105,0.3)', borderRadius: '6px', color: 'var(--green)', fontSize: '13px', padding: '9px 12px' },
  btnRow: { display: 'flex', gap: '10px' },
  badge: { borderRadius: '4px', fontSize: '12px', fontWeight: 500, padding: '3px 8px' },
  btn: { background: 'var(--accent)', border: 'none', borderRadius: '6px', color: '#fff', cursor: 'pointer', fontSize: '14px', fontWeight: 600, padding: '10px 16px' },
  btnSecondary: { background: 'transparent', border: '1px solid var(--border)', borderRadius: '6px', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '14px', padding: '10px 16px' },
  btnDisabled: { opacity: 0.5, cursor: 'not-allowed' },
}
