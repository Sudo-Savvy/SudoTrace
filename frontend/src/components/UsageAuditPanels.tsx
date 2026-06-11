import { useEffect, useState } from 'react'
import {
  fetchTokenUsage, fetchAuditLog,
  type TokenUsageRow, type TokenUsageTotals, type AuditEntry,
} from '../api/admin'
import { friendlyError } from '../utils/errors'
import { fmtDateTime } from '../utils/dateFormat'

// Settings → Token Usage panel. Read-only view over the token_usage
// table (populated since v0.6 on every Claude call). Shows rolling
// totals + the most recent 50 calls.

export function TokenUsagePanel() {
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState<string | null>(null)
  const [recent,  setRecent]  = useState<TokenUsageRow[]>([])
  const [totals,  setTotals]  = useState<{
    last24h: TokenUsageTotals; last7d: TokenUsageTotals;
    last30d: TokenUsageTotals; alltime: TokenUsageTotals;
  } | null>(null)

  const load = () => {
    setLoading(true); setError(null)
    fetchTokenUsage(50)
      .then(r => { setRecent(r.recent); setTotals(r.totals) })
      .catch(e => setError(friendlyError(e)))
      .finally(() => setLoading(false))
  }
  useEffect(() => { load() }, [])

  return (
    <div>
      <p style={panelStyles.desc}>
        Aggregate spend on Claude API calls. Per-row data captures the model, token counts and
        cost as billed at request time. Use it to spot runaway investigations or unusually large prompts.
      </p>
      {error && <p style={panelStyles.error}>{error}</p>}
      {loading ? (
        <p style={panelStyles.muted}>Loading…</p>
      ) : totals ? (
        <>
          <div style={panelStyles.totalsRow}>
            <TotalCard label="Last 24h" t={totals.last24h} />
            <TotalCard label="Last 7d"  t={totals.last7d} />
            <TotalCard label="Last 30d" t={totals.last30d} />
            <TotalCard label="All time" t={totals.alltime} />
          </div>
          <div style={panelStyles.toolbar}>
            <span style={panelStyles.muted}>
              {recent.length} most recent call{recent.length === 1 ? '' : 's'}
            </span>
            <span style={{ flex: 1 }} />
            <button style={panelStyles.refreshBtn} onClick={load}>↻ refresh</button>
          </div>
          {recent.length === 0 ? (
            <p style={panelStyles.muted}>No AI calls recorded yet.</p>
          ) : (
            <div style={panelStyles.tableWrap}>
              <table style={panelStyles.table}>
                <thead>
                  <tr>
                    <th style={panelStyles.th}>Time</th>
                    <th style={panelStyles.th}>Action</th>
                    <th style={panelStyles.th}>Model</th>
                    <th style={{ ...panelStyles.th, textAlign: 'right' }}>Input</th>
                    <th style={{ ...panelStyles.th, textAlign: 'right' }}>Output</th>
                    <th style={{ ...panelStyles.th, textAlign: 'right' }}>Cost (USD)</th>
                    <th style={{ ...panelStyles.th, textAlign: 'right' }}>Duration</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map(r => (
                    <tr key={r.id}>
                      <td style={panelStyles.td}>{fmtDateTime(r.timestamp)}</td>
                      <td style={panelStyles.td}>{r.action ?? '—'}</td>
                      <td style={panelStyles.td}>{r.model ?? '—'}</td>
                      <td style={{ ...panelStyles.td, textAlign: 'right' }}>{fmtNum(r.input_tokens)}</td>
                      <td style={{ ...panelStyles.td, textAlign: 'right' }}>{fmtNum(r.output_tokens)}</td>
                      <td style={{ ...panelStyles.td, textAlign: 'right' }}>{fmtCost(r.cost_usd)}</td>
                      <td style={{ ...panelStyles.td, textAlign: 'right' }}>{fmtDuration(r.duration_ms)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      ) : null}
    </div>
  )
}

function TotalCard({ label, t }: { label: string; t: TokenUsageTotals }) {
  return (
    <div style={panelStyles.totalCard}>
      <div style={panelStyles.totalLabel}>{label}</div>
      <div style={panelStyles.totalCost}>{fmtCost(t.cost_usd)}</div>
      <div style={panelStyles.totalLine}>
        <span>{t.calls} call{t.calls === 1 ? '' : 's'}</span>
      </div>
      <div style={panelStyles.totalLine}>
        <span>{fmtNum(t.input_tokens)} in · {fmtNum(t.output_tokens)} out</span>
      </div>
    </div>
  )
}

// Settings → Audit Log panel. Newest events first, with an action
// filter dropdown so the analyst can narrow to login.failure /
// ai.analyse / credentials.save etc.

export function AuditLogPanel() {
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState<string | null>(null)
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [actions, setActions] = useState<string[]>([])
  const [filter,  setFilter]  = useState<string>('')

  const load = (actionFilter: string) => {
    setLoading(true); setError(null)
    fetchAuditLog({ limit: 200, action: actionFilter || undefined })
      .then(r => { setEntries(r.entries); setActions(r.actions) })
      .catch(e => setError(friendlyError(e)))
      .finally(() => setLoading(false))
  }
  useEffect(() => { load(filter) }, [filter])

  return (
    <div>
      <p style={panelStyles.desc}>
        Append-only trail of security-relevant events: authentication, credential changes, investigation
        starts, AI calls. Useful for incident review and access reconstruction.
      </p>
      {error && <p style={panelStyles.error}>{error}</p>}
      <div style={panelStyles.toolbar}>
        <label style={panelStyles.label} htmlFor="audit-action">Action</label>
        <select
          id="audit-action"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          style={panelStyles.select}>
          <option value="">all</option>
          {actions.map(a => <option key={a} value={a}>{a}</option>)}
        </select>
        <span style={panelStyles.muted}>
          {entries.length} event{entries.length === 1 ? '' : 's'}
        </span>
        <span style={{ flex: 1 }} />
        <button style={panelStyles.refreshBtn} onClick={() => load(filter)}>↻ refresh</button>
      </div>
      {loading ? (
        <p style={panelStyles.muted}>Loading…</p>
      ) : entries.length === 0 ? (
        <p style={panelStyles.muted}>No audited events match this filter.</p>
      ) : (
        <div style={panelStyles.tableWrap}>
          <table style={panelStyles.table}>
            <thead>
              <tr>
                <th style={panelStyles.th}>Time</th>
                <th style={panelStyles.th}>Action</th>
                <th style={panelStyles.th}>User</th>
                <th style={panelStyles.th}>IP</th>
                <th style={panelStyles.th}>Target</th>
                <th style={panelStyles.th}>Detail</th>
              </tr>
            </thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id}>
                  <td style={panelStyles.td}>{fmtDateTime(e.timestamp)}</td>
                  <td style={panelStyles.td}>
                    <span style={actionPillStyle(e.action)}>{e.action}</span>
                  </td>
                  <td style={panelStyles.td}>{e.username ?? '—'}</td>
                  <td style={panelStyles.td}>{e.ip ?? '—'}</td>
                  <td style={panelStyles.td}>{e.target ?? '—'}</td>
                  <td style={panelStyles.td}>
                    {e.detail ? (
                      <code style={panelStyles.detailCode}>{shortJson(e.detail)}</code>
                    ) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function fmtNum(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—'
  return n.toLocaleString('en-GB')
}
function fmtCost(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—'
  if (n === 0) return '$0.00'
  if (n < 0.01) return `$${n.toFixed(4)}`
  return `$${n.toFixed(2)}`
}
function fmtDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '—'
  if (ms < 1000) return `${ms} ms`
  return `${(ms / 1000).toFixed(1)} s`
}
function shortJson(d: Record<string, unknown>): string {
  const s = JSON.stringify(d)
  return s.length > 100 ? s.slice(0, 97) + '…' : s
}
function actionPillStyle(action: string): React.CSSProperties {
  let bg = 'rgba(168,85,247,0.10)'
  let border = 'var(--accent)'
  let color  = 'var(--accent)'
  if (action.startsWith('login.failure')) {
    bg = 'rgba(255,94,91,0.10)'; border = 'var(--red)'; color = 'var(--red)'
  } else if (action.startsWith('login.success') || action === 'logout') {
    bg = 'rgba(122,168,255,0.10)'; border = '#7AA8FF'; color = '#7AA8FF'
  } else if (action.startsWith('ai.')) {
    bg = 'rgba(240,179,64,0.10)'; border = 'var(--amber)'; color = 'var(--amber)'
  }
  return {
    display: 'inline-block', fontSize: 10, fontWeight: 600,
    letterSpacing: 0.4, padding: '1px 6px',
    background: bg, border: `1px solid ${border}`,
    color, borderRadius: 2, whiteSpace: 'nowrap',
  }
}

const panelStyles: Record<string, React.CSSProperties> = {
  desc: {
    color: 'var(--text-muted)', fontSize: 12.5, lineHeight: 1.6, margin: '0 0 12px',
  },
  muted: {
    color: 'var(--text-muted)', fontSize: 11.5, margin: 0,
  },
  error: {
    color: 'var(--red)', fontSize: 12, margin: '0 0 10px',
  },
  totalsRow: {
    display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
    gap: 10, marginBottom: 16,
  },
  totalCard: {
    background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4,
    padding: '10px 12px',
  },
  totalLabel: {
    color: 'var(--text-muted)', fontSize: 10.5, letterSpacing: 0.4,
    textTransform: 'uppercase', marginBottom: 4,
  },
  totalCost: {
    color: 'var(--accent)', fontSize: 18, fontWeight: 700, marginBottom: 4,
  },
  totalLine: {
    color: 'var(--text)', fontSize: 11, lineHeight: 1.5,
  },
  toolbar: {
    display: 'flex', alignItems: 'center', gap: 10,
    marginBottom: 8, fontFamily: 'var(--font-mono)', fontSize: 11.5,
  },
  label: {
    color: 'var(--text-muted)', fontSize: 11,
  },
  select: {
    background: 'var(--bg-card)', color: 'var(--text)',
    border: '1px solid var(--border)', borderRadius: 3,
    padding: '3px 8px', fontSize: 11,
    fontFamily: 'var(--font-mono)',
  },
  refreshBtn: {
    background: 'transparent', border: '1px solid var(--border)',
    borderRadius: 3, color: 'var(--text-muted)', cursor: 'pointer',
    fontFamily: 'var(--font-mono)', fontSize: 11,
    padding: '3px 10px',
  },
  tableWrap: {
    border: '1px solid var(--border)', borderRadius: 4,
    overflow: 'auto', maxHeight: 460,
  },
  table: {
    borderCollapse: 'collapse', width: '100%',
    fontFamily: 'var(--font-mono)', fontSize: 11,
  },
  th: {
    textAlign: 'left',
    padding: '6px 10px',
    background: 'var(--bg-card)',
    color: 'var(--text-muted)',
    fontWeight: 600, fontSize: 10.5,
    letterSpacing: 0.3, textTransform: 'uppercase',
    borderBottom: '1px solid var(--border)',
    position: 'sticky', top: 0,
  },
  td: {
    padding: '5px 10px', borderBottom: '1px solid var(--border-soft)',
    color: 'var(--text)', whiteSpace: 'nowrap', verticalAlign: 'top',
  },
  detailCode: {
    color: 'var(--text-muted)', fontSize: 10.5, whiteSpace: 'normal',
    wordBreak: 'break-all',
  },
}
