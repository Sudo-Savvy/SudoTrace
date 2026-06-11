import { useState } from 'react'
import type { AnalysisResult } from '../types'
import { addIoc, hasIoc, type IocEntry } from '../store/iocStore'

// "PID 1234", "PIDs 1234", "PID: 1234" — capture the first integer after the
// keyword. Plural lists like "PIDs 1234, 5678" only get the first one linked;
// the structured per_process_findings list covers full enumeration.
const PID_PATTERN = /\bPIDs?\s*:?\s*(\d{1,7})\b/g

function PidLink({ pid, onClick, children }: {
  pid: number
  onClick: (pid: number) => void
  children: React.ReactNode
}) {
  return (
    <span
      onClick={e => { e.stopPropagation(); onClick(pid) }}
      title={`Reveal PID ${pid} in the tree`}
      onMouseEnter={e => { e.currentTarget.style.textDecorationColor = 'var(--accent)' }}
      onMouseLeave={e => { e.currentTarget.style.textDecorationColor = 'rgba(168,85,247,0.4)' }}
      style={{
        color: 'var(--accent)', cursor: 'pointer',
        textDecoration: 'underline',
        textDecorationStyle: 'dotted',
        textDecorationColor: 'rgba(168,85,247,0.4)',
        transition: 'text-decoration-color 100ms',
      }}
    >{children}</span>
  )
}

function renderWithPids(text: string | undefined | null, onPidClick?: (pid: number) => void): React.ReactNode {
  if (!text) return text ?? null
  if (!onPidClick) return text
  const out: React.ReactNode[] = []
  let lastIdx = 0
  let i = 0
  PID_PATTERN.lastIndex = 0
  for (const m of text.matchAll(PID_PATTERN)) {
    const start = m.index ?? 0
    const end = start + m[0].length
    if (start > lastIdx) out.push(text.slice(lastIdx, start))
    out.push(<PidLink key={`pid-${i++}-${start}`} pid={parseInt(m[1], 10)} onClick={onPidClick}>{m[0]}</PidLink>)
    lastIdx = end
  }
  if (lastIdx === 0) return text
  if (lastIdx < text.length) out.push(text.slice(lastIdx))
  return out
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: '#FF5E5B',
  HIGH:     '#F0B340',
  MEDIUM:   '#F6AD55',
  LOW:      'var(--text-muted)',
  CLEAN:    '#7DD3A0',
}

const URGENCY_COLOR: Record<string, string> = {
  immediate:   '#FF5E5B',
  within_hour: '#F0B340',
  monitor:     'var(--text-muted)',
  none:        'var(--text-muted)',
}

const VERDICT_COLOR: Record<string, string> = {
  malicious:  '#FF5E5B',
  suspicious: '#F0B340',
  benign:     '#7DD3A0',
  unknown:    'var(--text-muted)',
}

const IOC_TYPE_LABEL: Record<string, string> = {
  ip:           'IP',
  domain:       'DOMAIN',
  hash:         'HASH',
  file_path:    'PATH',
  registry_key: 'REG',
}

function SeverityBadge({ severity, confidence }: { severity: string; confidence: number }) {
  const color = SEVERITY_COLOR[severity] ?? 'var(--text-muted)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <span style={{
        fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: 13,
        color, letterSpacing: 0.5,
        padding: '3px 10px',
        background: `${color}18`,
        border: `1px solid ${color}55`,
        borderRadius: 3,
      }}>{severity}</span>
      <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
        {confidence}% confidence
      </span>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 0 }}>
      <div style={{
        color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
        fontSize: 9.5, letterSpacing: 0.8, textTransform: 'uppercase',
        padding: '8px 14px 4px',
        borderTop: '1px solid var(--border-soft)',
      }}>{title}</div>
      <div style={{ padding: '0 14px 10px' }}>{children}</div>
    </div>
  )
}

function ProcessFinding({ f, onPidClick }: {
  f: AnalysisResult['per_process_findings'][0]
  onPidClick?: (pid: number) => void
}) {
  const [open, setOpen] = useState(false)
  const color = VERDICT_COLOR[f.verdict] ?? 'var(--text-muted)'
  return (
    <div style={{
      border: '1px solid var(--border-soft)', borderRadius: 3,
      marginBottom: 6, overflow: 'hidden',
    }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px',
          cursor: 'pointer', background: 'var(--bg-elevated)',
        }}
      >
        <span style={{ color: 'var(--text-muted)', fontSize: 9 }}>{open ? '▾' : '▸'}</span>
        <span style={{
          fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700,
          color, padding: '1px 5px',
          background: `${color}15`, border: `1px solid ${color}40`, borderRadius: 2,
          flexShrink: 0,
        }}>{f.verdict.toUpperCase()}</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)', fontWeight: 600 }}>
          {f.name}
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', flexShrink: 0 }}>
          {onPidClick ? (
            <PidLink pid={f.pid} onClick={onPidClick}>PID {f.pid}</PidLink>
          ) : (
            <>PID {f.pid}</>
          )}
        </span>
      </div>
      {open && (
        <div style={{ padding: '8px 10px', borderTop: '1px solid var(--border-soft)' }}>
          <p style={{
            fontFamily: 'var(--font-mono)', fontSize: 10.5, color: 'var(--text)',
            margin: '0 0 8px', lineHeight: 1.5,
          }}>{renderWithPids(f.summary, onPidClick)}</p>
          {f.evidence.map((ev, i) => (
            <div key={i} style={{
              display: 'flex', gap: 6, marginBottom: 4,
              fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.5,
            }}>
              <span style={{ color: 'var(--accent)', flexShrink: 0 }}>›</span>
              <span>{renderWithPids(ev, onPidClick)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function IocRow({ ioc }: { ioc: AnalysisResult['ioc_suggestions'][0] }) {
  const [confirmed, setConfirmed] = useState(() => hasIoc(ioc.value))
  const [dismissed, setDismissed] = useState(false)

  if (dismissed) return null

  const confColor = ioc.confidence === 'high' ? '#FF5E5B' : ioc.confidence === 'medium' ? '#F0B340' : 'var(--text-muted)'
  const typeLabel = IOC_TYPE_LABEL[ioc.type] ?? ioc.type.toUpperCase()

  function confirm() {
    // Map Claude's suggestion types to the IOC store's type union. The
    // earlier mapping collapsed everything that wasn't ip / domain to
    // 'hash' — which meant REG and PATH suggestions ended up wearing
    // the 'hash' tag and couldn't pivot to the right hunt query.
    const iocType: IocEntry['iocType'] =
      ioc.type === 'ip' ? 'ip'
      : ioc.type === 'domain' ? 'domain'
      : ioc.type === 'hash' ? 'hash'
      : ioc.type === 'registry_key' ? 'registry'
      : ioc.type === 'file_path' ? 'file_path'
      : 'hash'
    addIoc({
      ioc: ioc.value,
      iocType,
      verdict: 'unknown',
      addedAt: Date.now(),
    })
    setConfirmed(true)
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 8,
      padding: '8px 10px',
      background: 'var(--bg-elevated)', border: '1px solid var(--border-soft)', borderRadius: 3,
    }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 8.5, fontWeight: 700,
            color: 'var(--text-muted)', background: 'var(--bg-card)',
            border: '1px solid var(--border)', borderRadius: 2,
            padding: '1px 4px', flexShrink: 0,
          }}>{typeLabel}</span>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 10.5, color: 'var(--text)',
            wordBreak: 'break-all', fontWeight: 600,
          }}>{ioc.value}</span>
          <span style={{ fontSize: 9, color: confColor, flexShrink: 0, marginLeft: 'auto' }}>
            {ioc.confidence}
          </span>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.4 }}>
          {ioc.context}
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flexShrink: 0 }}>
        {confirmed ? (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#7DD3A0', padding: '2px 6px' }}>
            ✓ added
          </span>
        ) : (
          <button
            onClick={confirm}
            onMouseEnter={e => { e.currentTarget.style.borderColor = '#7DD3A0'; e.currentTarget.style.color = '#7DD3A0' }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
            style={{
              background: 'transparent', border: '1px solid var(--border)',
              borderRadius: 2, color: 'var(--text-muted)', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 9, padding: '2px 6px',
              transition: 'border-color 100ms, color 100ms',
            }}>confirm</button>
        )}
        <button
          onClick={() => setDismissed(true)}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--red)' }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)' }}
          style={{
            background: 'transparent', border: 'none', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)',
            padding: '2px 6px', transition: 'color 100ms',
          }}>dismiss</button>
      </div>
    </div>
  )
}

interface Props {
  result: AnalysisResult
  onBack: () => void
  onReanalyse: () => void
  onPidClick?: (pid: number) => void
}

export default function FindingsPanel({ result, onBack, onReanalyse, onPidClick }: Props) {
  const urgencyLevel = result.urgency?.level ?? 'none'
  const urgencyColor = URGENCY_COLOR[urgencyLevel] ?? 'var(--text-muted)'
  const showUrgency = urgencyLevel === 'immediate' || urgencyLevel === 'within_hour'

  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0,
      overflowY: 'auto', fontFamily: 'var(--font-mono)',
    }}>
      {/* Header */}
      <div style={{
        padding: '10px 14px', borderBottom: '1px solid var(--border-soft)',
        display: 'flex', flexDirection: 'column', gap: 8, flexShrink: 0,
      }}>
        <SeverityBadge severity={result.severity} confidence={result.confidence} />

        {/* Urgency banner */}
        {showUrgency && (
          <div style={{
            padding: '5px 10px',
            background: `${urgencyColor}12`,
            border: `1px solid ${urgencyColor}40`,
            borderRadius: 3,
            color: urgencyColor,
            fontSize: 10.5, fontWeight: 600, letterSpacing: 0.3,
          }}>
            {urgencyLevel === 'immediate' ? '⚠ CONTAIN IMMEDIATELY' : '⚠ CONTAIN WITHIN THE HOUR'}
            {' '}— {renderWithPids(result.urgency.reason, onPidClick)}
          </div>
        )}

        <p style={{ margin: 0, fontSize: 11, color: 'var(--text)', lineHeight: 1.6 }}>
          {renderWithPids(result.narrative, onPidClick)}
        </p>

        {/* Token usage */}
        {result.token_usage && (
          <div style={{ fontSize: 9.5, color: 'var(--text-muted)', display: 'flex', gap: 12 }}>
            <span>{result.token_usage.input_tokens.toLocaleString()} in</span>
            <span>{result.token_usage.output_tokens.toLocaleString()} out</span>
            <span>${result.token_usage.cost_usd.toFixed(4)}</span>
            <span>{(result.token_usage.duration_ms / 1000).toFixed(1)}s</span>
          </div>
        )}
      </div>

      {/* Delivery vector + root cause */}
      <Section title="Attack Origin">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>delivery vector </span>
            <span style={{ color: 'var(--text)', fontSize: 10.5, fontWeight: 600 }}>
              {result.delivery_vector?.type ?? 'Unknown'}
            </span>
            <span style={{
              marginLeft: 6, fontSize: 9, color: 'var(--text-muted)',
              padding: '1px 5px', border: '1px solid var(--border)',
              borderRadius: 2,
            }}>{result.delivery_vector?.confidence ?? '?'}</span>
          </div>
          {result.delivery_vector?.evidence && (
            <div style={{ fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.5 }}>
              {renderWithPids(result.delivery_vector.evidence, onPidClick)}
            </div>
          )}
          {result.root_cause && (
            <div style={{
              padding: '6px 8px',
              background: 'rgba(168,85,247,0.06)',
              border: '1px solid rgba(168,85,247,0.2)',
              borderRadius: 3, fontSize: 10.5, color: 'var(--text)', lineHeight: 1.5,
            }}>
              <span style={{ color: 'var(--accent)', fontWeight: 600 }}>root cause: </span>
              {renderWithPids(result.root_cause, onPidClick)}
            </div>
          )}
        </div>
      </Section>

      {/* Per-process findings */}
      {result.per_process_findings?.length > 0 && (
        <Section title={`Process Findings (${result.per_process_findings.length})`}>
          {result.per_process_findings.map((f, i) => (
            <ProcessFinding key={i} f={f} onPidClick={onPidClick} />
          ))}
        </Section>
      )}

      {/* IOC suggestions */}
      {result.ioc_suggestions?.length > 0 && (
        <Section title={`IOC Suggestions (${result.ioc_suggestions.length})`}>
          {result.ioc_suggestions.map((ioc, i) => (
            <IocRow key={i} ioc={ioc} />
          ))}
        </Section>
      )}

      <div style={{ flex: 1 }} />

      {/* Footer actions */}
      <div style={{
        borderTop: '1px solid var(--border-soft)',
        padding: '8px 14px',
        display: 'flex', gap: 8, flexShrink: 0,
      }}>
        <button
          onClick={onBack}
          title="Discard this analysis and return to the flagged-entities list so you can pick what to send next"
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
          style={{
            background: 'transparent', border: '1px solid var(--border)',
            borderRadius: 3, color: 'var(--text-muted)', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5, padding: '4px 10px',
            transition: 'border-color 100ms, color 100ms',
          }}>← edit flagged list</button>
        <button
          onClick={onReanalyse}
          title="Re-run with the same flagged entities"
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
          style={{
            background: 'transparent', border: '1px solid var(--border)',
            borderRadius: 3, color: 'var(--text-muted)', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5, padding: '4px 10px',
            transition: 'border-color 100ms, color 100ms',
          }}>↻ re-analyse same</button>
      </div>
    </div>
  )
}
