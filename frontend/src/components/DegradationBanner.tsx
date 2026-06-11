import { useDegradedSources, clearDegraded, clearAllDegraded } from '../store/degradationStore'

// Non-blocking banner that lists which sub-fetches in the current
// investigation failed (or returned empty due to upstream error).
// Sits between the top app bar and the tab strip in HomePage. The
// investigation itself stays usable — this banner is purely
// information + a retry affordance for each failed source.

export default function DegradationBanner() {
  const sources = useDegradedSources()
  if (sources.length === 0) return null
  return (
    <div style={{
      borderTop:    '1px solid var(--amber)',
      borderBottom: '1px solid var(--amber)',
      background:   'rgba(240, 179, 64, 0.07)',
      padding:      '6px 16px',
      display:      'flex',
      flexDirection: 'column',
      gap:          4,
      fontFamily:   'var(--font-mono)',
      fontSize:     11,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{
          color: 'var(--amber)', fontWeight: 700, fontSize: 11.5,
          letterSpacing: 0.3, textTransform: 'uppercase',
        }}>
          ⚠ Partial data
        </span>
        <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>
          The investigation loaded with {sources.length} source{sources.length === 1 ? '' : 's'} unavailable.
          Other tabs still work normally.
        </span>
        <span style={{ flex: 1 }} />
        {sources.length > 1 && (
          <span
            onClick={() => clearAllDegraded()}
            title="Dismiss all degraded-source notices"
            style={{
              cursor: 'pointer', userSelect: 'none',
              color: 'var(--text-muted)', fontSize: 10.5,
              padding: '1px 6px', borderRadius: 2,
              border: '1px solid var(--border)',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--text)' }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)' }}>
            dismiss all
          </span>
        )}
      </div>
      {sources.map(s => (
        <div
          key={s.source}
          style={{
            display: 'flex', alignItems: 'center', gap: 10,
            paddingLeft: 16,
          }}>
          <span style={{ color: 'var(--amber)', fontWeight: 600 }}>{s.label}</span>
          <span style={{ color: 'var(--text)' }}>—</span>
          <span style={{ color: 'var(--text)' }}>{s.message}</span>
          <span style={{ flex: 1 }} />
          {s.retry && (
            <span
              onClick={() => s.retry?.()}
              title={`Re-fetch ${s.label}`}
              style={{
                cursor: 'pointer', userSelect: 'none',
                color: 'var(--accent)', fontSize: 10.5, fontWeight: 600,
                padding: '1px 8px', borderRadius: 2,
                border: '1px solid var(--accent)',
                background: 'rgba(168,85,247,0.10)',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(168,85,247,0.22)' }}
              onMouseLeave={e => { e.currentTarget.style.background = 'rgba(168,85,247,0.10)' }}>
              ↻ retry
            </span>
          )}
          <span
            onClick={() => clearDegraded(s.source)}
            title="Dismiss this notice"
            style={{
              cursor: 'pointer', userSelect: 'none',
              color: 'var(--text-muted)', fontSize: 12, lineHeight: 1,
              padding: '0 4px',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--red)' }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)' }}>
            ×
          </span>
        </div>
      ))}
    </div>
  )
}
