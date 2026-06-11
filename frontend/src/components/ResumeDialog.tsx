import type { PersistedSessionState } from '../utils/sessionState'

// Modal shown after login when a previous investigation was auto-saved.
// Two flavours depending on the snapshot contents:
//
//  - With an investigation: Resume re-anchors into the same host/pid +
//    restores notes / IOCs / hunt flags / overrides / AI history.
//
//  - Without an investigation (data-only — e.g. analyst hit "← new
//    investigation" from an error panel before closing the session):
//    Resume restores the analyst-authored state but the dialog tells
//    them they'll land on the welcome screen and need to start a fresh
//    investigation to use the restored items, so the button doesn't
//    pretend to navigate them somewhere it can't.

interface Props {
  snapshot:   PersistedSessionState
  onResume:   () => void
  onDiscard:  () => void
}

export default function ResumeDialog({ snapshot, onResume, onDiscard }: Props) {
  const inv = snapshot.investigation
  const counts: string[] = []
  if (snapshot.iocs.length)            counts.push(`${snapshot.iocs.length} IOC${snapshot.iocs.length === 1 ? '' : 's'}`)
  if (snapshot.huntFlags.length)       counts.push(`${snapshot.huntFlags.length} hunt flag${snapshot.huntFlags.length === 1 ? '' : 's'}`)
  if (snapshot.timelineNotes.length)   counts.push(`${snapshot.timelineNotes.length} note${snapshot.timelineNotes.length === 1 ? '' : 's'}`)
  const annCount = Object.keys(snapshot.eventAnnotations).length
  if (annCount)                        counts.push(`${annCount} annotation${annCount === 1 ? '' : 's'}`)
  const titleCount = Object.keys(snapshot.eventTitleOverrides).length
  const detailCount = Object.keys(snapshot.eventDetailOverrides).length
  const editCount = titleCount + detailCount
  if (editCount)                       counts.push(`${editCount} timeline edit${editCount === 1 ? '' : 's'}`)
  if (snapshot.hiddenTimelineIds.length) counts.push(`${snapshot.hiddenTimelineIds.length} hidden event${snapshot.hiddenTimelineIds.length === 1 ? '' : 's'}`)
  if (snapshot.analysisHistory.length) counts.push(`${snapshot.analysisHistory.length} AI analys${snapshot.analysisHistory.length === 1 ? 'is' : 'es'}`)

  const savedDate = (() => {
    if (!snapshot.savedAt) return ''
    const d = new Date(snapshot.savedAt)
    const pad = (n: number) => String(n).padStart(2, '0')
    return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`
  })()

  const title = inv ? 'Resume previous investigation?' : 'Restore saved data?'

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(0,0,0,0.55)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 24,
    }}>
      <div style={{
        background: 'var(--bg-panel)', border: '1px solid var(--border)',
        borderRadius: 6, padding: '24px 28px', maxWidth: 520,
        fontFamily: 'var(--font-mono)',
        boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
      }}>
        <div style={{
          color: 'var(--accent)', fontWeight: 700, fontSize: 13, letterSpacing: 0.4,
          textTransform: 'uppercase', marginBottom: 14,
        }}>
          ▌ {title}
        </div>
        {inv ? (
          <div style={{ color: 'var(--text)', fontSize: 12, lineHeight: 1.7, marginBottom: 14 }}>
            <div>host&nbsp; <span style={{ color: 'var(--accent)' }}>{inv.hostname || '(none)'}</span></div>
            {inv.pid && <div>pid&nbsp;&nbsp; <span style={{ color: 'var(--text)' }}>{inv.pid}</span></div>}
            {inv.alertId && <div>alert&nbsp;{inv.alertId}</div>}
            <div>window&nbsp;{inv.timeWindow}</div>
          </div>
        ) : (
          <div style={{
            color: 'var(--text)', fontSize: 12, lineHeight: 1.6, marginBottom: 14,
            padding: '10px 12px',
            background: 'rgba(240,179,64,0.08)',
            border: '1px solid rgba(240,179,64,0.30)',
            borderRadius: 3,
          }}>
            <div style={{ color: 'var(--amber)', fontWeight: 700, fontSize: 10.5, letterSpacing: 0.4, textTransform: 'uppercase', marginBottom: 4 }}>
              ⚠ Data only — no active investigation
            </div>
            The host / PID context wasn't saved (the previous session
            ended without an active investigation). Your IOCs, notes
            and timeline edits will be restored, but you'll land on the
            welcome screen and need to <strong>start a fresh investigation</strong> to
            use them.
          </div>
        )}
        {counts.length > 0 && (
          <div style={{ color: 'var(--text-muted)', fontSize: 11, marginBottom: 14 }}>
            {inv ? 'also restored' : 'will be restored'}: {counts.join(' · ')}
          </div>
        )}
        {savedDate && (
          <div style={{ color: 'var(--text-muted)', fontSize: 10.5, marginBottom: 18 }}>
            saved {savedDate}
          </div>
        )}
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button
            onClick={onDiscard}
            title={inv ? 'Drop the saved state and start a fresh investigation' : 'Discard the saved data and start fresh'}
            style={{
              background: 'transparent', color: 'var(--text-muted)',
              border: '1px solid var(--border)', borderRadius: 3, cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 11,
              padding: '6px 14px',
            }}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--red)'; e.currentTarget.style.borderColor = 'var(--red)' }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}>
            {inv ? 'start fresh' : 'discard'}
          </button>
          <button
            onClick={onResume}
            title={inv ? 'Re-open the previous investigation with all your saved state' : 'Restore your IOCs / notes / edits — you’ll then need to start an investigation'}
            style={{
              background: 'var(--accent)', color: '#fff',
              border: 'none', borderRadius: 3, cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
              padding: '6px 14px',
            }}>
            {inv ? 'resume' : 'restore data'}
          </button>
        </div>
      </div>
    </div>
  )
}
