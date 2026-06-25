import { useState } from 'react'
import { BEC_CHECKLIST, TAG_META, type ChecklistItem } from '../utils/becChecklist'

// The always-available BEC runbook (doc §3). Works with no Graph connection.
// Local state for Milestone A; case-level persistence comes with the shared
// case model (later milestone). `checked` / `onToggle` are lifted so the
// parent can persist + drive the progress summary.

export default function BecChecklist({ checked, onToggle, notes, onNote }: {
  checked: Set<string>
  onToggle: (id: string) => void
  notes: Record<string, string>
  onNote: (id: string, text: string) => void
}) {
  const total = BEC_CHECKLIST.reduce((n, p) => n + p.items.length, 0)
  const done = BEC_CHECKLIST.reduce((n, p) => n + p.items.filter(i => checked.has(i.id)).length, 0)

  return (
    <div style={{ fontFamily: 'var(--font-mono)' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10,
      }}>
        <span style={{ color: 'var(--accent)', fontWeight: 700, fontSize: 12, letterSpacing: 0.4 }}>
          ▌ investigation checklist
        </span>
        <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>{done} / {total} complete</span>
        <div style={{ flex: 1, height: 4, background: 'var(--bg-card)', borderRadius: 2, overflow: 'hidden', maxWidth: 220 }}>
          <div style={{ width: `${total ? (done / total) * 100 : 0}%`, height: '100%', background: 'var(--accent)' }} />
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {BEC_CHECKLIST.map(phase => (
          <Phase
            key={phase.id}
            phase={phase}
            checked={checked}
            onToggle={onToggle}
            notes={notes}
            onNote={onNote}
          />
        ))}
      </div>
    </div>
  )
}

function Phase({ phase, checked, onToggle, notes, onNote }: {
  phase: typeof BEC_CHECKLIST[number]
  checked: Set<string>
  onToggle: (id: string) => void
  notes: Record<string, string>
  onNote: (id: string, text: string) => void
}) {
  const [open, setOpen] = useState(true)
  const done = phase.items.filter(i => checked.has(i.id)).length
  const allDone = done === phase.items.length
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 6, background: 'var(--bg-panel)' }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px',
          cursor: 'pointer', userSelect: 'none',
          borderBottom: open ? '1px solid var(--border-soft)' : 'none',
        }}>
        <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>{open ? '▾' : '▸'}</span>
        <span style={{ color: allDone ? '#7DD3A0' : 'var(--text)', fontSize: 12, fontWeight: 600 }}>
          {phase.title}
        </span>
        <span style={{ flex: 1 }} />
        <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>{done}/{phase.items.length}</span>
      </div>
      {open && (
        <div style={{ padding: '8px 12px 10px' }}>
          {phase.subtitle && (
            <div style={{ color: 'var(--text-muted)', fontSize: 10.5, lineHeight: 1.5, marginBottom: 8 }}>
              {phase.subtitle}
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
            {phase.items.map(item => (
              <Item
                key={item.id}
                item={item}
                checked={checked.has(item.id)}
                onToggle={() => onToggle(item.id)}
                note={notes[item.id] ?? ''}
                onNote={text => onNote(item.id, text)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function Item({ item, checked, onToggle, note, onNote }: {
  item: ChecklistItem
  checked: boolean
  onToggle: () => void
  note: string
  onNote: (text: string) => void
}) {
  const [noteOpen, setNoteOpen] = useState(!!note)
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
        <input
          type="checkbox"
          checked={checked}
          onChange={onToggle}
          style={{ cursor: 'pointer', marginTop: 2, flexShrink: 0 }}
        />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap',
          }}>
            <span style={{
              color: checked ? 'var(--text-muted)' : 'var(--text)',
              fontSize: 11.5, lineHeight: 1.45,
              textDecoration: checked ? 'line-through' : 'none',
            }}>{item.label}</span>
            {(item.tags ?? []).map(t => {
              const m = TAG_META[t]
              return (
                <span key={t} title={m.title} style={{
                  fontSize: 8, fontWeight: 700, letterSpacing: 0.3, padding: '1px 4px',
                  borderRadius: 2, color: m.color, border: `1px solid ${m.color}`,
                  background: `${m.color}1A`, whiteSpace: 'nowrap', flexShrink: 0,
                }}>{m.label}</span>
              )
            })}
          </div>
          {item.hint && (
            <div style={{ color: 'var(--text-muted)', fontSize: 9.5, lineHeight: 1.45, marginTop: 1 }}>
              {item.hint}
            </div>
          )}
        </div>
        <button
          onClick={() => setNoteOpen(o => !o)}
          title={note ? 'Edit note' : 'Add a note'}
          style={{
            background: 'transparent', border: '1px solid var(--border)', borderRadius: 2,
            color: note ? 'var(--accent)' : 'var(--text-muted)', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 9.5, padding: '1px 6px', flexShrink: 0,
          }}>
          {note ? '✎' : '+ note'}
        </button>
      </div>
      {noteOpen && (
        <textarea
          value={note}
          onChange={e => onNote(e.target.value)}
          placeholder="Analyst note for this item…"
          style={{
            marginLeft: 24, width: 'calc(100% - 24px)', minHeight: 36, resize: 'vertical',
            background: 'var(--bg-app)', color: '#fff', border: '1px solid var(--border)',
            borderRadius: 3, fontFamily: 'var(--font-mono)', fontSize: 10.5, lineHeight: 1.4,
            padding: '5px 7px', outline: 'none', boxSizing: 'border-box',
          }}
        />
      )}
    </div>
  )
}
