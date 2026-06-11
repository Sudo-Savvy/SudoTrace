import { useMemo, useState } from 'react'

interface Props {
  initialStart?: string  // ISO UTC, optional
  initialEnd?: string    // ISO UTC, optional — ignored when mode='single'
  onApply: (startIso: string, endIso: string) => void
  onCancel: () => void
  // 'range' (default): pick a start and an end, both required.
  // 'single': pick one date+time. onApply emits (iso, iso) with both
  // args equal to the chosen value so call sites stay one shape.
  mode?: 'range' | 'single'
}

const MONTH_NAMES = ['January','February','March','April','May','June','July','August','September','October','November','December']
const WEEKDAYS    = ['Mo','Tu','We','Th','Fr','Sa','Su']

function isoToParts(iso: string | undefined): { date: Date | null; time: string } {
  if (!iso) return { date: null, time: '00:00' }
  const d = new Date(iso)
  if (isNaN(d.getTime())) return { date: null, time: '00:00' }
  const pad = (n: number) => String(n).padStart(2, '0')
  return {
    date: new Date(d.getFullYear(), d.getMonth(), d.getDate()),
    time: `${pad(d.getHours())}:${pad(d.getMinutes())}`,
  }
}

function combineDateAndTime(date: Date, time: string): Date {
  const [h, m] = time.split(':').map(n => parseInt(n, 10) || 0)
  return new Date(date.getFullYear(), date.getMonth(), date.getDate(), h, m, 0, 0)
}

// Time input with explicit ▲ / ▼ stepper buttons (1-minute step). The native
// <input type="time"> renders inconsistently across browsers — some hide the
// spinner buttons entirely — so we render our own next to the input.
function TimeInput({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  function step(deltaMinutes: number) {
    const [h, m] = value.split(':').map(n => parseInt(n, 10) || 0)
    // Wrap within 0..1439 minutes (a full day) so that 23:59 + 1 → 00:00.
    const total = ((h * 60 + m + deltaMinutes) % 1440 + 1440) % 1440
    const newH = Math.floor(total / 60)
    const newM = total % 60
    onChange(`${String(newH).padStart(2, '0')}:${String(newM).padStart(2, '0')}`)
  }

  const stepBtn: React.CSSProperties = {
    background: 'var(--bg-elevated)', border: '1px solid var(--border)',
    color: 'var(--text-muted)', cursor: 'pointer',
    fontFamily: 'var(--font-mono)', fontSize: 8,
    width: 18, height: 14,
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    padding: 0, lineHeight: 1,
    transition: 'border-color 100ms, color 100ms, background 100ms',
  }
  const hoverOn = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.currentTarget.style.borderColor = 'var(--accent)'
    e.currentTarget.style.color = 'var(--accent)'
  }
  const hoverOff = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.currentTarget.style.borderColor = 'var(--border)'
    e.currentTarget.style.color = 'var(--text-muted)'
  }

  return (
    <div style={{ display: 'flex', alignItems: 'stretch', gap: 4 }}>
      <input type="time" value={value}
        onChange={e => onChange(e.target.value)}
        style={{
          background: 'var(--bg-elevated)', border: '1px solid var(--border)',
          borderRadius: 3, color: 'var(--text)', fontFamily: 'var(--font-mono)',
          fontSize: 11, padding: '4px 6px', flex: 1, outline: 'none',
          colorScheme: 'dark',
        }} />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
        <button type="button" onClick={() => step(1)} title="+1 minute"
          onMouseEnter={hoverOn} onMouseLeave={hoverOff}
          style={{ ...stepBtn, borderTopLeftRadius: 3, borderTopRightRadius: 3 }}>▲</button>
        <button type="button" onClick={() => step(-1)} title="−1 minute"
          onMouseEnter={hoverOn} onMouseLeave={hoverOff}
          style={{ ...stepBtn, borderBottomLeftRadius: 3, borderBottomRightRadius: 3 }}>▼</button>
      </div>
    </div>
  )
}

// Day cell — defined at module scope so React doesn't redeclare on every render.
function DayCell({ d, selected, onClick }: {
  d: { date: Date; inMonth: boolean; isStart: boolean; isEnd: boolean; inRange: boolean }
  selected: boolean
  onClick: () => void
}) {
  let bg: string = 'transparent'
  let color: string = d.inMonth ? 'var(--text)' : 'var(--text-muted)'
  let fontWeight = 400
  if (d.isStart || d.isEnd) {
    bg = 'var(--accent)'
    color = '#fff'
    fontWeight = 700
  } else if (d.inRange) {
    bg = 'rgba(168,85,247,0.18)'
  }
  return (
    <div
      onClick={onClick}
      onMouseEnter={e => { if (!d.isStart && !d.isEnd && !d.inRange) e.currentTarget.style.background = 'var(--bg-elevated)' }}
      onMouseLeave={e => { if (!d.isStart && !d.isEnd && !d.inRange) e.currentTarget.style.background = 'transparent' }}
      style={{
        height: 26, display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: bg, color, fontWeight,
        cursor: 'pointer', borderRadius: 3,
        opacity: d.inMonth ? 1 : 0.35,
        transition: 'background 100ms',
        outline: selected ? '1px solid var(--accent)' : 'none',
      }}
    >
      {d.date.getDate()}
    </div>
  )
}

export default function RangePicker({ initialStart, initialEnd, onApply, onCancel, mode = 'range' }: Props) {
  const isSingle = mode === 'single'
  const initStart = isoToParts(initialStart)
  const initEnd   = isoToParts(initialEnd)

  const [startDate, setStartDate] = useState<Date | null>(initStart.date)
  const [endDate,   setEndDate]   = useState<Date | null>(initEnd.date)
  const [startTime, setStartTime] = useState(initStart.time)
  const [endTime,   setEndTime]   = useState(initEnd.time === '00:00' && !initialEnd ? '23:59' : initEnd.time)
  const [viewMonth, setViewMonth] = useState(() => {
    const ref = initStart.date ?? new Date()
    return new Date(ref.getFullYear(), ref.getMonth(), 1)
  })
  const [err, setErr] = useState<string | null>(null)

  // Build a 6-row × 7-col grid of dates covering the visible month, with
  // leading days from the previous month and trailing days from the next.
  const grid = useMemo(() => {
    const firstOfMonth = new Date(viewMonth.getFullYear(), viewMonth.getMonth(), 1)
    // ISO week: Monday=0. JS getDay: Sunday=0, Monday=1 — shift so Monday is 0.
    const leadingBlanks = (firstOfMonth.getDay() + 6) % 7
    const startDay = new Date(firstOfMonth)
    startDay.setDate(startDay.getDate() - leadingBlanks)

    const cells: { date: Date; inMonth: boolean; isStart: boolean; isEnd: boolean; inRange: boolean }[] = []
    for (let i = 0; i < 42; i++) {
      const d = new Date(startDay)
      d.setDate(startDay.getDate() + i)
      const inMonth = d.getMonth() === viewMonth.getMonth()
      const isStart = !!startDate && sameDay(d, startDate)
      const isEnd   = !!endDate   && sameDay(d, endDate)
      const inRange = !!startDate && !!endDate
        && d > startDate && d < endDate
      cells.push({ date: d, inMonth, isStart, isEnd, inRange })
    }
    return cells
  }, [viewMonth, startDate, endDate])

  function handleDayClick(d: Date) {
    setErr(null)
    if (isSingle) {
      setStartDate(d)
      return
    }
    // Re-pick: if both already set OR start is missing, this click starts a new range.
    if (!startDate || (startDate && endDate)) {
      setStartDate(d)
      setEndDate(null)
      return
    }
    // Start is set, end is not. Clicking earlier than start swaps them.
    if (d < startDate) {
      setEndDate(startDate)
      setStartDate(d)
    } else {
      setEndDate(d)
    }
  }

  function shiftMonth(delta: number) {
    setViewMonth(prev => new Date(prev.getFullYear(), prev.getMonth() + delta, 1))
  }

  function jumpToToday() {
    const now = new Date()
    setViewMonth(new Date(now.getFullYear(), now.getMonth(), 1))
  }

  function apply() {
    if (isSingle) {
      if (!startDate) {
        setErr('Pick a day on the calendar.')
        return
      }
      const ts = combineDateAndTime(startDate, startTime)
      const iso = ts.toISOString()
      onApply(iso, iso)
      return
    }
    if (!startDate || !endDate) {
      setErr('Pick a start and end day on the calendar.')
      return
    }
    const start = combineDateAndTime(startDate, startTime)
    const end   = combineDateAndTime(endDate,   endTime)
    if (start >= end) {
      setErr('Start must be before end (including times).')
      return
    }
    onApply(start.toISOString(), end.toISOString())
  }

  const arrowBtn: React.CSSProperties = {
    background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
    color: 'var(--text-muted)', cursor: 'pointer',
    fontFamily: 'var(--font-mono)', fontSize: 12, padding: '2px 8px',
    transition: 'border-color 100ms, color 100ms',
  }

  return (
    <div style={{
      background: 'var(--bg-panel)', border: '1px solid var(--border)',
      borderRadius: 6, padding: '14px 16px', width: 320,
      fontFamily: 'var(--font-mono)', fontSize: 11,
      boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
    }}>
      {/* Month header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
        <button onClick={() => shiftMonth(-1)} aria-label="Previous month" style={arrowBtn}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}>‹</button>
        <div
          onClick={jumpToToday}
          title="Jump to current month"
          style={{ color: 'var(--text)', fontWeight: 600, cursor: 'pointer', fontSize: 12 }}>
          {MONTH_NAMES[viewMonth.getMonth()]} {viewMonth.getFullYear()}
        </div>
        <button onClick={() => shiftMonth(1)} aria-label="Next month" style={arrowBtn}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}>›</button>
      </div>

      {/* Weekday row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 2, marginBottom: 4 }}>
        {WEEKDAYS.map(w => (
          <div key={w} style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: 9.5, padding: '4px 0' }}>{w}</div>
        ))}
      </div>

      {/* Calendar grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 2 }}>
        {grid.map((d, i) => (
          <DayCell key={i} d={d} selected={false} onClick={() => handleDayClick(d.date)} />
        ))}
      </div>

      {/* Time inputs — only `start time` is shown in single mode. */}
      <div style={{ display: 'flex', gap: 10, marginTop: 12, alignItems: 'flex-end' }}>
        <div style={{ flex: 1 }}>
          <div style={{ color: 'var(--text-muted)', fontSize: 9.5, marginBottom: 3 }}>
            {isSingle ? 'time' : 'start time'}
          </div>
          <TimeInput value={startTime} onChange={v => { setStartTime(v); setErr(null) }} />
        </div>
        {!isSingle && (
          <div style={{ flex: 1 }}>
            <div style={{ color: 'var(--text-muted)', fontSize: 9.5, marginBottom: 3 }}>end time</div>
            <TimeInput value={endTime} onChange={v => { setEndTime(v); setErr(null) }} />
          </div>
        )}
      </div>

      {/* Selection summary */}
      <div style={{ marginTop: 8, color: 'var(--text-muted)', fontSize: 10, minHeight: 16 }}>
        {isSingle ? (
          startDate ? (
            <><span style={{ color: 'var(--accent)' }}>{formatDay(startDate)} {startTime}</span> (local)</>
          ) : (
            <>Click a day on the calendar.</>
          )
        ) : startDate && endDate ? (
          <>
            <span style={{ color: 'var(--accent)' }}>{formatDay(startDate)} {startTime}</span>
            {' → '}
            <span style={{ color: 'var(--accent)' }}>{formatDay(endDate)} {endTime}</span>
            {' (local)'}
          </>
        ) : startDate ? (
          <>Pick an end day…</>
        ) : (
          <>Click a start day, then an end day.</>
        )}
      </div>

      {err && <div style={{ color: 'var(--red)', fontSize: 10, marginTop: 6 }}>{err}</div>}

      {/* Action buttons */}
      <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end', marginTop: 12 }}>
        <button onClick={onCancel}
          onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}
          style={{
            background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
            color: 'var(--text-muted)', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5, padding: '4px 12px',
            transition: 'border-color 100ms, color 100ms',
          }}>cancel</button>
        <button onClick={apply} style={{
          background: 'var(--accent)', border: 'none', borderRadius: 3,
          color: '#fff', cursor: 'pointer', fontFamily: 'var(--font-mono)',
          fontSize: 10.5, fontWeight: 600, padding: '4px 14px',
        }}>apply</button>
      </div>
    </div>
  )
}

function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear()
    && a.getMonth() === b.getMonth()
    && a.getDate() === b.getDate()
}

function formatDay(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`
}
