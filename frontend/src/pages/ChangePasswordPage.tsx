import { useState } from 'react'
import type { FormEvent } from 'react'
import { changePassword } from '../api/auth'
import { friendlyError } from '../utils/errors'

interface Props {
  onChanged: () => void
}

export default function ChangePasswordPage({ onChanged }: Props) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')

    if (next.length < 8) {
      setError('Password must be at least 8 characters.')
      return
    }
    if (next !== confirm) {
      setError('Passwords do not match.')
      return
    }

    setLoading(true)
    try {
      await changePassword(current, next)
      onChanged()
    } catch (err) {
      setError(friendlyError(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={styles.root}>
      <div style={styles.card}>
        <div style={styles.logo}>
          <span style={styles.logoAccent}>sudo</span>
          <span style={styles.logoText}>trace</span>
        </div>

        <div style={styles.notice}>
          <strong>Default password must be changed</strong>
          <p style={styles.noticeText}>
            You are logged in with the default credentials. Set a strong password before continuing.
            This cannot be skipped.
          </p>
        </div>

        <form onSubmit={handleSubmit} style={styles.form}>
          <div style={styles.field}>
            <label style={styles.label} htmlFor="current">Current password</label>
            <input
              id="current"
              style={styles.input}
              type="password"
              autoComplete="current-password"
              autoFocus
              value={current}
              onChange={e => setCurrent(e.target.value)}
              disabled={loading}
              required
            />
          </div>

          <div style={styles.field}>
            <label style={styles.label} htmlFor="new-password">New password</label>
            <input
              id="new-password"
              style={styles.input}
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={e => setNext(e.target.value)}
              disabled={loading}
              required
            />
          </div>

          <div style={styles.field}>
            <label style={styles.label} htmlFor="confirm">Confirm new password</label>
            <input
              id="confirm"
              style={styles.input}
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
              disabled={loading}
              required
            />
          </div>

          {error && <p style={styles.error}>{error}</p>}

          <button
            style={{ ...styles.btn, ...(loading ? styles.btnDisabled : {}) }}
            type="submit"
            disabled={loading}
          >
            {loading ? 'Updating…' : 'Set new password'}
          </button>
        </form>
      </div>
    </div>
  )
}

const styles: Record<string, React.CSSProperties> = {
  root: {
    minHeight: '100vh',
    background: 'var(--bg-app)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '24px',
  },
  card: {
    background: 'var(--bg-panel)',
    border: '1px solid var(--border)',
    borderRadius: '12px',
    padding: '48px 40px',
    width: '100%',
    maxWidth: '420px',
    textAlign: 'center',
  },
  logo: {
    fontSize: '24px',
    fontWeight: 700,
    letterSpacing: '-0.5px',
    marginBottom: '20px',
  },
  logoAccent: { color: 'var(--accent)' },
  logoText: { color: 'var(--text)' },
  notice: {
    background: 'rgba(232, 99, 10, 0.08)',
    border: '1px solid rgba(232, 99, 10, 0.25)',
    borderRadius: '8px',
    color: 'var(--text)',
    fontSize: '13px',
    fontWeight: 600,
    marginBottom: '24px',
    padding: '14px 16px',
    textAlign: 'left',
  },
  noticeText: {
    color: 'var(--text-muted)',
    fontWeight: 400,
    marginTop: '4px',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
    textAlign: 'left',
  },
  field: {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
  },
  label: {
    color: 'var(--text-muted)',
    fontSize: '12px',
    fontWeight: 500,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
  },
  input: {
    background: 'var(--bg-card)',
    border: '1px solid var(--border)',
    borderRadius: '6px',
    color: 'var(--text)',
    fontSize: '14px',
    padding: '10px 12px',
    outline: 'none',
  },
  error: {
    background: 'rgba(229, 62, 62, 0.1)',
    border: '1px solid rgba(229, 62, 62, 0.3)',
    borderRadius: '6px',
    color: 'var(--red)',
    fontSize: '13px',
    padding: '10px 12px',
  },
  btn: {
    background: 'var(--accent)',
    border: 'none',
    borderRadius: '6px',
    color: '#fff',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: 600,
    marginTop: '4px',
    padding: '11px',
  },
  btnDisabled: {
    background: 'var(--accent-dim)',
    cursor: 'not-allowed',
  },
}
