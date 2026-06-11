import { useState } from 'react'
import type { FormEvent } from 'react'
import { login } from '../api/auth'
import type { User } from '../types'
import { friendlyError } from '../utils/errors'

interface Props {
  onLogin: (user: User) => void
}

export default function LoginPage({ onLogin }: Props) {
  const [username, setUsername] = useState('root')
  const [password, setPassword] = useState('root')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const result = await login(username, password)
      onLogin({ username, must_change_password: result.must_change_password, key_available: true })
    } catch (err) {
      setError(friendlyError(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={styles.root}>
      <div style={styles.card}>
        <div role="img" aria-label="SudoTrace" style={styles.logoImg} />
        <p style={styles.tagline}>SOC analyst workbench for Defender</p>

        <form onSubmit={handleSubmit} style={styles.form}>
          <div style={styles.field}>
            <label style={styles.label} htmlFor="username">Username</label>
            <input
              id="username"
              style={styles.input}
              type="text"
              autoComplete="username"
              autoFocus
              value={username}
              onChange={e => setUsername(e.target.value)}
              disabled={loading}
              required
            />
          </div>

          <div style={styles.field}>
            <label style={styles.label} htmlFor="password">Password</label>
            <input
              id="password"
              style={styles.input}
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              disabled={loading}
              required
            />
          </div>

          {error && <p style={styles.error}>{error}</p>}

          <button style={{ ...styles.btn, ...(loading ? styles.btnDisabled : {}) }} type="submit" disabled={loading}>
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  )
}

const styles: Record<string, React.CSSProperties> = {
  root: {
    minHeight: '100vh',
    backgroundColor: 'var(--bg-app)',
    backgroundImage: 'linear-gradient(rgba(8,8,12,0.62), rgba(8,8,12,0.62)), url(/tree-bg.png)',
    backgroundSize: 'cover',
    backgroundPosition: 'center',
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
    maxWidth: '400px',
    textAlign: 'center',
  },
  logoImg: {
    // Source image is 6912x2688 with the SUDO/TRACE text occupying only
    // the center ~30%. We zoom the background image 2x and centre it so
    // the dark-blue / purple gradient edges are clipped and the text
    // fills the rendered box.
    display: 'block',
    width: '100%',
    maxWidth: '320px',
    aspectRatio: '5 / 2',
    margin: '0 auto 6px',
    backgroundImage: 'url(/sudotrace-logo.png)',
    backgroundSize: '165% auto',
    backgroundPosition: 'center center',
    backgroundRepeat: 'no-repeat',
    borderRadius: '6px',
    // Gentle alpha mask on the rim so the rectangle softens at the
    // very edge. Lighter than the AppBar horizontal logo because the
    // stacked logo here is larger and a wider fade band makes the
    // text inside feel cut off.
    WebkitMaskImage:
      'linear-gradient(to right, transparent 0%, #000 2%, #000 98%, transparent 100%), ' +
      'linear-gradient(to bottom, transparent 0%, #000 3%, #000 97%, transparent 100%)',
    WebkitMaskComposite: 'source-in',
    maskImage:
      'linear-gradient(to right, transparent 0%, #000 2%, #000 98%, transparent 100%), ' +
      'linear-gradient(to bottom, transparent 0%, #000 3%, #000 97%, transparent 100%)',
    maskComposite: 'intersect',
  },
  tagline: {
    color: 'var(--text-muted)',
    fontSize: '13px',
    marginBottom: '32px',
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
    transition: 'border-color 0.15s',
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
    transition: 'background 0.15s',
  },
  btnDisabled: {
    background: 'var(--accent-dim)',
    cursor: 'not-allowed',
  },
}
