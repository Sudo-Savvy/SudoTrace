import { useState, useEffect, useRef } from 'react'
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { getMe, logout } from './api/auth'
import type { User, Investigation } from './types'
import LoginPage from './pages/LoginPage'
import ChangePasswordPage from './pages/ChangePasswordPage'
import HomePage from './pages/HomePage'
import SettingsPage from './pages/SettingsPage'
import ResumeDialog from './components/ResumeDialog'
import { useIocList } from './store/iocStore'
import { useHuntFlags } from './store/huntFlagStore'
import {
  useInvFlaggedNodes, useTimelineNotes, useEventAnnotations, useHiddenTimelineIds,
} from './store/investigationStore'
import { useAnalysisHistory } from './store/analysisHistoryStore'
import {
  getSessionState, putSessionState, deleteSessionState,
} from './api/session'
import {
  captureSessionState, hasResumableContent, parseSnapshot, restoreSessionState,
  type PersistedSessionState,
} from './utils/sessionState'

// Debounce delay between the analyst's last change and an auto-save.
// Tight enough that crash recovery loses only seconds of work; long
// enough that rapid edits (e.g. typing a note, dragging a row) coalesce
// into one PUT. The periodic safety-net heartbeat below covers any
// store that doesn't trigger the subscription-based effect.
const AUTOSAVE_DEBOUNCE_MS = 3_000
const AUTOSAVE_HEARTBEAT_MS = 5 * 60_000

function AuthenticatedApp({ user, setUser }: { user: User; setUser: (u: User | null) => void }) {
  const navigate = useNavigate()
  const [investigation, setInvestigation] = useState<Investigation | null>(null)
  const [investigationData, setInvestigationData] = useState<import('./types').InvestigateResponse | null>(null)

  // Session-recovery state: pendingResume holds a saved snapshot until
  // the analyst either accepts (resume) or rejects (start fresh). Until
  // they choose, autosave stays gated off so we don't overwrite the
  // snapshot before they've seen the prompt.
  const [pendingResume, setPendingResume] = useState<PersistedSessionState | null>(null)
  const [resumeChecked, setResumeChecked] = useState(false)
  const autosaveGate = useRef(false)
  // Reactive subscriptions — having these hooks at this level means any
  // change to the analyst-authored stores re-renders AuthenticatedApp and
  // re-runs the autosave effect below. We don't actually use the values.
  useIocList()
  useHuntFlags()
  useInvFlaggedNodes()
  useTimelineNotes()
  useEventAnnotations()
  useHiddenTimelineIds()
  useAnalysisHistory()

  // On first mount: check for a saved session. If there's something
  // resumable, surface the dialog. Otherwise enable autosave straight
  // away.
  useEffect(() => {
    let cancelled = false
    getSessionState()
      .then(res => {
        if (cancelled) return
        const snap = parseSnapshot(res.state)
        if (snap && hasResumableContent(snap)) {
          setPendingResume(snap)
        } else {
          autosaveGate.current = true
        }
        setResumeChecked(true)
      })
      .catch(() => {
        // The GET failed, so we DON'T know what's saved on the server.
        // Deliberately leave autosave DISABLED for this session — enabling
        // it would let an empty live-store snapshot overwrite a saved
        // investigation we simply failed to fetch. The analyst can still
        // work and use manual save/load; their server-side state is
        // preserved and offered again on the next successful login.
        if (!cancelled) {
          setResumeChecked(true)
        }
      })
    return () => { cancelled = true }
  }, [])

  // Debounced autosave whenever the analyst-authored state changes.
  // Reads the live snapshot from the stores so the effect itself can
  // stay dependency-light.
  useEffect(() => {
    if (!autosaveGate.current) return
    const handle = setTimeout(() => {
      const snap = captureSessionState(investigation)
      putSessionState(snap).catch(() => { /* surfaced on next attempt */ })
    }, AUTOSAVE_DEBOUNCE_MS)
    return () => clearTimeout(handle)
  })

  // Periodic safety-net save — runs on a fixed cadence regardless of
  // the change-driven debounce so a long-idle session still has a
  // recent snapshot if the browser is killed.
  useEffect(() => {
    if (!resumeChecked) return
    const id = setInterval(() => {
      if (!autosaveGate.current) return
      const snap = captureSessionState(investigation)
      putSessionState(snap).catch(() => { /* ignore */ })
    }, AUTOSAVE_HEARTBEAT_MS)
    return () => clearInterval(id)
  }, [resumeChecked, investigation])

  const handleLogout = async () => {
    // Force a final save before logging out. Must AWAIT — once logout()
    // invalidates the session cookie, a concurrent PUT lands as 401 and
    // the analyst's most recent changes are dropped on the floor.
    if (autosaveGate.current) {
      const snap = captureSessionState(investigation)
      try {
        await putSessionState(snap)
      } catch { /* don't block logout on save failure */ }
    }
    try { await logout() } finally { setUser(null) }
  }

  // Page-close safety net: the 3s debounce + heartbeat won't fire if the
  // analyst closes the tab quickly. We can't use navigator.sendBeacon —
  // it only sends POST and our endpoint is PUT — but `fetch` with the
  // `keepalive` flag lets the request outlive the page (up to ~64 KB,
  // which we're well under). The request is fire-and-forget; once the
  // page is unloading there's nothing we could do with an error anyway.
  useEffect(() => {
    if (!resumeChecked) return
    const handler = () => {
      if (!autosaveGate.current) return
      const snap = captureSessionState(investigation)
      try {
        fetch('/api/session/state', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(snap),
          keepalive: true,
        }).catch(() => { /* ignore — page is going away */ })
      } catch { /* ignore */ }
    }
    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [resumeChecked, investigation])

  function handleInvestigationChange(inv: Investigation | null) {
    setInvestigation(inv)
    if (!inv) setInvestigationData(null)   // clear cache when starting fresh
  }

  function handleResumeAccept() {
    if (!pendingResume) return
    restoreSessionState(pendingResume)
    if (pendingResume.investigation) setInvestigation(pendingResume.investigation)
    setPendingResume(null)
    autosaveGate.current = true
  }

  function handleResumeDiscard() {
    setPendingResume(null)
    autosaveGate.current = true
    deleteSessionState().catch(() => { /* server-side cleanup is best-effort */ })
  }

  return (
    <>
      {pendingResume && (
        <ResumeDialog
          snapshot={pendingResume}
          onResume={handleResumeAccept}
          onDiscard={handleResumeDiscard}
        />
      )}
      <Routes>
        <Route path="/" element={
          <HomePage
            user={user}
            onLogout={handleLogout}
            investigation={investigation}
            onInvestigationChange={handleInvestigationChange}
            investigationData={investigationData}
            onInvestigationDataChange={setInvestigationData}
          />
        } />
        <Route path="/settings" element={
          <SettingsPage
            user={user}
            onLogout={handleLogout}
            onHome={() => navigate('/')}
          />
        } />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  )
}

export default function App() {
  // undefined = loading, null = not authenticated, User = authenticated
  const [user, setUser] = useState<User | null | undefined>(undefined)

  useEffect(() => {
    getMe().then(u => {
      if (u && !u.key_available) {
        logout().finally(() => setUser(null))
      } else {
        setUser(u)
      }
    })
  }, [])

  if (user === undefined) {
    return <div style={{ background: 'var(--bg-app)', height: '100vh' }} />
  }

  if (!user) {
    return (
      <Routes>
        <Route path="*" element={<LoginPage onLogin={setUser} />} />
      </Routes>
    )
  }

  if (user.must_change_password) {
    return (
      <Routes>
        <Route
          path="*"
          element={
            <ChangePasswordPage
              onChanged={() => setUser({ ...user, must_change_password: false })}
            />
          }
        />
      </Routes>
    )
  }

  return <AuthenticatedApp user={user} setUser={setUser} />
}
