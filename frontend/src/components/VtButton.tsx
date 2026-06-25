import { useState, useRef, useEffect, useLayoutEffect } from 'react'
import { createPortal } from 'react-dom'
import { vtLookup } from '../api/vt'
import type { VtResult } from '../api/vt'
import { addIoc, hasIoc, updateIoc } from '../store/iocStore'
import { isMicrosoftDomain, isMicrosoftIp, isInternalIp } from '../utils/microsoftIps'
import { friendlyError } from '../utils/errors'
import { getCachedVt, setCachedVt } from '../utils/vtCache'

interface Props {
  ioc: string
  // VtButton only renders for VT-supported IOC types (hash / ip /
  // domain). Registry and file-path IOCs come in via Claude suggestions
  // and live in the same store but skip VT entirely.
  iocType: 'hash' | 'ip' | 'domain'
  // Optional hash subtype, captured from the source column when the
  // IOC was discovered (e.g. an `InitiatingProcessSHA1` cell yields
  // 'sha1'). Stored on the IOC entry so the "hunt for this IOC" pivot
  // can query the right KQL field without re-deriving from length.
  hashType?: 'sha1' | 'sha256' | 'md5'
  // Pure-lookup mode (e.g. the BEC module, which has no IOC-list panel):
  // show the VirusTotal verdict + ISP/location only, no "add to IOC list".
  lookupOnly?: boolean
}

const VERDICT_COLOR = {
  malicious:  '#FF5E5B',
  suspicious: '#F0B340',
  clean:      '#7DD3A0',
}

function getVerdict(r: VtResult): 'malicious' | 'suspicious' | 'clean' {
  if ((r.malicious ?? 0) > 0) return 'malicious'
  if ((r.suspicious ?? 0) > 0) return 'suspicious'
  return 'clean'
}

export function VtButton({ ioc, iocType, hashType, lookupOnly }: Props) {
  const isMsIp = (iocType === 'ip' && isMicrosoftIp(ioc)) ||
                 (iocType === 'domain' && isMicrosoftDomain(ioc))
  // Private RFC1918 / loopback / link-local IPs — never worth a VT lookup,
  // but still flag them so the analyst can add to the IOC list for
  // lateral-movement / east-west evidence.
  const isInternal = iocType === 'ip' && !isMsIp && isInternalIp(ioc)

  const [loading, setLoading] = useState(false)
  const [result, setResult]   = useState<VtResult | null>(() => getCachedVt(ioc))
  const [error, setError]     = useState<string | null>(null)
  const [open, setOpen]       = useState(false)
  const [added, setAdded]     = useState(() => hasIoc(ioc))
  const [anchor, setAnchor]   = useState({ bottom: 0, top: 0, left: 0, right: 0 })
  const [visible, setVisible] = useState(false)
  const btnRef                = useRef<HTMLButtonElement>(null)
  const popoverRef            = useRef<HTMLDivElement>(null)

  // Reset when the IOC value changes (different process, different hash/IP)
  useEffect(() => {
    setResult(getCachedVt(ioc))
    setError(null)
    setOpen(false)
    setAdded(hasIoc(ioc))
  }, [ioc])

  const verd     = result?.found ? getVerdict(result) : null
  const btnBg    = verd ? `${VERDICT_COLOR[verd]}22` : 'rgba(94,129,172,0.12)'
  const btnBorder= verd ? `${VERDICT_COLOR[verd]}55` : 'rgba(94,129,172,0.3)'
  const btnColor = verd ? VERDICT_COLOR[verd] : 'var(--accent)'

  if (isInternal) {
    return (
      <>
        <button
          ref={btnRef}
          onClick={() => { captureAnchor(); setVisible(false); setOpen(o => !o) }}
          title="Internal/private IP range — click to add to IOC list"
          style={{
            background: added ? 'rgba(125,211,160,0.12)' : 'rgba(240,179,64,0.10)',
            border: `1px solid ${added ? 'rgba(125,211,160,0.3)' : 'rgba(240,179,64,0.30)'}`,
            borderRadius: 3,
            color: added ? '#7DD3A0' : '#F0B340',
            cursor: 'pointer',
            fontFamily: 'var(--font-mono)',
            fontSize: 10,
            fontWeight: 600,
            letterSpacing: 0.3,
            lineHeight: 1.4,
            padding: '2px 7px',
            flexShrink: 0,
            whiteSpace: 'nowrap',
          }}>
          {added ? '✓ Internal' : 'Internal'}
        </button>

        {open && createPortal(
          <div
            ref={popoverRef}
            style={{
              position: 'fixed', top: anchor.bottom + 6, left: anchor.left,
              visibility: visible ? 'visible' : 'hidden',
              zIndex: 9999,
              background: 'var(--bg-panel)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '12px 14px', width: 240,
              fontFamily: 'var(--font-mono)', fontSize: 11,
              boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
            }}>
            <div style={{ color: '#F0B340', fontSize: 10, marginBottom: 10 }}>
              Internal/private IP range — VT lookup skipped.
            </div>
            {!lookupOnly && (
            <button onClick={() => {
              if (added) return
              addIoc({ ioc, iocType, hashType, verdict: 'unknown', addedAt: Date.now() })
              setAdded(true)
            }} disabled={added}
              style={{
                background: added ? 'rgba(125,211,160,0.12)' : 'rgba(94,129,172,0.12)',
                border: `1px solid ${added ? 'rgba(125,211,160,0.3)' : 'rgba(94,129,172,0.3)'}`,
                borderRadius: 3, cursor: added ? 'default' : 'pointer',
                color: added ? '#7DD3A0' : 'var(--accent)',
                fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                padding: '4px 10px', width: '100%',
              }}>
              {added ? '✓ Added to IOC list' : '+ Add to IOC list'}
            </button>
            )}
          </div>,
          document.body
        )}
      </>
    )
  }

  if (isMsIp) {
    return (
      <>
        <button
          ref={btnRef}
          onClick={() => { captureAnchor(); setVisible(false); setOpen(o => !o) }}
          title="Known Microsoft IP/domain — click to add to IOC list"
          style={{
            background: added ? 'rgba(125,211,160,0.12)' : 'rgba(0,120,212,0.10)',
            border: `1px solid ${added ? 'rgba(125,211,160,0.3)' : 'rgba(0,120,212,0.22)'}`,
            borderRadius: 3,
            color: added ? '#7DD3A0' : '#4aa3e8',
            cursor: 'pointer',
            fontFamily: 'var(--font-mono)',
            fontSize: 10,
            fontWeight: 600,
            letterSpacing: 0.3,
            lineHeight: 1.4,
            padding: '2px 7px',
            flexShrink: 0,
            whiteSpace: 'nowrap',
          }}>
          {added ? '✓ Microsoft' : 'Microsoft'}
        </button>

        {open && createPortal(
          <div
            ref={popoverRef}
            style={{
              position: 'fixed', top: anchor.bottom + 6, left: anchor.left,
              visibility: visible ? 'visible' : 'hidden',
              zIndex: 9999,
              background: 'var(--bg-panel)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '12px 14px', width: 240,
              fontFamily: 'var(--font-mono)', fontSize: 11,
              boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
            }}>
            <div style={{ color: '#4aa3e8', fontSize: 10, marginBottom: 10 }}>
              Known Microsoft IP range — VT lookup skipped.
            </div>
            {!lookupOnly && (
            <button onClick={() => {
              if (added) return
              addIoc({ ioc, iocType, hashType, verdict: 'unknown', addedAt: Date.now() })
              setAdded(true)
            }} disabled={added}
              style={{
                background: added ? 'rgba(125,211,160,0.12)' : 'rgba(94,129,172,0.12)',
                border: `1px solid ${added ? 'rgba(125,211,160,0.3)' : 'rgba(94,129,172,0.3)'}`,
                borderRadius: 3, cursor: added ? 'default' : 'pointer',
                color: added ? '#7DD3A0' : 'var(--accent)',
                fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                padding: '4px 10px', width: '100%',
              }}>
              {added ? '✓ Added to IOC list' : '+ Add to IOC list'}
            </button>
            )}
          </div>,
          document.body
        )}
      </>
    )
  }

  function captureAnchor() {
    if (!btnRef.current) return
    setAnchor(btnRef.current.getBoundingClientRect())
  }

  async function handleClick(e: React.MouseEvent) {
    e.stopPropagation()
    if (result || error) {
      captureAnchor()
      setVisible(false)
      setOpen(o => !o)
      return
    }
    setLoading(true)
    try {
      const res = await vtLookup(ioc, iocType)
      setCachedVt(ioc, res)
      setResult(res)
      // If this IOC is already in the analyst's list (added earlier as
      // 'unknown' via the + IOC shortcut), push the fresh VT verdict
      // and metadata into the store so the IOCs tab shows the verdict
      // without forcing a second lookup. No-op if not in the list.
      const verdict = res.found ? getVerdict(res) : 'unknown'
      updateIoc(ioc, {
        verdict,
        name:       res.found ? res.name       : undefined,
        country:    res.found ? res.country    : undefined,
        as_owner:   res.found ? res.as_owner   : undefined,
        asn:        res.found ? res.asn        : undefined,
        total:      res.found ? res.total      : undefined,
        malicious:  res.found ? res.malicious  : undefined,
        suspicious: res.found ? res.suspicious : undefined,
        link:       res.found ? res.link       : undefined,
      })
    } catch (err) {
      setError(friendlyError(err))
    } finally {
      setLoading(false)
      captureAnchor()
      setVisible(false)
      setOpen(true)
    }
  }

  // After the popover mounts, measure it and pick a position that stays inside the viewport
  useLayoutEffect(() => {
    if (!open || !popoverRef.current) return
    const pop = popoverRef.current.getBoundingClientRect()
    const vw  = window.innerWidth
    const vh  = window.innerHeight
    const GAP = 6
    const PAD = 8

    // Prefer below, fall back to above
    let top = anchor.bottom + GAP
    if (top + pop.height > vh - PAD) {
      top = Math.max(PAD, anchor.top - pop.height - GAP)
    }

    // Prefer left-aligned to button, shift left if it clips the right edge
    let left = anchor.left
    if (left + pop.width > vw - PAD) {
      left = Math.max(PAD, vw - pop.width - PAD)
    }

    popoverRef.current.style.top  = `${top}px`
    popoverRef.current.style.left = `${left}px`
    setVisible(true)
  }, [open, anchor])

  function handleAddIoc() {
    if (added) return
    const verdict = result?.found ? getVerdict(result) : 'unknown'
    addIoc({
      ioc,
      iocType,
      hashType,
      verdict,
      name:       result?.found ? result.name      : undefined,
      country:    result?.found ? result.country   : undefined,
      as_owner:   result?.found ? result.as_owner  : undefined,
      asn:        result?.found ? result.asn       : undefined,
      total:      result?.found ? result.total     : undefined,
      malicious:  result?.found ? result.malicious : undefined,
      suspicious: result?.found ? result.suspicious: undefined,
      link:       result?.found ? result.link      : undefined,
      addedAt:    Date.now(),
    })
    setAdded(true)
  }

  useEffect(() => {
    if (!open) return
    function onMouseDown(e: MouseEvent) {
      const t = e.target as Node
      if (btnRef.current?.contains(t) || popoverRef.current?.contains(t)) return
      setOpen(false)
    }
    document.addEventListener('mousedown', onMouseDown)
    return () => document.removeEventListener('mousedown', onMouseDown)
  }, [open])

  return (
    <>
      <button
        ref={btnRef}
        onClick={handleClick}
        title="IOC lookup via VirusTotal"
        style={{
          background:   btnBg,
          border:       `1px solid ${btnBorder}`,
          borderRadius: 3,
          color:        btnColor,
          cursor:       'pointer',
          fontFamily:   'var(--font-mono)',
          fontSize:     10,
          fontWeight:   700,
          letterSpacing: 0.3,
          lineHeight:   1.4,
          padding:      '2px 7px',
          flexShrink:   0,
          whiteSpace:   'nowrap',
        }}>
        {loading ? '…' : 'IOC lookup'}
      </button>

      {open && createPortal(
        <div
          ref={popoverRef}
          style={{
            position:   'fixed',
            top:        anchor.bottom + 6,   // overwritten by layoutEffect
            left:       anchor.left,         // overwritten by layoutEffect
            visibility: visible ? 'visible' : 'hidden',
            zIndex:     9999,
            background: 'var(--bg-panel)',
            border:     '1px solid var(--border)',
            borderRadius: 6,
            padding:    '12px 14px',
            width:      280,
            fontFamily: 'var(--font-mono)',
            fontSize:   11,
            boxShadow:  '0 4px 24px rgba(0,0,0,0.5)',
          }}>

          {error && (
            <div style={{ color: 'var(--red)' }}>✗ {error}</div>
          )}

          {result && !result.found && (
            <div style={{ marginBottom: 10, color: 'var(--text-muted)' }}>Not found in VirusTotal.</div>
          )}

          {/* Add to IOC list — shown whenever we have a result (found or not),
              unless this is a pure-lookup placement (e.g. the BEC module). */}
          {!lookupOnly && (result || error) && (
            <div style={{ marginTop: result?.found ? 10 : 0, paddingTop: result?.found ? 10 : 0, borderTop: result?.found ? '1px solid var(--border-soft)' : 'none' }}>
              <button onClick={handleAddIoc} disabled={added}
                style={{
                  background: added ? 'rgba(125,211,160,0.12)' : 'rgba(94,129,172,0.12)',
                  border: `1px solid ${added ? 'rgba(125,211,160,0.3)' : 'rgba(94,129,172,0.3)'}`,
                  borderRadius: 3, cursor: added ? 'default' : 'pointer',
                  color: added ? '#7DD3A0' : 'var(--accent)',
                  fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
                  padding: '4px 10px', width: '100%',
                }}>
                {added ? '✓ Added to IOC list' : '+ Add to IOC list'}
              </button>
            </div>
          )}

          {result?.found && (() => {
            const v    = getVerdict(result)
            const c    = VERDICT_COLOR[v]
            const hits = (result.malicious ?? 0) + (result.suspicious ?? 0)
            return (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                  <span style={{
                    fontSize: 9, padding: '2px 7px', borderRadius: 2, fontWeight: 700,
                    background: `${c}22`, color: c, letterSpacing: 0.5,
                  }}>{v.toUpperCase()}</span>
                  <span style={{ color: 'var(--text)', fontWeight: 600, fontSize: 13 }}>
                    {hits} / {result.total}
                  </span>
                  <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>detections</span>
                </div>

                {result.name && (
                  <div style={{ color: 'var(--text-muted)', marginBottom: 6, fontSize: 10 }}>
                    {result.name}
                  </div>
                )}

                {result.country != null && (
                  <div style={{ color: 'var(--text-muted)', marginBottom: 6, fontSize: 10 }}>
                    {result.country}
                    {result.as_owner ? ` · ${result.as_owner}` : ''}
                    {result.asn ? ` · AS${result.asn}` : ''}
                  </div>
                )}

                {result.vendors && result.vendors.length > 0 && (
                  <div style={{ marginBottom: 8 }}>
                    {result.vendors.map((vd, i) => (
                      <div key={i} style={{ color: '#FF5E5B', fontSize: 10, lineHeight: 1.6 }}>{vd}</div>
                    ))}
                  </div>
                )}

                {result.link && (
                  <a href={result.link} target="_blank" rel="noopener noreferrer"
                    style={{ color: 'var(--accent)', fontSize: 10, textDecoration: 'none' }}>
                    View full report ↗
                  </a>
                )}
              </>
            )
          })()}
        </div>,
        document.body
      )}
    </>
  )
}
