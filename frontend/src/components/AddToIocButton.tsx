import { useState, useEffect } from 'react'
import { addIoc, hasIoc, removeIoc } from '../store/iocStore'
import type { IocEntry } from '../store/iocStore'
import { getCachedVt, verdictFromVt } from '../utils/vtCache'

// Small "+ IOC" / "✓ IOC" toggle. Shared by the Hunt-tab cell IOCs
// and the Telemetry-tab command-line IOCs so the visual + the
// add/remove semantics stay consistent across surfaces.
//
// Adding seeds the new entry with any cached VirusTotal verdict the
// analyst has already pulled in this session (for hash / ip / domain
// IOCs), so toggling on after a VT lookup doesn't lose the result.

interface Props {
  ioc:      string
  iocType:  IocEntry['iocType']
  hashType?: IocEntry['hashType']
  // Compact variant trims the padding for tight inline contexts
  // (e.g. command-line cells in the Telemetry table where horizontal
  // space matters more than the chip looking generous).
  compact?: boolean
}

export function AddToIocButton({ ioc, iocType, hashType, compact }: Props) {
  const [added, setAdded] = useState(() => hasIoc(ioc))
  useEffect(() => { setAdded(hasIoc(ioc)) }, [ioc])

  function onClick(e: React.MouseEvent) {
    e.stopPropagation()
    if (added) {
      removeIoc(ioc)
      setAdded(false)
      return
    }
    const cached = (iocType === 'hash' || iocType === 'ip' || iocType === 'domain')
      ? getCachedVt(ioc)
      : null
    addIoc({
      ioc, iocType, hashType,
      verdict:    verdictFromVt(cached),
      name:       cached?.name ?? null,
      country:    cached?.country ?? null,
      as_owner:   cached?.as_owner ?? null,
      asn:        cached?.asn ?? null,
      total:      cached?.total,
      malicious:  cached?.found ? cached.malicious  : undefined,
      suspicious: cached?.found ? cached.suspicious : undefined,
      link:       cached?.found ? cached.link       : undefined,
      addedAt:    Date.now(),
    })
    setAdded(true)
  }

  return (
    <button
      type="button"
      onClick={onClick}
      title={added ? 'Remove from IOC list' : 'Add to IOC list'}
      style={{
        background: added ? 'rgba(125,211,160,0.12)' : 'rgba(94,129,172,0.12)',
        border: `1px solid ${added ? 'rgba(125,211,160,0.3)' : 'rgba(94,129,172,0.3)'}`,
        borderRadius: 3,
        color: added ? '#7DD3A0' : 'var(--accent)',
        cursor: 'pointer',
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        fontWeight: 700,
        letterSpacing: 0.3,
        lineHeight: 1.4,
        padding: compact ? '1px 5px' : '2px 7px',
        whiteSpace: 'nowrap',
        flexShrink: 0,
      }}>
      {added ? '✓ IOC' : '+ IOC'}
    </button>
  )
}
