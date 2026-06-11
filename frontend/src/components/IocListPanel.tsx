import { useState } from 'react'
import { useIocList, addIoc, hasIoc, removeIoc, updateIoc } from '../store/iocStore'
import type { IocEntry } from '../store/iocStore'
import { vtLookup } from '../api/vt'
import { buildIocHuntRequest } from '../utils/iocHunt'
import type { HuntJumpRequest } from './HuntTab'

const VERDICT_COLOR: Record<string, string> = {
  malicious:  '#FF5E5B',
  suspicious: '#F0B340',
  clean:      '#7DD3A0',
  unknown:    '#888',
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {})
}

function getVerdict(malicious: number, suspicious: number): IocEntry['verdict'] {
  if (malicious > 0) return 'malicious'
  if (suspicious > 0) return 'suspicious'
  return 'clean'
}

function IocRow({ entry, onHunt, onEdit }: {
  entry: IocEntry
  onHunt?: (req: HuntJumpRequest) => void
  onEdit?: () => void
}) {
  const [looking, setLooking] = useState(false)
  const huntReq = onHunt ? buildIocHuntRequest(entry) : null
  const c = VERDICT_COLOR[entry.verdict] ?? '#888'
  const hits = (entry.malicious ?? 0) + (entry.suspicious ?? 0)
  const label = entry.name || entry.country
    ? (entry.name || [entry.country, entry.as_owner].filter(Boolean).join(' · '))
    : null
  // VirusTotal only indexes hashes, IPs and domains. Registry and file
  // paths aren't searchable there, so we hide the VT lookup button for
  // those IOC types.
  const vtLookupSupported = entry.iocType === 'hash' || entry.iocType === 'ip' || entry.iocType === 'domain'

  async function handleLookup() {
    setLooking(true)
    try {
      if (entry.iocType !== 'hash' && entry.iocType !== 'ip' && entry.iocType !== 'domain') return
      const res = await vtLookup(entry.ioc, entry.iocType)
      const verdict = res.found
        ? getVerdict(res.malicious ?? 0, res.suspicious ?? 0)
        : 'unknown'
      updateIoc(entry.ioc, {
        verdict,
        malicious:  res.malicious,
        suspicious: res.suspicious,
        total:      res.total,
        name:       res.name ?? undefined,
        country:    res.country ?? undefined,
        as_owner:   res.as_owner ?? undefined,
        asn:        res.asn ?? undefined,
        link:       res.link,
      })
    } catch (_) {}
    finally { setLooking(false) }
  }

  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: 8,
      padding: '8px 12px',
      borderBottom: '1px solid var(--border-soft)',
    }}>
      {/* Verdict badge */}
      <span style={{
        fontSize: 8, padding: '2px 5px', borderRadius: 2, fontWeight: 700,
        background: `${c}22`, color: c, letterSpacing: 0.5,
        flexShrink: 0, marginTop: 1,
      }}>{entry.verdict.toUpperCase()}</span>

      {/* IOC value + meta */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)',
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }} title={entry.ioc}>
          {entry.ioc}
        </div>
        <div style={{ display: 'flex', gap: 8, marginTop: 2, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            {entry.iocType === 'hash' && entry.hashType
              ? entry.hashType
              : entry.iocType === 'registry' ? 'registry'
              : entry.iocType === 'file_path' ? 'file path'
              : entry.iocType === 'cmdline' ? 'cmdline'
              : entry.iocType}
          </span>
          {entry.verdict !== 'unknown' && entry.total != null && (
            <span style={{ fontSize: 9, color: c, fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
              {hits}/{entry.total}
            </span>
          )}
          {label && (
            <span style={{
              fontSize: 9, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180,
            }} title={label}>{label}</span>
          )}
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 6, flexShrink: 0, alignItems: 'center' }}>
        {huntReq && onHunt && (
          <button
            onClick={() => onHunt(huntReq)}
            title={`Pivot to Hunt — where this ${entry.iocType} is seen in the environment (last 7 days)`}
            style={{
              background: 'rgba(168,85,247,0.10)', border: '1px solid var(--accent)',
              borderRadius: 4, color: 'var(--accent)', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
              padding: '5px 10px', lineHeight: 1,
              transition: 'background 100ms',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(168,85,247,0.22)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'rgba(168,85,247,0.10)' }}>
            hunt ↗
          </button>
        )}
        {vtLookupSupported && !entry.link && (
          <button onClick={handleLookup} disabled={looking}
            title="Run VirusTotal lookup"
            style={{
              background: 'rgba(94,129,172,0.12)', border: '1px solid rgba(94,129,172,0.25)',
              borderRadius: 4, color: 'var(--accent)', cursor: looking ? 'default' : 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
              padding: '5px 10px', lineHeight: 1,
            }}>{looking ? '…' : 'VT lookup'}</button>
        )}
        {entry.link && (
          <a href={entry.link} target="_blank" rel="noopener noreferrer" title="View in VirusTotal"
            style={{
              background: 'rgba(94,129,172,0.12)', border: '1px solid rgba(94,129,172,0.25)',
              borderRadius: 4, color: 'var(--accent)', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
              padding: '5px 10px', textDecoration: 'none', lineHeight: 1,
              display: 'inline-block',
            }}>VT ↗</a>
        )}
        {onEdit && (
          <button onClick={onEdit} title="Edit this IOC"
            style={{
              background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)',
              borderRadius: 4, color: 'var(--text-muted)', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
              padding: '5px 10px', lineHeight: 1,
            }}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.borderColor = 'var(--accent)' }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}>
            ✎ edit
          </button>
        )}
        <button onClick={() => copyToClipboard(entry.ioc)} title="Copy IOC"
          style={{
            background: 'rgba(255,255,255,0.04)', border: '1px solid var(--border)',
            borderRadius: 4, color: 'var(--text-muted)', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
            padding: '5px 10px', lineHeight: 1,
          }}>copy</button>
        <button onClick={() => removeIoc(entry.ioc)} title="Remove from list"
          style={{
            background: 'rgba(255,94,91,0.08)', border: '1px solid rgba(255,94,91,0.25)',
            borderRadius: 4, color: '#FF5E5B', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700,
            padding: '4px 10px', lineHeight: 1,
          }}>×</button>
      </div>
    </div>
  )
}

function copyAllIocs(entries: IocEntry[]) {
  copyToClipboard(entries.map(e => e.ioc).join('\n'))
}

// Heuristic type detection from a raw IOC string. Lets the manual-add
// form pre-pick a sensible type so the analyst usually only has to
// confirm. They can always override via the type dropdown.
function detectIocShape(raw: string): { iocType: IocEntry['iocType']; hashType?: IocEntry['hashType'] } {
  const v = raw.trim()
  if (/^[0-9a-fA-F]{64}$/.test(v)) return { iocType: 'hash', hashType: 'sha256' }
  if (/^[0-9a-fA-F]{40}$/.test(v)) return { iocType: 'hash', hashType: 'sha1' }
  if (/^[0-9a-fA-F]{32}$/.test(v)) return { iocType: 'hash', hashType: 'md5' }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return { iocType: 'ip' }
  if (/^[0-9a-f:]+$/i.test(v) && v.includes(':')) return { iocType: 'ip' }
  if (/^(HKEY_|HKLM|HKCU|HKU|HKCR|HKCC)/i.test(v)) return { iocType: 'registry' }
  if (/^[a-zA-Z]:[\\/]/.test(v) || v.startsWith('\\\\') || v.startsWith('/'))
    return { iocType: 'file_path' }
  if (/^[a-z0-9][a-z0-9\-\.]*\.[a-z]{2,}$/i.test(v)) return { iocType: 'domain' }
  return { iocType: 'hash' }
}

const TYPE_OPTIONS: { value: IocEntry['iocType']; label: string }[] = [
  { value: 'hash',      label: 'hash (SHA1/256, MD5)' },
  { value: 'ip',        label: 'ip address' },
  { value: 'domain',    label: 'domain' },
  { value: 'registry',  label: 'registry key / value' },
  { value: 'file_path', label: 'file path' },
  { value: 'cmdline',   label: 'command line' },
]

const VERDICT_OPTIONS: { value: IocEntry['verdict']; label: string }[] = [
  { value: 'unknown',    label: 'unknown' },
  { value: 'clean',      label: 'clean'   },
  { value: 'suspicious', label: 'suspicious' },
  { value: 'malicious',  label: 'malicious'  },
]

function IocEditForm({ entry, onClose }: { entry: IocEntry; onClose: () => void }) {
  const [value, setValue]       = useState(entry.ioc)
  const [iocType, setIocType]   = useState<IocEntry['iocType']>(entry.iocType)
  const [hashType, setHashType] = useState<IocEntry['hashType']>(entry.hashType ?? 'sha256')
  const [verdict, setVerdict]   = useState<IocEntry['verdict']>(entry.verdict)
  const [error, setError]       = useState<string | null>(null)

  function commit() {
    const v = value.trim()
    if (!v) { setError('IOC value cannot be empty.'); return }
    // If the value changed, it's now keyed differently — remove the old
    // entry and re-add. Otherwise patch in place. updateIoc preserves
    // any VT enrichment (name, country, asn, link) we already fetched
    // since it does a shallow merge.
    const updates: Partial<IocEntry> = {
      iocType,
      verdict,
      hashType: iocType === 'hash' ? hashType : undefined,
    }
    if (v !== entry.ioc) {
      if (hasIoc(v)) { setError('Another IOC already has that value.'); return }
      // Preserve VT enrichment by carrying the full entry over, then
      // overriding the changed fields.
      removeIoc(entry.ioc)
      addIoc({
        ...entry,
        ...updates,
        ioc: v,
        addedAt: entry.addedAt,
      })
    } else {
      updateIoc(entry.ioc, updates)
    }
    onClose()
  }

  return (
    <div style={{
      padding: '10px 12px',
      borderBottom: '1px solid var(--border-soft)',
      background: 'rgba(168,85,247,0.07)',
      display: 'flex', flexDirection: 'column', gap: 8,
      fontFamily: 'var(--font-mono)',
    }}>
      <input
        autoFocus
        value={value}
        onChange={e => { setValue(e.target.value); setError(null) }}
        onKeyDown={e => {
          if (e.key === 'Enter') { e.preventDefault(); commit() }
          else if (e.key === 'Escape') { e.preventDefault(); onClose() }
        }}
        placeholder="IOC value"
        style={{
          width: '100%',
          background: 'var(--bg-app)', color: '#fff',
          border: '1px solid var(--accent)', borderRadius: 3,
          fontFamily: 'var(--font-mono)', fontSize: 11.5, lineHeight: 1.45,
          padding: '6px 8px', outline: 'none', boxSizing: 'border-box',
        }}
      />
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>type</span>
        <select
          value={iocType}
          onChange={e => setIocType(e.target.value as IocEntry['iocType'])}
          style={{
            background: 'var(--bg-card)', color: 'var(--text)',
            border: '1px solid var(--border)', borderRadius: 3,
            fontFamily: 'var(--font-mono)', fontSize: 10.5,
            padding: '3px 6px',
          }}>
          {TYPE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        {iocType === 'hash' && (
          <>
            <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>algo</span>
            <select
              value={hashType}
              onChange={e => setHashType(e.target.value as IocEntry['hashType'])}
              style={{
                background: 'var(--bg-card)', color: 'var(--text)',
                border: '1px solid var(--border)', borderRadius: 3,
                fontFamily: 'var(--font-mono)', fontSize: 10.5,
                padding: '3px 6px',
              }}>
              <option value="sha256">sha256</option>
              <option value="sha1">sha1</option>
              <option value="md5">md5</option>
            </select>
          </>
        )}
        <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>verdict</span>
        <select
          value={verdict}
          onChange={e => setVerdict(e.target.value as IocEntry['verdict'])}
          style={{
            background: 'var(--bg-card)', color: 'var(--text)',
            border: '1px solid var(--border)', borderRadius: 3,
            fontFamily: 'var(--font-mono)', fontSize: 10.5,
            padding: '3px 6px',
          }}>
          {VERDICT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        {error && <span style={{ color: 'var(--red)', fontSize: 10 }}>{error}</span>}
        <span style={{ flex: 1 }} />
        <button onClick={commit}
          style={{
            background: 'var(--accent)', color: '#fff',
            border: 'none', borderRadius: 3, cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5, fontWeight: 600,
            padding: '4px 12px',
          }}>save</button>
        <button onClick={onClose}
          style={{
            background: 'transparent', color: 'var(--text-muted)',
            border: '1px solid var(--border)', borderRadius: 3, cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5,
            padding: '3px 10px',
          }}>cancel</button>
      </div>
    </div>
  )
}

function ManualAddForm({ onClose }: { onClose: () => void }) {
  const [value, setValue]       = useState('')
  const [iocType, setIocType]   = useState<IocEntry['iocType']>('hash')
  const [hashType, setHashType] = useState<IocEntry['hashType']>('sha256')
  const [error, setError]       = useState<string | null>(null)
  const [touched, setTouched]   = useState(false)

  function onValueChange(next: string) {
    setValue(next)
    setError(null)
    // Auto-detect only until the analyst manually overrides the type
    // (touched=true). That way pasting an IPv4 first then changing
    // the type to 'domain' doesn't keep getting overwritten.
    if (!touched && next.trim().length > 0) {
      const det = detectIocShape(next)
      setIocType(det.iocType)
      if (det.hashType) setHashType(det.hashType)
    }
  }

  function commit() {
    const v = value.trim()
    if (!v) { setError('Enter an IOC value.'); return }
    if (hasIoc(v)) { setError('That IOC is already on the list.'); return }
    addIoc({
      ioc: v,
      iocType,
      hashType: iocType === 'hash' ? hashType : undefined,
      verdict: 'unknown',
      addedAt: Date.now(),
    })
    onClose()
  }

  return (
    <div style={{
      padding: '8px 12px',
      borderBottom: '1px solid var(--border)',
      background: 'rgba(168,85,247,0.05)',
      display: 'flex', flexDirection: 'column', gap: 6,
      fontFamily: 'var(--font-mono)',
    }}>
      <input
        autoFocus
        value={value}
        onChange={e => onValueChange(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter') { e.preventDefault(); commit() }
          else if (e.key === 'Escape') { e.preventDefault(); onClose() }
        }}
        placeholder="IOC value (hash / IP / domain / HKLM\… / C:\…)"
        style={{
          width: '100%',
          background: 'var(--bg-app)', color: '#fff',
          border: '1px solid var(--accent)', borderRadius: 3,
          fontFamily: 'var(--font-mono)', fontSize: 11.5, lineHeight: 1.45,
          padding: '6px 8px', outline: 'none', boxSizing: 'border-box',
        }}
      />
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>type</span>
        <select
          value={iocType}
          onChange={e => { setIocType(e.target.value as IocEntry['iocType']); setTouched(true) }}
          style={{
            background: 'var(--bg-card)', color: 'var(--text)',
            border: '1px solid var(--border)', borderRadius: 3,
            fontFamily: 'var(--font-mono)', fontSize: 10.5,
            padding: '3px 6px',
          }}>
          {TYPE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        {iocType === 'hash' && (
          <>
            <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>algo</span>
            <select
              value={hashType}
              onChange={e => setHashType(e.target.value as IocEntry['hashType'])}
              style={{
                background: 'var(--bg-card)', color: 'var(--text)',
                border: '1px solid var(--border)', borderRadius: 3,
                fontFamily: 'var(--font-mono)', fontSize: 10.5,
                padding: '3px 6px',
              }}>
              <option value="sha256">sha256</option>
              <option value="sha1">sha1</option>
              <option value="md5">md5</option>
            </select>
          </>
        )}
        {error && <span style={{ color: 'var(--red)', fontSize: 10 }}>{error}</span>}
        <span style={{ flex: 1 }} />
        <button onClick={commit}
          style={{
            background: 'var(--accent)', color: '#fff',
            border: 'none', borderRadius: 3, cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5, fontWeight: 600,
            padding: '4px 12px',
          }}>add</button>
        <button onClick={onClose}
          style={{
            background: 'transparent', color: 'var(--text-muted)',
            border: '1px solid var(--border)', borderRadius: 3, cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10.5,
            padding: '3px 10px',
          }}>cancel</button>
      </div>
    </div>
  )
}

export default function IocListPanel({ onHunt }: {
  onHunt?: (req: HuntJumpRequest) => void
} = {}) {
  const list = useIocList()
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<string | null>(null)

  if (list.length === 0) {
    return (
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        {/* Toolbar still shown when empty so the analyst can add the first IOC. */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '5px 10px', borderBottom: '1px solid var(--border)',
          background: 'var(--bg-elevated)', flexShrink: 0,
        }}>
          <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flex: 1 }}>
            0 IOCs
          </span>
          <button onClick={() => setAdding(a => !a)}
            title="Type / paste an IOC value and add it to the list"
            style={{
              background: 'rgba(168,85,247,0.10)', border: '1px solid var(--accent)',
              borderRadius: 3, color: 'var(--accent)', cursor: 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
              padding: '3px 8px',
            }}>{adding ? '× cancel' : '+ add IOC'}</button>
        </div>
        {adding && <ManualAddForm onClose={() => setAdding(false)} />}
        {!adding && (
          <div style={{ flex: 1, overflow: 'auto', padding: '24px 18px', fontFamily: 'var(--font-mono)' }}>
            <div style={{ color: 'var(--accent)', marginBottom: 8, fontSize: 12 }}>▌ no IOCs collected</div>
            <div style={{ color: 'var(--text-muted)', lineHeight: 1.7, fontSize: 11.5 }}>
              click <span style={{ color: 'var(--text)' }}>+ add IOC</span> above to type one in,
              or use <span style={{ color: 'var(--text)' }}>IOC lookup</span> on any hash / IP in the tree or hunt results.
            </div>
          </div>
        )}
      </div>
    )
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      {/* Toolbar */}
      <div style={{
        display: 'flex', justifyContent: 'flex-end', alignItems: 'center',
        padding: '5px 10px', borderBottom: '1px solid var(--border)',
        background: 'var(--bg-elevated)', flexShrink: 0, gap: 6,
      }}>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flex: 1 }}>
          {list.length} IOC{list.length !== 1 ? 's' : ''}
        </span>
        <button onClick={() => setAdding(a => !a)}
          title="Type / paste an IOC value and add it to the list"
          style={{
            background: 'rgba(168,85,247,0.10)', border: '1px solid var(--accent)',
            borderRadius: 3, color: 'var(--accent)', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700,
            padding: '3px 8px',
          }}>{adding ? '× cancel' : '+ add IOC'}</button>
        <button onClick={() => copyAllIocs(list)}
          style={{
            background: 'transparent', border: '1px solid var(--border)', borderRadius: 3,
            color: 'var(--text-muted)', cursor: 'pointer',
            fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 600,
            padding: '3px 8px',
          }}>copy all</button>
      </div>
      {adding && <ManualAddForm onClose={() => setAdding(false)} />}

      {/* List */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        {list.map(entry =>
          editing === entry.ioc
            ? <IocEditForm key={entry.ioc} entry={entry} onClose={() => setEditing(null)} />
            : <IocRow
                key={entry.ioc}
                entry={entry}
                onHunt={onHunt}
                onEdit={() => setEditing(entry.ioc)}
              />
        )}
      </div>
    </div>
  )
}
