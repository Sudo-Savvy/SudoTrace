import type { IocEntry } from '../store/iocStore'
import type { HuntJumpRequest } from '../components/HuntTab'

// Build a HuntJumpRequest that pivots from an IOC into a hunt across
// the environment so the analyst can find every device that touched it.
// Wide timeframe by default (last 7 days) — IOC sweeps are typically
// not focused on a single window; the analyst can narrow it after the
// first run if needed.

function escapeKql(v: string): string {
  // KQL strings have no backslash escapes; strip embedded double-quotes
  // rather than try to escape them. Analyst-supplied IOCs shouldn't
  // contain quotes anyway.
  return v.replace(/"/g, '')
}

function hashType(v: string): 'sha256' | 'sha1' | 'md5' | null {
  const s = v.trim()
  if (!/^[0-9a-fA-F]+$/.test(s)) return null
  if (s.length === 64) return 'sha256'
  if (s.length === 40) return 'sha1'
  if (s.length === 32) return 'md5'
  return null
}

export function buildIocHuntRequest(entry: IocEntry): HuntJumpRequest | null {
  const v = entry.ioc.trim()
  if (!v) return null

  if (entry.iocType === 'hash') {
    // Prefer the stored hashType (captured from the source column when
    // the IOC was added). Fall back to length detection for legacy
    // entries and Claude-suggested IOCs that don't carry the subtype.
    const t = entry.hashType ?? hashType(v)
    if (!t) return null
    const field      = t.toUpperCase()                  // SHA256 / SHA1 / MD5
    const initField  = `InitiatingProcess${field}`      // InitiatingProcessSHA256 etc.
    const safe = escapeKql(v)
    // Union the tables where hashes live. DeviceImageLoadEvents and
    // DeviceProcessEvents cover process / DLL provenance; DeviceFileEvents
    // catches the write/rename path. Use `=~` for case-insensitive
    // matching — MDE normalises to lowercase but an analyst's clipboard
    // paste might be uppercase, and `==` is case-sensitive in KQL.
    const kql = [
      `union DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents`,
      `| where ${field} =~ "${safe}" or ${initField} =~ "${safe}"`,
      `| order by Timestamp desc`,
      `| take 200`,
    ].join('\n')
    return { kql, timeframe: '7d' }
  }

  if (entry.iocType === 'ip') {
    const safe = escapeKql(v)
    const kql = [
      `DeviceNetworkEvents`,
      `| where RemoteIP == "${safe}" or LocalIP == "${safe}"`,
      `| order by Timestamp desc`,
      `| take 200`,
    ].join('\n')
    return { kql, timeframe: '7d' }
  }

  if (entry.iocType === 'domain') {
    const safe = escapeKql(v).toLowerCase()
    // `contains` is case-insensitive in KQL by default. RemoteUrl is
    // where DNS-resolved domains show up; subdomains and full URLs both
    // match against the bare domain string.
    const kql = [
      `DeviceNetworkEvents`,
      `| where RemoteUrl contains "${safe}"`,
      `| order by Timestamp desc`,
      `| take 200`,
    ].join('\n')
    return { kql, timeframe: '7d' }
  }

  if (entry.iocType === 'registry') {
    // Strip the hive prefix so an IOC pasted as either `HKLM\…` or
    // `HKEY_LOCAL_MACHINE\…` still matches MDE (which always stores
    // the long form). Then split the value on the final backslash so
    // we can match the key-portion against RegistryKey and the last
    // segment against RegistryValueName — MDE stores them in separate
    // columns, so the naive `RegistryKey contains <full path>` always
    // misses when the IOC includes the value name.
    const stripped = v.replace(
      /^(HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_USERS|HKU|HKEY_CLASSES_ROOT|HKCR|HKEY_CURRENT_CONFIG|HKCC)[\\\/]/i,
      '',
    )
    const safe = escapeKql(stripped)
    const lastSlash = stripped.lastIndexOf('\\')
    const prefix = lastSlash > 0 ? escapeKql(stripped.slice(0, lastSlash)) : ''
    const last   = lastSlash > 0 ? escapeKql(stripped.slice(lastSlash + 1)) : ''
    // Build the two unioned branches. Avoid `let` bindings + `strcat`
    // — both have tripped Graph's hunting endpoint in this query
    // shape. Verbatim strings (`@"…"`) keep Windows backslashes
    // literal.
    const regClauses: string[] = [
      `RegistryKey contains @"${safe}"`,
      `PreviousRegistryKey contains @"${safe}"`,
      `RegistryValueName =~ @"${safe}"`,
      `PreviousRegistryValueName =~ @"${safe}"`,
      `RegistryValueData contains @"${safe}"`,
      `PreviousRegistryValueData contains @"${safe}"`,
    ]
    if (prefix && last) {
      regClauses.push(`(RegistryKey contains @"${prefix}" and RegistryValueName =~ @"${last}")`)
      regClauses.push(`(PreviousRegistryKey contains @"${prefix}" and PreviousRegistryValueName =~ @"${last}")`)
    }
    const kql = [
      `union`,
      `(DeviceRegistryEvents`,
      `| where ${regClauses.join('\n   or ')}`,
      `| extend SourceTable = "DeviceRegistryEvents"),`,
      `(DeviceProcessEvents`,
      `| where ProcessCommandLine contains @"${safe}"`,
      `   or InitiatingProcessCommandLine contains @"${safe}"`,
      `| extend SourceTable = "DeviceProcessEvents")`,
      `| order by Timestamp desc`,
      `| take 200`,
    ].join('\n')
    return { kql, timeframe: '7d' }
  }

  if (entry.iocType === 'cmdline') {
    const safe = escapeKql(v)
    // Command lines often run thousands of chars wide and rarely match
    // verbatim across runs (PIDs, GUIDs, paths change). `contains` lets
    // an analyst paste a distinctive substring (a script name, an
    // unusual flag combo) and still match every process that ran it.
    // Verbatim string for the same backslash reasons as registry/path.
    const kql = [
      `DeviceProcessEvents`,
      `| where ProcessCommandLine contains @"${safe}"`,
      `   or InitiatingProcessCommandLine contains @"${safe}"`,
      `| order by Timestamp desc`,
      `| take 200`,
    ].join('\n')
    return { kql, timeframe: '7d' }
  }

  if (entry.iocType === 'file_path') {
    const safe = escapeKql(v)
    // Verbatim strings — same backslash reason as the registry branch.
    // File paths can appear in DeviceFileEvents (writes/renames/deletes)
    // as well as DeviceProcessEvents (the FolderPath of the executable).
    // Union both. `contains` catches partial path matches (e.g. just
    // the filename) without requiring the analyst to know the full form.
    const kql = [
      `union DeviceFileEvents, DeviceProcessEvents`,
      `| where FolderPath contains @"${safe}"`,
      `   or InitiatingProcessFolderPath contains @"${safe}"`,
      `   or FileName =~ @"${safe}"`,
      `   or InitiatingProcessFileName =~ @"${safe}"`,
      `| order by Timestamp desc`,
      `| take 200`,
    ].join('\n')
    return { kql, timeframe: '7d' }
  }

  return null
}
