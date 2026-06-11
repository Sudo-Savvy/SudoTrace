import React, { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { runHunt, type HuntResponse, type HuntTimeframe } from '../api/hunt'
import type { FlagStatus } from '../types'
import { VtButton } from './VtButton'
import RangePicker from './RangePicker'
import { addIoc, hasIoc, removeIoc } from '../store/iocStore'
import { setHuntFlag, getHuntFlag, useHuntFlags, clearHuntFlags, rowKey as rowContentKey } from '../store/huntFlagStore'
import { COLUMNS_BY_TABLE, COMMON_COLUMNS_FALLBACK, detectTableInQuery } from '../utils/kqlSchema'
import { fmtDateTime } from '../utils/dateFormat'
import { friendlyError } from '../utils/errors'
import { getCachedVt, verdictFromVt } from '../utils/vtCache'

// IOC detection — restricted to file hashes (SHA1/SHA256/MD5 columns) and
// IP addresses. Domain / URL lookup is intentionally out of scope here.
//
// Hash detection requires BOTH a hash-typed column name AND a value that
// looks like the right hex length — that way generic hex fields such as
// `DeviceId` don't get a misleading "hash IOC" button.
//
// IP detection accepts either an IP-typed column with any plausible IP
// value, or a raw IP-pattern value in any column (e.g. an IP appearing
// inside `ProcessCommandLine`).
function cleanValue(raw: string): string {
  if (!raw) return ''
  let v = raw.trim()
  if (v.length >= 2 && ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))) {
    v = v.slice(1, -1).trim()
  }
  return v
}

function isMd5(v: string)    { return /^[a-fA-F0-9]{32}$/.test(v) && !/^0+$/.test(v) }
function isSha1(v: string)   { return /^[a-fA-F0-9]{40}$/.test(v) && !/^0+$/.test(v) }
function isSha256(v: string) { return /^[a-fA-F0-9]{64}$/.test(v) && !/^0+$/.test(v) }

function isIpv4(v: string) {
  const m = v.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  return !!m && m.slice(1).every(o => Number(o) <= 255)
}
function isIpv6(v: string) {
  // Loose check — colon-separated hex segments, must contain `::` or
  // multiple `:` groups. Excludes simple "h:m" timestamps.
  if (!v.includes(':') || !/^[0-9a-fA-F:]+$/.test(v) || v.length < 3) return false
  return (v.match(/:/g) ?? []).length >= 2
}

// Pull the hostname out of a URL-ish value. Accepts either a full URL
// (http(s)://host/path…) or a bare hostname. Returns null for anything
// that doesn't look like a public-DNS-style name (e.g. "—", "null",
// raw IP literals — those should be handled via the IP branch instead).
function extractHostname(raw: string): string | null {
  let v = raw.trim()
  if (!v || v === '—') return null
  // Strip a scheme if present. URL() would be ideal but it rejects values
  // missing a scheme, and MDE columns are inconsistent.
  v = v.replace(/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//, '')
  // Drop path / query / fragment / port.
  v = v.split('/')[0].split('?')[0].split('#')[0].split(':')[0]
  v = v.trim().toLowerCase()
  if (!v) return null
  // Reject raw IPs (they should go through the IP branch).
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return null
  if (/^[0-9a-f:]+$/.test(v) && v.includes(':')) return null
  // Require something that looks like a DNS name: a dot, at least one
  // letter, only safe chars.
  if (!/^[a-z0-9][a-z0-9\-\.]*\.[a-z]{2,}$/.test(v)) return null
  return v
}

function detectIoc(column: string, rawValue: string):
  | { type: 'hash'; value: string; hashType: 'sha1' | 'sha256' | 'md5' }
  | { type: 'ip' | 'domain' | 'cmdline'; value: string }
  | null
{
  const v = cleanValue(rawValue)
  if (!v) return null
  if (v === '0' || /^0+$/.test(v) || v === '—' ||
      v.toLowerCase() === 'null' || v.toLowerCase() === 'none') return null

  const c = column.toLowerCase()

  // Hash columns: any column whose name contains sha1/sha256/md5 (covers
  // raw `SHA1`, `MD5`, `SHA256` plus prefixed variants like
  // `InitiatingProcessSHA1`). Value must match the expected hex length.
  // The matched algorithm is recorded so the IOC entry carries the
  // correct subtype for later hunt pivots.
  if (/sha1|sha256|md5/.test(c)) {
    if (isSha256(v)) return { type: 'hash', value: v, hashType: 'sha256' }
    if (isSha1(v))   return { type: 'hash', value: v, hashType: 'sha1'   }
    if (isMd5(v))    return { type: 'hash', value: v, hashType: 'md5'    }
    return null
  }

  // URL / domain columns: RemoteUrl, FileOriginUrl, RequestUrl, etc.
  // We parse the hostname out so VirusTotal gets a clean domain lookup
  // even when the original cell contains a full URL with path/query.
  if (/url$|domain$|fqdn$|dnsaddress|hostname$/.test(c)) {
    const host = extractHostname(v)
    if (host) return { type: 'domain', value: host }
    return null
  }

  // IP columns: explicit IP-typed column names only. We deliberately do
  // NOT fall back to "any column where the value looks like an IPv4" —
  // version strings (e.g. ProductVersion `10.0.26100.7705`) and similar
  // dotted-numeric fields produce false positives too easily.
  //
  // Matches: RemoteIP, LocalIP, PublicIP, SourceIP, DestinationIP, IP,
  // IPAddresses, IPList, IPv4Dialect, etc. Deliberately excludes columns
  // ending in `IPType` (those hold "Public"/"Private", not addresses).
  const looksLikeIpCol =
    /(^|[a-z])ip$/.test(c) ||
    /^ip(address|addresses|list)$/.test(c) ||
    /ipv[46]/.test(c)
  if (looksLikeIpCol) {
    if (isIpv4(v) || isIpv6(v)) return { type: 'ip', value: v }
    return null
  }

  // Command-line columns: ProcessCommandLine, InitiatingProcessCommandLine,
  // ParentProcessCommandLine, etc. Anything containing "commandline" in the
  // column name. The value passes through as-is — cmdlines are searched
  // via `contains` on the hunt pivot, not equality, so we don't reject
  // here on shape. Skip empty / placeholder values though (already
  // handled above by the cleanValue / "—" guards).
  if (/commandline/.test(c)) {
    return { type: 'cmdline', value: rawValue }
  }

  return null
}

// Shared flag cycle + colours — same palette the process and incident flag
// buttons use, so the analyst's mental model carries across surfaces.
const HUNT_FLAG_CYCLE: FlagStatus[] = [null, 'benign', 'suspicious', 'malicious']
const HUNT_FLAG_COLOURS: Record<NonNullable<FlagStatus>, string> = {
  malicious:   '#FF5E5B',
  suspicious:  '#F0B340',
  investigate: '#7AA8FF',
  benign:      '#7DD3A0',
}
function cycleFlag(current: FlagStatus): FlagStatus {
  const idx = HUNT_FLAG_CYCLE.indexOf(current)
  return HUNT_FLAG_CYCLE[(idx + 1) % HUNT_FLAG_CYCLE.length]
}

const TIMEFRAMES: { value: HuntTimeframe; label: string }[] = [
  { value: '24h',    label: 'Last 24 hours' },
  { value: '7d',     label: 'Last 7 days' },
  { value: '14d',    label: 'Last 14 days' },
  { value: '30d',    label: 'Last 30 days' },
  { value: 'custom', label: 'Custom range…' },
]

function fmtCustomLabel(startIso: string, endIso: string): string {
  const fmt = (iso: string) => {
    const m = iso.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/)
    if (m) return `${m[3]}/${m[2]} ${m[4]}:${m[5]}`
    return iso
  }
  return `${fmt(startIso)} → ${fmt(endIso)}`
}

// ── KQL syntax highlighting ────────────────────────────────────────────
// Lightweight tokeniser → coloured HTML for the editor overlay. We
// deliberately don't pull in a 200kB dependency (prismjs / monaco) for
// what amounts to keyword/string/number/comment colouring on a Defender
// hunting box. Token order matters: comments and strings first so their
// contents never get mistaken for keywords or operators.

const KQL_KEYWORDS = new Set([
  // tabular operators
  'where', 'project', 'project-away', 'project-keep', 'project-rename',
  'project-reorder', 'extend', 'summarize', 'sort', 'order', 'top', 'take',
  'limit', 'distinct', 'mv-expand', 'mv-apply', 'parse', 'parse-where',
  'parse-kv', 'evaluate', 'join', 'union', 'render', 'search', 'find',
  'getschema', 'sample', 'sample-distinct', 'lookup', 'invoke', 'partition',
  'range', 'datatable', 'print', 'fork', 'facet', 'consume', 'scan',
  'make-series', 'top-nested', 'top-hitters', 'externaldata',
  // control
  'let', 'asc', 'desc', 'by', 'on', 'kind', 'with', 'materialize', 'as',
  'into', 'from', 'step',
  // logical
  'and', 'or', 'not', 'in', 'has', 'has_any', 'has_all', 'has_cs',
  'contains', 'contains_cs', 'startswith', 'startswith_cs',
  'endswith', 'endswith_cs', 'matches', 'regex', 'between',
  // bool / null
  'true', 'false', 'null',
])

// Defender advanced-hunting tables. Matched anywhere they appear in a
// query (start of a pipeline, inside a subquery, after `union`, etc.)
// and rendered in orange so the data source is obvious at a glance.
// Original-case here because we also drive table-name autocompletion
// off this list and want to suggest the canonical casing.
const KQL_TABLE_NAMES = [
  'DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents',
  'DeviceRegistryEvents', 'DeviceLogonEvents', 'DeviceImageLoadEvents',
  'DeviceEvents', 'DeviceFileCertificateInfo',
  'DeviceInfo', 'DeviceNetworkInfo',
  'DeviceTvmSoftwareVulnerabilities', 'DeviceTvmSecureConfigurationAssessment',
  'DeviceTvmSoftwareInventory', 'DeviceTvmSoftwareEvidenceBeta',
  'AlertInfo', 'AlertEvidence',
  'EmailEvents', 'EmailUrlInfo', 'EmailAttachmentInfo',
  'EmailPostDeliveryEvents', 'UrlClickEvents',
  'IdentityLogonEvents', 'IdentityQueryEvents', 'IdentityDirectoryEvents',
  'IdentityInfo', 'CloudAppEvents',
  'BehaviorInfo', 'BehaviorEntities',
]
const KQL_TABLES = new Set(KQL_TABLE_NAMES.map(n => n.toLowerCase()))

// Walk back from the cursor through identifier-style chars to find the
// word the analyst is currently typing. Returns null if the cursor isn't
// inside a word.
export function getCursorWord(text: string, cursor: number): { word: string; start: number } | null {
  if (cursor < 0 || cursor > text.length) return null
  let start = cursor
  while (start > 0 && /[a-zA-Z0-9_-]/.test(text[start - 1])) start--
  if (start === cursor) return null
  return { word: text.slice(start, cursor), start }
}

// True if the cursor sits inside a KQL string literal on the current
// line. Used to suppress autocomplete when the analyst is typing a
// search value — they're spelling a hostname, a hash, or a registry
// path, not a column name, and suggestions like `DeviceName` would be
// noise. Handles regular `"…"` / `'…'`, escape sequences (`\"`), and
// verbatim `@"…"` strings (where `""` is the only escape).
export function isCursorInString(text: string, cursor: number): boolean {
  const lineStart = text.lastIndexOf('\n', cursor - 1) + 1
  let i = lineStart
  let inStr = false
  let verbatim = false
  let quote: '"' | "'" | null = null
  while (i < cursor) {
    const c = text[i]
    if (!inStr) {
      // Verbatim opener: @" or @'
      if (c === '@' && (text[i + 1] === '"' || text[i + 1] === "'")) {
        inStr = true; verbatim = true; quote = text[i + 1] as '"' | "'"
        i += 2; continue
      }
      if (c === '"' || c === "'") {
        inStr = true; verbatim = false; quote = c
        i += 1; continue
      }
      i += 1
    } else {
      // Inside a regular string, `\` escapes the next char.
      if (!verbatim && c === '\\') { i += 2; continue }
      if (c === quote) {
        // Verbatim strings escape a literal quote by doubling it.
        if (verbatim && text[i + 1] === quote) { i += 2; continue }
        inStr = false; verbatim = false; quote = null
        i += 1; continue
      }
      i += 1
    }
  }
  return inStr
}

const KQL_FUNCTIONS = new Set([
  // date / time
  'ago', 'now', 'datetime', 'totimespan', 'todatetime', 'format_datetime',
  'datetime_add', 'datetime_diff', 'datetime_part', 'make_datetime', 'make_timespan',
  'dayofweek', 'dayofmonth', 'dayofyear', 'monthofyear', 'getyear', 'getmonth',
  'hourofday', 'week_of_year',
  'startofday', 'startofweek', 'startofmonth', 'startofyear',
  'endofday', 'endofweek', 'endofmonth', 'endofyear',
  'bin', 'bin_at', 'bin_auto',
  // string
  'tolower', 'toupper', 'strcat', 'strcat_array', 'strcmp', 'strlen',
  'substring', 'replace', 'replace_string', 'split', 'trim', 'trim_start', 'trim_end',
  'indexof', 'reverse', 'format_string',
  // parsing
  'parse_json', 'parse_xml', 'parse_url', 'parse_urlquery', 'parse_path',
  'parse_user_agent', 'parse_version', 'extract', 'extract_all',
  // conversion
  'tostring', 'toint', 'tolong', 'todouble', 'tobool', 'tobinary',
  'todynamic', 'toguid', 'tohex', 'todecimal',
  // hashing
  'hash', 'hash_md5', 'hash_sha1', 'hash_sha256',
  // math
  'abs', 'ceiling', 'floor', 'exp', 'log', 'log10', 'log2', 'pow', 'round',
  'sqrt', 'sign', 'max_of', 'min_of', 'rand', 'isnan', 'isinf', 'isfinite',
  // logical
  'iif', 'iff', 'case', 'coalesce',
  'isnotempty', 'isempty', 'isnull', 'isnotnull',
  // arrays / dynamic
  'array_length', 'array_concat', 'array_slice', 'array_index_of',
  'array_reverse', 'array_sort_asc', 'array_sort_desc', 'array_sum', 'array_iif',
  'pack', 'pack_array', 'pack_dictionary', 'bag_pack', 'bag_unpack',
  'bag_keys', 'bag_merge', 'bag_remove_keys', 'repeat',
  'set_intersect', 'set_union', 'set_difference',
  // ip / network
  'parse_ipv4', 'parse_ipv6', 'ipv4_is_private', 'ipv4_is_in_range',
  'ipv4_is_match', 'format_ipv4', 'format_ipv6', 'ipv4_compare', 'ipv6_compare',
  // aggregations
  'count', 'countif', 'count_distinct', 'count_distinctif',
  'sum', 'sumif', 'avg', 'avgif', 'min', 'minif', 'max', 'maxif',
  'dcount', 'dcountif', 'dcount_hll', 'hll', 'hll_merge',
  'make_list', 'make_list_if', 'make_list_with_nulls', 'make_set', 'make_set_if',
  'percentile', 'percentiles', 'percentilew', 'percentilesw',
  'percentile_array', 'percentiles_array',
  'arg_max', 'arg_min', 'take_any', 'take_anyif',
  'stdev', 'stdevif', 'variance', 'varianceif', 'any', 'anyif',
])

// KQL keywords split by where they syntactically belong. Tabular
// operators only follow a pipe (`| where`, `| project` …); logical
// operators / boolean literals / clause introducers like `by`/`on`
// only belong inside expressions. Splitting them lets the autocomplete
// avoid nonsense suggestions like `| where where`.
const TABULAR_OPERATORS = new Set([
  'where', 'project', 'project-away', 'project-keep', 'project-rename',
  'project-reorder', 'extend', 'summarize', 'sort', 'order', 'top', 'take',
  'limit', 'count', 'distinct', 'mv-expand', 'mv-apply', 'parse', 'parse-where',
  'parse-kv', 'evaluate', 'join', 'union', 'render', 'search', 'find',
  'getschema', 'sample', 'sample-distinct', 'lookup', 'invoke', 'partition',
  'range', 'datatable', 'print', 'fork', 'facet', 'consume', 'scan',
  'make-series', 'top-nested', 'top-hitters', 'externaldata',
])

const EXPRESSION_KEYWORDS = new Set([
  // logical / comparison
  'and', 'or', 'not', 'in', 'has', 'has_any', 'has_all', 'has_cs',
  'contains', 'contains_cs', 'startswith', 'startswith_cs',
  'endswith', 'endswith_cs', 'matches', 'regex', 'between',
  // bool / null
  'true', 'false', 'null',
  // clause introducers — valid inside summarize/sort/join expressions
  'by', 'on', 'kind', 'with', 'asc', 'desc', 'as', 'into', 'from', 'step',
  // control words
  'let', 'materialize',
])

export type CompletionSlot = 'table' | 'operator' | 'expression'

// Classify what kind of token belongs at the cursor by looking at what
// comes before the word being typed. Three slots:
//   - 'table'      → start of the query, or right after a `union`/`join`/`lookup`
//   - 'operator'   → right after a `|`
//   - 'expression' → anywhere else (column names, functions, logical ops)
export function classifySlot(text: string, wordStart: number): CompletionSlot {
  // Skip back through whitespace immediately before the word.
  let i = wordStart - 1
  while (i >= 0 && /\s/.test(text[i])) i--
  if (i < 0) return 'table'  // nothing before us → top of query
  if (text[i] === '|') return 'operator'
  // Look at the previous identifier — `union`/`join`/`lookup` introduce
  // a table-name slot.
  let identEnd = i + 1
  while (i >= 0 && /[a-zA-Z0-9_-]/.test(text[i])) i--
  const prevWord = text.slice(i + 1, identEnd).toLowerCase()
  if (prevWord === 'union' || prevWord === 'join' || prevWord === 'lookup') {
    return 'table'
  }
  return 'expression'
}

// Sorted helper for the alphabetically-first match within a pool.
function pickFirstMatch(pool: string[], lower: string): { match: string | null; exact: boolean } {
  let best: string | null = null
  let exact = false
  for (const c of pool) {
    const cl = c.toLowerCase()
    if (cl === lower) { exact = true; continue }
    if (cl.startsWith(lower)) {
      if (best === null || cl.localeCompare(best.toLowerCase()) < 0) best = c
    }
  }
  return { match: best, exact }
}

// Slot-aware completion. Searches only the candidate pool appropriate
// for the cursor's position so we don't suggest, e.g., a table name in
// the middle of a `where` expression or an operator immediately after
// another operator. Returns null when the word is already a complete
// name in that slot.
export function findCompletion(word: string, slot: CompletionSlot, table: string | null): string | null {
  if (!word) return null
  const lower = word.toLowerCase()
  let pool: string[]
  if (slot === 'table') {
    pool = KQL_TABLE_NAMES
  } else if (slot === 'operator') {
    pool = Array.from(TABULAR_OPERATORS)
  } else {
    // Expression slot: functions + logical keywords + (if known) the
    // current table's columns. Table names are deliberately excluded —
    // a table identifier in expression position is almost always wrong.
    pool = [
      ...Array.from(EXPRESSION_KEYWORDS),
      ...Array.from(KQL_FUNCTIONS),
      ...(table && COLUMNS_BY_TABLE[table] ? COLUMNS_BY_TABLE[table] : COMMON_COLUMNS_FALLBACK),
    ]
  }
  const { match, exact } = pickFirstMatch(pool, lower)
  if (exact) return null
  return match
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c] as string))
}

const COLOR = {
  keyword:  'var(--accent)',
  table:    '#FF8C42',  // MDE advanced-hunting tables
  fn:       '#4aa3e8',
  string:   '#7DD3A0',
  number:   '#F0B340',
  comment:  '#888',
  op:       '#c8c8c8',
  pipe:     'var(--accent)',
} as const

function span(text: string, color: string, extra = ''): string {
  return `<span style="color:${color}${extra}">${escapeHtml(text)}</span>`
}

export function highlightKql(text: string): string {
  let out = ''
  let i = 0
  while (i < text.length) {
    const c = text[i]
    // line comment
    if (c === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i)
      const end = nl === -1 ? text.length : nl
      out += span(text.slice(i, end), COLOR.comment, ';font-style:italic')
      i = end
      continue
    }
    // string literal (single or double quoted)
    if (c === '"' || c === "'") {
      const quote = c
      let j = i + 1
      while (j < text.length && text[j] !== quote) {
        if (text[j] === '\\' && j + 1 < text.length) j++
        j++
      }
      const end = Math.min(j + 1, text.length)
      out += span(text.slice(i, end), COLOR.string)
      i = end
      continue
    }
    // number
    if (/[0-9]/.test(c)) {
      let j = i + 1
      while (j < text.length && /[0-9.]/.test(text[j])) j++
      // include trailing time-unit suffix (h, d, m, s, ms) on bare numbers
      // so things like `ago(7d)` highlight the whole token.
      if (j < text.length && /[a-z]/.test(text[j])) {
        let k = j
        while (k < text.length && /[a-z]/.test(text[k])) k++
        if (k - j <= 3) j = k
      }
      out += span(text.slice(i, j), COLOR.number)
      i = j
      continue
    }
    // pipe — visually anchors the start of each operator
    if (c === '|') {
      out += span('|', COLOR.pipe, ';font-weight:600')
      i++
      continue
    }
    // operators (two-char first, then single)
    const two = text.slice(i, i + 2)
    if (two === '==' || two === '!=' || two === '<=' || two === '>='
        || two === '=~' || two === '!~') {
      out += span(two, COLOR.op, ';font-weight:600')
      i += 2
      continue
    }
    if ('=<>+-*/%'.includes(c)) {
      out += span(c, COLOR.op, ';font-weight:600')
      i++
      continue
    }
    // identifier / keyword / function
    if (/[a-zA-Z_]/.test(c)) {
      let j = i + 1
      while (j < text.length && /[a-zA-Z0-9_\-]/.test(text[j])) j++
      const word = text.slice(i, j)
      const lower = word.toLowerCase()
      if (KQL_KEYWORDS.has(lower)) {
        out += span(word, COLOR.keyword, ';font-weight:600')
      } else if (KQL_TABLES.has(lower)) {
        out += span(word, COLOR.table, ';font-weight:600')
      } else if (KQL_FUNCTIONS.has(lower) && text[j] === '(') {
        out += span(word, COLOR.fn)
      } else {
        out += escapeHtml(word)
      }
      i = j
      continue
    }
    // anything else
    out += escapeHtml(c)
    i++
  }
  return out
}

function defaultKqlFor(hostname: string): string {
  const safe = (hostname || '').replace(/"/g, '')
  return `DeviceProcessEvents
| where DeviceName == "${safe}"
| take 100`
}

// localStorage keys — the analyst's last query, timeframe, and custom range
// persist across reloads so they don't lose their working set when they
// navigate away. Tab-level state persistence (results, expanded, flags) is
// handled higher up by keeping the HuntTab component mounted across tab
// switches; only inputs go to localStorage.
const STORAGE_TF_KEY        = 'sudotrace.huntTimeframe'
const STORAGE_PAGE_SIZE_KEY = 'sudotrace.huntPageSize'
const STORAGE_EDITOR_H_KEY  = 'sudotrace.huntEditorHeight'
const PAGE_SIZE_OPTIONS = [25, 50, 100, 200, 500]
const DEFAULT_PAGE_SIZE = 100
const DEFAULT_EDITOR_HEIGHT = 200
const MIN_EDITOR_HEIGHT     = 80
const MAX_EDITOR_HEIGHT     = 800

function loadPageSize(): number {
  try {
    const s = localStorage.getItem(STORAGE_PAGE_SIZE_KEY)
    const n = s ? parseInt(s, 10) : NaN
    if (PAGE_SIZE_OPTIONS.includes(n)) return n
  } catch { /* ignore */ }
  return DEFAULT_PAGE_SIZE
}

function loadEditorHeight(): number {
  try {
    const s = localStorage.getItem(STORAGE_EDITOR_H_KEY)
    const n = s ? parseInt(s, 10) : NaN
    if (!isNaN(n) && n >= MIN_EDITOR_HEIGHT && n <= MAX_EDITOR_HEIGHT) return n
  } catch { /* ignore */ }
  return DEFAULT_EDITOR_HEIGHT
}
const STORAGE_CUSTOM_KEY = 'sudotrace.huntCustomRange'
const STORAGE_HISTORY_KEY = 'sudotrace.huntHistory'
const HISTORY_MAX = 20

interface HistoryEntry {
  kql: string
  timeframe: string  // wire format: preset id or 'custom:<start>..<end>'
  ranAt: number      // epoch ms
  rowCount: number | null
  durationMs: number | null
  ok: boolean
}

// Always seed the editor with the host-specific default on fresh load.
// Previous queries are surfaced via the HistoryPanel (one click to
// reload + re-run), so there's no need to silently restore the last
// edited KQL across page reloads — that just confuses analysts who
// expect to start fresh.
function loadInitialKql(hostname: string): string {
  return defaultKqlFor(hostname)
}

function loadHistory(): HistoryEntry[] {
  try {
    const s = localStorage.getItem(STORAGE_HISTORY_KEY)
    if (!s) return []
    const parsed = JSON.parse(s)
    if (!Array.isArray(parsed)) return []
    return parsed.filter(e => e && typeof e.kql === 'string' && typeof e.timeframe === 'string')
  } catch { return [] }
}

function saveHistory(list: HistoryEntry[]): void {
  try { localStorage.setItem(STORAGE_HISTORY_KEY, JSON.stringify(list.slice(0, HISTORY_MAX))) } catch { /* ignore */ }
}
function loadInitialTf(): HuntTimeframe {
  try {
    const s = localStorage.getItem(STORAGE_TF_KEY)
    if (s === '24h' || s === '7d' || s === '14d' || s === '30d' || s === 'custom') return s
  } catch { /* ignore */ }
  return '24h'
}
function loadInitialCustom(): { startIso: string; endIso: string } | null {
  try {
    const s = localStorage.getItem(STORAGE_CUSTOM_KEY)
    if (!s) return null
    const parsed = JSON.parse(s)
    if (parsed && typeof parsed.startIso === 'string' && typeof parsed.endIso === 'string') {
      return parsed
    }
  } catch { /* ignore */ }
  return null
}

// Full-width drag bar that controls the KQL editor's height. The
// native CSS `resize: vertical` corner triangle is only ~12px square
// and very fiddly to grab; this bar runs the full width of the editor
// so the hit target is unmistakable. Listens on window during the
// drag so the pointer can leave the bar without losing the grip.
function EditorResizeHandle({ height, onChange, min, max }: {
  height: number
  onChange: (h: number) => void
  min: number
  max: number
}) {
  const draggingRef = useRef<{ startY: number; startH: number } | null>(null)
  const [active, setActive] = useState(false)

  function onMouseDown(e: React.MouseEvent) {
    e.preventDefault()
    draggingRef.current = { startY: e.clientY, startH: height }
    setActive(true)
    const onMove = (ev: MouseEvent) => {
      const d = draggingRef.current
      if (!d) return
      const next = Math.max(min, Math.min(max, d.startH + (ev.clientY - d.startY)))
      onChange(next)
    }
    const onUp = () => {
      draggingRef.current = null
      setActive(false)
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  const [hovered, setHovered] = useState(false)
  const lit = hovered || active
  return (
    // Outer: wide invisible hit target so the bar is easy to grab.
    // Visual height of the visible bar stays at 6px to keep the
    // layout density unchanged.
    <div
      onMouseDown={onMouseDown}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      title="Drag to resize the KQL editor"
      style={{
        height: 18,
        margin: 0,
        cursor: 'ns-resize',
        userSelect: 'none',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'transparent',
      }}>
      <div style={{
        position: 'relative',
        width: '100%',
        height: 6,
        borderRadius: 3,
        background: lit ? 'var(--accent)' : 'var(--border)',
        transition: active ? 'none' : 'background 120ms',
        pointerEvents: 'none',
      }}>
        {/* Grip dots in the centre, purely as an affordance hint. */}
        <div style={{
          position: 'absolute', top: '50%', left: '50%',
          transform: 'translate(-50%, -50%)',
          display: 'flex', gap: 3,
        }}>
          <span style={{ width: 3, height: 3, borderRadius: '50%', background: lit ? '#fff' : 'var(--bg-app)' }} />
          <span style={{ width: 3, height: 3, borderRadius: '50%', background: lit ? '#fff' : 'var(--bg-app)' }} />
          <span style={{ width: 3, height: 3, borderRadius: '50%', background: lit ? '#fff' : 'var(--bg-app)' }} />
        </div>
      </div>
    </div>
  )
}

// Build a KQL query that returns exactly the one flagged event, by
// pinning on the row's stable identifiers (Timestamp + DeviceId + ReportId
// where available). Returns null if the row lacks enough discriminators
// to be reasonably targeted — caller should then fall back to re-running
// the original query.
function buildTargetedKql(originalKql: string, row: Record<string, unknown>): string | null {
  // Drop leading comments and `let` bindings so the first token we read
  // is the source table.
  const trimmed = originalKql
    .split('\n')
    .filter(l => {
      const t = l.trim()
      return t.length > 0 && !t.startsWith('//') && !t.startsWith('let ')
    })
    .join('\n')
    .trim()
  const tableMatch = trimmed.match(/^([A-Za-z][A-Za-z0-9_]*)/)
  if (!tableMatch) return null
  const table = tableMatch[1]

  const filters: string[] = []
  const ts = row.Timestamp
  if (typeof ts === 'string' && ts) {
    filters.push(`Timestamp == datetime("${ts.replace(/"/g, '')}")`)
  }
  const dev = row.DeviceId
  if (typeof dev === 'string' && dev) {
    filters.push(`DeviceId == "${dev.replace(/"/g, '')}"`)
  }
  const rid = row.ReportId
  if (typeof rid === 'number') {
    filters.push(`ReportId == ${rid}`)
  } else if (typeof rid === 'string' && rid) {
    filters.push(`ReportId == "${rid.replace(/"/g, '')}"`)
  }
  // Need at least Timestamp + one other identifier to be reasonably
  // unique. (ReportId alone isn't globally unique — it's per-device.)
  if (filters.length < 2) return null
  return `${table}\n| where ${filters.join('\n  and ')}\n| take 1`
}

// Build a tight custom timeframe centred on the event's timestamp so
// the backend's mandatory `| where Timestamp` clause still lets the
// event through, regardless of how long ago the event was originally
// flagged. ±5 minutes is plenty of slack for clock skew.
function tightTimeframeAround(timestamp: unknown): { wire: string; iso: { startIso: string; endIso: string } } | null {
  if (typeof timestamp !== 'string' || !timestamp) return null
  const t = new Date(timestamp)
  if (isNaN(t.getTime())) return null
  const startIso = new Date(t.getTime() - 5 * 60_000).toISOString()
  const endIso   = new Date(t.getTime() + 5 * 60_000).toISOString()
  return { wire: `custom:${startIso}..${endIso}`, iso: { startIso, endIso } }
}

function cellToString(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  try {
    return JSON.stringify(v)
  } catch {
    return String(v)
  }
}

// Request to load a specific query into the Hunt tab from elsewhere
// (currently fired by Timeline-row clicks). Includes the row to scroll
// into view once the results arrive — if absent, we just run the query
// and let the analyst eyeball the result set.
export interface HuntJumpRequest {
  kql:           string
  timeframe:     string  // wire format
  targetRow?:    Record<string, unknown>
  customRange?:  { startIso: string; endIso: string }
}

export default function HuntTab({ hostname = '', pendingRequest, onRequestConsumed }: {
  hostname?: string
  pendingRequest?: HuntJumpRequest | null
  onRequestConsumed?: () => void
}) {
  const [kql, setKql] = useState<string>(() => loadInitialKql(hostname))
  const [cursor, setCursor] = useState(0)
  const [history, setHistory] = useState<HistoryEntry[]>(() => loadHistory())

  // Position-aware autocompletion. We classify what slot the cursor is
  // in (table / operator / expression) and only suggest from the pool
  // that makes sense there — so `| where Devi` suggests `DeviceName`
  // (column) instead of `DeviceProcessEvents` (table), and `| ` after
  // a `|` only suggests tabular operators. The query's source table
  // drives column suggestions in expression slots.
  const currentWord = getCursorWord(kql, cursor)
  const slot        = currentWord ? classifySlot(kql, currentWord.start) : 'table'
  const tableInUse  = detectTableInQuery(kql, KQL_TABLES)
  // Suppress completion while the cursor is inside a string literal —
  // the analyst is typing a search value (hostname, hash, path), not
  // a KQL identifier, so suggestions would only ever be noise.
  const inString    = isCursorInString(kql, cursor)
  const completion  = currentWord && !inString
    ? findCompletion(currentWord.word, slot, tableInUse)
    : null
  const ghostSuffix = completion && currentWord
    ? completion.slice(currentWord.word.length)
    : null
  const [timeframe, setTimeframe] = useState<HuntTimeframe>(() => loadInitialTf())
  const [customRange, setCustomRange] = useState<{ startIso: string; endIso: string } | null>(() => loadInitialCustom())
  const [pickerOpen, setPickerOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<HuntResponse | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const textareaRef = useRef<HTMLTextAreaElement | null>(null)
  // Per-run abort controller so the analyst can cancel an in-flight
  // hunt. Replaced fresh on every runKql; null between runs.
  const abortRef = useRef<AbortController | null>(null)
  // Anchor for the portal'd RangePicker — positioned beneath the timeframe
  // select so the picker floats over the page instead of pushing the editor
  // down. Same pattern WindowControl in the AppBar uses.
  const tfAnchorRef = useRef<HTMLLabelElement | null>(null)
  // Per-row expand + flag state. Both keyed by the row's index in the current
  // result set, so they reset whenever a new query runs (different rows, same
  // index would otherwise carry stale state across).
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [rowFlags, setRowFlags] = useState<Map<number, FlagStatus>>(new Map())
  // Result pagination — slice the response into pages so a 5000-row
  // result doesn't render 5000 DOM rows at once. Page size is persisted
  // across sessions; page index resets to 0 on every new run.
  const [pageSize, setPageSize] = useState<number>(() => loadPageSize())
  const [pageIndex, setPageIndex] = useState(0)
  // Analyst-controlled height of the KQL editor. Persisted across
  // sessions so the layout the analyst chose doesn't reset on every
  // page load. The editor scrolls internally when the query exceeds
  // this height, so a long query doesn't squash the results below.
  const [editorHeight, setEditorHeight] = useState<number>(() => loadEditorHeight())
  useEffect(() => {
    try { localStorage.setItem(STORAGE_EDITOR_H_KEY, String(editorHeight)) } catch { /* ignore */ }
  }, [editorHeight])
  // Subscriber to the cross-query flagged-events store. Drives the
  // header badge so the analyst always sees how many hunt events are
  // currently feeding into the AI Analyse payload, even after running
  // a different query.
  const persistedFlags = useHuntFlags()
  const [flagListOpen, setFlagListOpen] = useState(false)
  const flagBadgeRef = useRef<HTMLSpanElement | null>(null)
  // Row index to briefly flash (yellow highlight pulse) after the analyst
  // clicks a flagged-event entry in the popover. Cleared by a timeout.
  const [flashRow, setFlashRow] = useState<number | null>(null)
  useEffect(() => {
    if (flashRow === null) return
    const t = setTimeout(() => setFlashRow(null), 1600)
    return () => clearTimeout(t)
  }, [flashRow])

  // After a jump-triggered re-run finishes, we need to find the row in
  // the freshly-loaded results and navigate to it. The state setter
  // can't read the just-set result inline, so we stash the target row
  // here and a useEffect watching `result` does the navigation.
  const [pendingJumpRow, setPendingJumpRow] = useState<Record<string, unknown> | null>(null)
  const [jumpStatus, setJumpStatus] = useState<string | null>(null)
  useEffect(() => {
    if (!pendingJumpRow || !result) return
    const targetKey = rowContentKey(pendingJumpRow)
    const idx = result.rows.findIndex(r => rowContentKey(r) === targetKey)
    setPendingJumpRow(null)
    if (idx < 0) {
      setJumpStatus('Flagged event not found in re-run results — it may have been ingestion-aged out.')
      setTimeout(() => setJumpStatus(null), 3000)
      return
    }
    // Found and navigated — clear the "Loading event…" banner.
    setJumpStatus(null)
    // Switch to the page containing the target row before scrolling —
    // otherwise the row id won't be in the DOM.
    setPageIndex(Math.floor(idx / pageSize))
    setExpanded(prev => { const n = new Set(prev); n.add(idx); return n })
    setFlashRow(idx)
    requestAnimationFrame(() => {
      document.getElementById(`hunt-row-${idx}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    })
  }, [result, pendingJumpRow, pageSize])

  // Jump-to-flagged-event handler used by the popover. If the event is
  // in the current result set, navigate directly. Otherwise, restore the
  // KQL + timeframe used when the flag was set, re-run the query, then
  // navigate to the row once the new results arrive (via the effect above).
  function jumpToFlaggedEvent(entry: { row: Record<string, unknown>; kql: string; timeframe: string }): void {
    setFlagListOpen(false)
    if (result) {
      const targetKey = rowContentKey(entry.row)
      const idx = result.rows.findIndex(r => rowContentKey(r) === targetKey)
      if (idx >= 0) {
        setPageIndex(Math.floor(idx / pageSize))
        setExpanded(prev => { const n = new Set(prev); n.add(idx); return n })
        setFlashRow(idx)
        requestAnimationFrame(() => {
          document.getElementById(`hunt-row-${idx}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
        })
        return
      }
    }
    // Out of view → fetch JUST this one event by building a targeted
    // KQL keyed on the row's stable identifiers, with a tight custom
    // timeframe centred on the event's timestamp. The pending-jump
    // effect navigates to the row once the new result arrives.
    if (!entry.kql) {
      setJumpStatus('This flag has no stored query — flag it again to capture context.')
      setTimeout(() => setJumpStatus(null), 3000)
      return
    }
    const targetedKql = buildTargetedKql(entry.kql, entry.row)
    const tight = tightTimeframeAround(entry.row.Timestamp)
    if (!targetedKql || !tight) {
      setJumpStatus('This event lacks the identifiers (Timestamp / DeviceId) needed to navigate directly.')
      setTimeout(() => setJumpStatus(null), 3500)
      return
    }
    setKql(targetedKql)
    setCustomRange(tight.iso)
    setTimeframe('custom')
    setPendingJumpRow(entry.row)
    setJumpStatus('Loading flagged event…')
    runKql(targetedKql, tight.wire)
  }

  // Persist the timeframe so it survives a tab navigation. KQL itself
  // isn't persisted across reloads — the HistoryPanel is the way to
  // recover a previous query.
  useEffect(() => {
    try { localStorage.setItem(STORAGE_TF_KEY, timeframe) } catch { /* ignore */ }
  }, [timeframe])
  useEffect(() => {
    try { localStorage.setItem(STORAGE_PAGE_SIZE_KEY, String(pageSize)) } catch { /* ignore */ }
  }, [pageSize])
  useEffect(() => {
    try {
      if (customRange) localStorage.setItem(STORAGE_CUSTOM_KEY, JSON.stringify(customRange))
      else             localStorage.removeItem(STORAGE_CUSTOM_KEY)
    } catch { /* ignore */ }
  }, [customRange])

  // Brief copy-to-clipboard toast notifications.
  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 1400)
    return () => clearTimeout(t)
  }, [toast])

  // Serialise the chosen timeframe to the wire format the backend expects.
  function serialiseTimeframe(): string | null {
    if (timeframe !== 'custom') return timeframe
    if (!customRange) return null
    return `custom:${customRange.startIso}..${customRange.endIso}`
  }
  const canRun = !loading && (timeframe !== 'custom' || !!customRange)

  // Core query runner — takes explicit kql + wire-format timeframe so
  // callers (handleRun, jumpToFlaggedEvent) can run a query that's
  // different from the current state without fighting setState async-ness.
  async function runKql(kqlText: string, tfWire: string) {
    if (loading) return
    // Replace any previous controller and start fresh. handleStop
    // grabs whatever's in this ref to cancel.
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    setLoading(true)
    setResult(null)
    setExpanded(new Set())
    setRowFlags(new Map())
    setPageIndex(0)
    try {
      const res = await runHunt({ kql: kqlText, timeframe: tfWire }, controller.signal)
      if (controller.signal.aborted) return  // user hit Stop; ignore late result
      setResult(res)
      const rehydrated = new Map<number, FlagStatus>()
      res.rows.forEach((row, i) => {
        const f = getHuntFlag(row)
        if (f !== null) rehydrated.set(i, f)
      })
      if (rehydrated.size > 0) setRowFlags(rehydrated)
      recordHistory({
        kql: kqlText, timeframe: tfWire, ranAt: Date.now(),
        rowCount: res.ok ? res.row_count : null,
        durationMs: res.duration_ms ?? null,
        ok: res.ok,
      })
    } catch (e) {
      // Cancellation is not an error — clear the loading state and
      // show an empty results area with a brief notice.
      const aborted = (e as { name?: string })?.name === 'AbortError'
                     || controller.signal.aborted
      if (aborted) {
        setResult({
          ok: false,
          error_message: 'Query cancelled.',
          rows: [], columns: [], row_count: 0, duration_ms: 0,
        })
      } else {
        setResult({
          ok: false,
          error_message: friendlyError(e),
          rows: [], columns: [], row_count: 0, duration_ms: 0,
        })
        recordHistory({
          kql: kqlText, timeframe: tfWire, ranAt: Date.now(),
          rowCount: null, durationMs: null, ok: false,
        })
      }
    } finally {
      if (abortRef.current === controller) abortRef.current = null
      setLoading(false)
    }
  }

  function handleStop() {
    abortRef.current?.abort()
  }

  // Push a new entry to the front of history, dedupe by (kql, timeframe)
  // so re-running the same query just bumps its timestamp instead of
  // filling the list with duplicates.
  function recordHistory(entry: HistoryEntry) {
    setHistory(prev => {
      const filtered = prev.filter(e => !(e.kql === entry.kql && e.timeframe === entry.timeframe))
      const next = [entry, ...filtered].slice(0, HISTORY_MAX)
      saveHistory(next)
      return next
    })
  }

  // Honour an external jump request — e.g. from a Timeline row click.
  // Mirrors the popover-jump flow but the request comes in via a prop
  // when the analyst is being navigated TO the Hunt tab.
  useEffect(() => {
    if (!pendingRequest) return
    setKql(pendingRequest.kql)
    if (pendingRequest.customRange) {
      setCustomRange(pendingRequest.customRange)
      setTimeframe('custom')
    } else if (pendingRequest.timeframe.startsWith('custom:')) {
      const parts = pendingRequest.timeframe.slice('custom:'.length).split('..')
      if (parts.length === 2) {
        setCustomRange({ startIso: parts[0], endIso: parts[1] })
        setTimeframe('custom')
      }
    } else if (['24h', '7d', '14d', '30d'].includes(pendingRequest.timeframe)) {
      setTimeframe(pendingRequest.timeframe as HuntTimeframe)
    }
    if (pendingRequest.targetRow) {
      // Only surface the "Loading event…" banner when we actually intend
      // to navigate to a specific row — otherwise (e.g. an IOC sweep
      // from the IOCs page) there's no row to chase and the banner
      // would never clear.
      setPendingJumpRow(pendingRequest.targetRow)
      setJumpStatus('Loading event from timeline…')
    } else {
      setJumpStatus(null)
    }
    runKql(pendingRequest.kql, pendingRequest.timeframe)
    onRequestConsumed?.()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingRequest])

  function rerunFromHistory(entry: HistoryEntry) {
    setKql(entry.kql)
    if (entry.timeframe.startsWith('custom:')) {
      const parts = entry.timeframe.slice('custom:'.length).split('..')
      if (parts.length === 2) {
        setCustomRange({ startIso: parts[0], endIso: parts[1] })
        setTimeframe('custom')
      }
    } else if (entry.timeframe === '24h' || entry.timeframe === '7d' ||
               entry.timeframe === '14d' || entry.timeframe === '30d') {
      setTimeframe(entry.timeframe)
    }
    runKql(entry.kql, entry.timeframe)
  }

  async function handleRun() {
    const tf = serialiseTimeframe()
    if (!tf) {
      setResult({
        ok: false,
        error_message: 'Pick a custom range from the calendar before running.',
        rows: [], columns: [], row_count: 0, duration_ms: 0,
      })
      return
    }
    await runKql(kql, tf)
  }

  function handleClear() {
    setKql('')
    setResult(null)
    setExpanded(new Set())
    setRowFlags(new Map())
    textareaRef.current?.focus()
  }

  function toggleExpand(i: number) {
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(i)) next.delete(i); else next.add(i)
      return next
    })
  }
  function cycleRowFlag(i: number) {
    setRowFlags(prev => {
      const cur = prev.get(i) ?? null
      const nextFlag = cycleFlag(cur)
      const next = new Map(prev)
      if (nextFlag === null) next.delete(i); else next.set(i, nextFlag)
      // Mirror into the module-level store, but ONLY for evidence-worthy
      // flags (suspicious / malicious). 'benign' means "I've reviewed
      // this and it's fine" — there's no reason to feed it into the AI
      // Analyse payload, so we leave it as a purely visual marker.
      const row = result?.rows[i]
      if (row) {
        if (nextFlag === 'malicious' || nextFlag === 'suspicious') {
          // Capture the query context so the popover can jump back to
          // this exact event even after the analyst runs a different KQL.
          const tf = serialiseTimeframe() ?? timeframe
          setHuntFlag(row, nextFlag, { kql, timeframe: tf })
        } else {
          setHuntFlag(row, null)
        }
      }
      return next
    })
  }
  const flaggedCount = rowFlags.size

  async function copyCell(value: unknown) {
    const text = cellToString(value)
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      setToast(`Copied: ${text.length > 40 ? text.slice(0, 40) + '…' : text}`)
    } catch {
      setToast('Copy failed')
    }
  }

  // Cmd/Ctrl+Enter and Shift+Enter from inside the editor both run the
  // query — Shift+Enter mirrors the Defender hunting console. Tab accepts
  // the table-name suggestion when one is active.
  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Tab' && completion && currentWord && !e.shiftKey) {
      e.preventDefault()
      const newKql = kql.slice(0, currentWord.start) + completion + kql.slice(cursor)
      const newCursor = currentWord.start + completion.length
      setKql(newKql)
      setCursor(newCursor)
      // selectionStart isn't updated by setState — push it into the DOM
      // after React's commit so the caret lands at the end of the
      // accepted completion.
      requestAnimationFrame(() => {
        const ta = textareaRef.current
        if (ta) { ta.selectionStart = newCursor; ta.selectionEnd = newCursor }
      })
      return
    }
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey || e.shiftKey)) {
      e.preventDefault()
      handleRun()
    }
  }

  return (
    <div style={{
      flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0,
      background: 'var(--bg-panel)', fontFamily: 'var(--font-mono)', fontSize: 11,
      position: 'relative',
    }}>
      {/* Title strip */}
      <div style={{
        padding: '8px 14px', borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0,
      }}>
        <span style={{ color: 'var(--accent)', fontWeight: 600, fontSize: 12 }}>▌ hunt</span>
        {persistedFlags.length > 0 && (
          <span
            ref={flagBadgeRef}
            onClick={() => setFlagListOpen(o => !o)}
            title="Hunt-tab flagged events — feed into the AI Analyse payload on the Analysis tab"
            style={{
              color: 'var(--amber)', fontSize: 10.5, fontWeight: 600,
              cursor: 'pointer',
              padding: '2px 8px',
              border: '1px solid rgba(240,179,64,0.4)', borderRadius: 3,
              background: 'rgba(240,179,64,0.08)',
              userSelect: 'none',
              whiteSpace: 'nowrap',
            }}>
            ⚑ {persistedFlags.length} flagged event{persistedFlags.length === 1 ? '' : 's'}
          </span>
        )}
      </div>

      {/* Flagged-events popover — anchored to the badge. Lists every
          event currently in the store regardless of which query the
          analyst was running when they flagged it. */}
      {flagListOpen && persistedFlags.length > 0 && (() => {
        const rect = flagBadgeRef.current?.getBoundingClientRect()
        const POP_W = 460
        const top = (rect?.bottom ?? 50) + 6
        let left = rect?.left ?? 12
        if (left + POP_W > window.innerWidth - 12) {
          left = Math.max(12, window.innerWidth - POP_W - 12)
        }
        return createPortal(
          <>
            <div
              onClick={() => setFlagListOpen(false)}
              style={{ position: 'fixed', inset: 0, zIndex: 9998 }}
            />
            <div style={{
              position: 'fixed', top, left, zIndex: 9999, width: POP_W,
              background: 'var(--bg-panel)', border: '1px solid var(--border)',
              borderRadius: 6, boxShadow: '0 6px 24px rgba(0,0,0,0.55)',
              fontFamily: 'var(--font-mono)', fontSize: 11,
              maxHeight: '60vh', display: 'flex', flexDirection: 'column',
            }}>
              <div style={{
                padding: '10px 14px', borderBottom: '1px solid var(--border)',
                display: 'flex', alignItems: 'center', gap: 10,
              }}>
                <span style={{ color: 'var(--amber)', fontWeight: 600 }}>
                  ⚑ {persistedFlags.length} flagged hunt event{persistedFlags.length === 1 ? '' : 's'}
                </span>
                <span style={{ flex: 1 }} />
                <span
                  onClick={() => { clearHuntFlags(); setRowFlags(new Map()); setFlagListOpen(false) }}
                  title="Remove all flagged hunt events"
                  style={{
                    color: 'var(--text-muted)', fontSize: 10, cursor: 'pointer',
                    padding: '2px 6px', borderRadius: 2,
                    border: '1px solid var(--border)',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.color = 'var(--red)'; e.currentTarget.style.borderColor = 'var(--red)' }}
                  onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}>
                  clear all
                </span>
              </div>
              <div style={{ overflowY: 'auto', padding: '4px 0' }}>
                {persistedFlags.map(entry => {
                  const r = entry.row
                  const tsIso = String(r.Timestamp ?? '')
                  const ts = tsIso ? fmtDateTime(tsIso, false) : ''
                  const action = String(r.ActionType ?? '')
                  const dev = String(r.DeviceName ?? '')
                  const file = String(r.FileName ?? r.InitiatingProcessFileName ?? '')
                  const remote = r.RemoteIP ? `${r.RemoteIP}${r.RemotePort ? ':' + r.RemotePort : ''}` : ''
                  const url = String(r.RemoteUrl ?? '')
                  const summary = [action, file, remote, url].filter(Boolean).join(' · ')
                  const colour = HUNT_FLAG_COLOURS[entry.flag] ?? 'var(--amber)'
                  const inCurrent = !!result && (() => {
                    const targetKey = rowContentKey(entry.row)
                    return result.rows.some(r => rowContentKey(r) === targetKey)
                  })()
                  return (
                    <div key={entry.key}
                      onClick={() => jumpToFlaggedEvent(entry)}
                      title={inCurrent ? 'Click to jump to this event' : 'Click to load just this event'}
                      onMouseEnter={e => { e.currentTarget.style.background = 'rgba(168,85,247,0.08)' }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}
                      style={{
                        padding: '8px 14px',
                        borderBottom: '1px solid var(--border-soft)',
                        display: 'flex', alignItems: 'flex-start', gap: 10,
                        cursor: 'pointer',
                        transition: 'background 100ms',
                      }}>
                      <span style={{
                        color: colour, fontSize: 9.5, fontWeight: 700,
                        letterSpacing: 0.4, padding: '2px 6px',
                        border: `1px solid ${colour}`, borderRadius: 2,
                        textTransform: 'uppercase', flexShrink: 0,
                        background: `${colour}1A`,
                      }}>{entry.flag}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ color: 'var(--text)', fontSize: 11, wordBreak: 'break-all' }}>
                          {summary || '(empty row)'}
                        </div>
                        <div style={{ color: 'var(--text-muted)', fontSize: 10, marginTop: 2 }}>
                          {[ts, dev].filter(Boolean).join(' · ')}
                          {!inCurrent && entry.kql && (
                            <span style={{ color: 'var(--text-muted)', fontStyle: 'italic', marginLeft: 6 }}>
                              · (loads just this event)
                            </span>
                          )}
                        </div>
                      </div>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          setHuntFlag(entry.row, null)
                          if (result) {
                            const targetKey = rowContentKey(entry.row)
                            const idx = result.rows.findIndex(rr => rowContentKey(rr) === targetKey)
                            if (idx >= 0) {
                              setRowFlags(prev => {
                                const n = new Map(prev)
                                n.delete(idx)
                                return n
                              })
                            }
                          }
                        }}
                        title="Remove this flag"
                        style={{
                          background: 'transparent', border: '1px solid var(--border)',
                          borderRadius: 2, color: 'var(--text-muted)', cursor: 'pointer',
                          fontFamily: 'var(--font-mono)', fontSize: 11,
                          padding: '0 6px', lineHeight: 1.4, flexShrink: 0,
                        }}
                        onMouseEnter={e => { e.currentTarget.style.color = 'var(--red)'; e.currentTarget.style.borderColor = 'var(--red)' }}
                        onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}>
                        ×
                      </button>
                    </div>
                  )
                })}
              </div>
            </div>
          </>,
          document.body,
        )
      })()}

      {/* Editor */}
      <div style={{ padding: '10px 14px', flexShrink: 0 }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 14, marginBottom: 8, flexWrap: 'wrap',
        }}>
          <label ref={tfAnchorRef} style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 10.5 }}>timeframe</span>
            <select
              value={timeframe}
              onChange={e => {
                const v = e.target.value as HuntTimeframe
                setTimeframe(v)
                if (v === 'custom') setPickerOpen(true)
                else                setPickerOpen(false)
              }}
              style={{
                background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                borderRadius: 3, color: 'var(--text)', cursor: 'pointer',
                fontFamily: 'var(--font-mono)', fontSize: 10.5, padding: '2px 6px',
                outline: 'none',
              }}>
              {TIMEFRAMES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </label>
          {timeframe === 'custom' && customRange && (
            <span
              onClick={() => setPickerOpen(true)}
              title="Edit custom range"
              style={{
                color: 'var(--text)', cursor: 'pointer',
                fontSize: 10.5, padding: '2px 6px',
                border: '1px dashed var(--border)', borderRadius: 3,
              }}>
              {fmtCustomLabel(customRange.startIso, customRange.endIso)}
            </span>
          )}
          {timeframe === 'custom' && !customRange && (
            <span style={{ color: 'var(--amber)', fontSize: 10.5 }}>
              ⚠ pick a range below
            </span>
          )}
          <span style={{ flex: 1 }} />
          <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
            Tab to accept suggestion · Shift+Enter or Ctrl+Enter to run
          </span>
        </div>

        {/* Floating calendar picker — portal'd to document.body and
            positioned beneath the timeframe select, so it doesn't reflow
            the editor area when it opens. Backdrop swallows outside clicks. */}
        {timeframe === 'custom' && pickerOpen && (() => {
          const rect = tfAnchorRef.current?.getBoundingClientRect()
          const PICKER_W = 320
          const top  = (rect?.bottom ?? 50) + 6
          let left   = rect?.left ?? 12
          if (left + PICKER_W > window.innerWidth - 12) {
            left = Math.max(12, window.innerWidth - PICKER_W - 12)
          }
          return createPortal(
            <>
              <div
                onClick={() => setPickerOpen(false)}
                style={{ position: 'fixed', inset: 0, zIndex: 9998 }}
              />
              <div style={{ position: 'fixed', top, left, zIndex: 9999 }}>
                <RangePicker
                  initialStart={customRange?.startIso}
                  initialEnd={customRange?.endIso}
                  onApply={(startIso, endIso) => {
                    setCustomRange({ startIso, endIso })
                    setPickerOpen(false)
                  }}
                  onCancel={() => setPickerOpen(false)}
                />
              </div>
            </>,
            document.body,
          )
        })()}

        {/* KQL editor: a transparent <textarea> overlaid on a <pre> that
            renders the same text as syntax-highlighted HTML. Height is
            analyst-controlled via the drag bar rendered just below the
            editor — the native CSS `resize: vertical` corner triangle
            was too small to find. A long query scrolls internally
            instead of pushing the results below off-screen. */}
        <div
          style={{
            height: editorHeight,
            minHeight: MIN_EDITOR_HEIGHT,
            maxHeight: MAX_EDITOR_HEIGHT,
            border: '1px solid var(--border)',
            borderRadius: 4,
            background: 'var(--bg-app)',
            overflow: 'auto',
            boxSizing: 'border-box',
          }}>
          <div style={{ position: 'relative', minHeight: '100%' }}>
            <pre
              aria-hidden
              style={{
                margin: 0, padding: '8px 10px',
                minHeight: '100%', boxSizing: 'border-box',
                color: 'var(--text)',
                fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1.55,
                whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                pointerEvents: 'none',
              }}
              // Trailing newline keeps the bottom line height stable when
              // the last keystroke is Enter — without it the wrapper
              // briefly shrinks before the next char arrives. The ghost
              // suffix (table-name completion) is injected at the cursor
              // position by splitting the text and highlighting each half
              // separately — keeps the suggestion visually distinct from
              // committed text without breaking tokenisation.
              dangerouslySetInnerHTML={{
                __html: ghostSuffix
                  ? highlightKql(kql.slice(0, cursor))
                    + `<span style="color:#666;opacity:0.55">${ghostSuffix.replace(/[&<>"']/g, c => ({
                        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
                      }[c] as string))}</span>`
                    + highlightKql(kql.slice(cursor)) + '\n'
                  : highlightKql(kql) + '\n',
              }}
            />
            <textarea
              ref={textareaRef}
              value={kql}
              onChange={e => {
                setKql(e.target.value)
                setCursor(e.target.selectionStart)
              }}
              onSelect={e => setCursor((e.target as HTMLTextAreaElement).selectionStart)}
              onClick={e => setCursor((e.currentTarget).selectionStart)}
              onKeyUp={e => setCursor((e.currentTarget).selectionStart)}
              onKeyDown={onKeyDown}
              spellCheck={false}
              style={{
                position: 'absolute', inset: 0,
                width: '100%', height: '100%',
                padding: '8px 10px', boxSizing: 'border-box',
                background: 'transparent',
                color: 'transparent',
                caretColor: 'var(--text)',
                border: 'none', borderRadius: 4,
                fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1.55,
                outline: 'none', resize: 'none',
                whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                overflow: 'hidden',
              }}
            />
          </div>
        </div>
        <EditorResizeHandle
          height={editorHeight}
          onChange={setEditorHeight}
          min={MIN_EDITOR_HEIGHT}
          max={MAX_EDITOR_HEIGHT}
        />

        <div style={{
          display: 'flex', alignItems: 'center', gap: 8, marginTop: 8,
        }}>
          {loading ? (
            <button
              onClick={handleStop}
              title="Cancel the running query"
              style={{
                background: 'var(--red)', color: '#fff',
                border: 'none', padding: '5px 14px', borderRadius: 3,
                cursor: 'pointer',
                fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
                letterSpacing: 0.4,
              }}>
              ◼ Stop
            </button>
          ) : (
            <button
              onClick={handleRun}
              disabled={!canRun}
              title={!canRun && timeframe === 'custom' ? 'Pick a custom range first' : ''}
              style={{
                background: canRun ? 'var(--accent)' : 'var(--bg-elevated)',
                color: canRun ? '#fff' : 'var(--text-muted)',
                border: 'none', padding: '5px 14px', borderRadius: 3,
                cursor: canRun ? 'pointer' : 'default',
                fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600,
                letterSpacing: 0.4,
              }}>
              Run ▸
            </button>
          )}
          <button
            onClick={handleClear}
            disabled={loading}
            style={{
              background: 'transparent', color: 'var(--text-muted)',
              border: '1px solid var(--border)', padding: '4px 12px', borderRadius: 3,
              cursor: loading ? 'default' : 'pointer',
              fontFamily: 'var(--font-mono)', fontSize: 10.5,
            }}
            onMouseEnter={e => { if (!loading) { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' } }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-muted)' }}>
            Clear
          </button>
          <span style={{ flex: 1 }} />
          {result && result.ok && (() => {
            const total = result.row_count
            const pageCount = Math.max(1, Math.ceil(total / pageSize))
            const safePage  = Math.min(pageIndex, pageCount - 1)
            const start = safePage * pageSize
            const end   = Math.min(start + pageSize, total)
            return (
              <span style={{
                color: 'var(--text-muted)', fontSize: 10.5,
                display: 'inline-flex', alignItems: 'center', gap: 8, flexWrap: 'wrap',
              }}>
                <span>
                  {total > 0 ? `${start + 1}–${end} of ${total}` : '0'} row{total === 1 ? '' : 's'}
                  {result.truncated ? ` (truncated)` : ''} · {result.duration_ms} ms
                  {flaggedCount > 0 && (
                    <>
                      {' '}·{' '}
                      <span style={{ color: 'var(--amber)' }}>
                        {flaggedCount} flagged
                      </span>
                    </>
                  )}
                </span>
                {pageCount > 1 && (
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                    marginLeft: 4,
                  }}>
                    <PagerBtn disabled={safePage === 0}
                      onClick={() => setPageIndex(0)} title="First page">«</PagerBtn>
                    <PagerBtn disabled={safePage === 0}
                      onClick={() => setPageIndex(p => Math.max(0, p - 1))} title="Previous page">‹</PagerBtn>
                    <span style={{ color: 'var(--text)', minWidth: 60, textAlign: 'center' }}>
                      {safePage + 1} / {pageCount}
                    </span>
                    <PagerBtn disabled={safePage >= pageCount - 1}
                      onClick={() => setPageIndex(p => Math.min(pageCount - 1, p + 1))} title="Next page">›</PagerBtn>
                    <PagerBtn disabled={safePage >= pageCount - 1}
                      onClick={() => setPageIndex(pageCount - 1)} title="Last page">»</PagerBtn>
                  </span>
                )}
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ color: 'var(--text-muted)' }}>page size</span>
                  <select
                    value={pageSize}
                    onChange={e => { setPageSize(parseInt(e.target.value, 10)); setPageIndex(0) }}
                    style={{
                      background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                      borderRadius: 2, color: 'var(--text)', cursor: 'pointer',
                      fontFamily: 'var(--font-mono)', fontSize: 10.5, padding: '0 4px',
                      outline: 'none',
                    }}>
                    {PAGE_SIZE_OPTIONS.map(n => <option key={n} value={n}>{n}</option>)}
                  </select>
                </span>
              </span>
            )
          })()}
        </div>
      </div>

      {/* Results / error */}
      <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        {loading ? (
          <div style={{
            flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--accent)', fontSize: 11,
          }}>
            ▌ running query…
          </div>
        ) : !result ? (
          <HistoryPanel
            history={history}
            onRerun={rerunFromHistory}
            onClear={() => { setHistory([]); saveHistory([]) }}
          />
        ) : !result.ok ? (
          <div style={{ padding: '14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div style={{
              background: 'rgba(255,94,91,0.08)', border: '1px solid rgba(255,94,91,0.35)',
              borderRadius: 4, color: 'var(--red)', padding: '10px 12px', fontSize: 11.5,
              lineHeight: 1.5,
            }}>
              ✗ {result.error_message || 'Query failed.'}
            </div>
            {result.executed_kql && (
              <details style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>
                <summary style={{ cursor: 'pointer', padding: '3px 0' }}>executed KQL</summary>
                <pre style={{
                  background: 'var(--bg-app)', border: '1px solid var(--border)',
                  borderRadius: 3, padding: '8px 10px', margin: '4px 0 0',
                  whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                  color: 'var(--text)', fontSize: 10.5,
                }}>{result.executed_kql}</pre>
              </details>
            )}
          </div>
        ) : result.rows.length === 0 ? (
          <div style={{
            flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: 'var(--text-muted)', fontSize: 11, flexDirection: 'column', gap: 6,
          }}>
            <span>Query returned no rows in the chosen timeframe.</span>
            <span style={{ fontSize: 10 }}>{result.duration_ms} ms</span>
          </div>
        ) : (
          <>
            {result.truncated && (
              <div style={{
                padding: '8px 14px',
                background: 'rgba(240,179,64,0.10)',
                borderTop: '1px solid rgba(240,179,64,0.35)',
                borderBottom: '1px solid rgba(240,179,64,0.25)',
                color: 'var(--amber)', fontSize: 10.5, lineHeight: 1.5,
                display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0,
              }}>
                <span style={{ fontWeight: 600 }}>⚠ Result truncated</span>
                <span style={{ color: 'var(--text-muted)' }}>
                  Showing the first {result.row_count} rows. Add a tighter time
                  filter, a more specific <code style={{ color: 'var(--text)' }}>| where</code>, or a
                  smaller <code style={{ color: 'var(--text)' }}>| take N</code> to narrow the result.
                </span>
              </div>
            )}
            {(() => {
              const pageCount = Math.max(1, Math.ceil(result.row_count / pageSize))
              const safePage  = Math.min(pageIndex, pageCount - 1)
              const start = safePage * pageSize
              const end   = Math.min(start + pageSize, result.rows.length)
              return (
                <ResultsTable
                  columns={result.columns}
                  rows={result.rows.slice(start, end)}
                  startIndex={start}
                  onCellClick={copyCell}
                  expanded={expanded}
                  onToggleExpand={toggleExpand}
                  rowFlags={rowFlags}
                  onCycleFlag={cycleRowFlag}
                  flashRow={flashRow}
                />
              )
            })()}
          </>
        )}
      </div>

      {/* Toast */}
      {toast && (
        <div style={{
          position: 'absolute', bottom: 16, left: '50%', transform: 'translateX(-50%)',
          background: 'var(--bg-elevated)', border: '1px solid var(--border)',
          borderRadius: 4, color: 'var(--text)', padding: '6px 12px',
          fontSize: 11, boxShadow: '0 4px 16px rgba(0,0,0,0.45)',
          pointerEvents: 'none',
        }}>{toast}</div>
      )}
      {jumpStatus && (
        <div style={{
          position: 'absolute', bottom: 16, left: '50%', transform: 'translateX(-50%)',
          background: 'var(--bg-elevated)', border: '1px solid var(--accent)',
          borderRadius: 4, color: 'var(--accent)', padding: '6px 14px',
          fontSize: 11, boxShadow: '0 4px 16px rgba(0,0,0,0.45)',
          pointerEvents: 'none', fontFamily: 'var(--font-mono)',
        }}>{jumpStatus}</div>
      )}
    </div>
  )
}

function ResultsTable({
  columns, rows, onCellClick,
  expanded, onToggleExpand,
  rowFlags, onCycleFlag,
  flashRow,
  startIndex = 0,
}: {
  columns: string[]
  rows: Record<string, unknown>[]
  onCellClick: (v: unknown) => void
  expanded: Set<number>
  onToggleExpand: (i: number) => void
  rowFlags: Map<number, FlagStatus>
  onCycleFlag: (i: number) => void
  flashRow?: number | null
  // Absolute index of the first visible row in the underlying result set,
  // used to keep rowFlags / expanded keys aligned across pages.
  startIndex?: number
}) {
  const totalCols = columns.length + 2 // expand + flag pinned columns
  return (
    <div style={{
      flex: 1, minHeight: 0, overflow: 'auto',
      borderTop: '1px solid var(--border)',
    }}>
      <table style={{
        borderCollapse: 'separate', borderSpacing: 0, fontSize: 11,
        fontFamily: 'var(--font-mono)', width: 'max-content', minWidth: '100%',
      }}>
        <thead>
          <tr>
            <th style={{ ...stickyHeaderCell, width: 28, paddingLeft: 6, paddingRight: 0 }} />
            <th style={{ ...stickyHeaderCell, width: 36, paddingLeft: 4, paddingRight: 4, textAlign: 'center' }}>⚑</th>
            {columns.map(c => (
              <th key={c} style={stickyHeaderCell}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, localIdx) => {
            const i = startIndex + localIdx
            const isOpen = expanded.has(i)
            const flag = rowFlags.get(i) ?? null
            const flagColour = flag ? HUNT_FLAG_COLOURS[flag] : null
            const isFlash = flashRow === i
            const rowBg = isFlash
              ? 'rgba(168,85,247,0.28)'
              : flagColour
                ? `linear-gradient(${flagColour}1F, ${flagColour}1F), ${i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.012)'}`
                : (i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.012)')
            return (
              <React.Fragment key={i}>
                <tr id={`hunt-row-${i}`} style={{
                  background: rowBg,
                  transition: 'background 250ms',
                }}>
                  <td style={{
                    ...cellBase, width: 28, paddingLeft: 6, paddingRight: 0, cursor: 'pointer',
                    color: 'var(--text-muted)', textAlign: 'center',
                    borderLeft: flagColour ? `3px solid ${flagColour}` : '3px solid transparent',
                  }}
                    onClick={() => onToggleExpand(i)}
                    title={isOpen ? 'Collapse row' : 'Expand row to see all fields'}>
                    <span style={{ fontSize: 12, color: isOpen ? 'var(--accent)' : 'var(--text-muted)' }}>
                      {isOpen ? '▾' : '▸'}
                    </span>
                  </td>
                  <td style={{
                    ...cellBase, width: 36, paddingLeft: 4, paddingRight: 4, textAlign: 'center',
                  }}>
                    <button
                      onClick={() => onCycleFlag(i)}
                      title={flag ? `Flagged: ${flag} — click to cycle` : 'Click to flag this event'}
                      onMouseDown={e => e.preventDefault()}
                      style={{
                        background: 'transparent',
                        border: `1px solid ${flagColour ?? 'var(--border)'}`,
                        color: flagColour ?? 'var(--text-muted)',
                        borderRadius: 3, cursor: 'pointer',
                        fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1,
                        padding: '2px 5px', outline: 'none', userSelect: 'none',
                      }}>⚑</button>
                  </td>
                  {columns.map(c => {
                    const v = row[c]
                    const display = cellToString(v)
                    return (
                      <td
                        key={c}
                        onClick={() => onCellClick(v)}
                        title={display.length > 80 ? `${display}\n\n(click to copy)` : 'click to copy'}
                        style={{
                          ...cellBase,
                          cursor: 'pointer',
                          maxWidth: 360,
                          overflow: 'hidden', textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}>
                        {display === '' ? <span style={{ color: 'var(--text-muted)' }}>—</span> : display}
                      </td>
                    )
                  })}
                </tr>
                {isOpen && (
                  <tr style={{ background: flagColour ? `${flagColour}10` : 'var(--bg-app)' }}>
                    <td style={{
                      borderLeft: flagColour ? `3px solid ${flagColour}` : '3px solid transparent',
                      borderBottom: '1px solid var(--border)',
                    }} />
                    <td colSpan={totalCols - 1} style={{
                      borderBottom: '1px solid var(--border)',
                      padding: '10px 16px',
                    }}>
                      {/* The expanded TD spans the FULL table width (many
                          columns wide → often far past the viewport). Without
                          this sticky+maxWidth wrapper, the inner grid would
                          stretch to the TD's width and the button column
                          would land thousands of pixels off-screen to the
                          right. sticky+left:0 anchors the expanded panel to
                          the visible viewport even when the table is scrolled
                          horizontally. */}
                      <div style={{
                        position: 'sticky',
                        left: 16,
                        maxWidth: 'calc(100vw - 80px)',
                        display: 'grid',
                        gridTemplateColumns: 'minmax(140px, max-content) 1fr',
                        rowGap: 6, columnGap: 18,
                        alignItems: 'start',
                        fontSize: 11, lineHeight: 1.55,
                      }}>
                        {columns.map(c => {
                          const v = row[c]
                          const display = cellToString(v)
                          const ioc = detectIoc(c, display)
                          return (
                            <React.Fragment key={c}>
                              <span style={{
                                color: 'var(--text-muted)',
                                wordBreak: 'break-all',
                                paddingRight: 6,
                              }}>{c}</span>
                              <span style={{ minWidth: 0 }}>
                                <span
                                  onClick={() => onCellClick(v)}
                                  title="click to copy"
                                  style={{
                                    color: 'var(--text)', cursor: 'pointer',
                                    wordBreak: 'break-all',
                                  }}>
                                  {display === '' ? <span style={{ color: 'var(--text-muted)' }}>—</span> : display}
                                </span>
                                {ioc && (
                                  <span style={{
                                    display: 'inline-flex', alignItems: 'center',
                                    gap: 6, marginLeft: 10, verticalAlign: 'middle',
                                  }}>
                                    <IocAddButton
                                      ioc={ioc.value}
                                      iocType={ioc.type}
                                      hashType={ioc.type === 'hash' ? ioc.hashType : undefined}
                                    />
                                    {/* VirusTotal doesn't index command lines,
                                        so the lookup button is hidden for
                                        cmdline-typed cells. The "+ IOC"
                                        toggle is the only useful action. */}
                                    {ioc.type !== 'cmdline' && (
                                      <VtButton
                                        ioc={ioc.value}
                                        iocType={ioc.type}
                                        hashType={ioc.type === 'hash' ? ioc.hashType : undefined}
                                      />
                                    )}
                                  </span>
                                )}
                              </span>
                            </React.Fragment>
                          )
                        })}
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

const stickyHeaderCell: React.CSSProperties = {
  position: 'sticky', top: 0, zIndex: 1,
  background: 'var(--bg-elevated)',
  color: 'var(--accent)', fontWeight: 600,
  padding: '6px 10px', textAlign: 'left',
  borderBottom: '1px solid var(--border)',
  borderRight: '1px solid var(--border-soft)',
  whiteSpace: 'nowrap',
}

const cellBase: React.CSSProperties = {
  padding: '4px 10px',
  borderBottom: '1px solid var(--border-soft)',
  borderRight: '1px solid var(--border-soft)',
  color: 'var(--text)',
  verticalAlign: 'top',
}

function PagerBtn({ disabled, onClick, title, children }: {
  disabled: boolean; onClick: () => void; title: string; children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      style={{
        background: 'transparent',
        color: disabled ? 'var(--text-muted)' : 'var(--text)',
        border: '1px solid var(--border)',
        borderRadius: 2,
        cursor: disabled ? 'default' : 'pointer',
        fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1,
        padding: '0 6px', minWidth: 18,
      }}
      onMouseEnter={e => { if (!disabled) { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.color = 'var(--accent)' } }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = disabled ? 'var(--text-muted)' : 'var(--text)' }}>
      {children}
    </button>
  )
}

// Previous-queries panel shown in the results area before any query has
// been run this session. Click any entry to load it into the editor and
// run it. Persisted via localStorage so history survives reloads.
function HistoryPanel({
  history, onRerun, onClear,
}: {
  history: HistoryEntry[]
  onRerun: (e: HistoryEntry) => void
  onClear: () => void
}) {
  // Per-entry expanded state — keyed by index. Collapsed by default so
  // the panel stays scannable; click chevron (or the meta row) to
  // reveal the full KQL. Top "expand all / collapse all" toggle drives
  // the whole panel.
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const allExpanded = history.length > 0 && expanded.size === history.length
  function toggleOne(i: number) {
    setExpanded(prev => {
      const n = new Set(prev)
      if (n.has(i)) n.delete(i); else n.add(i)
      return n
    })
  }
  function toggleAll() {
    if (allExpanded) setExpanded(new Set())
    else             setExpanded(new Set(history.map((_, i) => i)))
  }
  if (history.length === 0) {
    return (
      <div style={{
        flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: 'var(--text-muted)', fontSize: 11,
      }}>
        Run a query to see results here.
      </div>
    )
  }
  function tfLabel(tf: string): string {
    if (tf.startsWith('custom:')) {
      const parts = tf.slice('custom:'.length).split('..')
      if (parts.length === 2) return fmtCustomLabel(parts[0], parts[1])
      return 'custom'
    }
    const m = TIMEFRAMES.find(t => t.value === tf)
    return m?.label ?? tf
  }
  function ago(ms: number): string {
    const d = Date.now() - ms
    if (d < 60_000) return 'just now'
    if (d < 3_600_000) return `${Math.floor(d / 60_000)}m ago`
    if (d < 86_400_000) return `${Math.floor(d / 3_600_000)}h ago`
    return `${Math.floor(d / 86_400_000)}d ago`
  }
  return (
    <div style={{ flex: 1, minHeight: 0, overflow: 'auto', padding: '12px 14px' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8,
      }}>
        <span style={{ color: 'var(--accent)', fontSize: 11, fontWeight: 600 }}>
          ▌ previous queries
        </span>
        <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
          click to re-run · ▸ to expand
        </span>
        <span style={{ flex: 1 }} />
        <span
          onClick={toggleAll}
          title={allExpanded ? 'Collapse every entry' : 'Expand every entry'}
          style={{
            color: 'var(--text-muted)', fontSize: 10, cursor: 'pointer',
            padding: '2px 6px', borderRadius: 2,
            border: '1px solid var(--border)',
          }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.borderColor = 'var(--accent)' }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}>
          {allExpanded ? 'collapse all' : 'expand all'}
        </span>
        <span
          onClick={onClear}
          title="Clear query history"
          style={{
            color: 'var(--text-muted)', fontSize: 10, cursor: 'pointer',
            padding: '2px 6px', borderRadius: 2,
            border: '1px solid var(--border)',
          }}
          onMouseEnter={e => { e.currentTarget.style.color = 'var(--red)'; e.currentTarget.style.borderColor = 'var(--red)' }}
          onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}>
          clear history
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {history.map((h, i) => {
          const isOpen = expanded.has(i)
          // Single-line collapsed preview of the query so the analyst
          // still sees what it was without expanding.
          const firstLine = h.kql.split('\n')[0]
          return (
            <div key={i}
              style={{
                padding: '6px 10px',
                background: 'var(--bg-app)',
                border: '1px solid var(--border)',
                borderRadius: 4,
                transition: 'border-color 100ms, background 100ms',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent)'; e.currentTarget.style.background = 'rgba(168,85,247,0.06)' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.background = 'var(--bg-app)' }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8,
                fontSize: 10, color: 'var(--text-muted)',
              }}>
                <span
                  onClick={(e) => { e.stopPropagation(); toggleOne(i) }}
                  title={isOpen ? 'Collapse' : 'Expand to see full KQL'}
                  style={{
                    cursor: 'pointer', userSelect: 'none',
                    color: isOpen ? 'var(--accent)' : 'var(--text-muted)',
                    fontSize: 12, lineHeight: 1, width: 12, textAlign: 'center',
                  }}>
                  {isOpen ? '▾' : '▸'}
                </span>
                <span>{tfLabel(h.timeframe)}</span>
                <span>·</span>
                <span>{ago(h.ranAt)}</span>
                {h.ok && h.rowCount != null && (
                  <>
                    <span>·</span>
                    <span style={{ color: 'var(--text)' }}>
                      {h.rowCount} row{h.rowCount === 1 ? '' : 's'}
                    </span>
                  </>
                )}
                {!h.ok && (
                  <>
                    <span>·</span>
                    <span style={{ color: 'var(--red)' }}>failed</span>
                  </>
                )}
                {h.durationMs != null && (
                  <>
                    <span>·</span>
                    <span>{h.durationMs} ms</span>
                  </>
                )}
                <span style={{ flex: 1 }} />
                <span
                  onClick={() => onRerun(h)}
                  title="Load this KQL into the editor and re-run it"
                  style={{
                    cursor: 'pointer', userSelect: 'none',
                    color: 'var(--accent)', fontSize: 10, fontWeight: 600,
                    padding: '1px 6px', borderRadius: 2,
                    border: '1px solid var(--accent)',
                    background: 'rgba(168,85,247,0.10)',
                  }}>
                  re-run ▸
                </span>
              </div>
              {/* Collapsed preview (single line) or full pre when expanded. */}
              {isOpen ? (
                <pre style={{
                  margin: '6px 0 0 20px', color: 'var(--text)', fontSize: 11,
                  fontFamily: 'var(--font-mono)', lineHeight: 1.45,
                  whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                }}>{h.kql}</pre>
              ) : (
                <div
                  onClick={() => toggleOne(i)}
                  title="Click to expand and see the full KQL"
                  style={{
                    margin: '2px 0 0 20px', color: 'var(--text-muted)', fontSize: 10.5,
                    fontFamily: 'var(--font-mono)',
                    whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                    cursor: 'pointer',
                  }}>
                  {firstLine}{h.kql.includes('\n') ? ' …' : ''}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// One-click toggle beside each detected IOC in the expanded row: adds the
// IOC to the IOC list, or removes it if already present. Sits next to the
// VtButton which handles the VirusTotal lookup + add-from-popover flow.
// Added IOCs start with a verdict of 'unknown' and are enriched later if
// the analyst runs a lookup from the IOC List panel.
function IocAddButton({ ioc, iocType, hashType }: {
  ioc: string
  iocType: 'hash' | 'ip' | 'domain' | 'cmdline'
  hashType?: 'sha1' | 'sha256' | 'md5'
}) {
  const [added, setAdded] = useState(() => hasIoc(ioc))
  useEffect(() => { setAdded(hasIoc(ioc)) }, [ioc])
  function onClick(e: React.MouseEvent) {
    e.stopPropagation()
    if (added) {
      removeIoc(ioc)
      setAdded(false)
    } else {
      // If the analyst already ran a VT lookup for this IOC during this
      // session, seed the new entry with the cached verdict + counts
      // instead of writing 'unknown' and losing the result. They were
      // hitting this when looking up a hash in Hunt and then clicking
      // "+ IOC" — the verdict was right there in memory but ignored.
      const cached = getCachedVt(ioc)
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
        padding: '2px 7px',
        whiteSpace: 'nowrap',
      }}>
      {added ? '✓ IOC' : '+ IOC'}
    </button>
  )
}
