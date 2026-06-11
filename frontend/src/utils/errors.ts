// Centralised translator for error strings shown to the analyst.
// Raw httpx / fetch error text ("ReadTimeout", "HTTPStatusError: 502 Bad Gateway")
// is not analyst-friendly — this maps the common cases into plain English while
// passing through anything we don't recognise unchanged. Better to surface an
// ugly string than to hide a real failure mode by accident.
//
// Used by the degradation banner (sub-fetch failures), Hunt/AI/VT call sites,
// and the welcome-screen lookup. Backend already produces friendly text for
// the few errors that are *deliberately* analyst-facing (e.g. the Graph 403
// permission message); this helper handles the residue.

export function friendlyError(raw: unknown): string {
  const s = raw instanceof Error ? raw.message : String(raw ?? '').trim()
  if (!s) return 'Unknown error.'
  if (s === 'CREDENTIALS_MISSING') {
    return 'MDE credentials are not configured. Open Settings to add them.'
  }
  if (/timed?\s*out|ReadTimeout|ConnectTimeout|WriteTimeout/i.test(s)) {
    return 'Microsoft Graph did not respond in time. Try again in a moment.'
  }
  if (/Failed to fetch|NetworkError|ConnectError|getaddrinfo|EAI_AGAIN|ENOTFOUND/i.test(s)) {
    return 'Could not reach the server. Check the host’s network connection.'
  }
  if (/\b403\b/.test(s) || /permission/i.test(s)) {
    // Backend already crafts a useful 403 message for the Graph permission
    // case (which app role is missing, where to grant consent). Pass it
    // through verbatim rather than collapsing to a generic line.
    return s
  }
  if (/\b401\b/.test(s) || /unauthori[sz]ed/i.test(s)) {
    return 'Authentication was rejected. Re-check the app credentials in Settings.'
  }
  if (/\b429\b|throttl|rate.?limit/i.test(s)) {
    return 'Microsoft Graph throttled the request. Wait a moment, then retry.'
  }
  if (/\b5\d\d\b|InternalServerError|BadGateway|ServiceUnavailable|GatewayTimeout/i.test(s)) {
    return 'Microsoft Graph returned a server error. Retry usually helps within a minute.'
  }
  if (/JSON|Unexpected token/i.test(s)) {
    return 'The server response was malformed. Try the request again.'
  }
  return s
}
