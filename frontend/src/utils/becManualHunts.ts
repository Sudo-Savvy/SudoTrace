// Manual-hunt fallback for the BEC module: when Graph API access isn't
// available, the analyst runs the same investigation by hand in Microsoft
// Defender Advanced Hunting (KQL). No PowerShell — the only non-KQL step is the
// Purview Audit *portal* for the handful of O365 audit ops that aren't in any
// hunting table without Defender for Cloud Apps.
//
// Queries are pre-filled with the account UPN and window. As the analyst finds
// suspicious IPs in the output, they add them and every query narrows to those.

export interface ManualQuery {
  label: string
  lang: 'kql' | 'text'
  note?: string
  query: string
}

export interface ManualHuntSection {
  title: string
  where: string
  queries: ManualQuery[]
}

export function resolveWindow(timeWindow: string): { start: string; end: string } {
  const now = new Date()
  const iso = (d: Date) => d.toISOString().slice(0, 19) + 'Z'
  if (timeWindow?.startsWith('custom:')) {
    const [s, e] = timeWindow.slice('custom:'.length).split('..')
    if (s && e) return { start: s, end: e }
  }
  const back = (ms: number) => ({ start: iso(new Date(now.getTime() - ms)), end: iso(now) })
  if (timeWindow === 'last24h') return back(24 * 3600_000)
  if (timeWindow === 'last30d') return back(30 * 86_400_000)
  return back(7 * 86_400_000)
}

export function buildManualHunts(upn: string, timeWindow: string, ips: string[] = []): ManualHuntSection[] {
  const { start, end } = resolveWindow(timeWindow)
  const u = (upn || 'user@domain.com').replace(/"/g, '')
  const localPart = u.split('@')[0] || u
  const clean = ips.map(i => i.trim()).filter(Boolean)
  const list = clean.map(i => `"${i}"`).join(', ')
  const kqlIp = clean.length ? `\n| where IPAddress in (${list})` : ''
  const emailIp = clean.length ? `\n| where SenderIPv4 in (${list})` : ''

  return [
    {
      title: 'Advanced Hunting — identity & app access (KQL)',
      where: 'Microsoft Defender portal → Hunting → Advanced hunting → paste & Run',
      queries: [
        {
          label: 'Access-origin triage — sign-ins grouped by IP',
          lang: 'kql',
          note: 'EntraIdSignInEvents (use AADSignInEventsBeta if the GA table is empty)',
          query:
`EntraIdSignInEvents
| where Timestamp between (datetime(${start}) .. datetime(${end}))
| where AccountUpn =~ "${u}"${kqlIp}
| summarize SignIns=count(), Success=countif(ErrorCode==0), Failures=countif(ErrorCode!=0),
            Devices=make_set(DeviceName,5), Trust=make_set(DeviceTrustType,3),
            ClientApps=make_set(ClientAppUsed,5), MFA=make_set(AuthenticationRequirement,3),
            FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
        by IPAddress, Country, City
| order by Failures desc, SignIns desc`,
        },
        {
          label: 'Risky sign-ins (Identity Protection)',
          lang: 'kql',
          query:
`EntraIdSignInEvents
| where Timestamp between (datetime(${start}) .. datetime(${end}))
| where AccountUpn =~ "${u}"${kqlIp}
| where RiskLevelDuringSignIn != 0 or RiskState in ("atRisk","confirmedCompromised")
| project Timestamp, IPAddress, Country, City, RiskLevelDuringSignIn, RiskState, RiskDetail, ClientAppUsed
| order by Timestamp desc`,
        },
        {
          label: 'App / service-principal sign-ins — the consented OAuth app authenticating',
          lang: 'kql',
          note: 'EntraIdSpnSignInEvents — cross-reference the AppId against the consent grant you found',
          query:
`EntraIdSpnSignInEvents
| where Timestamp between (datetime(${start}) .. datetime(${end}))${kqlIp}
| project Timestamp, ServicePrincipalName, AppId, ResourceDisplayName, IPAddress, ErrorCode
| summarize Calls=count(), Resources=make_set(ResourceDisplayName,8), IPs=make_set(IPAddress,8) by ServicePrincipalName, AppId
| order by Calls desc`,
        },
        {
          label: 'Microsoft Graph API activity — app reading mail / directory via Graph',
          lang: 'kql',
          note: 'GraphAPIAuditEvents — catches mailbox read / exfil through a consented app',
          query:
`GraphAPIAuditEvents
| where Timestamp between (datetime(${start}) .. datetime(${end}))
| where RequestUri has "${u}" or RequestUri has "${localPart}"${kqlIp}
| project Timestamp, IPAddress, RequestMethod, RequestUri, AppId, UserAgent
| order by Timestamp desc`,
        },
        {
          label: 'Account context & roles (no-Graph enrichment)',
          lang: 'kql',
          note: 'IdentityInfo — privileged? enabled? what department?',
          query:
`IdentityInfo
| where AccountUpn =~ "${u}"
| project AccountUpn, AccountDisplayName, JobTitle, Department, AccountObjectId, IsAccountEnabled, City, Country
| take 1`,
        },
        {
          label: 'Endpoint logons by the account (if the device is onboarded)',
          lang: 'kql',
          note: 'DeviceLogonEvents — spot endpoint-side token theft / lateral movement',
          query:
`DeviceLogonEvents
| where Timestamp between (datetime(${start}) .. datetime(${end}))
| where AccountUpn =~ "${u}" or AccountName =~ "${localPart}"
| project Timestamp, DeviceName, ActionType, LogonType, RemoteIP, AccountName
| order by Timestamp desc`,
        },
      ],
    },
    {
      title: 'Advanced Hunting — mail, links & objectives (KQL)',
      where: 'Microsoft Defender portal → Hunting → Advanced hunting',
      queries: [
        {
          label: 'Action on objectives — mail sent by the account (+ attachments)',
          lang: 'kql',
          query:
`EmailEvents
| where Timestamp between (datetime(${start}) .. datetime(${end}))
| where SenderFromAddress =~ "${u}"
| where EmailDirection in ("Outbound","Intra-org")${emailIp}
| join kind=leftouter (EmailAttachmentInfo | summarize Attachments=make_set(FileName,10) by NetworkMessageId) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, Subject, DeliveryAction, SenderIPv4, Attachments, NetworkMessageId
| order by Timestamp desc`,
        },
        {
          label: 'Phishing / payment links in the account’s mail',
          lang: 'kql',
          note: 'EmailUrlInfo — the URLs the attacker sent',
          query:
`EmailEvents
| where Timestamp between (datetime(${start}) .. datetime(${end}))
| where SenderFromAddress =~ "${u}" or RecipientEmailAddress =~ "${u}"
| join kind=inner EmailUrlInfo on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url, UrlDomain
| order by Timestamp desc`,
        },
        {
          label: 'Blast radius — who clicked the malicious links',
          lang: 'kql',
          note: 'UrlClickEvents — Safe Links click-throughs by recipients',
          query:
`UrlClickEvents
| where Timestamp between (datetime(${start}) .. datetime(${end}))
| where ActionType != "ClickBlocked" or IsClickedThrough != 0
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, IPAddress, NetworkMessageId
| order by Timestamp desc`,
        },
      ],
    },
    {
      title: 'Mailbox & file audit — Purview Audit (portal)',
      where: 'compliance.microsoft.com → Audit → New search. On this tenant (no Defender for Cloud Apps) this is the ONLY place inbox-rule / MailItemsAccessed / file-op data lives — there is no KQL table for it.',
      queries: [
        {
          label: 'Run this audit search in the portal, then Export → CSV',
          lang: 'text',
          query:
`Users:      ${u}
Date range: ${start}  →  ${end}
Activities (Operations) to search:
  Mailbox    New-InboxRule, Set-InboxRule, UpdateInboxRules, Set-Mailbox (forwarding),
             Add-MailboxPermission, Add-MailboxFolderPermission, New-TransportRule, Set-CASMailbox
  Recon      MailItemsAccessed, FileAccessed, SearchQueryInitiatedExchange / SearchQueryInitiatedSharePoint
  Exfil      FileDownloaded, FileUploaded, AnonymousLinkCreated, New-MailboxExportRequest, New-ComplianceSearch
  Forensics  HardDelete, SoftDelete, Set-MailboxAuditBypassAssociation
  Persistence "Consent to application", "Add service principal credentials"

Then Export → CSV and inspect the ClientIP / AuditData column${clean.length ? `; focus on ${clean.join(', ')}` : ''}.`,
        },
        {
          label: 'If — and only if — your tenant HAS Defender for Cloud Apps',
          lang: 'kql',
          note: 'then the same ops are in CloudAppEvents (skip the portal). Empty otherwise — that includes this tenant.',
          query:
`CloudAppEvents
| where Timestamp between (datetime(${start}) .. datetime(${end}))
| where AccountId =~ "${u}"${kqlIp}
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox","Add-MailboxPermission","Add-MailboxFolderPermission","New-TransportRule","MailItemsAccessed","FileAccessed","FileDownloaded","FileUploaded","AnonymousLinkCreated","New-MailboxExportRequest","HardDelete","SoftDelete","Set-MailboxAuditBypassAssociation","Consent to application","Add service principal credentials")
| project Timestamp, ActionType, IPAddress, ObjectName, RawEventData
| order by Timestamp desc`,
        },
      ],
    },
    {
      title: 'Entra directory audit (portal)',
      where: 'Microsoft Entra admin center — no PowerShell',
      queries: [
        {
          label: 'Persistence & defence tampering by the account',
          lang: 'text',
          query:
`Entra admin center → Users → ${u}
  → Sign-in logs   (origins / device / MFA / risk)
  → Audit logs     (MFA-method registration, device joins, role adds, app consents,
                    Conditional Access / authentication-policy changes)
Window: ${start}  →  ${end}${clean.length ? `\nFocus IPs: ${clean.join(', ')}` : ''}`,
        },
      ],
    },
  ]
}
