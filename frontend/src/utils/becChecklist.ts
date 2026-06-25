// The BEC investigation checklist (doc §3) as static, always-available data.
// This is the core analyst deliverable and works with NO Graph connection —
// enter a UPN (+ optional suspected IP) and you get the phased runbook. Live
// sign-in / hunt data, when Graph is reachable, enriches it but isn't required.
//
// Tags drive the rendering:
//   out-of-band — confirmed done elsewhere; this tool verifies, doesn't execute
//   invariant   — a containment invariant that must KEEP holding (watcher §5)
//   comms       — a staged client communication (MSSP deliverable)
//   optional    — defer-able
//   parallel    — runs alongside other phases, not strictly after

export type ChecklistTag = 'out-of-band' | 'invariant' | 'comms' | 'optional' | 'parallel'

export interface ChecklistItem {
  id:    string
  label: string
  hint?: string
  tags?: ChecklistTag[]
}

export interface ChecklistPhase {
  id:        string
  title:     string
  subtitle?: string
  items:     ChecklistItem[]
}

export const BEC_CHECKLIST: ChecklistPhase[] = [
  {
    id: 'phase0',
    title: 'Phase 1 — Triage & assign',
    subtitle: 'Frame the incident before you dig in.',
    items: [
      { id: 'tr-severity', label: 'Classify severity (low / medium / high) from likely impact — privileged account, finance access, data sensitivity', hint: 'a Global Admin or finance mailbox is high by default' },
      { id: 'tr-owner', label: 'Assign an incident owner and open the case record' },
    ],
  },
  {
    id: 'phase1',
    title: 'Phase 2 — Isolate & contain',
    subtitle: 'Do this immediately, out-of-band — don’t wait for scoping. This tool verifies; it doesn’t execute containment.',
    items: [
      { id: 'p2-revoked', label: 'Sessions / tokens revoked?', hint: 'do this FIRST — disabling the account does NOT kill an already-stolen token; only revoking sessions evicts the live attacker' },
      { id: 'p2-disabled', label: 'Account disabled / sign-in blocked, and staying disabled?', hint: 'prevents re-authentication after the tokens are revoked' },
      { id: 'p2-password', label: 'Password reset to a strong, unique value?', hint: 'pair with the session revoke — a reset alone doesn’t invalidate existing tokens' },
      { id: 'p2-isolate', label: 'If an endpoint is involved, isolate the affected device(s) from the network', hint: 'stops lateral movement / token re-harvesting from the device' },
      { id: 'p2-blockioc', label: 'Block the attacker IOCs tenant-wide (Tenant Allow/Block lists, CA named-location blocks)', hint: 'use the IOC lookups on the access-origin IPs' },
    ],
  },
  {
    id: 'phase2',
    title: "Phase 3 — Identify the attacker's access",
    subtitle: 'Separate the attacker’s sessions from the legitimate user’s.',
    items: [
      { id: 'p1-signins', label: 'Pull sign-in history', hint: 'Entra sign-in logs / AADSignInEventsBeta' },
      { id: 'p1-breakdown', label: 'Review IP / country / ASN / device breakdown vs per-user baseline', hint: 'flag hosting/datacenter ASNs' },
      { id: 'p1-select', label: 'Separate attacker sessions from the user’s; select origin (IP / country)' },
      { id: 'p1-sessions', label: 'Resolve selection to session IDs + time window', hint: 'all downstream hunts scope by session, not raw IP' },
      { id: 'p1-entry', label: 'Characterise the entry: access vector, Identity Protection risk state, MFA satisfied legitimately vs via stolen token (AiTM)' },
    ],
  },
  {
    id: 'phase3',
    title: 'Phase 4 — Scope activity & assess impact',
    subtitle: 'Each item maps to a hunt in the playbook (§4). Drives the eradication list below.',
    items: [
      { id: 'p3-persist', label: 'Persistence: new MFA methods, registered/joined devices, OAuth consent grants, app credentials, SSPR info changes, mailbox delegation / Send-As, privileged or CA-excluded group adds' },
      { id: 'p3-mailbox', label: 'Mailbox manipulation: inbox rules, external forwarding, folder permissions, transport rules, mailbox-audit bypass' },
      { id: 'p3-recon', label: 'Recon: messages/folders read (MailItemsAccessed), files accessed, mailbox/SharePoint searches, GAL enumeration' },
      { id: 'p3-exfil', label: 'Exfiltration: OneDrive/SharePoint downloads, uploads & full-sync, anonymous sharing links, mailbox export, eDiscovery' },
      { id: 'p3-objective', label: 'Action on objectives: mail sent (subjects + attachments), thread hijacking, staged drafts, payment-detail changes, sent-item deletions' },
      { id: 'p3-lateral', label: 'Lateral / blast radius: internal recipients (and whether they clicked), shared mailboxes, Teams messages, PIM role activations' },
      { id: 'p3-antiforensic', label: 'Anti-forensics & defence tampering: deleted mail (incl. Recoverable Items), auto-delete rules, audit/CA/auth-policy disabled' },
      { id: 'p3-tenantsweep', label: 'Sweep the rest of the tenant for the SAME rules / IOCs — are other mailboxes hit by the campaign?' },
    ],
  },
  {
    id: 'phase4',
    title: 'Phase 5 — Eradicate attacker changes',
    subtitle: 'Remove everything Phase 4 surfaced — these survive a password reset, so each must be undone explicitly.',
    items: [
      { id: 'p4-hold', label: 'Enable Litigation Hold / preserve the mailbox & evidence BEFORE remediating', hint: 'do this first so deletions during cleanup don’t destroy evidence' },
      { id: 'p3e-mfa', label: 'Attacker-added MFA methods removed?', hint: 'see the MFA-method findings in Scope' },
      { id: 'p3e-rules', label: 'Malicious inbox rules / external forwarding / transport rules removed?' },
      { id: 'p3e-deleg', label: 'Unauthorised mailbox delegations / Send-As / folder permissions removed?' },
      { id: 'p3e-apps', label: 'Enterprise apps / OAuth grants reviewed; unauthorised ones disabled and their credentials revoked?', hint: 'OAuth grants & added app secrets survive password reset — the #1 missed persistence' },
      { id: 'p3e-sentmail', label: 'Attacker’s sent fraudulent / phishing mail purged (soft-delete / quarantine)?' },
      { id: 'p2-invariants', label: 'Verify the containment invariants still hold (§5)', hint: 'final gate: account disabled AND no session survived the revocation' },
    ],
  },
  {
    id: 'phase-restore',
    title: 'Phase 6 — Restore',
    subtitle: 'Only after eradication is confirmed and the account is verified clean.',
    items: [
      { id: 'rs-confirm', label: 'Confirm no residual threat — no rogue rules, grants, MFA methods or live sessions remain', hint: 're-run Scope and the watcher; they should come back clean' },
      { id: 'rs-mfa', label: 'Re-register the user’s legitimate MFA (the attacker’s methods were removed)' },
      { id: 'rs-reenable', label: 'Re-enable the account once verified clean' },
      { id: 'rs-access', label: 'Restore access to mail / OneDrive / SharePoint / Teams' },
    ],
  },
  {
    id: 'phase-harden',
    title: 'Phase 7 — Harden',
    subtitle: 'Close the gap that let this happen.',
    items: [
      { id: 'hd-mfa', label: 'Enforce phishing-resistant MFA, block legacy auth, tighten Conditional Access (trusted locations / device compliance)' },
      { id: 'hd-safelinks', label: 'Enable Safe Links & Safe Attachments; review anti-phishing policy' },
      { id: 'hd-score', label: 'Review Microsoft Secure Score / CIS M365 benchmark and close the top gaps' },
    ],
  },
  {
    id: 'phase5',
    title: 'Phase 8 — Notify & monitor',
    items: [
      { id: 'p4-recipients', label: 'Contact affected recipients of fraudulent mail — warn them not to act on payment / data requests', hint: 'the BEC payload’s real targets' },
      { id: 'p4-watcher', label: 'Start the “stays-contained” watcher (§5)' },
      { id: 'p4-alerting', label: 'Confirm alerting is live for invariant violations' },
    ],
  },
  {
    id: 'phase6',
    title: 'Phase 9 — Document & post-incident',
    items: [
      { id: 'p5-timeline', label: 'Export timeline' },
      { id: 'p5-evidence', label: 'Compile evidence package' },
      { id: 'p5-affected', label: 'Produce affected-parties / blast-radius list' },
      { id: 'p5-outcome', label: 'Record case outcome (confirmed-compromise scope, or closed-benign with rationale)' },
      { id: 'pi-regulatory', label: 'Regulatory / legal breach notification assessed (GDPR / CCPA / sector) if sensitive data was exposed', hint: 'driven by the exfil / data-accessed findings' },
      { id: 'pi-lessons', label: 'Lessons-learned review held; detection & response gaps captured' },
      { id: 'pi-close', label: 'Close the incident ticket once all actions are complete and documented' },
    ],
  },
  {
    id: 'comms',
    title: 'Client communications',
    subtitle: 'Staged — each fires at a trigger point and runs across phases. AI-drafted, analyst-reviewed before sending.',
    items: [
      { id: 'c-initial', label: 'Initial BEC notification', hint: 'trigger: compromise suspected + containment initiated (Phase 2)', tags: ['comms'] },
      { id: 'c-how', label: 'How the account was compromised', hint: 'trigger: Phase 3 entry characterised', tags: ['comms', 'optional'] },
      { id: 'c-what', label: 'What the attacker did', hint: 'trigger: Phase 4 scoping complete', tags: ['comms'] },
      { id: 'c-final', label: 'Final report / closure', hint: 'trigger: Phase 9 (closure)', tags: ['comms'] },
    ],
  },
]

export const TAG_META: Record<ChecklistTag, { label: string; color: string; title: string }> = {
  'out-of-band': { label: 'OUT-OF-BAND', color: '#7AA8FF', title: 'Confirmed done elsewhere — this tool verifies, it does not execute containment' },
  'invariant':   { label: 'INVARIANT',   color: '#F0B340', title: 'A containment invariant that must keep holding — monitored by the watcher (§5)' },
  'comms':       { label: 'CLIENT COMM',  color: '#A878FF', title: 'A staged client communication (MSSP deliverable), AI-drafted + analyst-reviewed' },
  'optional':    { label: 'OPTIONAL',    color: '#888',    title: 'Defer-able' },
  'parallel':    { label: 'PARALLEL',    color: '#888',    title: 'Runs alongside other phases' },
}
