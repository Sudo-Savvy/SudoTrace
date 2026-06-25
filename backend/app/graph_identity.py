"""
Identity-plane Microsoft Graph calls for the BEC / account-compromise module.

Kept separate from graph.py (which is the endpoint/advanced-hunting surface)
because this reaches Graph endpoints that are NOT the Security hunting query:
  - /users/{id}                       (Directory.Read.All)
  - /auditLogs/signIns                (AuditLog.Read.All)
Both go through the shared, retried `graph_request` helper from graph.py so
they inherit 429/5xx backoff and the off-host nextLink guard.

Sign-ins use the beta endpoint deliberately — it exposes the richer fields the
triage needs (autonomousSystemNumber, sessionId, authenticationDetails,
riskState) that v1.0 doesn't reliably return.
"""
import time
import asyncio
import logging
from datetime import datetime, timedelta
from urllib.parse import quote

from app.graph import graph_request, _is_graph_url, run_hunting_query

log = logging.getLogger(__name__)

GRAPH_V1   = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"

# Curated set of cloud/hosting/datacenter autonomous systems. A consumer
# residential sign-in should not originate from these; an interactive sign-in
# from one is a strong "this is automation / a proxy" tell (the doc calls out
# Azure / AWS / OVH explicitly). Not exhaustive — extend as new hosters show
# up in real cases. ASN number -> human label.
HOSTING_ASNS: dict[int, str] = {
    8075:   "Microsoft Azure",
    8068:   "Microsoft",
    16509:  "Amazon AWS",
    14618:  "Amazon AWS",
    15169:  "Google",
    396982: "Google Cloud",
    16276:  "OVH",
    14061:  "DigitalOcean",
    24940:  "Hetzner",
    63949:  "Akamai/Linode",
    20473:  "Vultr/Choopa",
    60781:  "Leaseweb",
    28753:  "Leaseweb",
    9009:   "M247",
    51167:  "Contabo",
    206092: "Internet-Vikings",
    13335:  "Cloudflare",
    62240:  "Clouvider",
    212238: "Datacamp/CDN77",
    49981:  "WorldStream",
    200651: "FlokiNET",
}

# clientAppUsed values that indicate legacy authentication (no modern-auth /
# no MFA enforcement path) — a classic compromise enabler.
_LEGACY_CLIENT_APPS = frozenset({
    "Other clients", "IMAP4", "POP3", "SMTP", "MAPI", "Exchange ActiveSync",
    "Exchange Web Services", "Authenticated SMTP", "AutoDiscover",
    "Offline Address Book", "Exchange Online PowerShell",
})


async def resolve_user(token: str, identifier: str) -> dict | None:
    """Resolve a UPN or object id to the core Entra user fields. Returns None
    on 404 (no such user). Raises PermissionError on 403 (missing
    Directory.Read.All) so the caller can surface a precise message."""
    ident = quote(identifier.strip(), safe="@.")
    url = (
        f"{GRAPH_V1}/users/{ident}"
        "?$select=id,displayName,userPrincipalName,accountEnabled,mail,"
        "jobTitle,createdDateTime,onPremisesSyncEnabled,signInSessionsValidFromDateTime"
    )
    resp = await graph_request("GET", url, token=token, timeout=30.0)
    if resp.status_code == 404:
        return None
    if resp.status_code == 403:
        raise PermissionError(
            "Graph API 403 on /users — the app registration is missing "
            "Directory.Read.All (Application permission). Add it in Entra → "
            "App registrations → API permissions → Microsoft Graph, then Grant "
            "admin consent."
        )
    resp.raise_for_status()
    return resp.json()


# ── Directory-audit persistence hunt (Phase 3 §4) ──────────────────────────
# Entra audit `activityDisplayName` values, grouped into the persistence
# categories the BEC playbook hunts. Matched case-insensitively against the
# start of the operation name so minor wording variants still classify.
_PERSIST_CATEGORIES: list[tuple[str, list[str]]] = [
    # App-credential persistence FIRST — its prefixes are more specific than the
    # generic "add service principal" that new_app/oauth_grant also match.
    ("app_credential", [
        "update application – certificates and secrets management",
        "update application - certificates and secrets management",
        "update application – certificates",
        "update application - certificates",
        "add service principal credentials",
        "add service principal credential",
    ]),
    ("new_app", [
        "add application",
        "add service principal",
    ]),
    ("oauth_grant", [
        "consent to application",
        "add delegated permission grant",
        "add app role assignment grant to user",
        "add oauth2permissiongrant",
    ]),
    ("mfa_method", [
        "user registered security info",
        "user started security info registration",
        "admin registered security info",
        "user changed default security info",
        "user deleted security info",
        "register security info",
    ]),
    ("device", [
        "add registered owner to device",
        "add registered users to device",
        "register device",
        "add device",
    ]),
    ("new_user", [
        "add user",
        "invite external user",
    ]),
    ("credential", [
        "reset password (self-service)",
        "change password (self-service)",
        "reset user password",
        "update user",  # often carries security-info / property changes
        "update stsrefreshtokenvalidfrom timestamp",
    ]),
    ("group_role", [
        "add member to group",
        "add member to role",
        "add eligible member to role",
        "add owner to group",
    ]),
    # ── Defence / policy tampering — weakening the tenant's own controls.
    ("ca_policy", [
        "add conditional access policy",
        "update conditional access policy",
        "delete conditional access policy",
        "add named location",
        "update named location",
        "delete named location",
    ]),
    ("auth_policy", [
        "disable strong authentication",
        "update authentication methods policy",
        "update authorization policy",
        "update security defaults",
        "set company information",
        "update company settings",
    ]),
]

# Which top-level finding bucket each directory-audit sub-category lands in.
# Most are "persistence"; CA / auth-policy tampering is its own "defense" bucket.
_PERSIST_BUCKET: dict[str, str] = {
    "app_credential": "persistence", "new_app": "persistence",
    "oauth_grant": "persistence", "mfa_method": "persistence",
    "device": "persistence", "new_user": "persistence",
    "credential": "persistence", "group_role": "persistence",
    "ca_policy": "defense", "auth_policy": "defense",
}


async def get_directory_audits(token: str, user_id: str, start: datetime, end: datetime,
                               max_pages: int = 20) -> list[dict]:
    """Pull Entra directory audit events initiated BY the account in the window
    (i.e. what the attacker did while using it). Raises PermissionError on 403
    (missing AuditLog.Read.All)."""
    s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    uid = user_id.replace("'", "")
    flt = (f"activityDateTime ge {s} and activityDateTime le {e} "
           f"and initiatedBy/user/id eq '{uid}'")
    url: str | None = f"{GRAPH_V1}/auditLogs/directoryAudits"
    params: dict | None = {"$filter": flt, "$top": "999"}
    out: list[dict] = []
    pages = 0
    while url and pages < max_pages:
        resp = await graph_request("GET", url, token=token, params=params, timeout=60.0)
        if resp.status_code == 403:
            raise PermissionError(
                "Graph API 403 on /auditLogs/directoryAudits — missing "
                "AuditLog.Read.All (Application permission, admin consent), or "
                "the tenant lacks Entra ID P1/P2."
            )
        if resp.status_code == 400:
            # The initiatedBy/user/id filter is occasionally rejected; retry
            # with a time-only window and filter client-side below.
            resp2 = await graph_request(
                "GET", f"{GRAPH_V1}/auditLogs/directoryAudits", token=token,
                params={"$filter": f"activityDateTime ge {s} and activityDateTime le {e}", "$top": "999"},
                timeout=60.0,
            )
            resp2.raise_for_status()
            data = resp2.json()
            for a in data.get("value") or []:
                init = ((a.get("initiatedBy") or {}).get("user") or {}).get("id")
                if init == user_id:
                    out.append(a)
            return out
        resp.raise_for_status()
        data = resp.json()
        out.extend(data.get("value") or [])
        nxt = data.get("@odata.nextLink")
        if nxt and not _is_graph_url(nxt):
            log.warning("Refusing off-host directoryAudits nextLink: %s", nxt)
            nxt = None
        url = nxt
        params = None
        pages += 1
    return out


def _clean_val(v) -> str:
    """Tidy an audit modifiedProperty value: strip wrapping quotes/brackets,
    collapse whitespace, cap length."""
    if v is None:
        return ""
    s = str(v).strip().strip('"').strip("[]").replace('\\"', '"').replace('\\r\\n', ' ')
    s = " ".join(s.split())
    return s[:160]


# Audit-detail keys that are pure noise in a findings view — internal ids,
# provisioning metadata, opaque permission blobs, agent flags. Excluded so the
# detail line shows only what a human needs ("Email: x@y", "Phone: +44…").
_NOISE_KEYS = (
    "transactionid", "initiatedby", "initiatedfrom", "resourceid", "principalid",
    "serviceprincipalprovisioningtype", "consentaction.permissions", "appid",
    "clientid", "included updated properties", "targetid", "key id", "flowtype",
    "correlationid", "user-agent",
)


def _audit_props(audit: dict):
    """Yield (name, value) for every modifiedProperty (preferring newValue) and
    additionalDetail of a directory-audit event, cleaned."""
    for t in (audit.get("targetResources") or []):
        if not isinstance(t, dict):
            continue
        for mp in (t.get("modifiedProperties") or []):
            if isinstance(mp, dict):
                name = (mp.get("displayName") or "").strip()
                val = _clean_val(mp.get("newValue")) or _clean_val(mp.get("oldValue"))
                if name:
                    yield name, val
    for ad in (audit.get("additionalDetails") or []):
        if isinstance(ad, dict):
            yield (ad.get("key") or "").strip(), _clean_val(ad.get("value"))


def _mfa_kind_value(audit: dict) -> tuple[str, str]:
    """Determine the MFA method KIND (Email / Phone / Authenticator / …) and its
    VALUE (email address / phone number) from a security-info audit event. Either
    may be '' — used to collapse the started/registered/duplicate event spam into
    one finding per distinct method."""
    email = phone = mtype = ""
    for name, val in _audit_props(audit):
        low = name.lower()
        if not val:
            continue
        if "email" in low and "@" in val:
            email = val
        elif "phonenumber" in low or ("phone" in low and any(c.isdigit() for c in val)):
            phone = val
        elif low in ("method", "authenticationmethod") or "authenticationmethodtype" in low:
            mtype = val
    t = (mtype or "").lower()
    kind = ""
    if email or "email" in t:
        kind = "Email"
    elif phone or "phone" in t or "sms" in t or "voice" in t:
        kind = "Phone / SMS"
    elif "authenticator" in t or "app" in t:
        kind = "Authenticator app"
    elif "fido" in t or "passkey" in t:
        kind = "FIDO / passkey"
    elif "oath" in t or "token" in t:
        kind = "OATH token"
    elif mtype:
        kind = mtype
    return kind, (email or phone or "")


def _clean_detail(audit: dict) -> str:
    """Concise, human-useful 'what changed' string — noise keys dropped."""
    bits: list[str] = []
    seen: set[str] = set()
    for name, val in _audit_props(audit):
        low = name.lower()
        if not val or any(n in low for n in _NOISE_KEYS):
            continue
        b = f"{name}: {val}"
        if b not in seen:
            seen.add(b)
            bits.append(b)
        if len(bits) >= 3:
            break
    return " · ".join(bits)


def classify_persistence(audits: list[dict]) -> dict[str, list[dict]]:
    """Bucket directory-audit events into persistence + defense findings, then
    DEDUPLICATE:
    Entra emits the same logical action many times (a 'started' + 'registered'
    pair, echoed across load-balancer IPs, padded with internal ids). We collapse
    MFA-method spam into one finding per distinct method, and merge identical
    events elsewhere — each finding notes how many raw events / IPs it covers."""
    raw: list[dict] = []
    for a in audits:
        name = (a.get("activityDisplayName") or "").strip()
        low = name.lower()
        category = None
        for cat, prefixes in _PERSIST_CATEGORIES:
            if any(low.startswith(p) for p in prefixes):
                category = cat
                break
        if not category:
            continue
        targets = a.get("targetResources") or []
        target_label = ""
        if targets and isinstance(targets[0], dict):
            t = targets[0]
            target_label = t.get("displayName") or t.get("userPrincipalName") or t.get("id") or ""
        raw.append({
            "category": category, "activity": name,
            "timestamp": a.get("activityDateTime") or "", "result": a.get("result") or "",
            "target": target_label,
            "ip": ((a.get("initiatedBy") or {}).get("user") or {}).get("ipAddress") or "",
            "audit": a,
        })

    findings: list[dict] = []

    # MFA method changes → one finding per distinct method (Email, Phone, …).
    groups: dict[str, dict] = {}
    for r in (x for x in raw if x["category"] == "mfa_method"):
        kind, value = _mfa_kind_value(r["audit"])
        if not kind and not value:
            continue  # noise duplicate with no method context — drop it
        key = (kind or value).lower()
        g = groups.get(key)
        if not g:
            g = {"kind": kind, "value": value, "ts": r["timestamp"], "ips": set(), "count": 0}
            groups[key] = g
        if r["timestamp"] and (not g["ts"] or r["timestamp"] < g["ts"]):
            g["ts"] = r["timestamp"]
        if value and not g["value"]:
            g["value"] = value
        if kind and not g["kind"]:
            g["kind"] = kind
        if r["ip"]:
            g["ips"].add(r["ip"])
        g["count"] += 1
    for g in groups.values():
        kind = g["kind"] or "MFA method"
        ips = sorted(g["ips"])
        findings.append({
            "category": "mfa_method",
            "activity": f"Registered a new MFA method — {kind}",
            "timestamp": g["ts"], "result": "success", "target": "",
            "initiated_by_ip": ips[0] if ips else "",
            "detail": g["value"], "ip_count": len(ips), "event_count": g["count"],
            "id": f"mfa:{kind}:{g['value']}", "raw": {},
        })

    # Everything else → merge identical (category, activity, detail) events.
    merged: dict[tuple, dict] = {}
    for r in raw:
        if r["category"] == "mfa_method":
            continue
        detail = _clean_detail(r["audit"])
        key = (r["category"], r["activity"].lower(), detail)
        f = merged.get(key)
        if not f:
            f = {
                "category": r["category"], "activity": r["activity"],
                "timestamp": r["timestamp"], "result": r["result"], "target": r["target"],
                "initiated_by_ip": r["ip"], "detail": detail,
                "_ips": set(), "event_count": 0,
                "id": r["audit"].get("id") or "", "raw": r["audit"],
            }
            merged[key] = f
            findings.append(f)
        if r["timestamp"] and r["timestamp"] < f["timestamp"]:
            f["timestamp"] = r["timestamp"]
        if r["ip"]:
            f["_ips"].add(r["ip"])
        f["event_count"] += 1
    for f in findings:
        if "_ips" in f:
            f["ip_count"] = len(f["_ips"])
            if not f["initiated_by_ip"] and f["_ips"]:
                f["initiated_by_ip"] = sorted(f["_ips"])[0]
            del f["_ips"]

    # Split into top-level buckets (persistence vs defense) by sub-category.
    out: dict[str, list[dict]] = {"persistence": [], "defense": []}
    for f in findings:
        out[_PERSIST_BUCKET.get(f["category"], "persistence")].append(f)
    for items in out.values():
        items.sort(key=lambda f: f["timestamp"], reverse=True)
    return out


# ── Unified Audit Log hunt (Phase 3 §4: mailbox manipulation + exfil) ───────
# Reached via the Graph Audit Log Query API (/security/auditLog/queries),
# which is ASYNCHRONOUS: create a query, poll until it succeeds, then read the
# records. Needs AuditLogsQuery.Read.All + audit enabled in the tenant.

# Exchange + SharePoint operations we hunt, by the finding sub-category the UI
# renders. Mailbox-manipulation ops + exfil ops are queried together and split
# client-side.
_UAL_OPERATIONS = [
    # mailbox manipulation
    "New-InboxRule", "Set-InboxRule", "Enable-InboxRule", "Disable-InboxRule",
    "Remove-InboxRule", "UpdateInboxRules", "Set-Mailbox",
    "Add-MailboxPermission", "Add-RecipientPermission",
    "Add-MailboxFolderPermission", "Set-MailboxFolderPermission",
    "New-TransportRule", "Set-TransportRule", "Remove-TransportRule",
    "Set-CASMailbox",
    # recon / data accessed (MailItemsAccessed needs E5 / Audit-Premium mailbox
    # auditing; harmless to request on lower tiers — it just returns nothing)
    "MailItemsAccessed", "MessageBind",
    "FileAccessed", "FileAccessedExtended", "FilePreviewed",
    "SearchQueryInitiatedExchange", "SearchQueryInitiatedSharePoint",
    # exfiltration
    "FileDownloaded", "FileSyncDownloadedFull",
    "AnonymousLinkCreated", "AnonymousLinkUpdated", "SecureLinkCreated",
    "SharingInvitationCreated", "AddedToSecureLink",
    "New-ComplianceSearch", "New-ComplianceSearchAction", "New-MailboxExportRequest",
    # staging / upload
    "FileUploaded", "FileSyncUploadedFull",
    # anti-forensics (incl. blinding the audit trail itself)
    "HardDelete", "SoftDelete", "MoveToDeletedItems",
    "FileDeleted", "FileRecycled",
    "FileDeletedFirstStageRecycleBin", "FileDeletedSecondStageRecycleBin",
    "Set-MailboxAuditBypassAssociation", "Set-AdminAuditLogConfig",
]

_MAILBOX_CATS      = {"inbox_rule", "forwarding", "delegation", "mailbox_config",
                      "folder_perm", "transport_rule", "legacy_protocol"}
_EXFIL_CATS        = {"file_download", "sharing_link", "mailbox_export", "file_upload",
                      "ediscovery"}
_RECON_CATS        = {"mail_read", "file_read", "search"}
_ANTIFORENSIC_CATS = {"mail_delete", "file_delete", "audit_bypass"}

# Sub-category → which top-level finding bucket it lands in.
_UAL_BUCKET: dict[str, str] = {
    **{c: "mailbox" for c in _MAILBOX_CATS},
    **{c: "exfil" for c in _EXFIL_CATS},
    **{c: "recon" for c in _RECON_CATS},
    **{c: "antiforensic" for c in _ANTIFORENSIC_CATS},
}


def _ual_category(operation: str, audit_data: dict | None) -> str:
    o = (operation or "").lower()
    if o in ("new-inboxrule", "set-inboxrule", "enable-inboxrule",
             "disable-inboxrule", "remove-inboxrule", "updateinboxrules"):
        return "inbox_rule"
    if o == "set-mailbox":
        params = (audit_data or {}).get("Parameters") or []
        names = " ".join(str(p.get("Name", "")).lower() for p in params if isinstance(p, dict))
        if "forwarding" in names or "delivertomailboxandforward" in names:
            return "forwarding"
        return "mailbox_config"
    if o in ("add-mailboxpermission", "add-recipientpermission",
             "add-mailboxfolderpermission", "set-mailboxfolderpermission"):
        return "delegation" if o in ("add-mailboxpermission", "add-recipientpermission") else "folder_perm"
    if o in ("new-transportrule", "set-transportrule", "remove-transportrule"):
        return "transport_rule"
    if o == "set-casmailbox":
        return "legacy_protocol"
    # recon / read
    if o in ("mailitemsaccessed", "messagebind"):
        return "mail_read"
    if o in ("fileaccessed", "fileaccessedextended", "filepreviewed"):
        return "file_read"
    if o in ("searchqueryinitiatedexchange", "searchqueryinitiatedsharepoint"):
        return "search"
    # exfiltration
    if o in ("filedownloaded", "filesyncdownloadedfull"):
        return "file_download"
    if o in ("fileuploaded", "filesyncuploadedfull"):
        return "file_upload"
    if o in ("anonymouslinkcreated", "anonymouslinkupdated", "securelinkcreated",
             "sharinginvitationcreated", "addedtosecurelink"):
        return "sharing_link"
    if o in ("new-compliancesearchaction", "new-mailboxexportrequest"):
        return "mailbox_export"
    if o == "new-compliancesearch":
        return "ediscovery"
    # anti-forensics
    if o in ("harddelete", "softdelete", "movetodeleteditems"):
        return "mail_delete"
    if o in ("filedeleted", "filerecycled", "filedeletedfirststagerecyclebin",
             "filedeletedsecondstagerecyclebin"):
        return "file_delete"
    if o in ("set-mailboxauditbypassassociation", "set-adminauditlogconfig"):
        return "audit_bypass"
    return "other"


# Audit Log Query API is ASYNCHRONOUS and can take several minutes to
# materialise on a busy tenant — longer than one request budget. Cache the
# query id per (upn, window) so a re-run RESUMES polling the same query instead
# of spawning a fresh one that restarts the clock. Tenant-scoped ids are safe to
# share across sessions; entries are cleared once the query succeeds or fails.
_UAL_QUERY_CACHE: dict[tuple[str, str], str] = {}


async def query_unified_audit(token: str, upn: str, start: datetime, end: datetime,
                              poll_budget_s: float = 70.0) -> list[dict]:
    """Run a Unified Audit Log query for the account's mailbox/exfil ops in the
    window. Async: create → poll → read records. Raises PermissionError on 403,
    TimeoutError('AUDIT_QUERY_RUNNING') if it doesn't finish within the budget
    (the query id is cached so the next call resumes the same query)."""
    s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    # Key on the stable scope ANCHOR (upn + start). The UI bumps `end` to now()
    # on every run, so including it would never let a re-run rejoin the query.
    cache_key = (upn.lower(), s)

    qid = _UAL_QUERY_CACHE.get(cache_key)
    if not qid:
        body = {
            "displayName": f"sudotrace-bec-{int(time.time())}",
            "filterStartDateTime": s,
            "filterEndDateTime": e,
            "operationFilters": _UAL_OPERATIONS,
            "userPrincipalNameFilters": [upn],
        }
        resp = await graph_request(
            "POST", f"{GRAPH_BETA}/security/auditLog/queries",
            token=token, json_body=body, timeout=30.0,
        )
        if resp.status_code == 403:
            raise PermissionError(
                "Graph API 403 on /security/auditLog/queries — missing "
                "AuditLogsQuery.Read.All (Application permission, admin consent), or "
                "unified audit log isn't enabled / licensed in the tenant."
            )
        if resp.status_code >= 400:
            log.warning("auditLog/queries create %d body: %s", resp.status_code, resp.text[:500])
        resp.raise_for_status()
        qid = resp.json().get("id")
        if not qid:
            raise RuntimeError("Audit query did not return an id.")
        _UAL_QUERY_CACHE[cache_key] = qid

    deadline = time.monotonic() + poll_budget_s
    while time.monotonic() < deadline:
        await asyncio.sleep(4)
        st = await graph_request(
            "GET", f"{GRAPH_BETA}/security/auditLog/queries/{qid}", token=token, timeout=30.0,
        )
        st.raise_for_status()
        status = (st.json().get("status") or "").lower()
        if status == "succeeded":
            break
        if status in ("failed", "cancelled"):
            _UAL_QUERY_CACHE.pop(cache_key, None)
            raise RuntimeError(f"Audit query {status}.")
    else:
        # Out of budget but the query is still running — keep the id so the next
        # Scope picks up where we left off rather than starting over.
        raise TimeoutError("AUDIT_QUERY_RUNNING")

    # Succeeded — done with this query id.
    _UAL_QUERY_CACHE.pop(cache_key, None)

    url: str | None = f"{GRAPH_BETA}/security/auditLog/queries/{qid}/records"
    records: list[dict] = []
    pages = 0
    while url and pages < 20:
        r = await graph_request("GET", url, token=token, timeout=60.0)
        r.raise_for_status()
        data = r.json()
        records.extend(data.get("value") or [])
        nxt = data.get("@odata.nextLink")
        if nxt and not _is_graph_url(nxt):
            nxt = None
        url = nxt
        pages += 1
    return records


def _ual_target(rec: dict, audit: dict) -> str:
    """Best readable target for a UAL record — the file path / message subject /
    folder rather than the raw objectId where we can get it."""
    if isinstance(audit, dict):
        # SharePoint/OneDrive file ops carry a friendly path.
        for k in ("SourceFileName", "ObjectId", "SourceRelativeUrl"):
            v = audit.get(k)
            if v:
                return str(v)[:200]
        # Mailbox access records list folders / item counts.
        folders = (audit.get("Folders") or [])
        if folders and isinstance(folders[0], dict):
            path = folders[0].get("Path")
            n = len(folders[0].get("FolderItems") or [])
            if path:
                return f"{path}" + (f" ({n} item{'s' if n != 1 else ''})" if n else "")
    return rec.get("objectId") or ""


def _ual_detail(cat: str, audit: dict) -> str:
    """Extra context for a UAL finding — file location, sharing target, client —
    so 'File download' becomes 'File download · /sites/Finance/… · shared with …'."""
    if not isinstance(audit, dict):
        return ""
    parts: list[str] = []
    if cat in ("file_read", "file_download", "file_upload", "file_delete", "sharing_link"):
        # Full location of the file (the filename itself is already the target).
        # ObjectId is the complete URL; otherwise stitch the site + folder path.
        obj = str(audit.get("ObjectId") or "")
        if obj.lower().startswith("http"):
            parts.append(obj[:240])
        else:
            site = str(audit.get("SiteUrl") or "").rstrip("/")
            rel = str(audit.get("SourceRelativeUrl") or "").strip("/")
            loc = "/".join(x for x in (site, rel) if x)
            if loc:
                parts.append(loc[:240])
    if cat == "sharing_link":
        who = (audit.get("TargetUserOrGroupName") or audit.get("UserSharedWith")
               or audit.get("EventData") or "")
        if who:
            parts.append(f"shared with {str(who)[:80]}")
    return " · ".join(parts)


def _ual_client(rec: dict, audit: dict) -> tuple[str, str]:
    """Best source IP + client/device string for a UAL record. The IP usually
    lives in auditData (ClientIP / ClientIPAddress / ActorIpAddress), not the
    top-level field, for file/mailbox ops — so dig there."""
    ip = (rec.get("clientIp") or "").strip()
    if isinstance(audit, dict):
        if not ip:
            for k in ("ClientIP", "ClientIPAddress", "ActorIpAddress", "ClientIPAddressV6"):
                v = audit.get(k)
                if v:
                    ip = str(v).strip()
                    break
        # Strip the [v]:port wrapper Exchange sometimes adds, e.g. "[1.2.3.4]:443".
        if ip:
            ip = ip.strip("[]").split("]:")[0].rstrip("]")
            if ip.count(":") == 1 and "." in ip:   # ipv4:port
                ip = ip.split(":")[0]
    device = ""
    if isinstance(audit, dict):
        device = (audit.get("ClientInfoString") or audit.get("DeviceDisplayName")
                  or audit.get("UserAgent") or "")
        device = str(device)[:120]
    return ip, device


def classify_ual(records: list[dict]) -> dict[str, list[dict]]:
    """Bucket UAL records into mailbox / exfil / recon / antiforensic findings,
    deduplicated (same op on the same target collapses, with an event_count).
    Normalised to the persistence finding shape so the UI renders them all the
    same way."""
    buckets: dict[str, dict[tuple, dict]] = {
        "mailbox": {}, "exfil": {}, "recon": {}, "antiforensic": {}
    }
    for rec in records:
        op = rec.get("operation") or ""
        audit = rec.get("auditData") or {}
        if not isinstance(audit, dict):
            audit = {}
        cat = _ual_category(op, audit)
        bucket_name = _UAL_BUCKET.get(cat)
        if not bucket_name:
            continue
        target = _ual_target(rec, audit)
        ts = rec.get("createdDateTime") or ""
        ip, device = _ual_client(rec, audit)
        b = buckets[bucket_name]
        key = (cat, op, target)
        f = b.get(key)
        if not f:
            f = {
                "category": cat, "activity": op, "timestamp": ts, "result": "",
                "target": target, "initiated_by_ip": ip, "device": device,
                "detail": _ual_detail(cat, audit),
                "_ips": set(), "event_count": 0, "id": rec.get("id") or "", "raw": rec,
                "_msg_ids": set(), "access_type": "",
            }
            b[key] = f
        if ts and ts > f["timestamp"]:   # keep the most recent occurrence's time
            f["timestamp"] = ts
        if ip:
            f["_ips"].add(ip)
        if device and not f.get("device"):
            f["device"] = device
        f["event_count"] += 1
        # For mailbox reads, collect the InternetMessageIds of the specific
        # messages the attacker opened so we can resolve them to subjects later.
        if cat == "mail_read":
            at = audit.get("MailAccessType")
            if at and not f["access_type"]:
                f["access_type"] = at
            for fdr in (audit.get("Folders") or []):
                if isinstance(fdr, dict):
                    for it in (fdr.get("FolderItems") or []):
                        mid = isinstance(it, dict) and it.get("InternetMessageId")
                        if mid:
                            f["_msg_ids"].add(mid)

    out: dict[str, list[dict]] = {}
    for name, b in buckets.items():
        items = []
        for f in b.values():
            f["ip_count"] = len(f["_ips"])
            if not f["initiated_by_ip"] and f["_ips"]:
                f["initiated_by_ip"] = sorted(f["_ips"])[0]
            del f["_ips"]
            f["message_ids"] = sorted(f.pop("_msg_ids"))
            items.append(f)
        items.sort(key=lambda x: x["timestamp"], reverse=True)
        out[name] = items
    return out


async def hunt_subjects_for_messages(token: str, message_ids: list[str],
                                     end: datetime) -> dict[str, str]:
    """Resolve a set of InternetMessageIds to their subjects via EmailEvents
    (advanced hunting) — this is what turns 'read 9 items in \\Inbox' into the
    actual subject lines the attacker opened. Best-effort: EmailEvents only
    retains ~30 days and only messages that transited EOP, so some reads
    (older / internal-only) won't resolve. ThreatHunting.Read.All."""
    ids = [m for m in message_ids if m][:150]
    if not ids:
        return {}
    start = end - timedelta(days=30)
    s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    id_list = ", ".join('"' + _kql_str(m) + '"' for m in ids)
    kql = (
        "EmailEvents\n"
        f"| where Timestamp between (datetime({s}) .. datetime({e}))\n"
        f"| where InternetMessageId in ({id_list})\n"
        "| project InternetMessageId, Subject, SenderFromAddress\n"
        "| take 300"
    )
    rows = await run_hunting_query(token, kql)
    out: dict[str, str] = {}
    for r in rows:
        mid = r.get("InternetMessageId")
        if mid and mid not in out:
            subj = (r.get("Subject") or "").strip() or "(no subject)"
            sender = r.get("SenderFromAddress")
            out[mid] = f'{subj}' + (f' — from {sender}' if sender else '')
    return out


# ── Action-on-objectives hunt (Phase 3 §4: outbound mail / thread hijack) ───
# Runs against EmailEvents via advanced hunting (ThreatHunting.Read.All — the
# permission SudoTrace already uses for the endpoint side). Surfaces what the
# attacker DID with the mailbox: mail they sent as the user, and replies/
# forwards into existing threads (thread hijack — the classic BEC payload).

# Reply / forward subject prefixes across common locales. A genuinely NEW
# outbound mail won't carry these; a thread hijack reuses the original subject.
_REPLY_PREFIXES = ("re:", "fw:", "fwd:", "aw:", "wg:", "tr:", "rv:", "sv:", "vs:")


def _kql_str(s: str) -> str:
    """Escape a value for safe embedding in a double-quoted KQL string."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


async def hunt_objective_email(token: str, upn: str, start: datetime,
                               end: datetime, cap: int = 500) -> list[dict]:
    """Pull outbound / intra-org mail sent AS the account in the window from
    EmailEvents. Raises PermissionError on 403 (missing ThreatHunting.Read.All).
    The time bounds are baked in as datetime literals (the whole query is
    constructed here, so this is controlled, not analyst string-injection)."""
    s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    addr = _kql_str(upn.strip())
    kql = (
        "EmailEvents\n"
        f"| where Timestamp between (datetime({s}) .. datetime({e}))\n"
        f'| where SenderFromAddress =~ "{addr}" or SenderMailFromAddress =~ "{addr}"\n'
        '| where EmailDirection in ("Outbound", "Intra-org")\n'
        "| join kind=leftouter (\n"
        "    EmailAttachmentInfo\n"
        f"    | where Timestamp between (datetime({s}) .. datetime({e}))\n"
        "    | summarize Attachments = make_set(FileName, 20) by NetworkMessageId\n"
        "  ) on NetworkMessageId\n"
        "| project Timestamp, NetworkMessageId, SenderFromAddress, "
        "SenderMailFromAddress, RecipientEmailAddress, Subject, EmailDirection, "
        "DeliveryAction, SenderIPv4, ThreatTypes, Attachments\n"
        "| order by Timestamp desc\n"
        f"| take {int(cap)}"
    )
    # run_hunting_query already maps 403 → PermissionError(ThreatHunting…).
    return await run_hunting_query(token, kql)


def _att_list(v) -> list[str]:
    """Normalise the Attachments column (a KQL make_set → JSON array, sometimes
    delivered as a JSON string) into a list of file names."""
    if isinstance(v, list):
        return [str(x) for x in v if x]
    if isinstance(v, str) and v.strip() and v.strip() not in ("[]", "null"):
        try:
            import json as _json
            parsed = _json.loads(v)
            if isinstance(parsed, list):
                return [str(x) for x in parsed if x]
        except Exception:
            return [v.strip()]
    return []


def classify_objective(rows: list[dict]) -> list[dict]:
    """Normalise EmailEvents rows into objective findings, deduplicated by
    message (one email to N recipients is ONE finding), tagging thread hijacks
    vs newly composed mail and surfacing subject, recipients, attachments and
    any threat verdicts."""
    groups: dict[str, dict] = {}
    for r in rows:
        subject = (r.get("Subject") or "").strip()
        low = subject.lower()
        is_hijack = any(low.startswith(p) for p in _REPLY_PREFIXES)
        mid = r.get("NetworkMessageId") or (subject + (r.get("Timestamp") or ""))
        g = groups.get(mid)
        if not g:
            g = {
                "subject": subject, "is_hijack": is_hijack,
                "ts": r.get("Timestamp") or "", "delivery": r.get("DeliveryAction") or "",
                "ip": r.get("SenderIPv4") or "", "id": mid,
                "recipients": set(), "attachments": set(), "threats": set(),
            }
            groups[mid] = g
        if r.get("RecipientEmailAddress"):
            g["recipients"].add(r["RecipientEmailAddress"])
        for a in _att_list(r.get("Attachments")):
            g["attachments"].add(a)
        tt = (r.get("ThreatTypes") or "").strip()
        if tt:
            g["threats"].add(tt)

    findings: list[dict] = []
    for g in groups.values():
        recips = sorted(g["recipients"])
        target = (recips[0] + (f" (+{len(recips) - 1} more)" if len(recips) > 1 else "")) if recips else ""
        parts = [f'Subject: "{g["subject"] or "(no subject)"}"']
        atts = sorted(g["attachments"])
        if atts:
            parts.append("📎 " + ", ".join(atts[:6]) + (f" +{len(atts) - 6} more" if len(atts) > 6 else ""))
        if g["threats"]:
            parts.append("⚠ threats: " + ", ".join(sorted(g["threats"])))
        findings.append({
            "category":   "thread_hijack" if g["is_hijack"] else "mail_sent",
            "activity":   "Thread-hijack reply / forward" if g["is_hijack"] else "Outbound mail sent",
            "timestamp":  g["ts"], "result": g["delivery"],
            "target":     target, "initiated_by_ip": g["ip"],
            "detail":     " · ".join(parts),
            "id":         g["id"], "raw": {},
        })
    findings.sort(key=lambda f: f["timestamp"], reverse=True)
    return findings


# ── Identity Protection + directory-role enrichment (P2) ────────────────────
# Risk state and privilege context for the account: who they are to the attacker
# (privileged?) and what Entra Identity Protection already flagged. All P2 /
# premium surfaces — each degrades independently with a precise reason.

async def get_risk_state(token: str, user_id: str) -> dict | None:
    """Entra Identity Protection riskyUser record for the account, or None if
    the user has never been flagged (404). 403 → IdentityRiskyUser.Read.All."""
    url = f"{GRAPH_V1}/identityProtection/riskyUsers/{user_id.replace(chr(39), '')}"
    resp = await graph_request("GET", url, token=token, timeout=30.0)
    if resp.status_code == 404:
        return None
    if resp.status_code == 403:
        raise PermissionError(
            "Graph API 403 on /identityProtection/riskyUsers — missing "
            "IdentityRiskyUser.Read.All (Application permission, admin consent), "
            "or the tenant lacks Entra ID P2."
        )
    resp.raise_for_status()
    d = resp.json()
    return {
        "risk_level":  d.get("riskLevel"),
        "risk_state":  d.get("riskState"),
        "risk_detail": d.get("riskDetail"),
        "updated":     d.get("riskLastUpdatedDateTime"),
    }


async def get_risk_detections(token: str, user_id: str, max_pages: int = 5) -> list[dict]:
    """Identity Protection risk detections for the account (most recent first).
    403 → IdentityRiskEvent.Read.All."""
    uid = user_id.replace("'", "")
    url: str | None = f"{GRAPH_V1}/identityProtection/riskDetections"
    params: dict | None = {"$filter": f"userId eq '{uid}'", "$top": "100"}
    out: list[dict] = []
    pages = 0
    while url and pages < max_pages:
        resp = await graph_request("GET", url, token=token, params=params, timeout=45.0)
        if resp.status_code == 403:
            raise PermissionError(
                "Graph API 403 on /identityProtection/riskDetections — missing "
                "IdentityRiskEvent.Read.All (Application permission, admin "
                "consent), or the tenant lacks Entra ID P2."
            )
        resp.raise_for_status()
        data = resp.json()
        for d in data.get("value") or []:
            loc = d.get("location") or {}
            out.append({
                "risk_event_type": d.get("riskEventType"),
                "risk_level":      d.get("riskLevel"),
                "risk_state":      d.get("riskState"),
                "detected":        d.get("detectedDateTime") or d.get("activityDateTime") or "",
                "ip":              d.get("ipAddress") or "",
                "location":        ", ".join(filter(None, [loc.get("city"), loc.get("countryOrRegion")])),
                "detail":          d.get("riskDetail"),
                "source":          d.get("source"),
                "id":              d.get("id") or "",
            })
        nxt = data.get("@odata.nextLink")
        if nxt and not _is_graph_url(nxt):
            nxt = None
        url = nxt
        params = None
        pages += 1
    out.sort(key=lambda r: r["detected"], reverse=True)
    return out


async def get_directory_roles(token: str, user_id: str) -> dict:
    """Active directory-role assignments + PIM-eligible roles for the account.
    Tells the analyst whether a compromised account is privileged. 403 →
    RoleManagement.Read.Directory."""
    uid = user_id.replace("'", "")

    async def _pull(path: str, kind: str) -> list[dict]:
        url = (f"{GRAPH_V1}/roleManagement/directory/{path}"
               f"?$filter=principalId eq '{uid}'&$expand=roleDefinition")
        resp = await graph_request("GET", url, token=token, timeout=45.0)
        if resp.status_code == 403:
            raise PermissionError(
                "Graph API 403 on /roleManagement/directory — missing "
                "RoleManagement.Read.Directory (Application permission, admin consent)."
            )
        # roleEligibilitySchedules 400s on tenants without PIM enabled — treat
        # as "no eligible roles" rather than failing the whole enrichment.
        if resp.status_code == 400 and kind == "eligible":
            return []
        resp.raise_for_status()
        rows = []
        for a in resp.json().get("value") or []:
            rd = a.get("roleDefinition") or {}
            rows.append({
                "role_name":       rd.get("displayName") or a.get("roleDefinitionId") or "(role)",
                "role_id":         a.get("roleDefinitionId") or rd.get("id") or "",
                "assignment_type": kind,
                "scope":           a.get("directoryScopeId") or "/",
            })
        return rows

    active = await _pull("roleAssignments", "active")
    eligible = await _pull("roleEligibilitySchedules", "eligible")
    return {"active": active, "eligible": eligible}


def _signin_filter(user_id: str, start: datetime, end: datetime) -> str:
    s = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    e = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    # userId is the object GUID; createdDateTime bounds the window. Both are
    # $filter-able on the signIns resource.
    uid = user_id.replace("'", "")
    return f"userId eq '{uid}' and createdDateTime ge {s} and createdDateTime le {e}"


async def get_signins(
    token: str, user_id: str, start: datetime, end: datetime,
    max_pages: int = 20,
) -> list[dict]:
    """Pull the account's sign-ins in [start, end] from beta /auditLogs/signIns.
    Paginates @odata.nextLink (host-guarded) up to max_pages × 1000. Raises
    PermissionError on 403 (missing AuditLog.Read.All, or no Entra ID P1+)."""
    url: str | None = f"{GRAPH_BETA}/auditLogs/signIns"
    params: dict | None = {
        "$filter": _signin_filter(user_id, start, end),
        "$top": "1000",
    }
    out: list[dict] = []
    pages = 0
    while url and pages < max_pages:
        resp = await graph_request("GET", url, token=token, params=params, timeout=60.0)
        if resp.status_code == 403:
            raise PermissionError(
                "Graph API 403 on /auditLogs/signIns — either the app is missing "
                "AuditLog.Read.All (Application permission, needs admin consent) "
                "or the tenant lacks Entra ID P1/P2 (sign-in logs are a premium "
                "feature)."
            )
        resp.raise_for_status()
        data = resp.json()
        out.extend(data.get("value") or [])
        nxt = data.get("@odata.nextLink")
        if nxt and not _is_graph_url(nxt):
            log.warning("Refusing off-host signIns nextLink: %s", nxt)
            nxt = None
        url = nxt
        params = None  # nextLink carries the query
        pages += 1
    return out


# ── Aggregation: sign-ins → access-origin rows ─────────────────────────────

def _is_success(si: dict) -> bool:
    status = si.get("status") or {}
    code = status.get("errorCode")
    return code == 0 or code is None and not status.get("failureReason")


def _mfa_label(si: dict) -> str:
    """Best-effort read of how (or whether) MFA was satisfied. The AiTM /
    token-claim nuance is refined in a later milestone; here we report the
    requirement + whether an MFA step actually executed."""
    req = (si.get("authenticationRequirement") or "").strip()
    details = si.get("authenticationDetails") or []
    mfa_steps = [
        d for d in details
        if isinstance(d, dict)
        and "multifactor" in (d.get("authenticationStepRequirement") or "").lower()
    ]
    if req == "singleFactorAuthentication":
        return "single-factor"
    if mfa_steps:
        method = mfa_steps[0].get("authenticationMethod") or "MFA"
        ok = (mfa_steps[0].get("authenticationStepResultDetail") or "").lower()
        if "satisf" in ok or "success" in ok or "correct" in ok:
            return f"MFA satisfied ({method})"
        return f"MFA ({method})"
    if req == "multiFactorAuthentication":
        # MFA was required but we see no interactive step → likely satisfied by
        # an existing token/claim (a token-theft / AiTM tell worth flagging).
        return "MFA via token/claim"
    return req or "unknown"


def _haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    from math import radians, sin, cos, asin, sqrt
    lat1, lon1 = a
    lat2, lon2 = b
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    h = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return 2 * 6371 * asin(sqrt(h))


def build_access_origins(signins: list[dict]) -> dict:
    """Collapse raw sign-ins into per-IP access-origin rows + cross-cutting
    anomaly flags. Returns {origins: [...], anomalies: {...}}. The analyst
    decides; we only highlight."""
    by_ip: dict[str, dict] = {}
    # session-id -> set of IPs, for AiTM (same token from 2 IPs) detection.
    session_ips: dict[str, set[str]] = {}

    for si in signins:
        ip = (si.get("ipAddress") or "").strip() or "(unknown)"
        loc = si.get("location") or {}
        dev = si.get("deviceDetail") or {}
        ts = si.get("createdDateTime") or ""
        asn = si.get("autonomousSystemNumber")
        sid = si.get("sessionId") or si.get("correlationId") or ""

        row = by_ip.get(ip)
        if row is None:
            row = {
                "ip": ip,
                "country": loc.get("countryOrRegion") or "",
                "city": loc.get("city") or "",
                "geo": loc.get("geoCoordinates") or {},
                "asn": asn,
                "asn_org": HOSTING_ASNS.get(asn) if isinstance(asn, int) else None,
                "is_hosting_asn": isinstance(asn, int) and asn in HOSTING_ASNS,
                "devices": set(),
                "user_agents": set(),
                "client_apps": set(),
                "first_seen": ts,
                "last_seen": ts,
                "success": 0,
                "failure": 0,
                "mfa_labels": {},
                "session_ids": set(),
                "legacy_auth": False,
                "trust_types": set(),
                "managed": False,
                "compliant": False,
                "device_ids": set(),
                "signins": [],
            }
            by_ip[ip] = row

        dev_label = " / ".join(filter(None, [
            dev.get("operatingSystem"), dev.get("browser"),
            dev.get("displayName"),
        ])) or "—"
        row["devices"].add(dev_label)
        # Device trust posture — a sign-in from an Entra-registered/joined,
        # managed or compliant device is a strong "this is the real user's
        # device" signal (and, on a NEW device id, a possible attacker
        # device-registration persistence tell).
        tt = (dev.get("trustType") or "").strip()
        if tt:
            row["trust_types"].add(tt)
        if dev.get("isManaged"):
            row["managed"] = True
        if dev.get("isCompliant"):
            row["compliant"] = True
        did = (dev.get("deviceId") or "").strip()
        if did and did not in ("{PII Removed}", "00000000-0000-0000-0000-000000000000"):
            row["device_ids"].add(did)
        if si.get("userAgent"):
            row["user_agents"].add(si["userAgent"])
        client_app = si.get("clientAppUsed") or ""
        if client_app:
            row["client_apps"].add(client_app)
            if client_app in _LEGACY_CLIENT_APPS:
                row["legacy_auth"] = True

        if ts and (not row["first_seen"] or ts < row["first_seen"]):
            row["first_seen"] = ts
        if ts and ts > row["last_seen"]:
            row["last_seen"] = ts

        if _is_success(si):
            row["success"] += 1
        else:
            row["failure"] += 1

        label = _mfa_label(si)
        row["mfa_labels"][label] = row["mfa_labels"].get(label, 0) + 1

        # Keep the per-sign-in detail so the UI can expand a row to the exact
        # events behind the aggregate. Capped below to bound the payload.
        status = si.get("status") or {}
        row["signins"].append({
            "timestamp":       ts,
            "success":         _is_success(si),
            "error_code":      status.get("errorCode"),
            "failure_reason":  status.get("failureReason"),
            "mfa":             label,
            "auth_requirement": si.get("authenticationRequirement"),
            "app":             si.get("appDisplayName"),
            "resource":        si.get("resourceDisplayName"),
            "client_app":      client_app,
            "user_agent":      si.get("userAgent"),
            "device":          dev_label,
            "trust_type":      dev.get("trustType"),
            "ca_status":       si.get("conditionalAccessStatus"),
            "risk_state":      si.get("riskState"),
            "risk_level":      si.get("riskLevelDuringSignIn"),
            "correlation_id":  si.get("correlationId"),
            "session_id":      sid,
        })

        if sid:
            row["session_ids"].add(sid)
            session_ips.setdefault(sid, set()).add(ip)

    # AiTM: a single session id observed from two or more distinct IPs.
    aitm_sessions = {sid for sid, ips in session_ips.items() if len(ips) >= 2}
    aitm_ips = {ip for sid in aitm_sessions for ip in session_ips[sid]}

    # Impossible travel: any two SUCCESSFUL origins with geo coords whose
    # separation implies an implausible travel speed between their windows.
    travel_ips: set[str] = set()
    geo_rows = [
        r for r in by_ip.values()
        if r["geo"].get("latitude") is not None and r["success"] > 0
    ]
    for i in range(len(geo_rows)):
        for j in range(i + 1, len(geo_rows)):
            a, b = geo_rows[i], geo_rows[j]
            try:
                km = _haversine_km(
                    (a["geo"]["latitude"], a["geo"]["longitude"]),
                    (b["geo"]["latitude"], b["geo"]["longitude"]),
                )
            except Exception:
                continue
            if km < 500:
                continue
            # gap between the two windows (hours)
            try:
                ta = datetime.fromisoformat(a["last_seen"].replace("Z", "+00:00"))
                tb = datetime.fromisoformat(b["first_seen"].replace("Z", "+00:00"))
                gap_h = abs((tb - ta).total_seconds()) / 3600.0
            except Exception:
                continue
            # >900 km/h implied speed = not a flight either
            if gap_h < 0.1 or (km / gap_h) > 900:
                travel_ips.add(a["ip"])
                travel_ips.add(b["ip"])

    origins = []
    for r in by_ip.values():
        flags = []
        if r["is_hosting_asn"]:
            flags.append("hosting-asn")
        if r["legacy_auth"]:
            flags.append("legacy-auth")
        if r["ip"] in aitm_ips:
            flags.append("aitm-token-reuse")
        if r["ip"] in travel_ips:
            flags.append("impossible-travel")
        origins.append({
            "ip":            r["ip"],
            "country":       r["country"],
            "city":          r["city"],
            "asn":           r["asn"],
            "asn_org":       r["asn_org"],
            "is_hosting_asn": r["is_hosting_asn"],
            "devices":       sorted(r["devices"]),
            "user_agents":   sorted(r["user_agents"])[:5],
            "client_apps":   sorted(r["client_apps"]),
            "first_seen":    r["first_seen"],
            "last_seen":     r["last_seen"],
            "success":       r["success"],
            "failure":       r["failure"],
            "mfa":           r["mfa_labels"],
            "session_ids":   sorted(r["session_ids"]),
            "device_trust":  sorted(r["trust_types"]),
            "device_managed":   r["managed"],
            "device_compliant": r["compliant"],
            "device_ids":    sorted(r["device_ids"]),
            # Newest-first, capped to keep the payload sane on chatty IPs.
            "signins":       sorted(r["signins"], key=lambda s: s["timestamp"] or "", reverse=True)[:100],
            "flags":         flags,
        })

    # Anomalous origins to the top: most flags first, then most sign-ins.
    origins.sort(key=lambda o: (-len(o["flags"]), -(o["success"] + o["failure"])))
    return {
        "origins": origins,
        "anomalies": {
            "aitm_sessions": sorted(aitm_sessions),
            "impossible_travel_ips": sorted(travel_ips),
            "hosting_asn_ips": sorted(o["ip"] for o in origins if o["is_hosting_asn"]),
        },
    }
