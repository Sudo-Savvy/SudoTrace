// Per-table column lists for Defender advanced-hunting tables, used by
// the Hunt-tab autocomplete to suggest field names that make sense in
// the table the analyst is querying. Schemas are pragmatic: the
// fields an analyst actually queries on, not every nullable backfill
// column the API can return.
//
// Source: Microsoft Defender XDR advanced-hunting schema reference
// (https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables).

// Fields that appear on virtually every device-* hunting row. Folded
// into each table's column list so we don't have to repeat them.
const DEVICE_COMMON = [
  'Timestamp', 'DeviceId', 'DeviceName', 'ReportId', 'AdditionalFields',
]

// Initiator process fields appear on every action-style table (process /
// network / file / registry / image-load / etc.) — keep them in one
// constant so additions stay in sync.
const INITIATING_PROCESS = [
  'InitiatingProcessId', 'InitiatingProcessFileName', 'InitiatingProcessFolderPath',
  'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
  'InitiatingProcessSHA1', 'InitiatingProcessSHA256', 'InitiatingProcessMD5',
  'InitiatingProcessFileSize',
  'InitiatingProcessAccountDomain', 'InitiatingProcessAccountName',
  'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
  'InitiatingProcessAccountObjectId',
  'InitiatingProcessIntegrityLevel', 'InitiatingProcessTokenElevation',
  'InitiatingProcessLogonId',
  'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoProductName',
  'InitiatingProcessVersionInfoProductVersion', 'InitiatingProcessVersionInfoInternalFileName',
  'InitiatingProcessVersionInfoOriginalFileName', 'InitiatingProcessVersionInfoFileDescription',
  'InitiatingProcessSignerType', 'InitiatingProcessSignatureStatus',
  'InitiatingProcessParentId', 'InitiatingProcessParentFileName',
  'InitiatingProcessParentCreationTime',
]

export const COLUMNS_BY_TABLE: Record<string, string[]> = {
  DeviceProcessEvents: [
    ...DEVICE_COMMON,
    'ActionType', 'FileName', 'FolderPath', 'SHA1', 'SHA256', 'MD5', 'FileSize',
    'ProcessId', 'ProcessCommandLine', 'ProcessCreationTime',
    'ProcessIntegrityLevel', 'ProcessTokenElevation', 'ProcessUniqueId',
    'AccountDomain', 'AccountName', 'AccountSid', 'AccountUpn', 'AccountObjectId',
    'LogonId',
    'ProcessVersionInfoCompanyName', 'ProcessVersionInfoProductName',
    'ProcessVersionInfoProductVersion', 'ProcessVersionInfoInternalFileName',
    'ProcessVersionInfoOriginalFileName', 'ProcessVersionInfoFileDescription',
    ...INITIATING_PROCESS,
    'AppGuardContainerId',
  ],
  DeviceNetworkEvents: [
    ...DEVICE_COMMON,
    'ActionType', 'RemoteIP', 'RemotePort', 'RemoteUrl',
    'LocalIP', 'LocalPort', 'Protocol', 'LocalIPType', 'RemoteIPType',
    ...INITIATING_PROCESS,
  ],
  DeviceFileEvents: [
    ...DEVICE_COMMON,
    'ActionType', 'FileName', 'FolderPath', 'SHA1', 'SHA256', 'MD5', 'FileSize',
    'PreviousFileName', 'PreviousFolderPath',
    'FileOriginUrl', 'FileOriginReferrerUrl', 'FileOriginIP',
    'SensitivityLabel', 'IsAzureInfoProtectionApplied',
    'RequestProtocol', 'RequestSourceIP', 'RequestSourcePort',
    'RequestAccountName', 'RequestAccountDomain', 'RequestAccountSid',
    'ShareName',
    ...INITIATING_PROCESS,
  ],
  DeviceRegistryEvents: [
    ...DEVICE_COMMON,
    'ActionType',
    'RegistryKey', 'RegistryValueType', 'RegistryValueName', 'RegistryValueData',
    'PreviousRegistryKey', 'PreviousRegistryValueName', 'PreviousRegistryValueData',
    ...INITIATING_PROCESS,
  ],
  DeviceLogonEvents: [
    ...DEVICE_COMMON,
    'ActionType', 'LogonType',
    'AccountDomain', 'AccountName', 'AccountSid', 'Protocol',
    'FailureReason', 'IsLocalAdmin', 'LogonId',
    'RemoteDeviceName', 'RemoteIP', 'RemoteIPType', 'RemotePort',
    ...INITIATING_PROCESS,
  ],
  DeviceImageLoadEvents: [
    ...DEVICE_COMMON,
    'ActionType', 'FileName', 'FolderPath', 'SHA1', 'SHA256', 'MD5',
    ...INITIATING_PROCESS,
  ],
  DeviceEvents: [
    ...DEVICE_COMMON,
    'ActionType', 'FileName', 'FolderPath', 'SHA1', 'SHA256', 'MD5', 'FileSize',
    'ProcessId', 'ProcessCommandLine', 'AccountName', 'AccountDomain', 'AccountSid',
    'RemoteIP', 'RemotePort', 'RemoteUrl', 'LocalIP', 'LocalPort',
    'RegistryKey', 'RegistryValueName', 'RegistryValueData',
    ...INITIATING_PROCESS,
  ],
  DeviceInfo: [
    ...DEVICE_COMMON,
    'ClientVersion', 'PublicIP', 'OSArchitecture', 'OSPlatform', 'OSBuild',
    'OSVersion', 'IsAzureADJoined', 'IsAzureInfoProtectionApplied',
    'LoggedOnUsers', 'RegistryDeviceTag', 'OSBuildNumber',
    'MachineGroup', 'OnboardingStatus', 'DeviceCategory', 'DeviceType',
    'DeviceSubtype', 'Model', 'Vendor', 'OSDistribution', 'OSVersionInfo',
    'JoinType', 'SensorHealthState',
  ],
  DeviceNetworkInfo: [
    ...DEVICE_COMMON,
    'NetworkAdapterName', 'NetworkAdapterType', 'NetworkAdapterStatus',
    'TunnelType', 'MacAddress', 'IPAddresses', 'IPv4Dhcp', 'IPv6Dhcp',
    'DefaultGateways', 'DnsAddresses', 'ConnectedNetworks',
  ],
  AlertInfo: [
    'Timestamp', 'AlertId', 'Title', 'Category', 'Severity',
    'AttackTechniques', 'ServiceSource', 'DetectionSource', 'ThreatFamilyName',
  ],
  AlertEvidence: [
    'Timestamp', 'AlertId', 'ServiceSource', 'EntityType',
    'EvidenceRole', 'EvidenceDirection', 'EvidenceCreationTime',
    'FileName', 'FolderPath', 'SHA1', 'SHA256', 'FileSize',
    'ThreatFamily', 'RemoteIP', 'RemoteUrl', 'LocalIP',
    'AccountName', 'AccountDomain', 'AccountSid', 'AccountUpn', 'AccountObjectId',
    'DeviceId', 'DeviceName',
    'ProcessId', 'ProcessCommandLine', 'ProcessCreationTime',
    'AdditionalFields', 'Title', 'Categories', 'AttackTechniques', 'ServiceSource',
    'DetectionSource', 'Severity',
  ],
  CloudAppEvents: [
    'Timestamp', 'ActionType', 'Application', 'ApplicationId',
    'AccountObjectId', 'AccountId', 'AccountDisplayName', 'IsAdminOperation',
    'DeviceType', 'OSPlatform', 'IPAddress', 'IPCategory', 'IPTags',
    'CountryCode', 'City', 'ISP', 'UserAgent', 'UserAgentTags',
    'ActivityType', 'ActivityObjects', 'ObjectName', 'ObjectType', 'ObjectId',
    'AdditionalFields', 'RawEventData', 'ApplicationOperation',
    'ApplicationOperationId',
    'ReportId',
  ],
  EmailEvents: [
    'Timestamp', 'NetworkMessageId', 'InternetMessageId', 'SenderMailFromAddress',
    'SenderFromAddress', 'SenderDisplayName', 'SenderObjectId',
    'SenderMailFromDomain', 'SenderFromDomain', 'SenderIPv4', 'SenderIPv6',
    'RecipientEmailAddress', 'RecipientObjectId',
    'Subject', 'EmailClusterId', 'EmailLanguage', 'EmailDirection',
    'DeliveryAction', 'DeliveryLocation', 'EmailAction', 'EmailActionPolicy',
    'ThreatTypes', 'ThreatNames', 'DetectionMethods', 'ConfidenceLevel',
    'OrgLevelAction', 'OrgLevelPolicy', 'UserLevelAction', 'UserLevelPolicy',
    'PhishConfidenceLevel', 'AttachmentCount', 'UrlCount', 'Connectors',
    'ReportId',
  ],
  IdentityLogonEvents: [
    'Timestamp', 'ActionType', 'Application', 'LogonType', 'Protocol',
    'FailureReason', 'AccountName', 'AccountDomain', 'AccountUpn', 'AccountSid',
    'AccountObjectId', 'AccountDisplayName',
    'DeviceName', 'DeviceType', 'OSPlatform', 'IPAddress', 'Port',
    'DestinationDeviceName', 'DestinationIPAddress', 'DestinationPort',
    'TargetDeviceName', 'TargetAccountUpn', 'TargetAccountSid',
    'ReportId', 'AdditionalFields',
  ],
}

// Columns to suggest when the analyst is in an expression slot but the
// query's table can't be identified (no recognised first identifier,
// or the table isn't in our schema). The most-universal subset across
// the device-* tables.
export const COMMON_COLUMNS_FALLBACK = [
  'Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'ReportId',
  'FileName', 'FolderPath', 'SHA1', 'SHA256', 'MD5',
  'ProcessId', 'ProcessCommandLine',
  'AccountName', 'AccountDomain', 'AccountSid',
  'RemoteIP', 'RemotePort', 'RemoteUrl', 'LocalIP', 'LocalPort',
  'RegistryKey', 'RegistryValueName', 'RegistryValueData',
  ...INITIATING_PROCESS,
]

// Walks the query text looking for its source table. Skips leading
// whitespace, line comments, and trivial single-line `let` bindings
// (`let x = ...;` on one line). Returns the canonical table name if
// the first real identifier is a known MDE table, otherwise null.
//
// Doesn't try to handle multi-line let blocks or queries that start
// with `union (...)`/`materialize(...)` — those are edge cases that
// just fall through to a null result, which means "no columns to
// suggest, just generic functions".
export function detectTableInQuery(text: string, knownTables: Set<string>): string | null {
  const lines = text.split('\n')
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue
    if (trimmed.startsWith('//')) continue
    // Single-line let binding: skip entirely. Multi-line lets fall
    // through (we'd hit the next real identifier inside the binding).
    if (/^let\s+\w+\s*=.*;\s*(\/\/.*)?$/.test(trimmed)) continue
    if (trimmed.startsWith('let ')) continue
    const m = trimmed.match(/^([A-Za-z][A-Za-z0-9_]*)/)
    if (!m) return null
    const lower = m[1].toLowerCase()
    if (knownTables.has(lower)) {
      // Return the canonical case form. Caller supplies the
      // case-insensitive set; canonical-case lookup happens there.
      return m[1]
    }
    return null
  }
  return null
}
