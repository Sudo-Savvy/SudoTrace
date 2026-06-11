// Curated list of Microsoft-owned CIDR blocks.
// Sources: Azure Service Tags, Office 365 endpoints, Microsoft published IP ranges.
// Covers Azure compute, Office 365, Teams/Skype, Windows Update, Defender, and
// Microsoft corporate. Not exhaustive — updated manually as needed.
const MICROSOFT_CIDRS: string[] = [
  // Azure global (major blocks)
  '13.64.0.0/11',
  '13.96.0.0/13',
  '13.104.0.0/14',
  '20.33.0.0/16',
  '20.34.0.0/15',
  '20.36.0.0/14',
  '20.40.0.0/13',
  '20.48.0.0/12',
  '20.64.0.0/10',
  '20.128.0.0/16',
  '20.150.0.0/15',
  '20.157.0.0/16',
  '20.160.0.0/12',
  '20.176.0.0/14',
  '20.180.0.0/14',
  '20.184.0.0/13',
  '20.192.0.0/10',
  '23.96.0.0/13',
  // Azure / O365 compute blocks
  '40.64.0.0/10',
  '40.74.0.0/15',
  '40.76.0.0/14',
  '40.80.0.0/12',
  '40.96.0.0/12',
  '40.112.0.0/13',
  '40.120.0.0/14',
  '40.124.0.0/16',
  // Azure Europe
  '51.4.0.0/15',
  '51.8.0.0/16',
  '51.10.0.0/15',
  '51.12.0.0/15',
  '51.103.0.0/16',
  '51.104.0.0/15',
  '51.107.0.0/16',
  '51.116.0.0/16',
  '51.120.0.0/16',
  '51.132.0.0/16',
  '51.136.0.0/15',
  '51.140.0.0/14',
  // Office 365 / Exchange Online
  '52.96.0.0/12',
  // Teams / Skype for Business / media relay
  '52.112.0.0/14',
  '52.120.0.0/14',
  // Azure compute (East US, West US, etc.)
  '52.224.0.0/11',
  '104.40.0.0/13',
  '104.146.0.0/15',
  '104.208.0.0/13',
  // Microsoft corporate network
  '131.107.0.0/16',
  '134.170.0.0/16',
  // Windows Update / Microsoft Update / WSUS
  '23.103.0.0/16',
  '157.54.0.0/15',
  '157.56.0.0/14',
  '157.60.0.0/16',
  // Microsoft cloud infrastructure
  '167.220.0.0/16',
  '168.61.0.0/16',
  '168.62.0.0/15',
  // Azure Brazil South
  '191.232.0.0/13',
  // Bing / Microsoft search
  '204.79.197.0/24',
]

function ipToInt(ip: string): number {
  const p = ip.split('.')
  return (
    ((parseInt(p[0]) << 24) |
     (parseInt(p[1]) << 16) |
     (parseInt(p[2]) << 8)  |
      parseInt(p[3])) >>> 0
  )
}

function cidrMatch(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf('/')
  const base   = cidr.slice(0, slash)
  const prefix = parseInt(cidr.slice(slash + 1))
  const mask   = prefix === 0 ? 0 : ((~0 << (32 - prefix)) >>> 0)
  return (ipToInt(ip) & mask) === (ipToInt(base) & mask)
}

const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/

export function isMicrosoftIp(ip: string): boolean {
  if (!IPV4_RE.test(ip)) return false
  return MICROSOFT_CIDRS.some(cidr => cidrMatch(ip, cidr))
}

// RFC1918 + loopback + link-local + CGNAT — addresses that should never
// reach the internet and aren't worth a VirusTotal lookup. We still let
// the analyst add them to the IOC list (an internal IP can absolutely
// be evidence in a lateral-movement investigation), just labelled as
// internal so the verdict isn't ambiguous.
const INTERNAL_CIDRS = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '127.0.0.0/8',     // loopback
  '169.254.0.0/16',  // link-local
  '100.64.0.0/10',   // CGNAT
  '0.0.0.0/8',       // "this network"
]

export function isInternalIp(ip: string): boolean {
  if (!IPV4_RE.test(ip)) return false
  return INTERNAL_CIDRS.some(cidr => cidrMatch(ip, cidr))
}

// Known Microsoft-owned domain suffixes.
const MICROSOFT_DOMAINS = [
  'microsoft.com', 'microsoftonline.com', 'microsoftazure.com',
  'windows.com', 'windowsupdate.com', 'windowsazure.com',
  'azure.com', 'azureedge.net', 'azure-dns.com', 'azure-dns.net',
  'azurewebsites.net', 'azurefd.net', 'trafficmanager.net',
  'office.com', 'office365.com', 'office.net',
  'outlook.com', 'hotmail.com', 'live.com',
  'sharepoint.com', 'onedrive.com', 'onenote.com',
  'teams.microsoft.com', 'skype.com', 'skypeforbusiness.com',
  'bing.com', 'msn.com', 'msedge.net',
  'msftncsi.com', 'msftconnecttest.com',
  'visualstudio.com', 'vsassets.io', 'vscode.dev',
  'nuget.org', 'powershellgallery.com',
  'msecnd.net', 'akamaitech.net',
  'xbox.com', 'xboxlive.com',
  'linkedin.com', 'github.com', 'githubcopilot.com',
]

export function isMicrosoftDomain(domain: string): boolean {
  const d = domain.toLowerCase().replace(/^www\./, '')
  return MICROSOFT_DOMAINS.some(ms => d === ms || d.endsWith(`.${ms}`))
}
