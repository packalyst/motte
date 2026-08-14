// Shared presentation for the geo reputation verdict (backend Reputation.Level).
// One source of truth for colors/labels so badges, the lookup tool and the
// Security Overview all render the traffic light identically.

const META = {
  high:    { label: 'High risk',   dot: 'bg-destructive', text: 'text-destructive', ring: 'border-destructive/30 bg-destructive/10' },
  medium:  { label: 'Suspicious',  dot: 'bg-warning',     text: 'text-warning',     ring: 'border-warning/30 bg-warning/10' },
  low:     { label: 'Looks clean', dot: 'bg-success',     text: 'text-success',     ring: 'border-success/30 bg-success/10' },
  unknown: { label: 'Unknown',     dot: 'bg-muted-foreground/50', text: 'text-muted-foreground', ring: 'border-border bg-muted/40' },
}

// reputationMeta returns styling for a level, falling back to "unknown".
export function reputationMeta(level) {
  return META[level] || META.unknown
}

// Short proxy/usage-type descriptions for chips and tooltips (IP2Proxy codes).
const PROXY_TYPE = {
  VPN: 'VPN', TOR: 'Tor', PUB: 'Public proxy', WEB: 'Web proxy',
  DCH: 'Data center', SES: 'Search bot', RES: 'Residential proxy',
  CPN: 'Consumer VPN', EPN: 'Enterprise VPN',
}
const USAGE_TYPE = {
  COM: 'Commercial', ORG: 'Organization', GOV: 'Government', MIL: 'Military',
  EDU: 'Education', LIB: 'Library', CDN: 'CDN', ISP: 'ISP', MOB: 'Mobile',
  DCH: 'Data center', SES: 'Search engine', RSV: 'Reserved',
}

export function proxyTypeLabel(code) {
  const c = (code || '').toUpperCase().trim()
  return PROXY_TYPE[c] || (c && c !== '-' ? c : '')
}

export function usageTypeLabel(code) {
  const c = (code || '').toUpperCase().trim()
  return USAGE_TYPE[c] || (c && c !== '-' ? c : '')
}
