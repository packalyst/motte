// Plain-English translations for the jargon the panel surfaces. Keyed by a
// lowercased term; the Explain component looks terms up here so the same
// definition is reused everywhere it appears.

export const GLOSSARY = {
  'policy drop':   'The default rule: anything not explicitly allowed is blocked.',
  'default drop':  'The firewall blocks everything except what you explicitly allow.',
  'aaaa':          'A DNS record for an IPv6 address. Blocking it forces IPv4-only.',
  'a record':      'A DNS record pointing a name to an IPv4 address.',
  'syn':           'The first packet of a TCP connection. Floods of these are a common denial-of-service pattern.',
  'nxdomain':      'DNS answer meaning "this name does not exist".',
  'ttl':           'Time-to-live: how long a DNS answer may be cached before it must be looked up again.',
  'asn':           'Autonomous System Number — identifies the network/provider that owns an IP (e.g. an ISP or a cloud host).',
  'dch':           'Data-center / hosting network — traffic from a server rather than a home connection.',
  'masquerade':    'Rewrites outgoing traffic to appear from the gateway (NAT) so replies can find their way back.',
  'dnat':          'Destination NAT — forwards traffic aimed at one address to another (used to expose a LAN device).',
  'conntrack':     'The kernel connection tracker — remembers active flows so replies are allowed back through.',
  'handshake':     'A WireGuard key exchange. A recent handshake means the peer is currently connected.',
  'proxy':         'An intermediary that hides the real origin — VPNs, Tor and open proxies are common examples.',
  'fraud score':   'A 0–100 estimate of how risky an IP is, from the IP2Proxy database.',
}

// lookup returns the definition for a term (case-insensitive) or ''.
export function explain(term) {
  if (!term) return ''
  return GLOSSARY[String(term).toLowerCase().trim()] || ''
}
