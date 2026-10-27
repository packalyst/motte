/**
 * Host / address helpers shared by the DNS pages.
 */

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

/** Accept a hostname (optionally a *. wildcard) or an IPv4/IPv6 literal. */
export function isValidHost(v) {
  const s = (v || '').trim()
  if (!s) return false
  if (IPV4.test(s)) return s.split('.').every((o) => +o >= 0 && +o <= 255)
  if (s.includes(':') && /^[0-9a-fA-F:]+$/.test(s)) return true // IPv6 (loose)
  return /^(\*\.)?([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,}$/.test(s)
}

/**
 * What a DNS rewrite answers with, as AdGuard reads it: an IPv4 or IPv6 address, the literal
 * "A"/"AAAA" (keep the upstream's records of that type), or another domain (an alias / CNAME).
 */
export function rewriteKind(answer) {
  const a = (answer || '').trim()
  if (a === 'A' || a === 'AAAA') return { label: 'Upstream ' + a, variant: 'muted' }
  if (IPV4.test(a)) return { label: 'IPv4', variant: 'info' }
  if (a.includes(':')) return { label: 'IPv6', variant: 'info' }
  return { label: 'Alias', variant: 'secondary' }
}
