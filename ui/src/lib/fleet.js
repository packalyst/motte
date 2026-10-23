// Shared fleet helpers — used by the machine detail page, its CVE drill-down and the clients page
// so status/severity/usage logic lives in one place.

// usageTone maps a 0–100 utilization to a semantic tone (also a CSS token: var(--<tone>)).
export function usageTone(pct) {
  if (pct >= 85) return 'destructive'
  if (pct >= 60) return 'warning'
  return 'success'
}
const USAGE_BG = { destructive: 'bg-destructive', warning: 'bg-warning', success: 'bg-success' }
// usageColor is the bar colour class for that tone.
export const usageColor = (pct) => USAGE_BG[usageTone(pct)]

// sevVariant maps a Trivy severity to a Badge variant.
export function sevVariant(sev) {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'danger'
    case 'HIGH': return 'warning'
    case 'MEDIUM': return 'info'
    default: return 'muted'
  }
}

// statusInfo derives a machine's state. online comes from the server: the agent's link to the
// panel is up — exact, never guessed from report age. reachable mirrors what the server requires
// before it queues a command.
export function statusInfo(m) {
  if (m?.status === 'uninstalled') return { dot: 'bg-muted-foreground', variant: 'muted', label: 'uninstalled', online: false, gone: true }
  if (m?.revoked) return { dot: 'bg-destructive', variant: 'danger', label: 'revoked', online: false }
  if (m?.online) return { dot: 'bg-success', variant: 'success', label: 'online', online: true, reachable: true }
  if (!m?.last_seen) return { dot: 'bg-muted-foreground', variant: 'muted', label: 'never reported', online: false }
  return { dot: 'bg-muted-foreground', variant: 'danger', label: 'offline', online: false }
}

// round rounds a percentage for display (no decimals).
export function round(n) {
  return Math.round(Number(n) || 0)
}

// fmtUptime turns seconds into a compact "6d 4h" / "3h 12m" string.
export function fmtUptime(secs) {
  secs = Number(secs) || 0
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}
