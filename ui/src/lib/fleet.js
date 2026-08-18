// Shared fleet helpers — used by both the machine list (MachinesView) and the machine
// detail page (MachineDetail) so status/severity/usage logic lives in one place.

// usageColor maps a 0–100 utilization to a semantic bar color.
export function usageColor(pct) {
  if (pct >= 85) return 'bg-destructive'
  if (pct >= 60) return 'bg-warning'
  return 'bg-success'
}

// sevVariant maps a Trivy severity to a Badge variant.
export function sevVariant(sev) {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'danger'
    case 'HIGH': return 'warning'
    case 'MEDIUM': return 'info'
    default: return 'muted'
  }
}

// statusInfo derives a machine's connection state from its last_seen timestamp.
// online = reported within 2 min; idle = within 10 min; else offline.
export function statusInfo(m) {
  if (m?.revoked) return { dot: 'bg-destructive', label: 'revoked', online: false }
  if (!m?.last_seen) return { dot: 'bg-muted-foreground', label: 'never reported', online: false }
  const mins = (Date.now() - new Date(m.last_seen)) / 60000
  if (mins < 2) return { dot: 'bg-success', label: 'online', online: true }
  if (mins < 10) return { dot: 'bg-warning', label: 'idle', online: true }
  return { dot: 'bg-muted-foreground', label: 'offline', online: false }
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
