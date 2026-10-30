// Headscale key helpers shared by the Auth keys and API keys sections of the Headscale page.
import { isExpired, getDaysUntilExpiry, parseDate } from './utils/format.js'

// keyState is a key's state (a pre-auth key or an API key): 'expired'; 'used' for a single-use
// pre-auth key that already joined a device; 'soon' when it expires within a week; else 'active'.
// Only 'active' and 'soon' keys still work.
export function keyState(k) {
  if (isExpired(k.expiration)) return 'expired'
  if (k.used && !k.reusable) return 'used'
  const days = getDaysUntilExpiry(k.expiration)
  return days !== null && days <= 7 ? 'soon' : 'active'
}

export const KEY_STATE = {
  soon: { label: 'Active', text: 'text-warning', dot: 'status-dot-warning', tint: 'bg-warning/10 text-warning', works: true },
  active: { label: 'Active', text: 'text-success', dot: 'status-dot-success', tint: 'bg-success/10 text-success', works: true },
  used: { label: 'Used', text: 'text-muted-foreground', dot: 'status-dot-muted', tint: 'bg-muted text-muted-foreground', works: false },
  expired: { label: 'Expired', text: 'text-destructive', dot: 'status-dot-error', tint: 'bg-destructive/10 text-destructive', works: false },
}
const ORDER = Object.keys(KEY_STATE)

export const keyWorks = (k) => KEY_STATE[keyState(k)].works

// sortKeys: keys that still work first (the soonest to expire first), then used, then expired
// (the most recent first).
export function sortKeys(keys) {
  const at = (k) => parseDate(k.expiration)?.getTime() ?? Infinity
  return [...keys].sort((a, b) => {
    const sa = keyState(a), sb = keyState(b)
    if (sa !== sb) return ORDER.indexOf(sa) - ORDER.indexOf(sb)
    return KEY_STATE[sa].works ? at(a) - at(b) : at(b) - at(a)
  })
}

// keyOwner is a pre-auth key's user name (Headscale 0.25 sends the name; later versions a user).
export const keyOwner = (k) => (typeof k.user === 'string' ? k.user : k.user?.name) || ''
