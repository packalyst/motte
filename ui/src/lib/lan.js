// LAN device actions shared by the device cards and the device modal. All admin-only and audited
// on the server.
import { apiPost, apiPut, withStepUp } from '../stores/app.js'

const base = (id) => `/api/dhcp/clients/${id}`

export const approveDevice = (id) => apiPost(base(id) + '/approve')
export const blockDevice = (id) => apiPost(base(id) + '/block')
export const unblockDevice = (id) => apiPost(base(id) + '/unblock')

// setDeviceInternet turns a device's internet on or off; change may also set its internet address
// (egress_ip) or what it may reach (services). Whenever that gives it more, the server asks for a
// password or passkey first; off, or taking a service away, doesn't. Resolves to STEPUP_CANCELLED
// when the prompt is closed.
export const setDeviceInternet = (id, on, change = {}) => withStepUp(
  (extra) => apiPut(base(id) + '/internet', { enabled: on, ...change, ...extra }),
  { title: 'Internet access', message: "Confirm to change this device's internet access.", confirmText: 'Confirm' }
)

// Services: what a device may reach on the internet, as a list "web,time,tcp:8883" (the catalog
// and the default come from the server: GET /api/dhcp/interfaces or a device).
export const splitServices = (list) => (list || '').split(',').map((t) => t.trim()).filter(Boolean)

// servicesLabel names a list for people: "Web, Time, TCP 8883".
export function servicesLabel(list, catalog = []) {
  return splitServices(list)
    .map((t) => catalog.find((s) => s.id === t)?.name || t.replace(':', ' ').toUpperCase())
    .join(', ')
}

// egressOptions lists the internet addresses a choice can take, from the server's offer
// ({ main, extras, use }). An extra address is shared (networks' default) or dedicated (one
// device), never both: one held the other way, or by another device, is listed but can't be
// picked (the server refuses it too). For a device, self is its id and inherit its network's
// default ("" = the main address), and the list starts with "Network default"; for a network, self
// is its interface and inherit is undefined. A saved address the server no longer has stays
// listed, marked, so the choice shows what is stored.
export function egressOptions(addrs, current, inherit, self) {
  const main = addrs?.main ? `Server's main address (${addrs.main})` : "Server's main address"
  const forDevice = inherit !== undefined
  const opts = forDevice
    ? [{ value: '', label: `Network default (${inherit || addrs?.main || 'main address'})` }, { value: 'main', label: main }]
    : [{ value: '', label: main }]
  for (const ip of addrs?.extras || []) {
    const use = addrs?.use?.[ip] || {}
    const others = (use.devices || []).filter((d) => !forDevice || d.id !== self)
    const sharers = (use.networks || []).filter((n) => forDevice || n !== self)
    let label = forDevice ? `${ip} — dedicated to this device` : `${ip} — shared`
    let disabled = false
    if (others.length) { label = `${ip} — dedicated to ${others.map((d) => d.name).join(', ')}`; disabled = true }
    else if (forDevice && sharers.length) { label = `${ip} — shared by network ${sharers.join(', ')}`; disabled = true }
    else if (sharers.length) label = `${ip} — shared, also by ${sharers.join(', ')}`
    opts.push({ value: ip, label, disabled: disabled && ip !== current })
  }
  if (egressMissing(addrs, current)) opts.push({ value: current, label: `${current} — not on this server` })
  return opts
}

// egressConflict: a saved extra address held by more than one device, or both shared and
// dedicated: everyone on it is without internet until one moves.
export function egressConflict(addrs, v) {
  const use = addrs?.use?.[v]
  return !!use && ((use.devices || []).length > 1 || ((use.devices || []).length > 0 && (use.networks || []).length > 0))
}

// egressMissing: a saved extra address the server doesn't have (its devices have no internet).
export const egressMissing = (addrs, v) => !!v && v !== 'main' && !(addrs?.extras || []).includes(v)
