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
// ({ main, extras }). For a device, inherit is its network's default ("" = the main address) and
// the list starts with "Network default"; for a network it is undefined. A saved address the
// server no longer has stays listed, marked, so the choice shows what is stored.
export function egressOptions(addrs, current, inherit) {
  const main = addrs?.main ? `Server's main address (${addrs.main})` : "Server's main address"
  const extras = addrs?.extras || []
  const opts = inherit === undefined
    ? [{ value: '', label: main }]
    : [{ value: '', label: `Network default (${inherit || addrs?.main || 'main address'})` }, { value: 'main', label: main }]
  for (const ip of extras) opts.push({ value: ip, label: `${ip} — dedicated` })
  if (egressMissing(addrs, current)) opts.push({ value: current, label: `${current} — not on this server` })
  return opts
}

// egressMissing: a saved extra address the server doesn't have (its devices have no internet).
export const egressMissing = (addrs, v) => !!v && v !== 'main' && !(addrs?.extras || []).includes(v)
