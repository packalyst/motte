// LAN device actions shared by the device cards and the device modal. All admin-only and audited
// on the server.
import { apiPost, apiPut } from '../stores/app.js'

const base = (id) => `/api/dhcp/clients/${id}`

export const approveDevice = (id) => apiPost(base(id) + '/approve')
export const blockDevice = (id) => apiPost(base(id) + '/block')
export const unblockDevice = (id) => apiPost(base(id) + '/unblock')
export const setDeviceInternet = (id, on) => apiPut(base(id) + '/internet', { enabled: on })
