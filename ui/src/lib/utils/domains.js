/**
 * Domain routes utilities
 */

/**
 * Default sentinel middleware configuration
 * @returns {Object} Default sentinel config
 */
export function defaultSentinelConfig() {
  return {
    enabled: true,
    errorMode: '403',
    ipFilter: { sourceRange: [] },
    maintenance: { enabled: false, message: '' },
    timeAccess: { timezone: 'UTC', days: [], allowRange: '', denyRange: '' },
    headers: [],
    userAgents: { block: [], allow: [] }
  }
}

/**
 * Normalize sentinel config from API response
 * Ensures all nested objects exist with defaults
 * @param {Object} config - Config from API
 * @returns {Object|null} Normalized config or null
 */
export function normalizeSentinelConfig(config) {
  if (!config) return null
  return {
    enabled: config.enabled ?? true,
    errorMode: config.errorMode || '403',
    ipFilter: { sourceRange: config.ipFilter?.sourceRange || [] },
    maintenance: {
      enabled: config.maintenance?.enabled || false,
      message: config.maintenance?.message || ''
    },
    timeAccess: {
      timezone: config.timeAccess?.timezone || 'UTC',
      days: config.timeAccess?.days || [],
      allowRange: config.timeAccess?.allowRange || '',
      denyRange: config.timeAccess?.denyRange || ''
    },
    headers: config.headers || [],
    userAgents: {
      block: config.userAgents?.block || [],
      allow: config.userAgents?.allow || []
    }
  }
}

/**
 * Build route payload for create/update API calls
 * @param {Object} formData - Form data from modal
 * @returns {Object} API payload
 */
export function buildRoutePayload(formData) {
  return {
    domain: formData.domain,
    targetIp: formData.targetIp,
    targetPort: parseInt(formData.targetPort),
    vpnClientId: formData.vpnClientId ? parseInt(formData.vpnClientId) : null,
    httpsBackend: formData.httpsBackend,
    skipCertVerify: formData.skipCertVerify,
    backendSni: formData.backendSni,
    middlewares: formData.middlewares,
    description: formData.description,
    accessMode: formData.reach === 'public' ? 'public' : 'vpn',
    frontendSsl: formData.frontendSsl,
    certResolver: formData.certResolver || '',
    sentinelConfig: formData.sentinelConfig,
    lanAll: formData.reach === 'lan' && formData.lanPick === 'all',
    lanDevices: formData.reach === 'lan' && formData.lanPick === 'some' ? formData.lanDevices : []
  }
}

/**
 * Default form data for domain route
 * @returns {Object} Default form values
 */
export function defaultRouteForm() {
  return {
    domain: '',
    targetIp: '',
    targetPort: 80,
    vpnClientId: null,
    httpsBackend: false,
    skipCertVerify: false,
    backendSni: false,
    middlewares: [],
    description: '',
    // Who can reach it (REACH_OPTIONS): a new route is private and lets every approved LAN device in.
    reach: 'lan',
    lanPick: 'all', // 'all' LAN devices, or 'some': only lanDevices
    lanDevices: [],
    frontendSsl: false,
    certResolver: '',
    sentinelConfig: null
  }
}

/**
 * Map route from API to form data
 * @param {Object} route - Route from API
 * @returns {Object} Form data
 */
export function routeToFormData(route) {
  return {
    domain: route.domain,
    targetIp: route.targetIp,
    targetPort: route.targetPort,
    vpnClientId: route.vpnClientId || '',
    httpsBackend: route.httpsBackend,
    skipCertVerify: route.skipCertVerify || false,
    backendSni: route.backendSni || false,
    middlewares: route.middlewares || [],
    description: route.description || '',
    reach: route.accessMode === 'public' ? 'public' : route.lanAll || route.lanDevices?.length ? 'lan' : 'vpn',
    lanPick: route.lanDevices?.length ? 'some' : 'all',
    lanDevices: route.lanDevices || [],
    frontendSsl: route.frontendSsl || false,
    certResolver: route.certResolver || '',
    sentinelConfig: normalizeSentinelConfig(route.sentinelConfig)
  }
}

/** A wildcard domain (`*.example.com`) covers many hostnames, so it has no single one. */
export const isWildcardDomain = (domain) => !!domain?.startsWith('*.')

/**
 * The address a route's site opens at: https when the route serves HTTPS, else http. A wildcard
 * route has no single site to open.
 * @param {Object} route - Route from API
 * @returns {string|null}
 */
export function routeURL(route) {
  if (!route?.domain || isWildcardDomain(route.domain)) return null
  return `${route.frontendSsl ? 'https' : 'http'}://${route.domain}`
}

// Who can open a route: VPN devices only, anyone, or VPN devices and local-network (LAN) devices
// (last: it is the one that opens a choice of devices under it).
export const REACH_OPTIONS = [
  { value: 'vpn', icon: 'lock', color: 'primary', title: 'Only my VPN devices',
    description: 'Connected to the VPN' },
  { value: 'public', icon: 'world', color: 'warning', title: 'Anyone on the internet',
    description: 'No VPN needed' },
  { value: 'lan', icon: 'router', color: 'info', title: 'My VPN devices and my local network',
    description: 'Also devices plugged into the networks this panel runs. Over HTTPS only.' }
]

// Which local-network devices, when the local network may open a route.
export const LAN_PICK_OPTIONS = [
  { value: 'all', title: 'Every approved device', description: 'On every network, also ones you approve later.' },
  { value: 'some', title: 'Only the devices I pick', description: 'Choose them below.' }
]

// Constants
export const TIMEZONES = [
  'UTC', 'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Riga',
  'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
  'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Singapore', 'Australia/Sydney'
]

export const WEEK_DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

export const ERROR_MODES = [
  { value: '403', label: '403 Forbidden' },
  { value: '404', label: '404 Not Found' },
  { value: '503', label: '503 Service Unavailable' },
  { value: 'silent', label: 'Silent (close connection)' }
]
