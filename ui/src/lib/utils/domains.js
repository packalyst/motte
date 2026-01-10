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
    middlewares: formData.middlewares,
    description: formData.description,
    accessMode: formData.accessMode,
    frontendSsl: formData.frontendSsl,
    sentinelConfig: formData.sentinelConfig
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
    middlewares: [],
    description: '',
    accessMode: 'vpn',
    frontendSsl: false,
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
    middlewares: route.middlewares || [],
    description: route.description || '',
    accessMode: route.accessMode || 'vpn',
    frontendSsl: route.frontendSsl || false,
    sentinelConfig: normalizeSentinelConfig(route.sentinelConfig)
  }
}

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
