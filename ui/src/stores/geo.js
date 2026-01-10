// Geo lookup helper - reusable across views
import { apiGet, apiPost } from './app.js'

// Cache for geo results (persists during session)
let geoCache = {}
let geoEnabled = null

// Check if geo lookup is available
export async function checkGeoEnabled() {
  if (geoEnabled !== null) return geoEnabled

  try {
    const status = await apiGet('/api/geo/status')
    geoEnabled = status.lookup_provider !== 'none' &&
                 status.providers?.[status.lookup_provider]?.available
  } catch {
    geoEnabled = false
  }
  return geoEnabled
}

// Bulk lookup geo data for IPs, returns merged cache
export async function lookupIPs(ips) {
  if (!ips || ips.length === 0) return geoCache

  // Check if geo is enabled
  const enabled = await checkGeoEnabled()
  if (!enabled) return geoCache

  // Filter out IPs already in cache
  const uncachedIPs = [...new Set(ips)].filter(ip => ip && !geoCache[ip])
  if (uncachedIPs.length === 0) return geoCache

  try {
    const res = await apiPost('/api/geo/lookup', { ips: uncachedIPs })
    if (res.results) {
      geoCache = { ...geoCache, ...res.results }
    }
  } catch {
    // Ignore lookup errors
  }

  return geoCache
}

// Get geo data for a single IP (from cache)
export function getGeoData(ip) {
  return geoCache[ip] || null
}

// Get all cached geo data
export function getGeoCache() {
  return geoCache
}

// Clear cache (useful for testing or reset)
export function clearGeoCache() {
  geoCache = {}
  geoEnabled = null
}

// Check if geo is enabled (cached result)
export function isGeoEnabled() {
  return geoEnabled === true
}
