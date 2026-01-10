/**
 * Formatting utilities for dates, numbers, and durations
 */

// ============================================================================
// Number Formatting
// ============================================================================

/**
 * Format large numbers with K/M suffix
 * @param {number} num - Number to format
 * @returns {string} Formatted string (e.g., "1.5K", "2.3M")
 */
export function formatNumber(num) {
  if (!num) return '0'
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

/**
 * Format bytes to human readable format
 * @param {number} bytes - Bytes to format
 * @param {number} decimals - Decimal places (default: 1)
 * @returns {string} Formatted string (e.g., "1.5 GB")
 */
export function formatBytes(bytes, decimals = 1) {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i]
}

// ============================================================================
// Time/Duration Formatting
// ============================================================================

/**
 * Format time string to locale time
 * @param {string|Date} dateStr - Date to format
 * @returns {string} Locale time string
 */
export function formatTime(dateStr) {
  if (!dateStr) return '-'
  return new Date(dateStr).toLocaleTimeString()
}

/**
 * Format nanoseconds to human readable duration
 * @param {number} ns - Nanoseconds
 * @returns {string} Formatted duration (e.g., "150ms", "1.5s")
 */
export function formatDuration(ns) {
  if (!ns) return '-'
  const ms = ns / 1000000
  if (ms < 1) return '<1ms'
  if (ms < 1000) return Math.round(ms) + 'ms'
  return (ms / 1000).toFixed(2) + 's'
}

/**
 * Format seconds to human readable ban time
 * @param {number} seconds - Seconds
 * @returns {string} Formatted time (e.g., "5m", "2h", "1d")
 */
export function formatBanTime(seconds) {
  if (!seconds || seconds < 0) return '-'
  if (seconds < 60) return seconds + 's'
  if (seconds < 3600) return Math.floor(seconds / 60) + 'm'
  if (seconds < 86400) return Math.floor(seconds / 3600) + 'h'
  return Math.floor(seconds / 86400) + 'd'
}

// ============================================================================
// Date Formatting
// ============================================================================

/**
 * Format date to locale string
 * @param {string|Date|object} date - Date to format (can have .seconds property)
 * @returns {string} Formatted date string
 */
export function formatDate(date) {
  if (!date) return '-'
  const d = parseDate(date)
  if (!d || isNaN(d.getTime())) return '-'
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

/**
 * Format date as relative time (e.g., "Today" or "Dec 21")
 * @param {string|Date|object} date - Date to format
 * @returns {string} Relative date string
 */
export function formatRelativeDate(date) {
  if (!date) return '-'
  const d = parseDate(date)
  if (!d || isNaN(d.getTime())) return '-'

  const now = new Date()
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  const dateDay = new Date(d.getFullYear(), d.getMonth(), d.getDate())
  const diffDays = Math.floor((today - dateDay) / (1000 * 60 * 60 * 24))

  if (diffDays === 0) return 'Today'

  // Show short date (e.g., "Dec 21" or "Dec 21, 2024" if different year)
  const options = { month: 'short', day: 'numeric' }
  if (d.getFullYear() !== now.getFullYear()) {
    options.year = 'numeric'
  }
  return d.toLocaleDateString('en-US', options)
}

/**
 * Format time ago (e.g., "5m ago", "2h ago")
 * @param {string|Date|object} date - Date to format
 * @returns {string} Time ago string
 */
export function timeAgo(date) {
  if (!date) return '-'
  const d = parseDate(date)
  if (!d || isNaN(d.getTime())) return '-'

  const now = new Date()
  const diffMs = now - d
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 30) return `${diffDays}d ago`
  return formatRelativeDate(date)
}

// ============================================================================
// Date Parsing
// ============================================================================

/**
 * Parse various date formats to Date object
 * @param {string|Date|object|number} date - Date in various formats
 * @returns {Date|null} Parsed Date object or null
 */
export function parseDate(date) {
  if (!date) return null

  // Already a Date
  if (date instanceof Date) return date

  // Object with seconds property (protobuf timestamp)
  if (typeof date === 'object' && date.seconds) {
    return new Date(Number(date.seconds) * 1000)
  }

  // Number (unix timestamp in seconds or milliseconds)
  if (typeof date === 'number') {
    // If less than year 2000 in ms, assume seconds
    return date < 946684800000 ? new Date(date * 1000) : new Date(date)
  }

  // String
  if (typeof date === 'string') {
    // Check for zero/empty dates
    if (date.startsWith('0001') || date === '0' || date === '') return null
    return new Date(date)
  }

  return null
}

/**
 * Check if a date is expired
 * @param {string|Date|object} date - Date to check
 * @returns {boolean} True if expired
 */
export function isExpired(date) {
  const d = parseDate(date)
  if (!d) return false
  return d < new Date()
}

/**
 * Check if a date is expiring soon
 * @param {string|Date|object} date - Date to check
 * @param {number} days - Days threshold (default: 7)
 * @returns {boolean} True if expiring within threshold
 */
export function isExpiringSoon(date, days = 7) {
  const d = parseDate(date)
  if (!d) return false
  const threshold = new Date()
  threshold.setDate(threshold.getDate() + days)
  return d > new Date() && d < threshold
}

/**
 * Get days until expiry (negative if expired)
 * @param {string|Date|object} date - Date to check
 * @returns {number|null} Days until expiry or null if no date
 */
export function getDaysUntilExpiry(date) {
  const d = parseDate(date)
  if (!d) return null
  const now = new Date()
  return Math.ceil((d - now) / (1000 * 60 * 60 * 24))
}

/**
 * Format expiry date as relative string (e.g., "Expires in 3 days", "Expired yesterday")
 * @param {string|Date|object} date - Date to format
 * @returns {string} Expiry string
 */
export function formatExpiryDate(date) {
  const d = parseDate(date)
  if (!d) return 'Never'

  const now = new Date()
  const diffMs = d - now
  const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24))

  if (diffDays < 0) {
    const absDays = Math.abs(diffDays)
    if (absDays === 1) return 'Expired yesterday'
    if (absDays < 7) return `Expired ${absDays} days ago`
    if (absDays < 30) return `Expired ${Math.floor(absDays / 7)} weeks ago`
    return `Expired ${Math.floor(absDays / 30)} months ago`
  }
  if (diffDays === 0) return 'Expires today'
  if (diffDays === 1) return 'Expires tomorrow'
  if (diffDays < 7) return `Expires in ${diffDays} days`
  if (diffDays < 30) return `Expires in ${Math.floor(diffDays / 7)} weeks`
  if (diffDays < 365) return `Expires in ${Math.floor(diffDays / 30)} months`
  return `Expires in ${Math.floor(diffDays / 365)} years`
}

/**
 * Format date to simple locale date string
 * @param {string|Date|object} date - Date to format
 * @returns {string} Formatted date or 'Never'
 */
export function formatDateShort(date) {
  const d = parseDate(date)
  if (!d) return 'Never'
  return d.toLocaleDateString()
}
