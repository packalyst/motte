/**
 * Data transformation and filtering utilities
 */

/**
 * Group items by a key function or property name
 * @param {Array} items - Array of items to group
 * @param {Function|string} keyFn - Function to get key or property name
 * @returns {Object} Object with keys as group names and values as arrays
 *
 * Usage:
 *   groupBy(countries, 'continent')
 *   groupBy(items, item => item.type || 'other')
 */
export function groupBy(items, keyFn) {
  const fn = typeof keyFn === 'function' ? keyFn : (item) => item[keyFn]
  const groups = {}
  for (const item of items) {
    const key = fn(item) || 'other'
    if (!groups[key]) groups[key] = []
    groups[key].push(item)
  }
  return groups
}

/**
 * Filter items by searching multiple fields
 * @param {Array} items - Array of items to filter
 * @param {Array<string>} fields - Field names to search
 * @param {string} query - Search query (case insensitive)
 * @returns {Array} Filtered items
 *
 * Usage:
 *   filterByFields(routes, ['domain', 'targetIp', 'description'], searchQuery)
 */
export function filterByFields(items, fields, query) {
  if (!query || !query.trim()) return items
  const q = query.toLowerCase().trim()
  return items.filter(item =>
    fields.some(field => {
      const value = getNestedValue(item, field)
      return value && String(value).toLowerCase().includes(q)
    })
  )
}

/**
 * Get nested value from object using dot notation
 * @param {Object} obj - Object to get value from
 * @param {string} path - Dot-separated path (e.g., 'user.name')
 * @returns {*} Value at path or undefined
 */
export function getNestedValue(obj, path) {
  if (!obj || !path) return undefined
  return path.split('.').reduce((o, k) => o?.[k], obj)
}

/**
 * Sort items by multiple criteria
 * @param {Array} items - Array to sort
 * @param {Array} sorters - Array of sort configs: { field, dir: 'asc'|'desc', fn? }
 * @returns {Array} Sorted array (new reference)
 *
 * Usage:
 *   sortByMultiple(keys, [
 *     { fn: (a, b) => a.expired - b.expired },
 *     { field: 'expiration', dir: 'asc' }
 *   ])
 */
export function sortByMultiple(items, sorters) {
  return [...items].sort((a, b) => {
    for (const sorter of sorters) {
      let result
      if (sorter.fn) {
        result = sorter.fn(a, b)
      } else {
        const aVal = getNestedValue(a, sorter.field)
        const bVal = getNestedValue(b, sorter.field)
        if (aVal === bVal) {
          result = 0
        } else if (aVal === null || aVal === undefined) {
          result = 1
        } else if (bVal === null || bVal === undefined) {
          result = -1
        } else if (typeof aVal === 'string') {
          result = aVal.localeCompare(bVal)
        } else {
          result = aVal < bVal ? -1 : 1
        }
        if (sorter.dir === 'desc') result *= -1
      }
      if (result !== 0) return result
    }
    return 0
  })
}

/**
 * Create a debounced version of a function
 * @param {Function} fn - Function to debounce
 * @param {number} delay - Delay in milliseconds
 * @returns {Function} Debounced function
 */
export function debounce(fn, delay = 300) {
  let timeoutId
  return (...args) => {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => fn(...args), delay)
  }
}

/**
 * Unique items by key
 * @param {Array} items - Array of items
 * @param {Function|string} keyFn - Key function or property name
 * @returns {Array} Deduplicated array
 */
export function uniqueBy(items, keyFn) {
  const fn = typeof keyFn === 'function' ? keyFn : (item) => item[keyFn]
  const seen = new Set()
  return items.filter(item => {
    const key = fn(item)
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

/**
 * Partition array into two based on predicate
 * @param {Array} items - Array to partition
 * @param {Function} predicate - Function returning true/false
 * @returns {[Array, Array]} [matching, notMatching]
 */
export function partition(items, predicate) {
  const matching = []
  const notMatching = []
  for (const item of items) {
    if (predicate(item)) {
      matching.push(item)
    } else {
      notMatching.push(item)
    }
  }
  return [matching, notMatching]
}
