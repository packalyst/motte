/**
 * Array manipulation utilities
 */

/**
 * Toggle item in array (add if missing, remove if present)
 * @param {Array} arr - Array to modify
 * @param {*} item - Item to toggle
 * @returns {Array} New array with item toggled
 */
export function toggleInArray(arr, item) {
  if (!arr) return [item]
  return arr.includes(item)
    ? arr.filter(i => i !== item)
    : [...arr, item]
}

/**
 * Add item to array at path in object (immutable)
 * @param {Object} obj - Object containing the array
 * @param {string} path - Dot-separated path to array (e.g., 'ipFilter.sourceRange')
 * @param {*} item - Item to add
 * @returns {Object} New object with item added
 */
export function addToPath(obj, path, item) {
  const parts = path.split('.')
  const clone = structuredClone(obj)
  let current = clone
  for (let i = 0; i < parts.length - 1; i++) {
    current = current[parts[i]]
  }
  const lastKey = parts[parts.length - 1]
  current[lastKey] = [...(current[lastKey] || []), item]
  return clone
}

/**
 * Remove item at index from array at path in object (immutable)
 * @param {Object} obj - Object containing the array
 * @param {string} path - Dot-separated path to array
 * @param {number} index - Index to remove
 * @returns {Object} New object with item removed
 */
export function removeFromPath(obj, path, index) {
  const parts = path.split('.')
  const clone = structuredClone(obj)
  let current = clone
  for (let i = 0; i < parts.length - 1; i++) {
    current = current[parts[i]]
  }
  const lastKey = parts[parts.length - 1]
  current[lastKey] = current[lastKey].filter((_, i) => i !== index)
  return clone
}

/**
 * Update item at index in array at path in object (immutable)
 * @param {Object} obj - Object containing the array
 * @param {string} path - Dot-separated path to array
 * @param {number} index - Index to update
 * @param {*} value - New value
 * @returns {Object} New object with item updated
 */
export function updateAtPath(obj, path, index, value) {
  const parts = path.split('.')
  const clone = structuredClone(obj)
  let current = clone
  for (let i = 0; i < parts.length - 1; i++) {
    current = current[parts[i]]
  }
  const lastKey = parts[parts.length - 1]
  current[lastKey] = current[lastKey].map((item, i) => i === index ? value : item)
  return clone
}
