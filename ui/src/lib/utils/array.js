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
