/**
 * Clipboard utilities
 */

/**
 * Copy text to clipboard with fallback for older browsers
 * @param {string} text - Text to copy
 * @returns {Promise<boolean>} True if successful
 */
export async function copyToClipboard(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
      return true
    } else {
      return fallbackCopy(text)
    }
  } catch (err) {
    return fallbackCopy(text)
  }
}

/**
 * Fallback copy method using textarea
 * @param {string} text - Text to copy
 * @returns {boolean} True if successful
 */
export function fallbackCopy(text) {
  const textArea = document.createElement('textarea')
  textArea.value = text
  textArea.style.position = 'fixed'
  textArea.style.left = '-999999px'
  textArea.style.top = '-999999px'
  document.body.appendChild(textArea)
  textArea.focus()
  textArea.select()

  try {
    document.execCommand('copy')
    return true
  } catch (err) {
    return false
  } finally {
    document.body.removeChild(textArea)
  }
}
