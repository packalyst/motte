import { copyToClipboard } from '../lib/utils/clipboard.js'

// localStorage helpers - safe JSON parse with SSR check
export function loadState(key, defaultValue = {}) {
  if (typeof localStorage === 'undefined') return defaultValue
  try {
    return JSON.parse(localStorage.getItem(key) || JSON.stringify(defaultValue))
  } catch {
    return defaultValue
  }
}

export function saveState(key, value) {
  if (typeof localStorage !== 'undefined') {
    localStorage.setItem(key, JSON.stringify(value))
  }
}

// Debounced search helper - returns { search, cleanup } for proper cleanup on unmount
export function createDebouncedSearch(callback, delay = 400) {
  let timeout = null
  return {
    search: (value) => {
      clearTimeout(timeout)
      timeout = setTimeout(() => callback(value), delay)
    },
    cleanup: () => {
      clearTimeout(timeout)
      timeout = null
    }
  }
}

// Copy to clipboard with toast notification
export async function copyWithToast(text, toastFn) {
  const success = await copyToClipboard(text)
  toastFn(success ? 'Copied!' : 'Failed to copy', success ? 'success' : 'error')
  return success
}

// Get default per-page from settings
export function getDefaultPerPage() {
  if (typeof localStorage === 'undefined') return 25
  return parseInt(localStorage.getItem('settings_items_per_page') || '25')
}

// Svelte action for lazy loading images in scrollable containers
export function lazyLoad(node, src) {
  const observer = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) {
      node.src = src
      observer.disconnect()
    }
  }, { rootMargin: '50px' })
  observer.observe(node)
  return { destroy: () => observer.disconnect() }
}
