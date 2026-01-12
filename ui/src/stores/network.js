/**
 * Network status store
 * Tracks online/offline state and provides reconnection events
 */

import { writable, derived } from 'svelte/store'

// Core online state
export const isOnline = writable(typeof navigator !== 'undefined' ? navigator.onLine : true)

// Reconnection event counter (increments when coming back online)
export const reconnectCount = writable(0)

// Initialize event listeners
if (typeof window !== 'undefined') {
  window.addEventListener('online', () => {
    isOnline.set(true)
    reconnectCount.update(n => n + 1)
  })

  window.addEventListener('offline', () => {
    isOnline.set(false)
  })
}

/**
 * Visibility change handling for PWA refresh
 */
export const isVisible = writable(typeof document !== 'undefined' ? !document.hidden : true)
export const visibilityChangeCount = writable(0)

if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    const visible = !document.hidden
    isVisible.set(visible)
    if (visible) {
      visibilityChangeCount.update(n => n + 1)
    }
  })
}

/**
 * Helper to listen for app refresh events (pull-to-refresh or visibility change)
 * @param {Function} callback - Function to call on refresh
 * @returns {Function} Cleanup function
 */
export function onAppRefresh(callback) {
  if (typeof window === 'undefined') return () => {}

  window.addEventListener('app-refresh', callback)
  return () => window.removeEventListener('app-refresh', callback)
}
