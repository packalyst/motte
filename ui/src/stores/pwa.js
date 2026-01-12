/**
 * PWA Store
 * Svelte stores for PWA state management
 */

import { writable, derived } from 'svelte/store'
import {
  PermissionType,
  PermissionState,
  getAllPermissions,
  getPermissionStatus,
  requestPermission,
  detectPlatform,
  isInstalledPWA,
  getPlatformCapabilities,
  isPushSupported
} from '../lib/pwa/permissions'
import {
  getCurrentSubscription,
  getPreferences,
  isPushEnabled
} from '../lib/pwa/push'

// Platform info (static after init)
export const platform = writable(detectPlatform())
export const isInstalled = writable(isInstalledPWA())
export const capabilities = writable(getPlatformCapabilities())

// Permission states (reactive)
export const permissions = writable({
  [PermissionType.NOTIFICATIONS]: PermissionState.PROMPT,
  [PermissionType.GEOLOCATION]: PermissionState.PROMPT,
  [PermissionType.CAMERA]: PermissionState.PROMPT,
  [PermissionType.MICROPHONE]: PermissionState.PROMPT,
  [PermissionType.CLIPBOARD_READ]: PermissionState.PROMPT,
  [PermissionType.CLIPBOARD_WRITE]: PermissionState.PROMPT,
  [PermissionType.PERSISTENT_STORAGE]: PermissionState.PROMPT
})

// Push notification state
export const pushSubscription = writable(null)
export const pushEnabled = derived(pushSubscription, $sub => $sub !== null)

// Notification preferences from server (key-value map)
// Keys match Go constants: node_offline, node_online, firewall_alert, login_new_device, system_alert
export const notificationPreferences = writable({
  node_offline: true,
  node_online: false,
  firewall_alert: true,
  login_new_device: true,
  system_alert: true
})

// Loading states
export const loading = writable({
  permissions: false,
  push: false,
  preferences: false
})

// Error state
export const error = writable(null)

/**
 * Refreshes all permission states
 */
export async function refreshPermissions() {
  loading.update(l => ({ ...l, permissions: true }))
  error.set(null)

  try {
    const states = await getAllPermissions()
    permissions.set(states)
  } catch (e) {
    error.set('Failed to check permissions')
    console.error('Permission refresh error:', e)
  } finally {
    loading.update(l => ({ ...l, permissions: false }))
  }
}

/**
 * Refreshes a single permission
 * @param {string} permType - Permission type
 */
export async function refreshPermission(permType) {
  try {
    const state = await getPermissionStatus(permType)
    permissions.update(p => ({ ...p, [permType]: state }))
  } catch (e) {
    console.error(`Permission refresh error for ${permType}:`, e)
  }
}

/**
 * Requests a permission and updates store
 * @param {string} permType - Permission type
 * @returns {Promise<string>} New permission state
 */
export async function requestAndRefresh(permType) {
  loading.update(l => ({ ...l, permissions: true }))
  error.set(null)

  try {
    const state = await requestPermission(permType)
    permissions.update(p => ({ ...p, [permType]: state }))
    return state
  } catch (e) {
    error.set(`Failed to request ${permType} permission`)
    console.error('Permission request error:', e)
    return PermissionState.DENIED
  } finally {
    loading.update(l => ({ ...l, permissions: false }))
  }
}

/**
 * Refreshes push subscription state
 */
export async function refreshPushState() {
  if (!isPushSupported()) {
    pushSubscription.set(null)
    return
  }

  loading.update(l => ({ ...l, push: true }))

  try {
    const sub = await getCurrentSubscription()
    pushSubscription.set(sub)
  } catch (e) {
    console.error('Push state refresh error:', e)
    pushSubscription.set(null)
  } finally {
    loading.update(l => ({ ...l, push: false }))
  }
}

/**
 * Refreshes notification preferences from server
 */
export async function refreshPreferences() {
  loading.update(l => ({ ...l, preferences: true }))
  error.set(null)

  try {
    const prefs = await getPreferences()
    // API returns key-value map directly, just use it
    notificationPreferences.set(prefs)
  } catch (e) {
    // Ignore error if not authenticated
    if (!e.message?.includes('401') && !e.message?.includes('Unauthorized')) {
      error.set('Failed to load notification preferences')
      console.error('Preferences refresh error:', e)
    }
  } finally {
    loading.update(l => ({ ...l, preferences: false }))
  }
}

/**
 * Initializes PWA store state
 * Call this once on app startup
 */
export async function initPWAStore() {
  // Update static values
  platform.set(detectPlatform())
  isInstalled.set(isInstalledPWA())
  capabilities.set(getPlatformCapabilities())

  // Refresh dynamic values
  await Promise.all([
    refreshPermissions(),
    refreshPushState()
  ])
}

/**
 * Watches for permission changes (some browsers support this)
 * @param {string} permType - Permission type to watch
 * @param {Function} callback - Callback on change
 * @returns {Function} Unsubscribe function
 */
export function watchPermission(permType, callback) {
  if (typeof navigator === 'undefined' || !navigator.permissions) {
    return () => {} // No-op unsubscribe
  }

  let permissionStatus = null

  navigator.permissions.query({ name: permType })
    .then(status => {
      permissionStatus = status
      status.onchange = () => {
        permissions.update(p => ({ ...p, [permType]: status.state }))
        callback?.(status.state)
      }
    })
    .catch(() => {
      // Permission query not supported
    })

  return () => {
    if (permissionStatus) {
      permissionStatus.onchange = null
    }
  }
}

// Auto-initialize on import in browser context
if (typeof window !== 'undefined') {
  // Defer initialization slightly to avoid blocking initial render
  setTimeout(() => {
    initPWAStore().catch(console.error)
  }, 100)
}
