/**
 * PWA Permissions Manager
 * Central manager for all PWA permission-related functionality.
 * Handles notifications, geolocation, camera, microphone, etc.
 */

// Permission types that can be checked/requested
export const PermissionType = {
  NOTIFICATIONS: 'notifications',
  GEOLOCATION: 'geolocation',
  CAMERA: 'camera',
  MICROPHONE: 'microphone',
  CLIPBOARD_READ: 'clipboard-read',
  CLIPBOARD_WRITE: 'clipboard-write',
  PERSISTENT_STORAGE: 'persistent-storage'
}

// Permission states
export const PermissionState = {
  GRANTED: 'granted',
  DENIED: 'denied',
  PROMPT: 'prompt',
  UNSUPPORTED: 'unsupported'
}

// Platform detection
export const Platform = {
  IOS: 'ios',
  ANDROID: 'android',
  DESKTOP: 'desktop',
  UNKNOWN: 'unknown'
}

/**
 * Detects the current platform
 * @returns {string} Platform identifier
 */
export function detectPlatform() {
  if (typeof navigator === 'undefined') return Platform.UNKNOWN

  const ua = navigator.userAgent || navigator.vendor || ''

  // iOS detection
  if (/iPad|iPhone|iPod/.test(ua) && !window.MSStream) {
    return Platform.IOS
  }

  // Android detection
  if (/android/i.test(ua)) {
    return Platform.ANDROID
  }

  // Desktop (macOS, Windows, Linux)
  if (/Macintosh|Windows|Linux/.test(ua) && !/Mobile/.test(ua)) {
    return Platform.DESKTOP
  }

  return Platform.UNKNOWN
}

/**
 * Checks if running as installed PWA
 * @returns {boolean} True if running as PWA
 */
export function isInstalledPWA() {
  if (typeof window === 'undefined') return false

  // Check display-mode
  if (window.matchMedia('(display-mode: standalone)').matches) {
    return true
  }

  // iOS Safari standalone check
  if (navigator.standalone === true) {
    return true
  }

  // Check for TWA (Trusted Web Activity) on Android
  if (document.referrer.includes('android-app://')) {
    return true
  }

  return false
}

/**
 * Gets the status of a specific permission
 * @param {string} permission - Permission type from PermissionType
 * @returns {Promise<string>} Permission state
 */
export async function getPermissionStatus(permission) {
  if (typeof navigator === 'undefined' || !navigator.permissions) {
    // Fallback for browsers without Permissions API
    return await getPermissionStatusFallback(permission)
  }

  try {
    // Some permissions need special handling
    switch (permission) {
      case PermissionType.NOTIFICATIONS:
        return getNotificationPermission()

      case PermissionType.PERSISTENT_STORAGE:
        return getPersistentStorageStatus()

      case PermissionType.GEOLOCATION:
        // iOS Safari doesn't support Permissions API for geolocation
        // Always use our localStorage-based check
        return await getPermissionStatusFallback(permission)

      default:
        // Try standard Permissions API
        const result = await navigator.permissions.query({ name: permission })
        return result.state
    }
  } catch (e) {
    // Permission not supported or query failed
    return await getPermissionStatusFallback(permission)
  }
}

/**
 * Gets notification permission status (special case)
 * @returns {string} Permission state
 */
function getNotificationPermission() {
  if (typeof Notification === 'undefined') {
    return PermissionState.UNSUPPORTED
  }
  return Notification.permission
}

/**
 * Gets persistent storage status
 * @returns {Promise<string>} Permission state
 */
async function getPersistentStorageStatus() {
  if (!navigator.storage || !navigator.storage.persisted) {
    return PermissionState.UNSUPPORTED
  }

  const isPersisted = await navigator.storage.persisted()
  return isPersisted ? PermissionState.GRANTED : PermissionState.PROMPT
}

/**
 * Fallback for browsers without Permissions API
 * @param {string} permission - Permission type
 * @returns {Promise<string>} Permission state
 */
async function getPermissionStatusFallback(permission) {
  switch (permission) {
    case PermissionType.NOTIFICATIONS:
      return getNotificationPermission()

    case PermissionType.GEOLOCATION:
      if (!navigator.geolocation) return PermissionState.UNSUPPORTED
      // iOS Safari doesn't support Permissions API for geolocation
      // Actually test access with a quick position request
      return await testGeolocationAccess()

    case PermissionType.CAMERA:
    case PermissionType.MICROPHONE:
      if (!navigator.mediaDevices) return PermissionState.UNSUPPORTED
      return PermissionState.PROMPT

    case PermissionType.CLIPBOARD_READ:
    case PermissionType.CLIPBOARD_WRITE:
      if (!navigator.clipboard) return PermissionState.UNSUPPORTED
      return PermissionState.PROMPT

    case PermissionType.PERSISTENT_STORAGE:
      return getPersistentStorageStatus()

    default:
      return PermissionState.UNSUPPORTED
  }
}

/**
 * Requests a specific permission
 * @param {string} permission - Permission type
 * @returns {Promise<string>} New permission state
 */
export async function requestPermission(permission) {
  switch (permission) {
    case PermissionType.NOTIFICATIONS:
      return await requestNotificationPermission()

    case PermissionType.GEOLOCATION:
      return await requestGeolocationPermission()

    case PermissionType.CAMERA:
      return await requestCameraPermission()

    case PermissionType.MICROPHONE:
      return await requestMicrophonePermission()

    case PermissionType.CLIPBOARD_READ:
      return await requestClipboardReadPermission()

    case PermissionType.PERSISTENT_STORAGE:
      return await requestPersistentStorage()

    default:
      return PermissionState.UNSUPPORTED
  }
}

/**
 * Requests notification permission
 * @returns {Promise<string>} Permission state
 */
async function requestNotificationPermission() {
  if (typeof Notification === 'undefined') {
    return PermissionState.UNSUPPORTED
  }

  const result = await Notification.requestPermission()
  return result
}

/**
 * Requests geolocation permission by getting current position
 * @returns {Promise<string>} Permission state
 */
async function requestGeolocationPermission() {
  if (!navigator.geolocation) {
    return PermissionState.UNSUPPORTED
  }

  return new Promise((resolve) => {
    navigator.geolocation.getCurrentPosition(
      () => resolve(PermissionState.GRANTED),
      (error) => {
        if (error.code === error.PERMISSION_DENIED) {
          resolve(PermissionState.DENIED)
        } else {
          resolve(PermissionState.PROMPT)
        }
      },
      { timeout: 10000, maximumAge: 0 }
    )
  })
}

/**
 * Tests geolocation access without triggering a visible prompt
 * Uses maximumAge: Infinity to check for cached permission
 * @returns {Promise<string>} Permission state
 */
async function testGeolocationAccess() {
  // Check localStorage flag first (set when user grants permission)
  if (localStorage.getItem('pwa_geolocation_granted') === 'true') {
    return PermissionState.GRANTED
  }
  // Otherwise assume prompt
  return PermissionState.PROMPT
}

/**
 * Marks geolocation as granted in localStorage
 * Call this after successful geolocation access
 */
export function markGeolocationGranted() {
  localStorage.setItem('pwa_geolocation_granted', 'true')
}

/**
 * Clears geolocation granted flag
 */
export function clearGeolocationGranted() {
  localStorage.removeItem('pwa_geolocation_granted')
}

/**
 * Requests camera permission
 * @returns {Promise<string>} Permission state
 */
async function requestCameraPermission() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    return PermissionState.UNSUPPORTED
  }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true })
    // Stop all tracks immediately
    stream.getTracks().forEach(track => track.stop())
    return PermissionState.GRANTED
  } catch (e) {
    if (e.name === 'NotAllowedError') {
      return PermissionState.DENIED
    }
    return PermissionState.UNSUPPORTED
  }
}

/**
 * Requests microphone permission
 * @returns {Promise<string>} Permission state
 */
async function requestMicrophonePermission() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    return PermissionState.UNSUPPORTED
  }

  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
    stream.getTracks().forEach(track => track.stop())
    return PermissionState.GRANTED
  } catch (e) {
    if (e.name === 'NotAllowedError') {
      return PermissionState.DENIED
    }
    return PermissionState.UNSUPPORTED
  }
}

/**
 * Requests clipboard read permission
 * @returns {Promise<string>} Permission state
 */
async function requestClipboardReadPermission() {
  if (!navigator.clipboard || !navigator.clipboard.readText) {
    return PermissionState.UNSUPPORTED
  }

  try {
    await navigator.clipboard.readText()
    return PermissionState.GRANTED
  } catch (e) {
    if (e.name === 'NotAllowedError') {
      return PermissionState.DENIED
    }
    return PermissionState.PROMPT
  }
}

/**
 * Requests persistent storage
 * @returns {Promise<string>} Permission state
 */
async function requestPersistentStorage() {
  if (!navigator.storage || !navigator.storage.persist) {
    return PermissionState.UNSUPPORTED
  }

  const granted = await navigator.storage.persist()
  return granted ? PermissionState.GRANTED : PermissionState.DENIED
}

/**
 * Gets all permission statuses at once
 * @returns {Promise<Object>} Map of permission type to state
 */
export async function getAllPermissions() {
  const permissions = {}

  for (const type of Object.values(PermissionType)) {
    permissions[type] = await getPermissionStatus(type)
  }

  return permissions
}

/**
 * Checks if push notifications are supported
 * @returns {boolean} True if supported
 */
export function isPushSupported() {
  return (
    typeof window !== 'undefined' &&
    'serviceWorker' in navigator &&
    'PushManager' in window &&
    typeof Notification !== 'undefined'
  )
}

/**
 * Checks if geolocation is supported
 * @returns {boolean} True if supported
 */
export function isGeolocationSupported() {
  return typeof navigator !== 'undefined' && 'geolocation' in navigator
}

/**
 * Checks if camera is supported
 * @returns {boolean} True if supported
 */
export function isCameraSupported() {
  return (
    typeof navigator !== 'undefined' &&
    navigator.mediaDevices &&
    navigator.mediaDevices.getUserMedia
  )
}

/**
 * Gets PWA installation prompt (Android only)
 * Returns null on iOS/desktop where different install flow is needed
 * @returns {Promise<BeforeInstallPromptEvent|null>} Install prompt event or null
 */
let deferredInstallPrompt = null

export function setupInstallPrompt() {
  if (typeof window === 'undefined') return

  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault()
    deferredInstallPrompt = e
  })
}

export function getInstallPrompt() {
  return deferredInstallPrompt
}

export async function promptInstall() {
  if (!deferredInstallPrompt) return false

  deferredInstallPrompt.prompt()
  const result = await deferredInstallPrompt.userChoice
  deferredInstallPrompt = null

  return result.outcome === 'accepted'
}

/**
 * Checks if the app can be installed
 * @returns {boolean} True if installable
 */
export function canInstall() {
  // Already installed
  if (isInstalledPWA()) return false

  // Android with prompt ready
  if (deferredInstallPrompt) return true

  // iOS Safari - can use "Add to Home Screen"
  const platform = detectPlatform()
  if (platform === Platform.IOS) {
    // Check if Safari on iOS (not other browsers)
    const ua = navigator.userAgent || ''
    const isSafari = /Safari/.test(ua) && !/Chrome|CriOS|FxiOS/.test(ua)
    return isSafari
  }

  return false
}

/**
 * Parses iOS version from user agent
 * @returns {number} iOS version (e.g., 16.4) or 0 if not iOS
 */
function parseIOSVersion() {
  const ua = navigator.userAgent || ''
  // Match "OS 16_4" or "OS 16_4_1" patterns
  const match = ua.match(/OS (\d+)[_.](\d+)/)
  if (match) {
    return parseFloat(`${match[1]}.${match[2]}`)
  }
  return 0
}

/**
 * Gets platform-specific capabilities
 * @returns {Object} Capabilities object
 */
export function getPlatformCapabilities() {
  const platform = detectPlatform()
  const isInstalled = isInstalledPWA()

  const capabilities = {
    platform,
    isInstalled,
    pushNotifications: isPushSupported(),
    geolocation: isGeolocationSupported(),
    camera: isCameraSupported(),
    backgroundSync: 'serviceWorker' in navigator && 'SyncManager' in window,
    badgeApi: 'setAppBadge' in navigator,
    share: 'share' in navigator,
    wakeLock: 'wakeLock' in navigator
  }

  // Platform-specific overrides
  if (platform === Platform.IOS) {
    // iOS 16.4+ supports push notifications in installed PWA mode
    const iosVersion = parseIOSVersion()
    const supportsPush = isInstalled && iosVersion >= 16.4 && isPushSupported()

    capabilities.pushNotifications = supportsPush
    capabilities.backgroundSync = false  // Not supported on iOS
    capabilities.badgeApi = supportsPush  // Badge API also added in iOS 16.4
  }

  return capabilities
}

// Initialize install prompt handler
if (typeof window !== 'undefined') {
  setupInstallPrompt()
}
