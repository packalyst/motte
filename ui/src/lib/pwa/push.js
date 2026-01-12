/**
 * Push Notification Manager
 * Handles Web Push subscription and API integration
 */

import { apiGet, apiPost, apiPut, apiDelete } from '../../stores/app'

const API_BASE = '/api/pwa'

/**
 * Gets the VAPID public key from the server
 * @returns {Promise<string>} VAPID public key
 */
export async function getVapidPublicKey() {
  const response = await apiGet(`${API_BASE}/vapid-key`)
  return response.publicKey
}

/**
 * Converts URL-safe base64 to Uint8Array (for VAPID key)
 * @param {string} base64String - Base64 encoded string
 * @returns {Uint8Array} Decoded bytes
 */
function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4)
  const base64 = (base64String + padding)
    .replace(/-/g, '+')
    .replace(/_/g, '/')

  const rawData = window.atob(base64)
  const outputArray = new Uint8Array(rawData.length)

  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i)
  }

  return outputArray
}

/**
 * Gets current push subscription from service worker
 * @returns {Promise<PushSubscription|null>} Current subscription or null
 */
export async function getCurrentSubscription() {
  if (!('serviceWorker' in navigator)) return null

  const registration = await navigator.serviceWorker.ready
  return await registration.pushManager.getSubscription()
}

/**
 * Subscribes to push notifications
 * @param {string} deviceName - Optional device name
 * @returns {Promise<Object>} Subscription result from server
 */
export async function subscribeToPush(deviceName = '') {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    throw new Error('Push notifications not supported')
  }

  // Request notification permission first
  const permission = await Notification.requestPermission()
  if (permission !== 'granted') {
    throw new Error('Notification permission denied')
  }

  // Get VAPID key
  const vapidPublicKey = await getVapidPublicKey()
  const applicationServerKey = urlBase64ToUint8Array(vapidPublicKey)

  // Get service worker registration
  const registration = await navigator.serviceWorker.ready

  // Subscribe to push
  const subscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey
  })

  // Extract subscription data
  const subscriptionData = subscription.toJSON()

  // Send to server
  const response = await apiPost(`${API_BASE}/subscribe`, {
    deviceName: deviceName || getDeviceName(),
    endpoint: subscriptionData.endpoint,
    keyP256dh: subscriptionData.keys.p256dh,
    keyAuth: subscriptionData.keys.auth
  })

  return response
}

/**
 * Unsubscribes from push notifications
 * @returns {Promise<boolean>} True if successful
 */
export async function unsubscribeFromPush() {
  const subscription = await getCurrentSubscription()

  if (!subscription) {
    return true // Already unsubscribed
  }

  // Unsubscribe locally
  await subscription.unsubscribe()

  // Remove from server
  await apiPost(`${API_BASE}/unsubscribe`, {
    endpoint: subscription.endpoint
  })

  return true
}

/**
 * Gets list of user's push subscriptions
 * @returns {Promise<Array>} List of subscriptions
 */
export async function getSubscriptions() {
  return await apiGet(`${API_BASE}/subscriptions`)
}

/**
 * Deletes a push subscription by ID (revokes another device)
 * @param {number} id - Subscription ID to delete
 * @returns {Promise<Object>} Result
 */
export async function deleteSubscription(id) {
  return await apiDelete(`${API_BASE}/subscriptions?id=${id}`)
}

/**
 * Gets notification preferences
 * @returns {Promise<Object>} Notification preferences
 */
export async function getPreferences() {
  return await apiGet(`${API_BASE}/preferences`)
}

/**
 * Updates notification preferences
 * @param {Object} preferences - Preferences to update
 * @returns {Promise<Object>} Updated preferences
 */
export async function updatePreferences(preferences) {
  return await apiPut(`${API_BASE}/preferences`, preferences)
}

/**
 * Generates a device name based on browser/OS info
 * @returns {string} Device name
 */
function getDeviceName() {
  const ua = navigator.userAgent || ''

  // Try to get a meaningful name
  let device = 'Unknown Device'

  // Check for mobile devices first
  if (/iPhone/.test(ua)) device = 'iPhone'
  else if (/iPad/.test(ua)) device = 'iPad'
  else if (/Android/.test(ua)) {
    // Try to extract Android device name
    const match = ua.match(/Android[^;]*;\s*([^)]+)\)/)
    device = match ? match[1].split(' Build')[0].trim() : 'Android Device'
  }
  else if (/Macintosh/.test(ua)) device = 'Mac'
  else if (/Windows/.test(ua)) device = 'Windows PC'
  else if (/Linux/.test(ua)) device = 'Linux'

  // Add browser info
  let browser = ''
  if (/Chrome/.test(ua) && !/Edg/.test(ua)) browser = 'Chrome'
  else if (/Firefox/.test(ua)) browser = 'Firefox'
  else if (/Safari/.test(ua) && !/Chrome/.test(ua)) browser = 'Safari'
  else if (/Edg/.test(ua)) browser = 'Edge'

  return browser ? `${device} (${browser})` : device
}

/**
 * Checks if push is currently enabled (subscribed)
 * @returns {Promise<boolean>} True if subscribed
 */
export async function isPushEnabled() {
  const subscription = await getCurrentSubscription()
  return subscription !== null
}

/**
 * Location tracking API
 */

/**
 * Stores a location on the server
 * @param {GeolocationPosition} position - Geolocation position
 * @param {string} deviceName - Device name
 * @returns {Promise<Object>} Stored location
 */
export async function storeLocation(position, deviceName = '') {
  return await apiPost(`${API_BASE}/location`, {
    deviceName: deviceName || getDeviceName(),
    latitude: position.coords.latitude,
    longitude: position.coords.longitude,
    accuracy: position.coords.accuracy,
    altitude: position.coords.altitude,
    heading: position.coords.heading,
    speed: position.coords.speed
  })
}

/**
 * Gets stored locations
 * @param {Object} options - Query options
 * @returns {Promise<Array>} List of locations
 */
export async function getLocations(options = {}) {
  const params = new URLSearchParams()
  if (options.latest) params.set('latest', 'true')
  if (options.limit) params.set('limit', options.limit.toString())

  const query = params.toString()
  return await apiGet(`${API_BASE}/locations${query ? '?' + query : ''}`)
}

/**
 * Deletes locations
 * @param {number|'all'} idOrAll - Location ID or 'all'
 * @returns {Promise<Object>} Result
 */
export async function deleteLocations(idOrAll) {
  if (idOrAll === 'all') {
    return await apiDelete(`${API_BASE}/locations?all=true`)
  }
  return await apiDelete(`${API_BASE}/locations?id=${idOrAll}`)
}

/**
 * Sends a test push notification
 * @returns {Promise<Object>} Result
 */
export async function sendTestNotification() {
  return await apiPost(`${API_BASE}/test`)
}
