// Service Worker for Wire Panel PWA
// Handles push notifications and basic PWA requirements

const CACHE_VERSION = 'v1'

// Install - activate immediately
self.addEventListener('install', () => self.skipWaiting())

// Activate - claim all clients
self.addEventListener('activate', (e) => e.waitUntil(clients.claim()))

// Fetch - pass through (no caching for now)
self.addEventListener('fetch', (e) => e.respondWith(fetch(e.request)))

// Push notification received
self.addEventListener('push', (event) => {
  // iOS REQUIRES event.waitUntil() to always be called
  // Parse notification data with fallback
  let data = {
    title: 'Wire Panel',
    body: 'New notification',
    icon: '/icon-192.png'
  }

  if (event.data) {
    try {
      data = { ...data, ...event.data.json() }
    } catch (e) {
      // Plain text fallback
      data.body = event.data.text() || data.body
    }
  }

  // iOS-compatible options: minimal, no badge, PNG icons only
  const options = {
    body: data.body || data.message || '',
    icon: '/icon-192.png', // Always use PNG, iOS doesn't support SVG
    tag: data.tag || 'wire-panel-notification',
    data: data.data || {}
  }

  // Always call waitUntil - iOS requires this
  event.waitUntil(
    self.registration.showNotification(data.title || 'Wire Panel', options)
      .catch(err => console.error('[SW] Notification error:', err))
  )
})

// Notification click handler
self.addEventListener('notificationclick', (event) => {
  event.notification.close()

  const data = event.notification.data || {}
  let targetUrl = data.url || '/'

  // Handle action buttons
  if (event.action) {
    switch (event.action) {
      case 'view':
        targetUrl = data.viewUrl || data.url || '/'
        break
      case 'dismiss':
        return // Just close
      default:
        if (data.actions?.[event.action]) {
          targetUrl = data.actions[event.action]
        }
    }
  }

  // Focus existing window or open new one
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then((clientList) => {
        // Try to focus existing window
        for (const client of clientList) {
          if (client.url.includes(self.location.origin) && 'focus' in client) {
            client.focus()
            if (targetUrl !== '/') {
              client.navigate(targetUrl)
            }
            return
          }
        }
        // Open new window
        if (clients.openWindow) {
          return clients.openWindow(targetUrl)
        }
      })
  )
})

// Notification close handler (for analytics/cleanup if needed)
self.addEventListener('notificationclose', (event) => {
  // Could send analytics here
})
