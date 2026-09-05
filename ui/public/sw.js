// Service Worker for Wire Panel PWA
// Handles push notifications and basic PWA requirements

const CACHE_VERSION = 'v3'

// The app shell. Cached so a failed SPA navigation can still boot the app
// instead of the browser's network-error page. It only loads the SPA bundle,
// which then makes its own fresh /api/ calls — no dynamic data is cached.
const SHELL = '/index.html'

// Install - precache the shell, then activate immediately.
self.addEventListener('install', (e) =>
  e.waitUntil(
    caches
      .open(CACHE_VERSION)
      .then((c) => c.add(SHELL))
      .catch(() => {}) // offline at install: shell fills in on first online nav
      .then(() => self.skipWaiting())
  )
)

// Activate - drop old cache versions, then claim all clients.
self.addEventListener('activate', (e) =>
  e.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k)))
      )
      .then(() => clients.claim())
  )
)

// Fetch. We deliberately do NOT intercept the API or the WebSocket: letting the
// browser handle /api/* natively means live/live-data and /api/ws are never
// routed through the Service Worker, so switching the panel between its public
// (Cloudflare) IP and its VPN IP can't leave them pinned to a stale kept-alive
// connection.
self.addEventListener('fetch', (e) => {
  const { request } = e
  const url = new URL(request.url)

  if (url.origin === self.location.origin && url.pathname.startsWith('/api/')) {
    return // don't call respondWith → default browser handling (fresh connection)
  }

  // SPA navigations: network-first, falling back to the cached shell. A
  // transient failure (or an IP switch mid-navigation) then boots the app
  // rather than surfacing a "FetchEvent resulted in a network error" page.
  if (request.mode === 'navigate') {
    e.respondWith(
      fetch(request)
        .then((res) => {
          if (res && res.ok) {
            const copy = res.clone() // keep the cached shell fresh while online
            caches.open(CACHE_VERSION).then((c) => c.put(SHELL, copy)).catch(() => {})
          }
          return res
        })
        .catch(() => caches.match(SHELL).then((cached) => cached || Response.error()))
    )
    return
  }

  // Everything else: plain pass-through, with the failure caught so a
  // blocked/offline request resolves to a network-error Response instead of an
  // uncaught promise rejection.
  e.respondWith(fetch(request).catch(() => Response.error()))
})

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
