// Service Worker for Motte PWA
// Handles push notifications and basic PWA requirements

const CACHE_VERSION = 'v4'

// The offline page: shown when a page load can't reach the panel (no internet, VPN off, server
// restarting) instead of a blank screen. Self-contained (inline styles and logo) plus its retry
// script; it reloads by itself once the panel answers. No app data is ever cached.
const OFFLINE = '/offline.html'
const PRECACHE = [OFFLINE, '/offline.js']

// Install - precache the offline page, then activate immediately.
self.addEventListener('install', (e) =>
  e.waitUntil(
    caches
      .open(CACHE_VERSION)
      .then((c) => c.addAll(PRECACHE))
      .catch(() => {}) // offline at install: cached on the next install
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

  // Other sites' requests aren't the panel's to handle (and fetching them from here would count
  // as a connection under the security policy, not an image): the browser does them itself.
  if (url.origin !== self.location.origin) return
  if (url.pathname.startsWith('/api/')) {
    return // don't call respondWith → default browser handling (fresh connection)
  }

  // Page loads: network first; if the panel can't be reached, the offline page (which retries,
  // so a brief blip such as an IP switch recovers on its own). A 444 counts as unreachable: it's
  // the VPN-only / blocked answer (Traefik's guard drops the request), which the browser would
  // otherwise show as a bare "HTTP ERROR 444".
  if (request.mode === 'navigate') {
    const offline = () => caches.match(OFFLINE).then((cached) => cached || Response.error())
    e.respondWith(fetch(request).then((res) => (res.status === 444 ? offline() : res)).catch(offline))
    return
  }

  // The offline page's own script, so it still loads with no connection.
  if (PRECACHE.includes(url.pathname)) {
    e.respondWith(fetch(request).catch(() => caches.match(url.pathname).then((cached) => cached || Response.error())))
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
    title: 'Motte',
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
    tag: data.tag || 'motte-notification',
    data: data.data || {}
  }

  // Always call waitUntil - iOS requires this
  event.waitUntil(
    self.registration.showNotification(data.title || 'Motte', options)
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
