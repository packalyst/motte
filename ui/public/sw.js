// Service Worker for Wire Panel PWA
// Minimal SW just to satisfy PWA requirements

self.addEventListener('install', () => self.skipWaiting())
self.addEventListener('activate', (e) => e.waitUntil(clients.claim()))
self.addEventListener('fetch', (e) => e.respondWith(fetch(e.request)))
