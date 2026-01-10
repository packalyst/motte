/**
 * WebSocket store for real-time updates
 * Manages connection, subscriptions, and data stores
 */

import { writable } from 'svelte/store'

// Connection state
export const wsConnected = writable(false)
export const wsReconnecting = writable(false)

// User info received on WebSocket connect
export const wsUserStore = writable(null)

// Data stores for each channel
export const generalInfoStore = writable(null) // General info channel (stats, firewall events, etc.)
export const nodesUpdatedStore = writable(0) // Counter that increments on nodes_updated
export const dockerStore = writable(null)
export const dockerLogsStore = writable([]) // Array of log entries for live streaming
export const statsStore = writable(null) // Overview dashboard stats

// Channel to store mapping
const storeMap = {
  general_info: generalInfoStore,
  nodes_updated: nodesUpdatedStore,
  docker: dockerStore,
  docker_logs: dockerLogsStore,
  stats: statsStore
}

// WebSocket instance
let ws = null
let reconnectTimer = null
let reconnectAttempts = 0
const maxReconnectAttempts = 5
const reconnectDelay = 3000

// Current subscriptions
let activeSubscriptions = new Set()

/**
 * Connect to WebSocket server
 */
export function connect() {
  const token = localStorage.getItem('session_token')
  if (!token) return

  // Clean up existing connection
  if (ws) {
    ws.close()
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const wsUrl = `${protocol}//${window.location.host}/api/ws`

  try {
    ws = new WebSocket(wsUrl)

    ws.onopen = () => {
      ws.send(JSON.stringify({ action: 'auth', token }))
    }

    ws.onmessage = (event) => {
      try {
        // Handle batched messages (newline separated)
        const messages = event.data.split('\n')
        for (const msgStr of messages) {
          if (!msgStr.trim()) continue
          const msg = JSON.parse(msgStr)
          handleMessage(msg)
        }
      } catch {
        // Ignore parse errors
      }
    }

    ws.onclose = (event) => {
      wsConnected.set(false)
      ws = null

      // Don't reconnect on:
      // - Clean close (1000)
      // - Auth failure (4001 or reason contains 'auth'/'invalid'/'expired')
      // - Max attempts reached
      const isAuthError = event.code === 4001 ||
        (event.reason && /auth|invalid|expired|unauthorized/i.test(event.reason))

      if (event.code !== 1000 && !isAuthError && reconnectAttempts < maxReconnectAttempts) {
        scheduleReconnect()
      }
    }

    ws.onerror = () => {}
  } catch {
    // Ignore connection errors
  }
}

/**
 * Handle incoming WebSocket message
 */
function handleMessage(msg) {
  const { type, payload } = msg

  // Handle init message (sent on connect with user info - confirms auth success)
  if (type === 'init') {
    wsConnected.set(true)
    wsReconnecting.set(false)
    reconnectAttempts = 0

    if (payload?.user) {
      wsUserStore.set(payload.user)
    }

    // Resubscribe to any active channels after reconnect
    if (activeSubscriptions.size > 0) {
      const channels = Array.from(activeSubscriptions)
      ws.send(JSON.stringify({
        action: 'subscribe',
        channels: channels
      }))
    }
    return
  }

  const store = storeMap[type]
  if (store) {
    // nodes_updated is a notification without payload - increment counter
    if (type === 'nodes_updated') {
      store.update(n => n + 1)
    } else if (type === 'docker_logs') {
      // Append log entry to array
      store.update(logs => [...logs, payload])
    } else if (type === 'general_info') {
      // For general_info, process events immediately to avoid missing rapid messages
      const event = payload?.event
      if (event === 'firewall:zones:progress' || event === 'firewall:zones:complete' || event === 'firewall:zones:start') {
        // Dispatch custom event for zone updates
        window.dispatchEvent(new CustomEvent('firewall-zone-update', { detail: payload }))
      } else if (event === 'scan:progress' || event === 'scan:complete') {
        // Dispatch custom event for port scan updates
        window.dispatchEvent(new CustomEvent('port-scan-update', { detail: payload }))
      }
      store.set(payload)
    } else {
      store.set(payload)
    }
  }
}

/**
 * Schedule a reconnection attempt
 */
function scheduleReconnect() {
  if (reconnectTimer) return

  wsReconnecting.set(true)
  reconnectAttempts++

  reconnectTimer = setTimeout(() => {
    reconnectTimer = null
    connect()
  }, reconnectDelay * reconnectAttempts)
}

/**
 * Subscribe to channels
 * @param {string[]} channels - Array of channel names
 */
export function subscribe(channels) {
  if (!Array.isArray(channels)) {
    channels = [channels]
  }

  // Track subscriptions
  channels.forEach(ch => activeSubscriptions.add(ch))

  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      action: 'subscribe',
      channels: channels
    }))
  }
}

/**
 * Unsubscribe from channels
 * @param {string[]} channels - Array of channel names
 */
export function unsubscribe(channels) {
  if (!Array.isArray(channels)) {
    channels = [channels]
  }

  // Remove from tracked subscriptions
  channels.forEach(ch => activeSubscriptions.delete(ch))

  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      action: 'unsubscribe',
      channels: channels
    }))
  }
}

/**
 * Subscribe to docker logs for a specific container
 * @param {string} containerName - Container name to stream logs from
 */
export function subscribeToLogs(containerName) {
  // Clear previous logs
  dockerLogsStore.set([])
  activeSubscriptions.add('docker_logs')

  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      action: 'subscribe',
      channels: ['docker_logs'],
      container: containerName
    }))
  }
}

/**
 * Unsubscribe from docker logs
 */
export function unsubscribeFromLogs() {
  activeSubscriptions.delete('docker_logs')
  dockerLogsStore.set([])

  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      action: 'unsubscribe',
      channels: ['docker_logs']
    }))
  }
}

/**
 * Stop reconnection attempts without closing current connection
 */
export function stopReconnect() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer)
    reconnectTimer = null
  }
  wsReconnecting.set(false)
  reconnectAttempts = maxReconnectAttempts // Prevent future reconnects
}

/**
 * Disconnect WebSocket
 */
export function disconnect() {
  stopReconnect()

  if (ws) {
    ws.close(1000, 'User logout')
    ws = null
  }

  wsConnected.set(false)
  activeSubscriptions.clear()
  reconnectAttempts = 0

  // Clear all stores
  wsUserStore.set(null)
  Object.values(storeMap).forEach(store => store.set(null))
}

/**
 * Check if connected
 */
export function isConnected() {
  return ws && ws.readyState === WebSocket.OPEN
}

/**
 * Get store for a channel
 * @param {string} channel - Channel name
 * @returns {import('svelte/store').Writable} - Svelte store
 */
export function getStore(channel) {
  return storeMap[channel]
}
