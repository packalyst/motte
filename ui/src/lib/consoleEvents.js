// Shared console-events WebSocket: one socket for the whole app that pushes the live session list
// across all machines and serves snapshot captures. Replaces polling. Same-origin, so the
// session cookie authenticates the handshake (like ConsoleSocket). Ref-counted: it connects on the
// first consumer and closes when the last one goes away, reconnecting with backoff while in use.
import { writable } from 'svelte/store'
import { apiPost, confirm, toast, consoleTarget, consoleReturn, currentView } from '../stores/app.js'

// The latest global session list: [{id,label,attached,viewers,machine_id,machine_name}].
export const consoleSessions = writable([])

let ws = null
let refs = 0
let backoff = 1000
let reconnectTimer = null
const snapWaiters = new Map() // "machine_id|session" → resolve fn

function wsUrl() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}/api/fleet/console/events`
}

function connect() {
  if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return
  ws = new WebSocket(wsUrl())
  ws.onopen = () => { backoff = 1000 }
  ws.onmessage = (e) => {
    let m
    try { m = JSON.parse(e.data) } catch { return }
    if (m.t === 'sessions') {
      consoleSessions.set(m.sessions || [])
    } else if (m.t === 'snapshot-result') {
      const k = m.machine_id + '|' + m.session
      const r = snapWaiters.get(k)
      if (typeof r === 'function') { snapWaiters.delete(k); r(m.data || '') }
    }
  }
  ws.onclose = () => {
    ws = null
    if (refs > 0) {
      clearTimeout(reconnectTimer)
      reconnectTimer = setTimeout(connect, backoff)
      backoff = Math.min(backoff * 2, 15000)
    }
  }
  ws.onerror = () => { try { ws?.close() } catch { /* noop */ } }
}

// open() registers a consumer and ensures the socket is live; the returned function releases it.
export function openConsoleEvents() {
  refs++
  connect()
  return () => {
    refs = Math.max(0, refs - 1)
    if (refs === 0) {
      clearTimeout(reconnectTimer)
      try { ws?.close() } catch { /* noop */ }
      ws = null
      consoleSessions.set([])
    }
  }
}

// requestSnapshot resolves with the base64 screen capture (or '' on timeout / when offline).
export function requestSnapshot(machineId, session) {
  return new Promise((resolve) => {
    const k = machineId + '|' + session
    snapWaiters.set(k, resolve)
    try {
      ws?.send(JSON.stringify({ t: 'snapshot', machine_id: machineId, session }))
    } catch { /* noop */ }
    setTimeout(() => {
      if (snapWaiters.has(k)) { snapWaiters.delete(k); resolve('') }
    }, 3000)
  })
}

// sessionColor is a session's accent colour: a stable hash of its id, so the console tab, split pane
// and the session's card on the Sessions page always match without storing anything.
export function sessionColor(id) {
  let h = 0
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0
  return `hsl(${h % 360} 68% 60%)`
}

// closeSession confirms, then kills one of the caller's own sessions (the server checks ownership);
// the socket pushes the updated list.
export async function closeSession(s, machineName) {
  const ok = await confirm({
    title: 'Close session',
    message: `Close Session ${s.label || ''} on ${machineName}? Anything running in it is terminated.`,
    variant: 'destructive', confirmText: 'Close',
  })
  if (!ok) return
  try {
    await apiPost('/api/fleet/console/kill', { machine_id: s.machine_id, session: s.id })
    toast('Session closed', 'success')
  } catch (e) {
    toast('Failed: ' + e.message, 'error')
  }
}

// openConsoleAt goes to the console page with a one-shot target (a session to resume, or fresh: true
// for a new one); closing the console returns to `back` ({ view, hash }).
export function openConsoleAt(target, back) {
  consoleTarget.set(target)
  consoleReturn.set(back)
  currentView.set('console')
}

// refresh asks the panel for a fresh live-queried list (e.g. after opening a tab).
export function refreshSessions() {
  try { ws?.send(JSON.stringify({ t: 'refresh' })) } catch { /* noop */ }
}
