import { writable, get } from 'svelte/store'

// The signed-in user (null when logged out). Set by App.svelte; read by step-up helpers and the
// idle lock so they know the caller's 2FA status and idle-lock policy without prop threading.
export const currentUser = writable(null)

// hasRole mirrors the server's role order; it only decides what the UI shows — every action is
// still checked on the server.
const ROLE_RANK = { viewer: 1, operator: 2, admin: 3, owner: 4 }
export const hasRole = (user, min) => (ROLE_RANK[user?.role] || 0) >= ROLE_RANK[min]

// Theme
const savedTheme = typeof localStorage !== 'undefined' ? localStorage.getItem('hs_theme') : 'dark'
export const theme = writable(savedTheme || 'dark')
theme.subscribe(value => {
  if (typeof document !== 'undefined') {
    if (value === 'dark') {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
    localStorage.setItem('hs_theme', value)
  }
})

// Valid view IDs for URL routing
export const validViews = ['overview', 'users', 'firewall', 'server', 'console', 'sessions', 'iplookup',
                           'clients', 'routes', 'authkeys', 'apikeys', 'domains', 'tunnels', 'adguard',
                           'logs', 'analytics', 'activity', 'routines', 'settings', 'profile', 'about']

// Get initial tab from URL hash (for tab persistence on refresh)
export function getInitialTab(defaultTab, validTabs) {
  if (typeof window === 'undefined') return defaultTab
  const hash = window.location.hash.slice(1)
  const params = new URLSearchParams(hash)
  const tabFromUrl = params.get('tab')
  return tabFromUrl && validTabs.includes(tabFromUrl) ? tabFromUrl : defaultTab
}

// Views that were merged into another page: old links and saved views land on the new one.
// networks: devices are on Clients, the networks themselves in Settings → Networks.
// A string maps to a view; [view, hash] also opens a section of it (the hash is only added when the
// URL has none, so an explicit one wins).
const viewAliases = { nodes: 'clients', fleet: 'clients', networks: 'clients', team: ['settings', 's=team'], traefik: ['settings', 's=web'], docker: ['settings', 's=docker'] }
function resolveView(v) {
  const a = viewAliases[v]
  if (!Array.isArray(a)) return a || v
  if (typeof window !== 'undefined' && !window.location.hash) {
    window.history.replaceState(window.history.state, '', window.location.pathname + '#' + a[1])
  }
  return a[0]
}

// Get view from current URL path
function getViewFromPath() {
  if (typeof window === 'undefined') return null
  const path = resolveView(window.location.pathname.slice(1)) // Remove leading /
  return validViews.includes(path) ? path : null
}

// Current view - URL takes priority, then localStorage, then default
const urlView = typeof window !== 'undefined' ? getViewFromPath() : null
const savedView = typeof localStorage !== 'undefined' ? resolveView(localStorage.getItem('hs_view')) : 'overview'
export const currentView = writable(urlView || savedView || 'overview')

// Track if we're handling popstate to avoid double-pushing
let handlingPopstate = false

// The view navigated away FROM (so the console's close button can return there), and a one-shot
// target the console page opens on arrival (set by a machine's session card before navigating).
export const previousView = writable(null)
export const consoleTarget = writable(null)
// Where the console's close button returns to: { view, hash? } captured when navigating in.
export const consoleReturn = writable(null)
let _lastView = urlView || savedView || 'overview'

currentView.subscribe(value => {
  if (typeof window !== 'undefined' && value) {
    if (value !== _lastView) { previousView.set(_lastView); _lastView = value }
    localStorage.setItem('hs_view', value)
    // Update URL without reload (skip if handling popstate)
    // An old path that's an alias of this view (/team → settings#s=team) keeps its hash.
    const aliased = resolveView(window.location.pathname.slice(1)) === value
    const newPath = '/' + value
    const newURL = newPath + (aliased ? window.location.hash : '')
    if (!handlingPopstate && window.location.pathname !== newPath) {
      // In a trivial session history (one entry — a fresh tab or standalone
      // PWA) pushState is treated as replaceState and Chrome logs a warning;
      // call replaceState directly there to keep the console clean. Once there
      // is real history to go back to, push so back/forward still work.
      if (window.history.length <= 1) {
        window.history.replaceState({ view: value }, '', newURL)
      } else {
        window.history.pushState({ view: value }, '', newURL)
      }
    }
  }
})

// openView navigates to a view with a deep-link hash (e.g. 'n=<id>') that the view reads once its
// data has loaded, to open that item. The view switch pushes the bare path synchronously, so the
// hash is added to that same history entry.
export function openView(view, hash) {
  currentView.set(view)
  if (typeof window !== 'undefined' && hash) {
    window.history.replaceState(window.history.state, '', '/' + view + '#' + hash)
  }
}

// takeHashParam returns a deep-link hash parameter once and strips the hash from the URL.
export function takeHashParam(key) {
  if (typeof window === 'undefined') return null
  const v = new URLSearchParams(window.location.hash.slice(1)).get(key)
  if (v !== null) window.history.replaceState(window.history.state, '', window.location.pathname)
  return v
}

// hashParam / setHashParam read and write one key of the URL hash (#a=1&b=2), e.g. a page's open
// section, so a refresh lands back on it. replaceState: no new history entry, no hashchange event.
export function hashParam(key) {
  if (typeof window === 'undefined') return null
  return new URLSearchParams(window.location.hash.slice(1)).get(key)
}
export function setHashParam(key, value) {
  if (typeof window === 'undefined') return
  const p = new URLSearchParams(window.location.hash.slice(1))
  if (value) p.set(key, value)
  else p.delete(key)
  const q = p.toString()
  history.replaceState(history.state, '', window.location.pathname + (q ? '#' + q : ''))
}

// Handle browser back/forward
if (typeof window !== 'undefined') {
  window.addEventListener('popstate', (event) => {
    const view = resolveView(event.state?.view) || getViewFromPath() || 'overview'
    if (validViews.includes(view)) {
      handlingPopstate = true
      currentView.set(view)
      handlingPopstate = false
    }
  })

  // Set initial history state (replaceState so we don't add to history)
  // Preserve the hash (for tab persistence)
  const initialView = getViewFromPath() || savedView || 'overview'
  const hash = window.location.hash || ''
  window.history.replaceState({ view: initialView }, '', '/' + initialView + hash)
}

// Toasts: rendered by Toaster.svelte as plain text (never HTML), stacked newest-in-front. At most
// TOAST_LIMIT at once — a new one pushes out the oldest. Each carries how long it stays (errors a
// little longer, so they can be read); the Toaster runs the timers and pauses them on hover.
export const toasts = writable([])
let toastSeq = 0
const TOAST_LIMIT = 5
const TOAST_MS = { error: 6000, warning: 5000 }
export function dismissToast(id) {
  toasts.update((list) => list.filter((t) => t.id !== id))
}
export function toast(message, type = 'info') {
  const t = { id: ++toastSeq, type, message: String(message ?? ''), duration: TOAST_MS[type] || 4000 }
  toasts.update((list) => [...list.slice(-(TOAST_LIMIT - 1)), t])
}

// Global confirm modal store
export const confirmModalStore = writable({
  open: false,
  title: '',
  message: '',
  description: '',
  details: '',
  warning: '',
  alert: false,
  confirmText: 'Confirm',
  cancelText: 'Cancel',
  variant: 'destructive',
  loading: false,
  checkbox: null,        // optional { label } — renders a checkbox in the dialog
  checkboxChecked: false,
  passwordPrompt: null,  // optional { label, placeholder } — renders a password field (step-up)
  passwordValue: '',
  totpPrompt: null,      // optional { label } — renders a 2FA code field (step-up when 2FA is on)
  totpValue: '',
  resolve: null
})

// Show confirm modal and return a Promise.
// Plain: resolves to a boolean (confirmed). With options.checkbox it resolves to
// { confirmed, checked }; with options.passwordPrompt it resolves to { confirmed, password }
// (both may be combined) so callers can read the extra inputs.
export function confirm(options) {
  return new Promise((resolve) => {
    confirmModalStore.set({
      open: true,
      title: options.title || 'Confirm',
      message: options.message || 'Are you sure?',
      description: options.description || '',
      details: options.details || '',
      warning: options.warning || '',
      alert: options.alert || false,
      confirmText: options.confirmText || 'Confirm',
      cancelText: options.cancelText || 'Cancel',
      variant: options.variant || 'destructive',
      loading: false,
      checkbox: options.checkbox || null,
      checkboxChecked: options.checkbox?.checked ?? false,
      passwordPrompt: options.passwordPrompt || null,
      passwordValue: '',
      totpPrompt: options.totpPrompt || null,
      totpValue: '',
      resolve
    })
  })
}

// Step-up confirm for sensitive actions: always prompts for the password and, when the current
// user has 2FA enabled, also prompts for a fresh authenticator code. Resolves to
// { confirmed, password, totp }. Callers send { currentPassword: r.password, totpCode: r.totp }.
export function stepUpConfirm(options = {}) {
  const u = get(currentUser)
  return confirm({
    variant: 'primary',
    confirmText: 'Confirm',
    ...options,
    passwordPrompt: options.passwordPrompt || { label: 'Your password' },
    totpPrompt: u?.totpEnabled ? (options.totpPrompt || { label: 'Authenticator code' }) : null
  })
}

// Close confirm modal (called by ConfirmModal component)
export function closeConfirmModal(confirmed) {
  confirmModalStore.update(state => {
    if (state.resolve) {
      if (state.checkbox || state.passwordPrompt || state.totpPrompt) {
        const out = { confirmed }
        if (state.checkbox) out.checked = state.checkboxChecked
        if (state.passwordPrompt) out.password = state.passwordValue
        if (state.totpPrompt) out.totp = state.totpValue
        state.resolve(out)
      } else {
        state.resolve(confirmed)
      }
    }
    return { ...state, open: false, resolve: null, passwordValue: '', totpValue: '' }
  })
}

// Update the confirm dialog's checkbox state (called by ConfirmModal)
export function setConfirmCheckbox(checked) {
  confirmModalStore.update(state => ({ ...state, checkboxChecked: checked }))
}

// Update the confirm dialog's password field (called by ConfirmModal)
export function setConfirmPassword(value) {
  confirmModalStore.update(state => ({ ...state, passwordValue: value }))
}

// Update the confirm dialog's 2FA code field (called by ConfirmModal)
export function setConfirmTotp(value) {
  confirmModalStore.update(state => ({ ...state, totpValue: value }))
}

// Set loading state on confirm modal
export function setConfirmLoading(loading) {
  confirmModalStore.update(state => ({ ...state, loading }))
}

// Auth header helper. The session now lives in an HttpOnly, SameSite=Strict cookie that the
// browser attaches automatically (same-origin), so JS neither reads nor sends the token —
// this removes the XSS token-theft risk. Kept as a seam for callers that pass extra headers.
function getAuthHeaders(extraHeaders = {}) {
  return { ...extraHeaders }
}

// Global logout handler - set by App.svelte to handle session expiration
let globalLogoutHandler = null
export function setGlobalLogoutHandler(handler) {
  globalLogoutHandler = handler
}

// Idle-lock: the server returns 423 for a locked session on any non-exempt request. IdleLock
// registers a handler so the lock overlay re-arms immediately instead of surfacing as an error.
let globalLockHandler = null
export function setGlobalLockHandler(handler) {
  globalLockHandler = handler
}

// Clear session tokens
export function clearSessionTokens() {
  localStorage.removeItem('session_token')
  localStorage.removeItem('session_expires')
}

// Base API helper - includes auth token automatically
async function api(endpoint, options = {}) {
  const headers = getAuthHeaders({
    'Content-Type': 'application/json',
    ...options.headers
  })

  const res = await fetch(endpoint, { ...options, headers })

  if (res.ok) {
    const text = await res.text()
    return text ? JSON.parse(text) : {}
  }

  // Handle 401 Unauthorized - session expired
  if (res.status === 401) {
    const error = await res.text().catch(() => 'Session expired')
    // Trigger global logout if not on login/setup endpoints
    if (!endpoint.includes('/api/auth/login') && !endpoint.includes('/api/setup/')) {
      clearSessionTokens()
      if (globalLogoutHandler) {
        globalLogoutHandler()
      }
    }
    throw new Error(error || 'Session expired')
  }

  // 423 Locked - the session is idle-locked server-side. Re-arm the lock overlay instead of
  // treating it as a generic error (never logs out; unlocking restores access).
  if (res.status === 423) {
    if (globalLockHandler) globalLockHandler()
    const error = await res.text().catch(() => 'Session locked')
    const err = new Error(error || 'Session locked')
    err.status = 423
    throw err
  }

  const error = await res.text().catch(() => res.statusText)
  const err = new Error(error || res.statusText)
  err.status = res.status // let callers branch on it (e.g. 428 → step-up re-auth)
  throw err
}

// HTTP method helpers
export const apiGet = (endpoint) => api(endpoint, { method: 'GET' })
export const apiPost = (endpoint, data) => api(endpoint, { method: 'POST', body: data ? JSON.stringify(data) : undefined })
export const apiPut = (endpoint, data) => api(endpoint, { method: 'PUT', body: data ? JSON.stringify(data) : undefined })
export const apiDelete = (endpoint, data) => api(endpoint, { method: 'DELETE', body: data ? JSON.stringify(data) : undefined })

// Raw text fetch (for config downloads etc)
export async function apiGetText(endpoint) {
  const res = await fetch(endpoint, { headers: getAuthHeaders() })
  if (!res.ok) throw new Error(await res.text() || res.statusText)
  return res.text()
}

// Blob fetch (for images like QR codes)
export async function apiGetBlob(endpoint) {
  const res = await fetch(endpoint, { headers: getAuthHeaders() })
  if (!res.ok) throw new Error(await res.text() || res.statusText)
  return res.blob()
}

// POST that returns a file download — resolves { blob, filename } (filename read
// from the Content-Disposition header). For endpoints that stream a file back.
export async function apiPostBlob(endpoint, data) {
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
    body: data ? JSON.stringify(data) : undefined,
  })
  if (!res.ok) throw new Error((await res.text()) || res.statusText)
  const blob = await res.blob()
  const cd = res.headers.get('Content-Disposition') || ''
  const m = cd.match(/filename="?([^"]+)"?/)
  return { blob, filename: m ? m[1] : 'download' }
}

// Generate random secure credentials for AdGuard using crypto API
export function generateAdguardCredentials() {
  const usernameChars = 'abcdefghijklmnopqrstuvwxyz0123456789'
  const passwordChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'

  const randomValues = new Uint32Array(24)
  crypto.getRandomValues(randomValues)

  let username = 'admin_'
  for (let i = 0; i < 8; i++) {
    username += usernameChars.charAt(randomValues[i] % usernameChars.length)
  }

  let password = ''
  for (let i = 8; i < 24; i++) {
    password += passwordChars.charAt(randomValues[i] % passwordChars.length)
  }

  return { username, password }
}
