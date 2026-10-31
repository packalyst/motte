import { writable, get } from 'svelte/store'
import { passkeysSupported } from '../lib/webauthn.js'

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
export const validViews = ['overview', 'headscale', 'firewall', 'server', 'console', 'sessions', 'iplookup',
                           'clients', 'domains', 'tunnels', 'adguard',
                           'logs', 'analytics', 'activity', 'routines', 'settings', 'profile', 'about']

// Get initial tab from URL hash (for tab persistence on refresh)
export function getInitialTab(defaultTab, validTabs) {
  if (typeof window === 'undefined') return defaultTab
  const hash = window.location.hash.slice(1)
  const params = new URLSearchParams(hash)
  const tabFromUrl = params.get('tab')
  return tabFromUrl && validTabs.includes(tabFromUrl) ? tabFromUrl : defaultTab
}

// Get view from current URL path
function getViewFromPath() {
  if (typeof window === 'undefined') return null
  const path = window.location.pathname.slice(1) // Remove leading /
  return validViews.includes(path) ? path : null
}

// Current view - URL takes priority, then localStorage, then default
const urlView = typeof window !== 'undefined' ? getViewFromPath() : null
const storedView = typeof localStorage !== 'undefined' ? localStorage.getItem('hs_view') : null
const savedView = validViews.includes(storedView) ? storedView : 'overview'
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
    const newPath = '/' + value
    if (!handlingPopstate && window.location.pathname !== newPath) {
      // In a trivial session history (one entry — a fresh tab or standalone
      // PWA) pushState is treated as replaceState and Chrome logs a warning;
      // call replaceState directly there to keep the console clean. Once there
      // is real history to go back to, push so back/forward still work.
      if (window.history.length <= 1) {
        window.history.replaceState({ view: value }, '', newPath)
      } else {
        window.history.pushState({ view: value }, '', newPath)
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

// Scroll the page area (the one scroller every page shares, .app-scroller) back to the top: a new
// page, a newly opened item (a machine) or a newly picked section starts at the top instead of
// keeping the previous scroll position.
export function scrollPageTop() {
  document.querySelector('.app-scroller')?.scrollTo({ top: 0 })
}

// selectSection picks a section in a section menu (rail, bottom bar or sticky select): the page
// switches, and the new section starts at the top.
export function selectSection(onselect, id) {
  onselect(id)
  scrollPageTop()
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
    const view = event.state?.view || getViewFromPath() || 'overview'
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
  passkey: null,         // optional { method, url } — offers "Use passkey" to confirm that request
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
      passkey: options.passkey || null,
      resolve
    })
  })
}

// The step-up lives here, nowhere else: screens never put a password or 2FA code into a request
// themselves, they send the proof these helpers give them (the build refuses anything else, see
// vite.config.js).

// passwordProof is the step-up proof of a password (+ 2FA code) typed into a screen's own field.
export function passwordProof(password, totp) {
  return { currentPassword: password, totpCode: totp || '' }
}

// Step-up confirm for sensitive actions: prompts for the password and, when the current user has
// 2FA enabled, also for a fresh authenticator code. options.action ({ method, url }: the one
// request it confirms, exactly as it will be sent) lets a user with a passkey confirm with it
// instead; options.passwordOnly is for the checks about the credentials themselves (the server
// takes no passkey there). One of the two is required, so no screen forgets the passkey.
// Resolves to { confirmed, password, totp, proof }: proof is what to put in that request's body
// (the password and code, or the passkey answer), null when cancelled.
export function stepUpConfirm(options = {}) {
  const u = get(currentUser)
  const { action, passwordOnly, ...rest } = options
  if (!action === !passwordOnly) throw new Error('stepUpConfirm: give the request (action) or passwordOnly')
  return confirm({
    variant: 'primary',
    confirmText: 'Confirm',
    ...rest,
    passwordPrompt: options.passwordPrompt || { label: 'Your password' },
    totpPrompt: u?.totpEnabled ? (options.totpPrompt || { label: 'Authenticator code' }) : null,
    passkey: action && u?.hasPasskey && passkeysSupported() ? action : null
  })
}

// withStepUp sends a request; a sensitive one the panel answers 428 until the user re-authenticates
// (fleet actions honour a short grace window instead), so it then prompts with
// stepUpConfirm(options) and retries once. send(extra) gets {} first, then the step-up proof.
// The 428 names the request and whether the server takes a passkey for it, so the prompt offers
// one only where it works. Resolves to send's result, or STEPUP_CANCELLED when the prompt is closed.
export const STEPUP_CANCELLED = Symbol('step-up cancelled')
export async function withStepUp(send, options = {}) {
  let stepUp
  try {
    return await send({})
  } catch (e) {
    if (e?.status !== 428) throw e
    stepUp = e.stepUp
  }
  const action = stepUp?.passkey ? stepUp.action : undefined
  const su = await stepUpConfirm({ ...options, action, passwordOnly: !action })
  if (!su?.proof) return STEPUP_CANCELLED
  return await send(su.proof)
}

// Close confirm modal (called by ConfirmModal component). passkeyAnswer: the step-up was confirmed
// with a passkey instead of the password.
export function closeConfirmModal(confirmed, passkeyAnswer = null) {
  confirmModalStore.update(state => {
    if (state.resolve) {
      if (state.checkbox || state.passwordPrompt || state.totpPrompt) {
        const out = { confirmed }
        if (state.checkbox) out.checked = state.checkboxChecked
        if (state.passwordPrompt) out.password = state.passwordValue
        if (state.totpPrompt) out.totp = state.totpValue
        if (state.passwordPrompt) {
          out.proof = !confirmed ? null
            : passkeyAnswer ? { passkey: passkeyAnswer }
            : state.passwordValue ? passwordProof(state.passwordValue, state.totpValue) : null
        }
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
    const error = errorText(await res.text().catch(() => ''))
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
    const error = errorText(await res.text().catch(() => ''))
    const err = new Error(error || 'Session locked')
    err.status = 423
    throw err
  }

  const text = await res.text().catch(() => '')
  const err = new Error(errorText(text) || res.statusText)
  err.status = res.status // let callers branch on it (e.g. 428 → step-up re-auth)
  if (res.status === 428) {
    // Which request needs the step-up, and whether the server takes a passkey for it.
    let passkey = false
    try { passkey = JSON.parse(text)?.passkey === true } catch { /* not JSON */ }
    err.stepUp = { passkey, action: { method: (options.method || 'GET').toUpperCase(), url: endpoint } }
  }
  throw err
}

// The API answers errors as {"error": "..."}: the message is that text, not the JSON around it.
function errorText(body) {
  try {
    const j = JSON.parse(body)
    if (typeof j?.error === 'string') return j.error
  } catch { /* not JSON: the body is the message */ }
  return body
}

// HTTP method helpers
export const apiGet = (endpoint) => api(endpoint, { method: 'GET' })
export const apiPost = (endpoint, data) => api(endpoint, { method: 'POST', body: data ? JSON.stringify(data) : undefined })
export const apiPut = (endpoint, data) => api(endpoint, { method: 'PUT', body: data ? JSON.stringify(data) : undefined })
export const apiDelete = (endpoint, data) => api(endpoint, { method: 'DELETE', body: data ? JSON.stringify(data) : undefined })

// Raw text fetch (for config downloads etc)
export async function apiGetText(endpoint) {
  const res = await fetch(endpoint, { headers: getAuthHeaders() })
  if (!res.ok) throw new Error(errorText(await res.text()) || res.statusText)
  return res.text()
}

// Blob fetch (for images like QR codes)
export async function apiGetBlob(endpoint) {
  const res = await fetch(endpoint, { headers: getAuthHeaders() })
  if (!res.ok) throw new Error(errorText(await res.text()) || res.statusText)
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
  if (!res.ok) throw new Error(errorText(await res.text()) || res.statusText)
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
