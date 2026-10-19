import { writable, get } from 'svelte/store'

// The signed-in user (null when logged out). Set by App.svelte; read by step-up helpers and the
// idle lock so they know the caller's 2FA status and idle-lock policy without prop threading.
export const currentUser = writable(null)

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
export const validViews = ['overview', 'nodes', 'users', 'firewall', 'server', 'fleet', 'iplookup',
                           'routes', 'authkeys', 'apikeys', 'traefik', 'domains', 'tunnels', 'adguard',
                           'docker', 'logs', 'analytics', 'activity', 'routines', 'settings', 'profile', 'team', 'about']

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
const savedView = typeof localStorage !== 'undefined' ? localStorage.getItem('hs_view') : 'overview'
export const currentView = writable(urlView || savedView || 'overview')

// Track if we're handling popstate to avoid double-pushing
let handlingPopstate = false

currentView.subscribe(value => {
  if (typeof window !== 'undefined' && value) {
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

// Toast config (module-level to avoid recreation on each call)
const toastVariants = {
  success: 'success',
  error: 'destructive',
  warning: 'warning',
  info: 'info'
}
const toastIcons = {
  success: '<span class="icon-[tabler--check] text-lg text-success"></span>',
  error: '<span class="icon-[tabler--alert-circle] text-lg text-destructive"></span>',
  warning: '<span class="icon-[tabler--alert-triangle] text-lg text-warning"></span>',
  info: '<span class="icon-[tabler--info-circle] text-lg text-info"></span>'
}
const toastTextClass = {
  success: 'text-success',
  error: 'text-destructive',
  warning: 'text-warning',
  info: 'text-info'
}

// escapeHtml renders a string as literal text inside HTML. KTToast injects `message`
// via innerHTML (not textContent), so any untrusted value interpolated into a toast —
// machine names, error text, IP-lookup results, CVE titles — would otherwise be a stored
// XSS sink. Escaping here closes that for ALL 200+ toast call sites at once.
function escapeHtml(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

// Toast using KTUI
export function toast(message, type = 'info') {
  if (window.KTToast) {
    window.KTToast.show({
      dismiss:false,
      cancel: {
        label: `<span class="icon-[tabler--circle-x] cursor-pointer text-base ${toastTextClass[type] || toastTextClass.info}"></span>`,
        onClick: function () {},
      },
      message: escapeHtml(message),
      variant: 'secondary',
      appearance: 'solid',
      progress: true,
      size: 'sm',
      pauseOnHover: true,
      position: 'top-end',
      icon: toastIcons[type] || toastIcons.info,
      className: toastTextClass[type] || toastTextClass.info
    })
  }
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
