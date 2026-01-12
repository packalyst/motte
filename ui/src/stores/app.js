import { writable } from 'svelte/store'

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
export const validViews = ['overview', 'nodes', 'users', 'firewall', 'routes', 'authkeys', 'apikeys',
                           'traefik', 'domains', 'adguard', 'docker', 'logs', 'settings', 'about']

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
      window.history.pushState({ view: value }, '', newPath)
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

// Toast using KTUI
export function toast(message, type = 'info') {
  if (window.KTToast) {
    window.KTToast.show({
      dismiss:false,
      cancel: {
        label: `<span class="icon-[tabler--circle-x] cursor-pointer text-base ${toastTextClass[type] || toastTextClass.info}"></span>`,
        onClick: function () {},
      },
      message,
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
  resolve: null
})

// Show confirm modal and return a Promise
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
      resolve
    })
  })
}

// Close confirm modal (called by ConfirmModal component)
export function closeConfirmModal(confirmed) {
  confirmModalStore.update(state => {
    if (state.resolve) state.resolve(confirmed)
    return { ...state, open: false, resolve: null }
  })
}

// Set loading state on confirm modal
export function setConfirmLoading(loading) {
  confirmModalStore.update(state => ({ ...state, loading }))
}

// Auth header helper (consolidated token retrieval)
function getAuthHeaders(extraHeaders = {}) {
  const token = localStorage.getItem('session_token')
  const headers = { ...extraHeaders }
  if (token) headers['Authorization'] = `Bearer ${token}`
  return headers
}

// Global logout handler - set by App.svelte to handle session expiration
let globalLogoutHandler = null
export function setGlobalLogoutHandler(handler) {
  globalLogoutHandler = handler
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

  const error = await res.text().catch(() => res.statusText)
  throw new Error(error || res.statusText)
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
