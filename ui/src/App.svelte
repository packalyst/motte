<script>
  import { onMount } from 'svelte'
  import { theme, apiGet, apiPost, currentView, validViews, setGlobalLogoutHandler, clearSessionTokens } from './stores/app.js'
  import { connect as wsConnect, disconnect as wsDisconnect, wsUserStore, stopReconnect } from './stores/websocket.js'
  import Dashboard from './views/Dashboard.svelte'
  import Login from './views/Login.svelte'
  import SetupWizard from './views/SetupWizard.svelte'
  import ConfirmModal from './components/ConfirmModal.svelte'
  import InstallPrompt from './components/InstallPrompt.svelte'
  import OfflineOverlay from './components/OfflineOverlay.svelte'

  let user = $state(null)
  let checking = $state(true)
  let needsSetup = $state(false)
  let showAdguardBanner = $state(false)

  // Set global logout handler for API 401 errors
  setGlobalLogoutHandler(() => {
    wsDisconnect()
    user = null
  })

  // React to WebSocket user info
  $effect(() => {
    if ($wsUserStore) {
      user = $wsUserStore
      checking = false
    }
  })

  // Note: session validity is decided by REST (/api/auth/me) on boot, not by
  // the WebSocket. A WS hiccup (slow handshake behind Cloudflare, cold backend,
  // transient drop) must NOT clear a valid session — otherwise a refresh logs
  // the user out. The WS is only for live updates.

  // Clear stale tokens when showing login page
  $effect(() => {
    if (!checking && !user && !needsSetup) {
      // About to show login page - ensure no stale tokens
      clearSessionTokens()
      stopReconnect()
    }
  })

  // Global click handler to intercept internal links
  function handleLinkClick(e) {
    const link = e.target.closest('a[href^="/"]')
    if (link && !link.target && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
      const path = link.getAttribute('href').slice(1) // Remove leading /
      if (validViews.includes(path)) {
        e.preventDefault()
        currentView.set(path)
      }
    }
  }

  onMount(async () => {
    // First check if setup is complete
    try {
      const setupStatus = await apiGet('/api/setup/status')
      if (!setupStatus.completed) {
        needsSetup = true
        checking = false
        return
      }
      // Check if AdGuard password needs to be configured
      showAdguardBanner = !setupStatus.adguardPassChanged
    } catch {
      // Ignore errors
    }

    // Setup is complete: validate any existing session via REST (the source of
    // truth), independent of the WebSocket. apiGet clears the token and triggers
    // logout automatically on a 401, so an invalid/expired token falls through
    // to the login page; a valid one keeps us signed in across refreshes even if
    // the WS is slow to connect.
    const token = localStorage.getItem('session_token')
    if (!token) {
      checking = false
      return
    }
    try {
      user = await apiGet('/api/auth/me')
      // Auth established — connect the WebSocket for live updates.
      wsConnect()
    } catch {
      // Invalid/expired token: apiGet already cleared the session.
      stopReconnect()
    } finally {
      checking = false
    }
  })

  function handleSetupComplete(loggedInUser) {
    needsSetup = false
    user = loggedInUser
    // After setup, AdGuard is not configured yet
    showAdguardBanner = true
    // Connect WebSocket
    wsConnect()
  }

  function handleLogin(loggedInUser) {
    user = loggedInUser
    // Connect WebSocket
    wsConnect()
  }

  function handleLogout() {
    // Disconnect WebSocket first
    wsDisconnect()
    apiPost('/api/auth/logout').catch(() => {})
    localStorage.removeItem('session_token')
    localStorage.removeItem('session_expires')
    user = null
  }
</script>

<svelte:window onclick={handleLinkClick} />

{#if checking}
  <div class="flex items-center justify-center h-full">
    <div class="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin"></div>
  </div>
{:else if needsSetup}
  <SetupWizard onComplete={handleSetupComplete} />
{:else if user}
  <Dashboard onLogout={handleLogout} {showAdguardBanner} onDismissAdguardBanner={() => showAdguardBanner = false} />
{:else}
  <Login onLogin={handleLogin} />
{/if}

<!-- Global confirm modal -->
<ConfirmModal />

<!-- PWA install prompt -->
<InstallPrompt />

<!-- Offline overlay -->
<OfflineOverlay />
