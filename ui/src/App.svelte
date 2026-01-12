<script>
  import { onMount } from 'svelte'
  import { theme, apiGet, apiPost, currentView, validViews, setGlobalLogoutHandler, clearSessionTokens } from './stores/app.js'
  import { connect as wsConnect, disconnect as wsDisconnect, wsUserStore, wsConnected, stopReconnect } from './stores/websocket.js'
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

  // Handle WebSocket connection failure (invalid token)
  let wsConnectAttempted = false
  $effect(() => {
    // If we attempted to connect and it failed (not connected, not reconnecting)
    if (wsConnectAttempted && !$wsConnected && !checking) {
      // WebSocket failed to connect - token might be invalid
      const token = localStorage.getItem('session_token')
      if (token && !user) {
        // Clear invalid session and stop reconnect attempts
        clearSessionTokens()
        stopReconnect()
        checking = false
      }
    }
  })

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

    // Setup is complete, check for existing session
    const token = localStorage.getItem('session_token')
    if (token) {
      // Connect WebSocket - it will validate token and send user info via 'init' message
      wsConnectAttempted = true
      wsConnect()
      // Give WebSocket time to connect, then show login if no user
      setTimeout(() => {
        if (!user) {
          checking = false
        }
      }, 2000)
    } else {
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
