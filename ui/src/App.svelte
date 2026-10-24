<script>
  import { onMount } from 'svelte'
  import { apiGet, apiPost, currentView, validViews, setGlobalLogoutHandler, clearSessionTokens, currentUser } from './stores/app.js'
  import { connect as wsConnect, disconnect as wsDisconnect, wsUserStore, stopReconnect } from './stores/websocket.js'
  import { setDisplayTimezone } from './lib/utils/format.js'
  import Dashboard from './views/Dashboard.svelte'
  import Login from './views/Login.svelte'
  import SetupWizard from './views/SetupWizard.svelte'
  import ConfirmModal from './components/ConfirmModal.svelte'
  import Toaster from './components/Toaster.svelte'
  import IdleLock from './components/IdleLock.svelte'
  import InstallPrompt from './components/InstallPrompt.svelte'
  import OfflineOverlay from './components/OfflineOverlay.svelte'
  import Console from './components/Console.svelte'

  // Read-only console share links: #fconsole=<machine>|<session>|<grant>
  let shareConsole = $state(null)
  function parseShareHash() {
    const m = location.hash.match(/fconsole=([^|]+)\|([^|]+)\|(.+)$/)
    shareConsole = m ? { id: decodeURIComponent(m[1]), session: decodeURIComponent(m[2]), grant: decodeURIComponent(m[3]) } : null
  }

  let user = $state(null)
  let checking = $state(true)
  let needsSetup = $state(false)
  let showAdguardBanner = $state(false)
  let fwInactive = $state(false)   // firewall enabled but failed to init — gate not managed

  // Set global logout handler for API 401 errors
  setGlobalLogoutHandler(() => {
    wsDisconnect()
    user = null
    currentUser.set(null)
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
    parseShareHash()
    window.addEventListener('hashchange', parseShareHash)
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
      // Firewall layer failed to come up → the gate isn't being managed. Warn prominently.
      fwInactive = setupStatus.firewallActive === false
    } catch {
      // Ignore errors
    }

    // Setup is complete: validate any existing session via REST (the source of
    // truth), independent of the WebSocket. The session lives in an HttpOnly cookie the
    // browser attaches automatically, so we simply ask the server who we are: a 200 keeps
    // us signed in across refreshes, a 401 falls through to the login page (apiGet triggers
    // the global logout on 401).
    try {
      user = applyMe(await apiGet('/api/auth/me'))
      // Auth established — connect the WebSocket for live updates.
      wsConnect()
    } catch {
      // Invalid/expired token: apiGet already cleared the session.
      stopReconnect()
    } finally {
      checking = false
    }
  })

  // /api/auth/me is the session's source of truth: the policy fields step-up and the idle lock
  // read (totpEnabled, idleLockMinutes) and the display timezone, applied before views render.
  function applyMe(me) {
    currentUser.set(me)
    setDisplayTimezone(me?.displayTimezone || 'browser')
    return me
  }

  async function handleSetupComplete(loggedInUser) {
    needsSetup = false
    user = loggedInUser
    applyMe(await apiGet('/api/auth/me').catch(() => loggedInUser))
    // After setup, AdGuard is not configured yet
    showAdguardBanner = true
    // Connect WebSocket
    wsConnect()
  }

  async function handleLogin(loggedInUser) {
    user = loggedInUser
    // The login response may omit policy fields — fetch the authoritative /me for them.
    applyMe(await apiGet('/api/auth/me').catch(() => loggedInUser))
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
    currentUser.set(null)
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
  {#if fwInactive}
    <div class="fixed bottom-0 inset-x-0 z-[9999] bg-destructive text-destructive-foreground text-sm text-center pt-2 pb-[calc(0.5rem+env(safe-area-inset-bottom))] px-4 font-medium shadow-lg">
      Firewall not active — the firewall layer failed to start, so your rules are <strong>not being managed</strong>. Check the panel host (nftables), then reload.
    </div>
  {/if}
  <Dashboard {user} onLogout={handleLogout} {showAdguardBanner} onDismissAdguardBanner={() => showAdguardBanner = false} />
{:else}
  <Login onLogin={handleLogin} />
{/if}

<!-- Global confirm modal and toasts -->
<ConfirmModal />
<Toaster />

<!-- Idle lock: self-arms only when the admin has set idle_lock_minutes > 0 -->
{#if user}
  <IdleLock onLogout={handleLogout} />
{/if}

<!-- Read-only shared console (opened from a #fconsole= link) -->
{#if user && shareConsole}
  <Console
    shareMachine={{ id: shareConsole.id, name: shareConsole.id }}
    shareGrant={shareConsole.grant}
    shareSession={shareConsole.session}
    onclose={() => { shareConsole = null; location.hash = '' }}
  />
{/if}

<!-- PWA install prompt -->
<InstallPrompt />

<!-- Offline overlay -->
<OfflineOverlay />
