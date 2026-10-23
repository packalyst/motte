<script>
  import { onMount, onDestroy } from 'svelte'
  import { slide } from 'svelte/transition'
  import { theme, currentView, hasRole } from '../stores/app.js'
  import { subscribe, unsubscribe } from '../stores/websocket.js'
  import { KINDS, clientsList, watchClients, summarize, openClients } from '../lib/clients.js'
  import { visibilityChangeCount } from '../stores/network.js'
  import { isInstalledPWA } from '../lib/pwa/permissions.js'
  import Icon from '../components/Icon.svelte'
  import Logo from '../components/Logo.svelte'
  import PullToRefresh from '../components/PullToRefresh.svelte'

  // Lazy load views - each becomes a separate chunk
  const views = {
    overview: () => import('./OverviewView.svelte'),
    clients: () => import('./ClientsView.svelte'),
    users: () => import('./UsersView.svelte'),
    firewall: () => import('./FirewallView.svelte'),
    server: () => import('./ServerView.svelte'),
    console: () => import('./ConsoleView.svelte'),
    sessions: () => import('./SessionsView.svelte'),
    iplookup: () => import('./IpLookupView.svelte'),
    routes: () => import('./RoutesView.svelte'),
    authkeys: () => import('./AuthKeysView.svelte'),
    apikeys: () => import('./ApiKeysView.svelte'),
    domains: () => import('./DomainRoutesView.svelte'),
    tunnels: () => import('./TunnelsView.svelte'),
    adguard: () => import('./AdGuardView.svelte'),
    logs: () => import('./LogsView.svelte'),
    analytics: () => import('./AnalyticsView.svelte'),
    activity: () => import('./ActivityView.svelte'),
    routines: () => import('./RoutinesView.svelte'),
    settings: () => import('./SettingsView.svelte'),
    profile: () => import('./ProfileView.svelte'),
    about: () => import('./AboutView.svelte')
  }

  let { user = null, onLogout, showAdguardBanner = false, onDismissAdguardBanner } = $props()


  let sidebarOpen = $state(false)
  let loading = $state(true)

  // Topbar dropdown state
  let githubDropdownOpen = $state(false)

  // Top-bar shortcuts: [view, icon, label]; the open one keeps its hover look
  const quickLinks = [
    ['iplookup', 'world-search', 'IP Lookup'],
    ['clients', 'devices', 'All clients'],
    ['settings', 'settings', 'Settings'],
    ['about', 'info-circle', 'About'],
  ]

  // Close the GitHub dropdown when clicking outside it
  function handleClickOutside(e) {
    if (!e.target.closest('.dropdown-github')) {
      githubDropdownOpen = false
    }
  }

  // Submenu groups → their child view ids. Drives auto-expand + collapse so the
  // logic works for every group, not one hardcoded menu.
  const menuGroups = {
    'grp-monitoring': ['analytics', 'logs', 'activity', 'routines'],
    'grp-web': ['domains', 'tunnels', 'adguard'],
    'grp-headscale': ['routes', 'users', 'authkeys', 'apikeys'],
  }
  // Expand the group that contains the current view on load.
  let expandedMenus = $state(
    Object.fromEntries(Object.entries(menuGroups).map(([g, kids]) => [g, kids.includes($currentView)]))
  )

  // Keep the group containing the active view expanded whenever navigation
  // happens — including programmatically (dashboard cards, topbar quick-links),
  // not just on load — so the sidebar always reflects where you are.
  $effect(() => {
    const v = $currentView
    const g = Object.entries(menuGroups).find(([, kids]) => kids.includes(v))?.[0]
    if (g) expandedMenus[g] = true
  })

  // Every client the user may see, live (same list as the Clients page).
  const summary = $derived(summarize($clientsList.clients))
  const SHORT = { wireguard: 'WireGuard', tailscale: 'Tailscale', machine: 'Machines', lan: 'LAN' }
  let releaseClients

  onMount(() => {
    releaseClients = watchClients()
    // Subscribe to real-time updates
    subscribe('general_info')
    // App-wide live host stats: the Dashboard shell is always mounted, so this
    // keeps the server_stats collector fed for any consumer (Server page,
    // sidebar, etc). The backend only samples while there's ≥1 subscriber.
    subscribe('server_stats')
  })

  onDestroy(() => {
    releaseClients?.()
    unsubscribe('general_info')
    unsubscribe('server_stats')
  })

  // Trigger refresh when app becomes visible.
  // Gated to installed-PWA mode only — in a regular browser tab we don't want
  // Alt-Tabbing back to wipe the current view and re-fetch everything.
  const shouldReloadOnVisible = isInstalledPWA()
  let lastVisibilityCount = 0
  $effect(() => {
    if (!shouldReloadOnVisible) return
    if ($visibilityChangeCount > lastVisibilityCount) {
      lastVisibilityCount = $visibilityChangeCount
      reloadCurrentView()
    }
  })

  // Force reload current view
  async function reloadCurrentView() {
    const current = $currentView
    if (!current) return
    loading = true
    currentView.set(null)
    await new Promise(r => setTimeout(r, 50))
    currentView.set(current)
  }

  // Pull-to-refresh handler
  async function handlePullRefresh() {
    await reloadCurrentView()
  }

  const navItems = [
    { id: 'overview', label: 'Overview', icon: 'dashboard' },
    { id: 'divider1', divider: true },
    { id: 'clients', label: 'Clients', icon: 'devices' },
    { id: 'sessions', label: 'Sessions', icon: 'terminal-2', minRole: 'operator' },
    {
      id: 'grp-headscale', label: 'Headscale', icon: 'key',
      children: [
        { id: 'routes', label: 'Routes', icon: 'git-branch' },
        { id: 'users', label: 'Users', icon: 'users' },
        { id: 'authkeys', label: 'Auth Keys', icon: 'key' },
        { id: 'apikeys', label: 'API Keys', icon: 'code' },
      ]
    },
    { id: 'divider2', divider: true },
    { id: 'firewall', label: 'Firewall', icon: 'shield' },
    { id: 'server', label: 'Host', icon: 'shield-lock' },
    { id: 'divider3', divider: true },
    {
      id: 'grp-web', label: 'Web & Proxy', icon: 'world-www',
      children: [
        { id: 'domains', label: 'Domain Routes', icon: 'world-www' },
        { id: 'tunnels', label: 'Tunnels', icon: 'arrows-right-left' },
        { id: 'adguard', label: 'DNS', icon: 'shield-check' },
      ]
    },
    { id: 'divider4', divider: true },
    {
      id: 'grp-monitoring', label: 'Monitoring', icon: 'chart-bar',
      children: [
        { id: 'analytics', label: 'Analytics', icon: 'chart-bar' },
        { id: 'logs', label: 'Logs', icon: 'file-text' },
        { id: 'activity', label: 'Activity', icon: 'activity' },
        { id: 'routines', label: 'Routines', icon: 'clock' },
      ]
    },
  ]

  // Items with a minRole are hidden below it (the page and the server enforce it as well).
  const visibleNav = $derived(navItems.filter((i) => !i.minRole || hasRole(user, i.minRole)))

  // Check if current view is a child of a menu
  function isChildActive(item) {
    if (!item.children) return false
    return item.children.some(child => child.id === $currentView)
  }

  function toggleMenu(id) {
    // Accordion: opening a group collapses the others so only one stays open.
    const willOpen = !expandedMenus[id]
    expandedMenus = Object.fromEntries(Object.keys(menuGroups).map(g => [g, g === id && willOpen]))
  }

  function toggleTheme() {
    theme.update(t => t === 'dark' ? 'light' : 'dark')
  }

  function navigate(id, isChild = false) {
    // Skip if already on this page
    if ($currentView === id) {
      sidebarOpen = false
      return
    }
    currentView.set(id)
    sidebarOpen = false
    loading = true
    // Close all submenus when navigating to a top-level (non-child) item
    if (!isChild) {
      expandedMenus = Object.fromEntries(Object.keys(menuGroups).map(g => [g, false]))
    }
  }

  function closeSidebar() {
    sidebarOpen = false
  }

  // Get label for header
  function getViewLabel(viewId) {
    if (viewId === 'profile') return 'Profile'
    // Topbar-only views (not in the sidebar nav):
    if (viewId === 'console') return 'Console'
    if (viewId === 'iplookup') return 'IP Lookup'
    if (viewId === 'settings') return 'Settings'
    if (viewId === 'about') return 'About'
    for (const item of navItems) {
      if (item.id === viewId) return item.label
      if (item.children) {
        const child = item.children.find(c => c.id === viewId)
        if (child) return child.label
      }
    }
    return 'Dashboard'
  }
</script>

<svelte:window onclick={handleClickOutside} />

<!-- Root container -->
<div class="flex h-screen bg-background text-foreground antialiased">

  <!-- Sidebar -->
  <aside
    class="fixed inset-y-0 left-0 z-40 flex w-60 -translate-x-full flex-col border-r border-border bg-card text-foreground shadow-sm transition-transform duration-200 ease-out lg:static lg:translate-x-0"
    class:translate-x-0={sidebarOpen}
  >
    <!-- Sidebar header (logo) -->
    <div class="flex h-14 items-center gap-3 border-b border-border px-4">
      <Logo size={28} wordmark tagline />
    </div>

    <!-- Sidebar nav -->
    <nav class="flex-1 space-y-1 overflow-y-auto px-3 py-3 text-sm bg-muted/50">
      {#each visibleNav as item}
        {#if item.divider}
          <div class="my-2 -mx-3 border-t border-dashed border-border"></div>
        {:else if item.children}
          <!-- Parent menu with children -->
          <div>
            <button
              onclick={() => toggleMenu(item.id)}
              class="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-[13px] cursor-pointer
                {isChildActive(item)
                  ? 'text-foreground'
                  : 'text-muted-foreground hover:bg-muted hover:text-foreground'}"
            >
              <span class="flex h-6 w-6 items-center justify-center rounded-md
                {isChildActive(item)
                  ? 'bg-primary/10 text-primary'
                  : 'bg-muted text-muted-foreground'}">
                <Icon name={item.icon} size={14} />
              </span>
              <span class="flex-1 font-medium">{item.label}</span>
              <Icon
                name="chevron-right"
                size={14}
                class="transition-transform duration-200 {expandedMenus[item.id] ? 'rotate-90' : ''}"
              />
            </button>
            <!-- Children -->
            {#if expandedMenus[item.id]}
              <div transition:slide={{ duration: 150 }} class="mt-1 ml-4 space-y-0.5 border-l border-border">
                {#each item.children as child}
                  <button
                    onclick={() => navigate(child.id, true)}
                    class="flex w-full items-center gap-2.5 rounded-lg px-3 py-1.5 text-left text-[12px] cursor-pointer ml-2
                      {$currentView === child.id
                        ? 'bg-slate-900 text-slate-50 dark:bg-zinc-800'
                        : 'text-muted-foreground hover:bg-muted hover:text-foreground'}"
                  >
                    <span class="flex h-5 w-5 items-center justify-center rounded
                      {$currentView === child.id
                        ? 'text-slate-200'
                        : 'text-dim'}">
                      <Icon name={child.icon} size={12} />
                    </span>
                    <span class="font-medium">{child.label}</span>
                  </button>
                {/each}
              </div>
            {/if}
          </div>
        {:else}
          <button
            onclick={() => navigate(item.id)}
            class="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-[13px] cursor-pointer
              {$currentView === item.id
                ? 'bg-slate-900 text-slate-50 dark:bg-zinc-800'
                : 'text-muted-foreground hover:bg-muted hover:text-foreground'}"
          >
            <span class="flex h-6 w-6 items-center justify-center rounded-md
              {$currentView === item.id
                ? 'bg-slate-800 text-slate-200 dark:bg-zinc-700'
                : 'bg-muted text-muted-foreground'}">
              <Icon name={item.icon} size={14} />
            </span>
            <span class="font-medium">{item.label}</span>
          </button>
        {/if}
      {/each}
    </nav>

    <!-- Sidebar footer -->
    <div class="border-t border-border p-3 space-y-3">
      <!-- Clients: online out of all, then each kind (opens Clients narrowed to it) -->
      <div class="space-y-2 text-[11px]">
        <button type="button" onclick={() => openClients('')} title="Open Clients"
          class="block w-full rounded-md bg-secondary px-2.5 py-2 text-left cursor-pointer hover:bg-muted">
          <span class="flex items-center gap-2">
            <span class="h-2 w-2 rounded-full bg-success"></span>
            <span class="flex-1 text-foreground"><b class="font-semibold tabular-nums">{summary.online}</b><span class="text-muted-foreground tabular-nums"> / {summary.total}</span> online</span>
            {#if summary.attention.length}
              <span class="inline-flex items-center gap-0.5 font-medium text-warning" title="{summary.attention.length} need attention"><Icon name="alert-triangle" size={11} />{summary.attention.length}</span>
            {/if}
          </span>
          <span class="mt-1.5 block h-1 overflow-hidden rounded-full bg-muted">
            <span class="block h-full rounded-full bg-success" style="width: {summary.total ? (summary.online / summary.total) * 100 : 0}%"></span>
          </span>
        </button>
        <div class="grid grid-cols-2 gap-2">
          {#each Object.entries(KINDS) as [k, meta] (k)}
            <button type="button" onclick={() => openClients(k)} title="{meta.group}: {summary.kinds[k].online} online of {summary.kinds[k].total}"
              class="flex min-w-0 items-center gap-1 rounded-md bg-secondary px-1.5 py-1.5 cursor-pointer hover:bg-muted">
              <span class="grid shrink-0 place-items-center" style="color: {meta.color}"><Icon name={meta.icon} size={12} /></span>
              <span class="min-w-0 flex-1 truncate text-left text-muted-foreground">{SHORT[k]}</span>
              <span class="shrink-0 tabular-nums text-foreground">{summary.kinds[k].total}</span>
            </button>
          {/each}
        </div>
      </div>

      <!-- Divider -->
      <div class="border-t border-dashed border-border"></div>

      <!-- User section with inline actions -->
      <div class="flex items-center gap-2">
        <button
          onclick={() => navigate('profile')}
          class="flex flex-1 items-center gap-2.5 rounded-lg p-2 hover:bg-muted transition-colors cursor-pointer group min-w-0"
        >
          <div class="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10 text-primary group-hover:bg-primary/20 flex-shrink-0">
            <Icon name="user" size={14} />
          </div>
          <div class="flex-1 min-w-0 text-left">
            <div class="truncate text-sm font-medium text-foreground">{user?.username || 'account'}</div>
            {#if user?.role}
              <div class="truncate text-[11px] text-muted-foreground capitalize">{user.role}</div>
            {/if}
          </div>
        </button>
        <button onclick={toggleTheme} class="custom_btns flex-shrink-0" title="Toggle theme">
          {#if $theme === 'dark'}
            <Icon name="sun" size={14} />
          {:else}
            <Icon name="moon" size={14} />
          {/if}
        </button>
        <button onclick={onLogout} class="custom_btns text-destructive hover:bg-destructive/10 flex-shrink-0" title="Logout">
          <Icon name="logout" size={14} />
        </button>
      </div>
    </div>
  </aside>

  <!-- Mobile overlay -->
  {#if sidebarOpen}
    <div
      class="fixed inset-0 z-30 bg-background/60 backdrop-blur-sm lg:hidden"
      onclick={closeSidebar}
      onkeydown={(e) => e.key === 'Escape' && closeSidebar()}
      role="button"
      tabindex="-1"
      aria-label="Close sidebar"
    ></div>
  {/if}

  <!-- Main column -->
  <main class="flex min-w-0 flex-1 flex-col">
    <!-- Top bar -->
    <header class="sticky top-0 z-10 flex h-14 items-center justify-between border-b border-border bg-card/95 px-4 backdrop-blur lg:px-5">
      <div class="flex items-center gap-3">
        <!-- Mobile menu button -->
        <button
          onclick={() => sidebarOpen = !sidebarOpen}
          class="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card text-muted-foreground hover:bg-muted lg:hidden cursor-pointer"
        >
          <Icon name="menu" size={16} />
        </button>

        <h1 class="text-sm font-semibold tracking-tight">
          {getViewLabel($currentView)}
        </h1>
      </div>

      <div class="flex items-center gap-2">
        <!-- Quick actions -->
        {#each quickLinks as [view, icon, label]}
          <button onclick={() => navigate(view)} class="custom_btns" title={label} aria-label={label}
            aria-current={$currentView === view ? 'page' : undefined}>
            <Icon name={icon} size={16} />
          </button>
        {/each}

        <div class="mx-1 h-5 w-px bg-border"></div>

        <!-- GitHub Dropdown -->
        <div class="relative dropdown-github">
          <button
            onclick={() => { githubDropdownOpen = !githubDropdownOpen }}
            class="custom_btns"
            title="GitHub"
            aria-expanded={githubDropdownOpen}
          >
            <Icon name="brand-github" size={16} />
          </button>
          {#if githubDropdownOpen}
            <div class="kt-dropdown w-52">
              <a href="https://github.com/packalyst/wireguard-admin-panel" target="_blank" rel="noopener noreferrer"
                class="kt-dropdown-item font-medium">
                <Icon name="brand-github" size={14} class="kt-dropdown-item-icon" />
                Motte
              </a>
              <div class="kt-dropdown-divider"></div>
              <a href="https://github.com/juanfont/headscale" target="_blank" rel="noopener noreferrer"
                class="kt-dropdown-item">
                <Icon name="brand-github" size={14} class="kt-dropdown-item-icon" />
                Headscale
              </a>
              <div class="kt-dropdown-divider"></div>
              <a href="https://github.com/AdguardTeam/AdGuardHome" target="_blank" rel="noopener noreferrer"
                class="kt-dropdown-item">
                <Icon name="brand-github" size={14} class="kt-dropdown-item-icon" />
                AdGuard Home
              </a>
              <div class="kt-dropdown-divider"></div>
              <a href="https://github.com/traefik/traefik" target="_blank" rel="noopener noreferrer"
                class="kt-dropdown-item">
                <Icon name="brand-github" size={14} class="kt-dropdown-item-icon" />
                Traefik
              </a>
              <div class="kt-dropdown-divider"></div>
              <a href="https://github.com/WireGuard" target="_blank" rel="noopener noreferrer"
                class="kt-dropdown-item">
                <Icon name="brand-github" size={14} class="kt-dropdown-item-icon" />
                WireGuard
              </a>
            </div>
          {/if}
        </div>
      </div>
    </header>

    <!-- AdGuard Banner -->
    {#if showAdguardBanner}
      <div class="bg-warning/10 border-b border-warning/20 px-4 py-2.5 flex items-center justify-between gap-3">
        <div class="flex items-center gap-2 text-sm">
          <Icon name="alert-triangle" size={16} class="text-warning" />
          <span class="text-warning font-medium">AdGuard credentials not configured.</span>
          <button onclick={() => currentView.set('settings')} class="underline hover:no-underline text-warning">
            Go to Settings
          </button>
        </div>
        <button onclick={onDismissAdguardBanner} class="text-warning/70 hover:text-warning p-1" title="Dismiss">
          <Icon name="x" size={14} />
        </button>
      </div>
    {/if}

    <!-- Content area with pull-to-refresh -->
    <section class="flex-1 overflow-hidden overflow-y-auto bg-background">
      <PullToRefresh onRefresh={handlePullRefresh}>
        <div class="p-3 lg:p-4">
          {#if loading}
            <div class="flex h-64 flex-col items-center justify-center gap-3 text-muted-foreground">
              <div class="h-6 w-6 animate-spin rounded-full border-2 border-muted border-t-foreground"></div>
              <p class="text-xs">Loading...</p>
            </div>
          {/if}
          <div class:hidden={loading}>
            {#await views[$currentView]?.() then module}
              {#if module}
                {@const Component = module.default}
                <Component bind:loading {onLogout} />
              {/if}
            {:catch error}
              <div class="flex h-64 flex-col items-center justify-center gap-3 text-muted-foreground">
                <p class="text-xs">Failed to load view</p>
              </div>
            {/await}
          </div>
        </div>
      </PullToRefresh>
    </section>
  </main>
</div>
