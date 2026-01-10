<script>
  import { onMount, onDestroy } from 'svelte'
  import { slide } from 'svelte/transition'
  import { theme, currentView, apiGet } from '../stores/app.js'
  import { subscribe, unsubscribe, generalInfoStore } from '../stores/websocket.js'
  import Icon from '../components/Icon.svelte'

  // Lazy load views - each becomes a separate chunk
  const views = {
    overview: () => import('./OverviewView.svelte'),
    nodes: () => import('./NodesView.svelte'),
    users: () => import('./UsersView.svelte'),
    firewall: () => import('./FirewallView.svelte'),
    routes: () => import('./RoutesView.svelte'),
    authkeys: () => import('./AuthKeysView.svelte'),
    apikeys: () => import('./ApiKeysView.svelte'),
    traefik: () => import('./TraefikView.svelte'),
    domains: () => import('./DomainRoutesView.svelte'),
    adguard: () => import('./AdGuardView.svelte'),
    docker: () => import('./DockerView.svelte'),
    logs: () => import('./LogsView.svelte'),
    settings: () => import('./SettingsView.svelte'),
    profile: () => import('./ProfileView.svelte'),
    about: () => import('./AboutView.svelte')
  }

  let { onLogout, showAdguardBanner = false, onDismissAdguardBanner } = $props()

  let sidebarOpen = $state(false)
  let loading = $state(true)

  // Topbar dropdown state
  let githubDropdownOpen = $state(false)
  let docsDropdownOpen = $state(false)

  // Close dropdowns when clicking outside
  function handleClickOutside(e) {
    if (!e.target.closest('.dropdown-github') && !e.target.closest('.dropdown-docs')) {
      githubDropdownOpen = false
      docsDropdownOpen = false
    }
  }

  // Expand menu only if current view is a child of it
  const headscaleChildren = ['nodes', 'routes', 'users', 'authkeys', 'apikeys']
  let expandedMenus = $state({
    headscale: headscaleChildren.includes($currentView)
  })

  // Stats from WebSocket
  let stats = $state({ online: 0, offline: 0, hsNodes: 0, wgPeers: 0 })

  // Update stats when WebSocket pushes new data
  $effect(() => {
    const info = $generalInfoStore
    if (info?.event === 'stats') {
      stats = info.data
    }
  })

  onMount(() => {
    // Subscribe to real-time updates
    subscribe('general_info')
  })

  onDestroy(() => {
    unsubscribe('general_info')
  })

  const navItems = [
    { id: 'overview', label: 'Overview', icon: 'dashboard' },
    { id: 'nodes', label: 'Nodes', icon: 'server' },
    {
      id: 'headscale',
      label: 'Headscale',
      icon: 'cloud',
      children: [
        { id: 'routes', label: 'Routes', icon: 'git-branch' },
        { id: 'users', label: 'Users', icon: 'users' },
        { id: 'authkeys', label: 'Auth Keys', icon: 'key' },
        { id: 'apikeys', label: 'API Keys', icon: 'key' },
      ]
    },
    { id: 'firewall', label: 'Firewall', icon: 'shield' },
    { id: 'divider1', divider: true },
    { id: 'traefik', label: 'Traefik', icon: 'world' },
    { id: 'domains', label: 'Domain Routes', icon: 'world-www' },
    { id: 'adguard', label: 'AdGuard', icon: 'shield-check' },
    { id: 'docker', label: 'Docker', icon: 'box' },
    { id: 'divider2', divider: true },
    { id: 'logs', label: 'Logs', icon: 'file-text' },
    { id: 'divider3', divider: true },
    { id: 'settings', label: 'Settings', icon: 'settings' },
    { id: 'about', label: 'About', icon: 'info-circle' }
  ]

  // Check if current view is a child of a menu
  function isChildActive(item) {
    if (!item.children) return false
    return item.children.some(child => child.id === $currentView)
  }

  function toggleMenu(id) {
    expandedMenus[id] = !expandedMenus[id]
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
    // Close all dropdowns when navigating to non-child items
    if (!isChild) {
      expandedMenus = { headscale: false }
    }
  }

  function closeSidebar() {
    sidebarOpen = false
  }

  // Get label for header
  function getViewLabel(viewId) {
    if (viewId === 'profile') return 'Profile'
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
      <div class="w-8 h-8 bg-primary rounded-xl flex items-center justify-center shadow-lg shadow-primary/20">
        <Icon name="shield" size={16} class="text-white" />
      </div>
      <span class="text-base font-semibold tracking-tight">WirePanel</span>
    </div>

    <!-- Sidebar nav -->
    <nav class="flex-1 space-y-1 overflow-y-auto px-3 py-3 text-sm bg-muted/50">
      {#each navItems as item}
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
      <!-- Stats section -->
      <div class="space-y-2">
        <div class="grid grid-cols-2 gap-2 text-[11px]">
          <div class="flex items-center gap-2 rounded-md bg-secondary px-2.5 py-2">
            <span class="h-2 w-2 rounded-full bg-success"></span>
            <span class="text-foreground">{stats.online} online</span>
          </div>
          <div class="flex items-center gap-2 rounded-md bg-secondary px-2.5 py-2">
            <span class="h-2 w-2 rounded-full bg-muted-foreground"></span>
            <span class="text-muted-foreground">{stats.offline} offline</span>
          </div>
        </div>
        <div class="grid grid-cols-2 gap-2 text-[11px]">
          <div class="flex items-center gap-2 rounded-md bg-secondary px-2.5 py-2">
            <Icon name="cloud" size={12} class="text-primary" />
            <span class="text-foreground">{stats.hsNodes} Tailscale</span>
          </div>
          <div class="flex items-center gap-2 rounded-md bg-secondary px-2.5 py-2">
            <Icon name="shield" size={12} class="text-success" />
            <span class="text-foreground">{stats.wgPeers} WireGuard</span>
          </div>
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
            <div class="truncate text-sm font-medium text-foreground">admin</div>
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
        <button
          onclick={() => navigate('nodes')}
          class="custom_btns"
          title="Nodes"
        >
          <Icon name="server" size={16} />
        </button>
        <button
          onclick={() => navigate('settings')}
          class="custom_btns"
          title="Settings"
        >
          <Icon name="settings" size={16} />
        </button>

        <div class="mx-1 h-5 w-px bg-border"></div>

        <!-- GitHub Dropdown -->
        <div class="relative dropdown-github">
          <button
            onclick={() => { githubDropdownOpen = !githubDropdownOpen; docsDropdownOpen = false }}
            class="custom_btns"
            title="GitHub"
          >
            <Icon name="brand-github" size={16} />
          </button>
          {#if githubDropdownOpen}
            <div class="kt-dropdown w-52">
              <a href="https://github.com/packalyst/wireguard-admin-panel" target="_blank" rel="noopener noreferrer"
                class="kt-dropdown-item font-medium">
                <Icon name="brand-github" size={14} class="kt-dropdown-item-icon" />
                Wire Panel
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

        <!-- Documentation Dropdown -->
        <div class="relative dropdown-docs">
          <button
            onclick={() => { docsDropdownOpen = !docsDropdownOpen; githubDropdownOpen = false }}
            class="custom_btns"
            title="Documentation"
          >
            <Icon name="book" size={16} />
          </button>
          {#if docsDropdownOpen}
            <div class="kt-dropdown">
              <a href="https://headscale.net/stable/" target="_blank" rel="noopener noreferrer"
                class="kt-dropdown-item">
                <Icon name="book" size={14} class="kt-dropdown-item-icon" />
                Headscale Docs
              </a>
              <div class="kt-dropdown-divider"></div>
              <a href="https://github.com/AdguardTeam/AdGuardHome/wiki" target="_blank" rel="noopener noreferrer"
                class="kt-dropdown-item">
                <Icon name="book" size={14} class="kt-dropdown-item-icon" />
                AdGuard Home Wiki
              </a>
              <div class="kt-dropdown-divider"></div>
              <a href="https://doc.traefik.io/traefik/" target="_blank" rel="noopener noreferrer"
                class="kt-dropdown-item">
                <Icon name="book" size={14} class="kt-dropdown-item-icon" />
                Traefik Docs
              </a>
              <div class="kt-dropdown-divider"></div>
              <a href="https://www.wireguard.com/" target="_blank" rel="noopener noreferrer"
                class="kt-dropdown-item">
                <Icon name="book" size={14} class="kt-dropdown-item-icon" />
                WireGuard Docs
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

    <!-- Content area -->
    <section class="flex-1 overflow-auto bg-background p-3 lg:p-4">
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
    </section>
  </main>
</div>
