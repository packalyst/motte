<script>
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPut, getInitialTab } from '../stores/app.js'
  import { formatNumber, withTz } from '../lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Modal from '../components/Modal.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import StatStrip from '../components/StatStrip.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'
  import Select from '../components/Select.svelte'
  import Tabs from '../components/Tabs.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import Explain from '../components/Explain.svelte'
  import blocklists from '../data/blocklists.json'

  let { loading = $bindable(true) } = $props()

  // Core state
  let activeTab = $state(getInitialTab('overview', ['overview', 'filters', 'rules', 'rewrites']))
  let status = $state(null)
  let stats = $state(null)

  // Tab-specific state (loaded on demand)
  let filters = $state([])
  let blockedServices = $state([])
  let allServices = $state([])
  let userRules = $state([])
  let safeBrowsing = $state(null)
  let parental = $state(null)
  let safeSearch = $state(null)
  let dnsConfig = $state(null)
  let rewrites = $state([])

  // Track which tabs have been loaded
  let loadedTabs = $state({})

  // Loading states
  let refreshingFilters = $state(false)

  // Modals
  let showAddFilterModal = $state(false)
  let addFilterMode = $state('list') // 'list' or 'manual'
  let selectedLists = $state([])
  let filterSearchQuery = $state('')
  let newFilterName = $state('')
  let newFilterUrl = $state('')
  let newRewriteDomain = $state('')
  let newRewriteAnswer = $state('')

  // Forms
  let newBlockDomain = $state('')
  let newAllowDomain = $state('')

  // Tab definitions
  const tabs = [
    { id: 'overview', label: 'Overview', icon: 'layout' },
    { id: 'filters', label: 'Filters', icon: 'filter' },
    { id: 'rules', label: 'Block Rules', icon: 'ban' },
    { id: 'rewrites', label: 'DNS Rewrites', icon: 'link' }
  ]

  // Service categories (fallback if API doesn't provide)
  const SERVICE_CATEGORIES = [
    { id: 'social', name: 'Social Media', services: ['facebook', 'instagram', 'tiktok', 'twitter', 'snapchat', 'pinterest', 'reddit', 'linkedin'] },
    { id: 'video', name: 'Video Streaming', services: ['youtube', 'twitch', 'netflix', 'amazon_prime_video', 'disney_plus', 'hulu'] },
    { id: 'messaging', name: 'Messaging', services: ['whatsapp', 'telegram', 'discord', 'viber', 'signal', 'skype'] },
    { id: 'gaming', name: 'Gaming', services: ['steam', 'epicgames', 'origin', 'riot_games', 'blizzard'] },
    { id: 'other', name: 'Other', services: ['spotify', 'tinder', 'ebay'] },
  ]

  // Load core data (status/stats) on mount - single request
  async function loadCoreData() {
    try {
      const data = await apiGet('/api/adguard/overview')
      status = data.status || null
      stats = data.stats || null
      safeBrowsing = data.safeBrowsing || null
      parental = data.parental || null
      safeSearch = data.safeSearch || null
      dnsConfig = data.dnsConfig || null
      blockedServices = Array.isArray(data.blockedServices) ? data.blockedServices : (data.blockedServices?.ids || [])
      if (data.availableServices?.blocked_services) {
        allServices = data.availableServices.blocked_services
      }
      loadedTabs.services = true
      loadedTabs.safety = true
    } catch (e) {
      toast('Failed to load AdGuard data: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  // Tab-specific loaders
  async function loadFilters() {
    if (loadedTabs.filters) return
    try {
      const res = await apiGet('/api/adguard/filtering')
      filters = res?.filters || []
      userRules = res?.user_rules || []
      loadedTabs.filters = true
      loadedTabs.rules = true
    } catch (e) {
      toast('Failed to load filters: ' + e.message, 'error')
    }
  }

  async function loadRewrites() {
    if (loadedTabs.rewrites) return
    try {
      rewrites = await apiGet('/api/adguard/rewrites')
      loadedTabs.rewrites = true
    } catch (e) {
      toast('Failed to load rewrites: ' + e.message, 'error')
    }
  }

  // Load tab data when tab changes
  $effect(() => {
    if (activeTab === 'filters') loadFilters()
    else if (activeTab === 'rules') loadFilters()
    else if (activeTab === 'rewrites') loadRewrites()
  })

  // Switch tabs and mirror the choice to the URL hash (?tab=), matching what the
  // Tabs component's urlKey did, so deep links + refresh keep the tab.
  function setTab(id) {
    activeTab = id
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.hash.slice(1))
      params.set('tab', id)
      window.history.replaceState(null, '', '#' + params.toString())
    }
  }

  // Computed
  const blockedDomains = $derived(
    userRules
      .filter(r => r.startsWith('||') && !r.startsWith('@@'))
      .map(r => r.replace('||', '').replace('^', ''))
  )

  const allowedDomains = $derived(
    userRules
      .filter(r => r.startsWith('@@||'))
      .map(r => r.replace('@@||', '').replace('^', ''))
  )

  const blockedQueries = $derived(stats?.num_blocked_filtering || 0)
  const totalQueries = $derived(stats?.num_dns_queries || 0)
  // The protection switches on the overview, in display order.
  const protections = $derived([
    { icon: 'shield-check', title: 'DNS protection', desc: 'Blocks ads, trackers and malware using the blocklists', on: status?.protection_enabled, toggle: toggleProtection },
    { icon: 'shield', title: 'Safe browsing', desc: 'Blocks known malware and phishing sites', on: safeBrowsing?.enabled, toggle: toggleSafeBrowsing },
    { icon: 'users', title: 'Parental control', desc: 'Blocks adult content', on: parental?.enabled, toggle: toggleParental },
    { icon: 'search', title: 'Safe search', desc: 'Forces safe search on search engines', on: safeSearch?.enabled, toggle: toggleSafeSearch },
    { icon: 'world-off', title: 'Block IPv6 (AAAA)', aaaa: true, on: dnsConfig?.disable_ipv6, toggle: toggleBlockAAAA },
  ])
  const protectionsOn = $derived(protections.filter((p) => p.on).length)
  const blockPercent = $derived(totalQueries > 0 ? ((blockedQueries / totalQueries) * 100).toFixed(1) : 0)
  const enabledFilters = $derived(filters.filter(f => f.enabled).length)

  // Helper to get services by category
  function getServicesByCategory(categoryId) {
    const category = SERVICE_CATEGORIES.find(c => c.id === categoryId)
    if (!category) return []

    // If we have all services from API, filter by category
    if (allServices.length > 0) {
      return allServices.filter(s => category.services.includes(s.id))
    }

    // Fallback to hardcoded
    return category.services.map(id => ({ id, name: id.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) }))
  }

  // Actions
  async function toggleProtection(enabled) {
    try {
      await apiPut('/api/adguard/config', { type: 'protection', enabled })
      toast(enabled ? 'Protection enabled' : 'Protection disabled', 'success')
      status = { ...status, protection_enabled: enabled }
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function addFilter() {
    if (addFilterMode === 'manual') {
      if (!newFilterName || !newFilterUrl) return
      try {
        await apiPut('/api/adguard/filtering', { action: 'add', filters: [{ name: newFilterName, url: newFilterUrl }] })
        toast('Filter added', 'success')
        newFilterName = ''
        newFilterUrl = ''
        showAddFilterModal = false
        loadedTabs.filters = false
        loadFilters()
      } catch (e) {
        toast('Failed: ' + e.message, 'error')
      }
    } else {
      // Add selected lists in batch
      if (selectedLists.length === 0) return
      const filtersToAdd = selectedLists
        .map(listId => blocklists.categories.flatMap(c => c.lists).find(l => l.id === listId))
        .filter(Boolean)
        .map(list => ({ name: list.name, url: list.url }))

      try {
        const result = await apiPut('/api/adguard/filtering', { action: 'add', filters: filtersToAdd })
        const added = result.added?.length || 0
        const failed = result.errors?.length || 0
        if (added > 0) toast(`Added ${added} filter${added > 1 ? 's' : ''}`, 'success')
        if (failed > 0) toast(`Failed to add ${failed} filter${failed > 1 ? 's' : ''}`, 'error')
      } catch (e) {
        toast('Failed: ' + e.message, 'error')
      }
      selectedLists = []
      filterSearchQuery = ''
      showAddFilterModal = false
      loadedTabs.filters = false
      loadFilters()
    }
  }

  function toggleListSelection(listId) {
    if (selectedLists.includes(listId)) {
      selectedLists = selectedLists.filter(id => id !== listId)
    } else {
      selectedLists = [...selectedLists, listId]
    }
  }

  function isListAlreadyAdded(url) {
    return filters.some(f => f.url === url)
  }

  const filteredBlocklists = $derived(
    blocklists.categories.map(category => ({
      ...category,
      lists: category.lists.filter(list => {
        if (filterSearchQuery) {
          return list.name.toLowerCase().includes(filterSearchQuery.toLowerCase())
        }
        return true
      })
    })).filter(category => category.lists.length > 0)
  )

  async function removeFilter(url) {
    try {
      await apiPut('/api/adguard/filtering', { action: 'remove', url })
      toast('Filter removed', 'success')
      loadedTabs.filters = false
      loadFilters()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function toggleFilter(url, name, enabled) {
    try {
      await apiPut('/api/adguard/filtering', { action: 'toggle', url, name, enabled })
      // Update local state optimistically
      filters = filters.map(f => f.url === url ? { ...f, enabled } : f)
      toast(enabled ? 'Filter enabled' : 'Filter disabled', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function refreshFilters() {
    refreshingFilters = true
    try {
      await apiPut('/api/adguard/filtering', { action: 'refresh' })
      toast('Filters updated', 'success')
      loadedTabs.filters = false
      await loadFilters()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      refreshingFilters = false
    }
  }

  async function addRule(rule) {
    try {
      const newRules = [...userRules, rule]
      await apiPut('/api/adguard/filtering', { action: 'setRules', rules: newRules })
      toast('Rule added', 'success')
      loadedTabs.filters = false
      loadFilters()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function removeRule(rule) {
    try {
      const newRules = userRules.filter(r => r !== rule)
      await apiPut('/api/adguard/filtering', { action: 'setRules', rules: newRules })
      toast('Rule removed', 'success')
      loadedTabs.filters = false
      loadFilters()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // Accept a hostname (optionally a *. wildcard) or an IPv4/IPv6 literal.
  function isValidHost(v) {
    const s = (v || '').trim()
    if (!s) return false
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s.split('.').every((o) => +o >= 0 && +o <= 255)
    if (s.includes(':') && /^[0-9a-fA-F:]+$/.test(s)) return true // IPv6 (loose)
    return /^(\*\.)?([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,}$/.test(s)
  }

  function handleAddBlockRule() {
    const d = newBlockDomain.trim()
    if (!d) return
    if (!isValidHost(d)) { toast('Enter a valid domain or IP', 'error'); return }
    addRule(`||${d}^`)
    newBlockDomain = ''
  }

  function handleAddAllowRule() {
    const d = newAllowDomain.trim()
    if (!d) return
    if (!isValidHost(d)) { toast('Enter a valid domain or IP', 'error'); return }
    addRule(`@@||${d}^`)
    newAllowDomain = ''
  }

  async function toggleService(serviceId, blocked) {
    try {
      const newServices = blocked
        ? [...blockedServices, serviceId]
        : blockedServices.filter(s => s !== serviceId)
      await apiPut('/api/adguard/config', { type: 'blockedServices', services: newServices })
      blockedServices = newServices
      toast(blocked ? `${serviceId} blocked` : `${serviceId} unblocked`, 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function toggleSafeBrowsing(enabled) {
    try {
      await apiPut('/api/adguard/config', { type: 'safeBrowsing', enabled })
      safeBrowsing = { ...safeBrowsing, enabled }
      toast(enabled ? 'Safe Browsing enabled' : 'Safe Browsing disabled', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function toggleParental(enabled) {
    try {
      await apiPut('/api/adguard/config', { type: 'parental', enabled })
      parental = { ...parental, enabled }
      toast(enabled ? 'Parental Control enabled' : 'Parental Control disabled', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function toggleSafeSearch(enabled) {
    try {
      await apiPut('/api/adguard/config', { type: 'safeSearch', enabled })
      safeSearch = { ...safeSearch, enabled }
      toast(enabled ? 'Safe Search enabled' : 'Safe Search disabled', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function toggleBlockAAAA(enabled) {
    try {
      await apiPut('/api/adguard/config', { type: 'blockAAAA', enabled })
      dnsConfig = { ...dnsConfig, disable_ipv6: enabled }
      toast(enabled ? 'IPv6 (AAAA) answers blocked' : 'IPv6 (AAAA) answers allowed', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function addRewrite() {
    const domain = newRewriteDomain.trim()
    const answer = newRewriteAnswer.trim()
    if (!domain || !answer) return
    if (!isValidHost(domain)) { toast('Rewrite domain must be a valid hostname', 'error'); return }
    if (!isValidHost(answer)) { toast('Rewrite answer must be a valid IP or domain', 'error'); return }
    try {
      await apiPut('/api/adguard/rewrites', { action: 'add', domain, answer })
      // Update local state
      rewrites = [...rewrites, { domain, answer }]
      toast('Rewrite added', 'success')
      newRewriteDomain = ''
      newRewriteAnswer = ''
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function deleteRewrite(domain, answer) {
    try {
      await apiPut('/api/adguard/rewrites', { action: 'delete', domain, answer })
      toast('Rewrite deleted', 'success')
      loadedTabs.rewrites = false
      loadRewrites()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  onMount(loadCoreData)
</script>

<div class="space-y-4">
  <InfoCard
    icon="shield"
    title="AdGuard DNS"
    description="Network-wide ad blocking and privacy protection. Block ads, trackers, and malware at the DNS level for all VPN clients."
  />

  {#if loading}
    <LoadingSpinner size="lg" centered />
  {:else}
    <StatStrip label="DNS summary" items={[
      { icon: 'activity', tone: 'info', value: formatNumber(totalQueries), label: 'DNS queries' },
      { icon: 'ban', tone: 'destructive', value: formatNumber(blockedQueries), label: 'blocked', sub: `${blockPercent}% of queries` },
      { icon: 'filter', tone: 'primary', value: enabledFilters, label: 'active blocklists' },
      { icon: 'globe', tone: 'warning', value: blockedServices.length, label: 'blocked services' },
    ]} />

    <!-- Segmented tab bar — pills on desktop, a select on mobile (matches Analytics) -->
    <div class="space-y-3">
      <div class="hidden sm:flex gap-0.5 bg-muted p-1 rounded-lg w-fit">
        {#each tabs as t}
          <button
            onclick={() => setTab(t.id)}
            class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-colors cursor-pointer {activeTab === t.id ? 'bg-card text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground'}"
          >
            <Icon name={t.icon} size={14} />
            {t.label}
          </button>
        {/each}
      </div>
      <div class="sm:hidden">
        <Select value={activeTab} onchange={(e) => setTab(e.target.value)}>
          {#each tabs as t}<option value={t.id}>{t.label}</option>{/each}
        </Select>
      </div>

      <!-- Overview is two panels of its own; the other tabs share one panel -->
      <div class={activeTab === 'overview' ? 'space-y-4' : 'panel'}>
        <!-- Overview Tab -->
        {#if activeTab === 'overview'}
          <!-- Protections: a tile each, switch on the right -->
          <div class="panel">
            <div class="panel-head">
              <span class="panel-icon text-primary"><Icon name="shield-check" size={17} /></span>
              <div class="min-w-0 flex-1">
                <div class="panel-title">Protections</div>
                <div class="panel-sub">{protectionsOn} of {protections.length} on · for every device using this DNS</div>
              </div>
            </div>
            <div class="grid gap-3 md:grid-cols-2">
              {#each protections as p (p.title)}
                <div class="flex items-center gap-3 rounded-lg border border-dashed border-border bg-muted/30 px-3 py-2.5">
                  <span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg {p.on ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}"><Icon name={p.icon} size={16} /></span>
                  <div class="min-w-0 flex-1">
                    <div class="text-sm font-medium text-foreground">{p.title}</div>
                    <div class="text-[11px] text-muted-foreground">
                      {#if p.aaaa}Drops <Explain term="AAAA" /> answers, so devices only get IPv4 addresses{:else}{p.desc}{/if}
                    </div>
                  </div>
                  <Checkbox variant="switch" checked={!!p.on} onchange={() => p.toggle(!p.on)} aria-label={p.title} />
                </div>
              {/each}
            </div>
          </div>

          <!-- Blocked services: a row per category, tap a service to block or allow it -->
          <div class="panel">
            <div class="panel-head">
              <span class="panel-icon text-destructive"><Icon name="ban" size={17} /></span>
              <div class="min-w-0 flex-1">
                <div class="panel-title">Blocked services</div>
                <div class="panel-sub">tap a service to block or allow it</div>
              </div>
              {#if blockedServices.length > 0}<Badge variant="destructive" size="sm">{blockedServices.length} blocked</Badge>{/if}
            </div>
            <div class="-mx-4 -mb-4 -mt-4 divide-y divide-dashed divide-border">
              {#each SERVICE_CATEGORIES as category (category.id)}
                {@const categoryServices = getServicesByCategory(category.id)}
                {#if categoryServices.length > 0}
                  {@const blockedInCategory = categoryServices.filter((x) => blockedServices.includes(x.id)).length}
                  <div class="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-start sm:gap-4">
                    <div class="shrink-0 sm:w-36 sm:pt-1">
                      <div class="text-xs font-medium text-foreground">{category.name}</div>
                      <div class="text-[11px] tabular-nums text-muted-foreground">
                        {#if blockedInCategory}<span class="font-medium text-destructive">{blockedInCategory} blocked</span> of {categoryServices.length}{:else}{categoryServices.length} allowed{/if}
                      </div>
                    </div>
                    <div class="flex flex-1 flex-wrap gap-1.5">
                      {#each categoryServices as service}
                        {@const serviceId = service.id}
                        {@const serviceName = service.name}
                        {@const serviceIcon = service.icon_svg}
                        {@const isBlocked = blockedServices.includes(serviceId)}
                        <button type="button" aria-pressed={isBlocked} onclick={() => toggleService(serviceId, !isBlocked)}
                          title={isBlocked ? `${serviceName} is blocked: tap to allow` : `Block ${serviceName}`}
                          class="inline-flex cursor-pointer items-center gap-1.5 rounded-md border px-2 py-1 text-xs transition-colors
                            {isBlocked ? 'border-destructive/40 bg-destructive/10 text-destructive' : 'border-border text-muted-foreground hover:border-muted-foreground/40 hover:text-foreground'}">
                          {#if serviceIcon}
                            <img src="data:image/svg+xml;base64,{serviceIcon}" alt="" class="h-3.5 w-3.5 {isBlocked ? '' : 'opacity-60 grayscale'}" />
                          {:else}
                            <Icon name="globe" size={14} class={isBlocked ? '' : 'opacity-60'} />
                          {/if}
                          {serviceName}
                          {#if isBlocked}<Icon name="ban" size={12} />{/if}
                        </button>
                      {/each}
                    </div>
                  </div>
                {/if}
              {/each}
            </div>
          </div>

        <!-- Filters Tab -->
        {:else if activeTab === 'filters'}
          {#if !loadedTabs.filters}
            <LoadingSpinner size="lg" centered />
          {:else}
            <!-- Summary bar -->
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-4 pb-4 border-b border-border">
              <div class="flex items-center gap-4 text-sm">
                {#if filters.length > 0}
                  <span class="text-muted-foreground">{filters.filter(f => f.enabled).length} active</span>
                  <span class="text-muted-foreground">·</span>
                  <span class="text-muted-foreground">{formatNumber(filters.reduce((sum, f) => sum + (f.rules_count || 0), 0))} rules</span>
                {:else}
                  <span class="text-muted-foreground">No blocklists configured</span>
                {/if}
              </div>
              <div class="kt-btn-group">
                {#if filters.length > 0}
                  <Button onclick={refreshFilters} variant="outline" size="sm" icon="refresh" loading={refreshingFilters} disabled={refreshingFilters}>
                    {refreshingFilters ? 'Updating...' : 'Update'}
                  </Button>
                {/if}
                <Button onclick={() => showAddFilterModal = true} size="sm" icon="plus">
                  Add
                </Button>
              </div>
            </div>

            {#if filters.length === 0}
              <EmptyState
                icon="filter"
                title="No Filters"
                description="Add blocklists to start filtering DNS queries"
              />
            {:else}
              <!-- Filters grid -->
              <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {#each filters as filter}
                  <div class="rounded-lg border border-border bg-card overflow-hidden {!filter.enabled ? 'opacity-50' : ''}">
                    <div class="p-3">
                      <div class="flex items-start justify-between gap-2 mb-1">
                        <span class="text-sm font-medium text-foreground line-clamp-2 leading-tight">{filter.name}</span>
                        <Checkbox
                          variant="switch"
                          checked={filter.enabled}
                          onchange={() => toggleFilter(filter.url, filter.name, !filter.enabled)}
                          class="flex-shrink-0"
                        />
                      </div>
                      <span class="text-xs text-muted-foreground">{formatNumber(filter.rules_count)} rules</span>
                    </div>
                    <div class="flex items-center justify-between px-3 py-2 border-t border-border bg-muted/30">
                      <span class="text-[10px] text-muted-foreground">
                        {#if filter.last_updated}
                          Updated {new Date(filter.last_updated).toLocaleDateString(undefined, withTz())}
                        {:else}
                          —
                        {/if}
                      </span>
                      <Button
                        onclick={() => removeFilter(filter.url)}
                        variant="destructive"
                        size="sm"
                        iconOnly
                        icon="trash"
                        class="kt-btn-outline"
                        title="Remove"
                      />
                    </div>
                  </div>
                {/each}
              </div>
            {/if}
          {/if}

        <!-- Block Rules Tab -->
        {:else if activeTab === 'rules'}
          {#if !loadedTabs.rules}
            <LoadingSpinner size="lg" centered />
          {:else}
            <!-- Add domain bar (stacks on mobile) -->
            <div class="flex flex-col sm:flex-row gap-2 mb-5 pb-4 border-b border-border">
              <Input
                type="text"
                bind:value={newBlockDomain}
                placeholder="Enter domain (e.g., facebook.com)"
                class="flex-1"
                prefixIcon="world"
                onkeydown={(e) => { if (e.key === 'Enter') handleAddBlockRule() }}
              />
              <div class="kt-toggle-group flex w-full sm:w-auto">
                <Button onclick={handleAddBlockRule} icon="ban" class="flex-1 sm:flex-none">Block</Button>
                <Button onclick={() => { newAllowDomain = newBlockDomain; newBlockDomain = ''; handleAddAllowRule() }} icon="check" class="flex-1 sm:flex-none">Allow</Button>
              </div>
            </div>

            <!-- Blocked -->
            <div class="mb-5">
              <div class="flex items-center gap-2 mb-3 pb-2 border-b border-border/50">
                <Icon name="ban" size={16} class="text-destructive" />
                <span class="text-sm font-medium text-foreground">Blocked</span>
                <Badge variant="destructive" size="sm">{blockedDomains.length}</Badge>
              </div>
              {#if blockedDomains.length > 0}
                <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-2">
                  {#each blockedDomains as domain}
                    <div class="flex items-center gap-2 pl-3 pr-1.5 py-1.5 rounded-md bg-muted/30 border border-border/50 border-l-2 border-l-destructive/60 hover:bg-muted/50">
                      <span class="font-mono text-xs truncate flex-1">{domain}</span>
                      <Button variant="ghost-danger" size="xs" iconOnly icon="trash" onclick={() => removeRule(`||${domain}^`)} title="Remove" aria-label="Remove {domain}" />
                    </div>
                  {/each}
                </div>
              {:else}
                <p class="text-xs text-muted-foreground italic">No blocked domains.</p>
              {/if}
            </div>

            <!-- Allowed -->
            <div>
              <div class="flex items-center gap-2 mb-3 pb-2 border-b border-border/50">
                <Icon name="check" size={16} class="text-success" />
                <span class="text-sm font-medium text-foreground">Allowed</span>
                <Badge variant="success" size="sm">{allowedDomains.length}</Badge>
              </div>
              {#if allowedDomains.length > 0}
                <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-2">
                  {#each allowedDomains as domain}
                    <div class="flex items-center gap-2 pl-3 pr-1.5 py-1.5 rounded-md bg-muted/30 border border-border/50 border-l-2 border-l-success/60 hover:bg-muted/50">
                      <span class="font-mono text-xs truncate flex-1">{domain}</span>
                      <Button variant="ghost-danger" size="xs" iconOnly icon="trash" onclick={() => removeRule(`@@||${domain}^`)} title="Remove" aria-label="Remove {domain}" />
                    </div>
                  {/each}
                </div>
              {:else}
                <p class="text-xs text-muted-foreground italic">No allowed domains.</p>
              {/if}
            </div>
          {/if}

        <!-- DNS Rewrites Tab -->
        {:else if activeTab === 'rewrites'}
          {#if !loadedTabs.rewrites}
            <LoadingSpinner size="lg" centered />
          {:else}
            <!-- Add rewrite bar (stacks on mobile; arrow hidden when stacked) -->
            <div class="flex flex-col sm:flex-row sm:items-center gap-2 mb-5 pb-4 border-b border-border">
              <Input type="text" bind:value={newRewriteDomain} placeholder="Domain (e.g., example.local)" class="flex-1" prefixIcon="world" onkeydown={(e) => e.key === 'Enter' && addRewrite()} />
              <Icon name="arrow-right" size={16} class="text-muted-foreground shrink-0 hidden sm:block" />
              <Input type="text" bind:value={newRewriteAnswer} placeholder="Answer (IP or domain)" class="flex-1" prefixIcon="server" onkeydown={(e) => e.key === 'Enter' && addRewrite()} />
              <Button onclick={addRewrite} icon="plus">Add</Button>
            </div>

            <!-- Rewrites list -->
            <div class="flex items-center gap-2 mb-3 pb-2 border-b border-border/50">
              <Icon name="link" size={16} class="text-info" />
              <span class="text-sm font-medium text-foreground">DNS Rewrites</span>
              <Badge variant="info" size="sm">{rewrites.length}</Badge>
            </div>

            {#if rewrites.length === 0}
              <p class="text-xs text-muted-foreground italic">No DNS rewrites configured.</p>
            {:else}
              <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-2">
                {#each rewrites as rewrite}
                  <div class="flex items-center gap-2 pl-3 pr-1.5 py-1.5 rounded-md bg-muted/30 border border-border/50 hover:bg-muted/50">
                    <span class="font-mono text-xs truncate">{rewrite.domain}</span>
                    <Icon name="arrow-right" size={12} class="text-muted-foreground shrink-0" />
                    <span class="font-mono text-xs text-primary truncate flex-1">{rewrite.answer}</span>
                    <Button variant="ghost-danger" size="xs" iconOnly icon="trash" onclick={() => deleteRewrite(rewrite.domain, rewrite.answer)} title="Remove" aria-label="Remove rewrite" />
                  </div>
                {/each}
              </div>
            {/if}
          {/if}
        {/if}
      </div>
    </div>
  {/if}
</div>

<!-- Add Filter Modal -->
<Modal bind:open={showAddFilterModal} title="Add Blocklist" size="lg">
  <!-- Mode tabs -->
  <Tabs
    tabs={[{id:'list',label:'Choose from List',icon:'list'},{id:'manual',label:'Add Manually',icon:'edit'}]}
    bind:activeTab={addFilterMode}
    size="sm"
    class="mb-4 -mt-2"
  />

  {#if addFilterMode === 'list'}
    <div class="mb-4">
      <Input
        type="text"
        bind:value={filterSearchQuery}
        placeholder="Search blocklists..."
        prefixIcon="search"
      />
    </div>

    <div class="max-h-[400px] overflow-y-auto space-y-4 pr-2">
      {#each filteredBlocklists as category}
        <div>
          <h4 class="text-sm font-semibold text-foreground mb-1">{category.name}</h4>
          <p class="text-xs text-muted-foreground mb-2">{category.description}</p>
          <div class="space-y-1">
            {#each category.lists as list}
              {@const alreadyAdded = isListAlreadyAdded(list.url)}
              {@const isSelected = selectedLists.includes(list.id)}
              <Checkbox
                checked={isSelected || alreadyAdded}
                disabled={alreadyAdded}
                onchange={() => !alreadyAdded && toggleListSelection(list.id)}
                class="!flex !gap-3 p-2 rounded-lg border transition-colors
                  {alreadyAdded ? 'border-success/30 bg-success/5 opacity-60' : isSelected ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'}"
              >
                <div class="flex-1 min-w-0">
                  <div class="text-sm font-medium text-foreground">{list.name}</div>
                </div>
                {#if alreadyAdded}
                  <Badge variant="success" size="sm">Added</Badge>
                {/if}
              </Checkbox>
            {/each}
          </div>
        </div>
      {/each}
    </div>
  {:else}
    <div class="space-y-4">
      <Input
        label="Filter Name"
        bind:value={newFilterName}
        placeholder="e.g., My Custom Blocklist"
      />
      <Input
        label="Filter URL"
        helperText="Enter a URL to a hosts file or AdBlock-style filter list"
        bind:value={newFilterUrl}
        placeholder="https://example.com/blocklist.txt"
      />
    </div>
  {/if}

  {#snippet footer()}
    {#if addFilterMode === 'list'}
      <span class="text-sm text-muted-foreground mr-auto">{selectedLists.length} selected</span>
      <Button onclick={() => { showAddFilterModal = false; selectedLists = []; filterSearchQuery = '' }} variant="secondary">Cancel</Button>
      <Button onclick={addFilter} disabled={selectedLists.length === 0}>
        Add {selectedLists.length} Blocklist{selectedLists.length !== 1 ? 's' : ''}
      </Button>
    {:else}
      <Button onclick={() => showAddFilterModal = false} variant="secondary">Cancel</Button>
      <Button onclick={addFilter} disabled={!newFilterName || !newFilterUrl}>Add Filter</Button>
    {/if}
  {/snippet}
</Modal>

