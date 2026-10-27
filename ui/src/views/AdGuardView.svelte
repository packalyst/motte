<script>
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPut, getInitialTab } from '../stores/app.js'
  import { formatNumber } from '../lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import StatStrip from '../components/StatStrip.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import MobileNav from '../components/MobileNav.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import Explain from '../components/Explain.svelte'
  import DnsRewrites from '../components/DnsRewrites.svelte'
  import BlockRules from '../components/BlockRules.svelte'
  import FilterLists from '../components/FilterLists.svelte'

  let { loading = $bindable(true) } = $props()

  // Core state
  let activeTab = $state(getInitialTab('overview', ['overview', 'filters', 'rules', 'rewrites']))
  let status = $state(null)
  let stats = $state(null)

  // Page state, loaded on mount
  let filters = $state([])
  let blockedServices = $state([])
  let allServices = $state([])
  let safeBrowsing = $state(null)
  let parental = $state(null)
  let safeSearch = $state(null)
  let dnsConfig = $state(null)

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
    } catch (e) {
      toast('Failed to load AdGuard data: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  // The blocklists: loaded with the page (the Overview counts them), reloaded by their tab.
  async function loadFilters() {
    try {
      const res = await apiGet('/api/adguard/filtering')
      filters = res?.filters || []
    } catch (e) {
      toast('Failed to load blocklists: ' + e.message, 'error')
    }
  }

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



  onMount(() => {
    loadCoreData()
    loadFilters()
  })
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

    <!-- Segmented tab bar — pills on desktop, MobileNav's app tab bar at the bottom below lg
         (like the machine page) -->
    <div class="space-y-3">
      <div class="hidden lg:flex gap-0.5 bg-muted p-1 rounded-lg w-fit">
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
      <MobileNav items={tabs} active={activeTab} onselect={setTab} label="DNS sections" look="bottom" />

      <!-- Overview is two panels of its own; the other tabs are a table each -->
      <div class={activeTab === 'overview' ? 'space-y-4' : ''}>
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
          <FilterLists bind:filters reload={loadFilters} />

        <!-- Block Rules Tab -->
        {:else if activeTab === 'rules'}
          <BlockRules />

        <!-- DNS Rewrites Tab: its own table -->
        {:else if activeTab === 'rewrites'}
          <DnsRewrites />
        {/if}
      </div>
    </div>
  {/if}
</div>


