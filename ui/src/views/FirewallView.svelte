<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet, apiPost, apiDelete, confirm, setConfirmLoading } from '../stores/app.js'
  import { createDebouncedSearch, lazyLoad } from '../stores/helpers.js'
  import { usePaginatedState } from '$lib/composables/index.js'
  import { formatRelativeDate, formatTime } from '$lib/utils/format.js'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Modal from '../components/Modal.svelte'
  import Pagination from '../components/Pagination.svelte'
  import Input from '../components/Input.svelte'
  import Select from '../components/Select.svelte'
  import Button from '../components/Button.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import DropdownButton from '../components/DropdownButton.svelte'
  let { loading = $bindable(true) } = $props()

  // Data state

  // Blocked entries state (server-side pagination)
  let blockedEntries = $state([])
  let blockedTotal = $state(0)
  let blockedTypes = $state([])
  let blockedSources = $state([])
  let loadingBlocked = $state(false)
  let removingEntryId = $state(null)
  let selectedBlockedEntries = $state([])
  let deletingSelectedEntries = $state(false)

  // Pagination with persistent state
  const blocked = usePaginatedState('firewall_blocked', { type: '', source: '' })
  let blockedSearchQuery = $state(blocked.search)

  // Listen for WebSocket zone progress updates via custom event
  // (store-based approach misses rapid messages)
  function handleZoneUpdate(e) {
    const info = e.detail
    if (!info?.event) return

    if (info.event === 'firewall:zones:progress' && info.country && info.rangeCount !== undefined) {
      // Update the hitCount for this country in blockedEntries
      blockedEntries = blockedEntries.map(entry => {
        if (entry.entryType === 'country' && entry.value === info.country) {
          return { ...entry, hitCount: info.rangeCount }
        }
        return entry
      })
    } else if (info.event === 'firewall:zones:complete') {
      // Reload blocked entries to get final state
      loadBlocked()
    }
  }

  onMount(() => {
    window.addEventListener('firewall-zone-update', handleZoneUpdate)
  })

  onDestroy(() => {
    window.removeEventListener('firewall-zone-update', handleZoneUpdate)
  })

  // Modals
  let showBlockModal = $state(false)

  // Forms
  let blockForm = $state({ ip: '', reason: '', duration: '30d' })

  // Blocklist import state
  let showImportModal = $state(false)
  let blocklists = $state([])
  let loadingBlocklists = $state(false)
  let importingSource = $state(null)
  let customURL = $state('')

  // Sync status state
  let syncStatus = $state(null)
  let checkingSyncStatus = $state(false)
  let refreshingZones = $state(false)

  // Country blocking state
  let availableCountries = $state([])
  let showBlockCountriesModal = $state(false)
  let countrySearch = $state('')
  let selectedCountries = $state([])
  let blockingCountries = $state(false)

  // Check sync status between DB and nftables
  async function checkSyncStatus() {
    checkingSyncStatus = true
    try {
      syncStatus = await apiGet('/api/fw/sync-status')
      if (!syncStatus.inSync) {
        if (syncStatus.lastApplyError) {
          toast('Firewall sync error: ' + syncStatus.lastApplyError, 'error')
        } else if (syncStatus.tables?.some(t => !t.exists)) {
          const missing = syncStatus.tables.filter(t => !t.exists).map(t => t.name).join(', ')
          toast(`Firewall table(s) not found in nftables: ${missing}`, 'warning')
        } else {
          // Show detailed mismatch info
          const mismatches = []
          if (syncStatus.dbBlockedIPs !== syncStatus.nftBlockedIPs) {
            mismatches.push(`IPs: DB=${syncStatus.dbBlockedIPs} vs NFT=${syncStatus.nftBlockedIPs}`)
          }
          if (syncStatus.dbBlockedRanges !== syncStatus.nftBlockedRanges) {
            mismatches.push(`Ranges: DB=${syncStatus.dbBlockedRanges} vs NFT=${syncStatus.nftBlockedRanges}`)
          }
          if (syncStatus.dbAllowedPorts !== syncStatus.nftAllowedPorts) {
            mismatches.push(`Ports: DB=${syncStatus.dbAllowedPorts} vs NFT=${syncStatus.nftAllowedPorts}`)
          }
          if (syncStatus.dbCountryRanges !== syncStatus.nftCountryRanges) {
            mismatches.push(`Countries: DB=${syncStatus.dbCountryRanges} vs NFT=${syncStatus.nftCountryRanges}`)
          }
          if (syncStatus.applyPending) {
            mismatches.push('Apply pending')
          }
          toast('Out of sync: ' + mismatches.join(', '), 'warning')
        }
      } else {
        const parts = [`${syncStatus.dbBlockedIPs} IPs`, `${syncStatus.dbAllowedPorts} ports`]
        if (syncStatus.dbBlockedRanges > 0) parts.push(`${syncStatus.dbBlockedRanges} ranges`)
        if (syncStatus.dbCountryRanges > 0) parts.push(`${syncStatus.dbCountryRanges} country ranges`)
        toast(`In sync: ${parts.join(', ')}`, 'success')
      }
    } catch (e) {
      toast('Failed to check sync status: ' + e.message, 'error')
    } finally {
      checkingSyncStatus = false
    }
  }

  async function loadBlocked() {
    loadingBlocked = true
    try {
      const params = new URLSearchParams({
        limit: blocked.perPage.toString(),
        offset: blocked.offset.toString(),
        action: 'block' // Only show blocked entries (not allowed ports)
      })
      if (blocked.search) params.set('search', blocked.search)
      if (blocked.filters.type) params.set('type', blocked.filters.type)
      if (blocked.filters.source) params.set('source', blocked.filters.source)

      const res = await apiGet(`/api/fw/entries?${params}`)
      blockedEntries = res.entries || []
      blockedTotal = res.total || 0
      blockedTypes = res.types || []
      blockedSources = res.sources || []
    } catch (e) {
      toast('Failed to load blocked entries: ' + e.message, 'error')
    } finally {
      loadingBlocked = false
    }
  }

  // Debounced search handlers
  const { search: debouncedBlockedSearch, cleanup: cleanupBlockedSearch } = createDebouncedSearch((value) => {
    blocked.setSearch(value)
    loadBlocked()
  })

  function handleBlockedSearchInput(e) {
    blockedSearchQuery = e.target.value
    debouncedBlockedSearch(blockedSearchQuery)
  }

  function setBlockedTypeFilter(type) {
    blocked.setFilter('type', type)
    loadBlocked()
  }

  function setBlockedSourceFilter(source) {
    blocked.setFilter('source', source)
    loadBlocked()
  }

  function clearBlockedFilters() {
    blocked.reset()
    blockedSearchQuery = ''
    loadBlocked()
  }

  // Reload blocked entries
  async function reloadBlocked() {
    await loadBlocked()
  }

  async function blockIP() {
    // Validate IP or CIDR (e.g., 192.168.1.100 or 192.168.1.0/24)
    const ipRegex = /^\d+\.\d+\.\d+\.\d+$/
    const cidrRegex = /^\d+\.\d+\.\d+\.\d+\/\d+$/
    if (!ipRegex.test(blockForm.ip) && !cidrRegex.test(blockForm.ip)) {
      toast('Invalid IP address or CIDR (e.g., 192.168.1.100 or 192.168.1.0/24)', 'error')
      return
    }
    // Validate CIDR prefix
    if (cidrRegex.test(blockForm.ip)) {
      const prefix = parseInt(blockForm.ip.split('/')[1])
      if (prefix < 8 || prefix > 32) {
        toast('CIDR prefix must be between /8 and /32', 'error')
        return
      }
    }
    let banTime = 0
    if (blockForm.duration !== 'permanent') {
      const match = blockForm.duration.match(/^(\d+)([hdm])$/)
      if (match) {
        const val = parseInt(match[1])
        const unit = match[2]
        if (unit === 'h') banTime = val * 3600
        else if (unit === 'd') banTime = val * 86400
        else if (unit === 'm') banTime = val * 60
      }
    }
    try {
      const isRange = cidrRegex.test(blockForm.ip)
      const res = await apiPost('/api/fw/entries', {
        type: isRange ? 'range' : 'ip',
        value: blockForm.ip,
        action: 'block',
        direction: 'inbound',
        reason: blockForm.reason || 'Manual block',
        banTime
      })
      const msg = isRange ? `Range ${blockForm.ip} blocked` : `IP ${blockForm.ip} blocked`
      toast(msg, 'success')
      showBlockModal = false
      blockForm = { ip: '', reason: '', duration: '30d' }
      await reloadBlocked()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function confirmUnblock(entry) {
    const label = entry.entryType === 'country' ? (entry.name || entry.value) : entry.value
    const description = entry.entryType === 'country'
      ? 'Traffic from this country will be allowed again.'
      : entry.entryType === 'range'
        ? 'This IP range will be able to connect again.'
        : 'This IP will be able to connect again.'

    const confirmed = await confirm({
      title: 'Unblock Entry',
      message: `Unblock ${label}?`,
      description,
      confirmText: 'Unblock',
      variant: 'success'
    })
    if (!confirmed) return

    removingEntryId = entry.id
    setConfirmLoading(true)
    try {
      await apiDelete(`/api/fw/entries/${entry.id}`)
      toast(`${label} unblocked`, 'success')
      await reloadBlocked()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      removingEntryId = null
      setConfirmLoading(false)
    }
  }

  // Blocklist import
  async function openImportModal() {
    showImportModal = true
    if (blocklists.length === 0) {
      loadingBlocklists = true
      try {
        blocklists = await apiGet('/api/fw/blocklists')
      } catch (e) {
        toast('Failed to load blocklists: ' + e.message, 'error')
      } finally {
        loadingBlocklists = false
      }
    }
  }

  async function importBlocklist(source) {
    importingSource = source
    try {
      const body = source === 'custom' ? { url: customURL } : { source }
      const res = await apiPost('/api/fw/entries/import', body)
      toast(`Imported ${res.added} IPs from ${res.source} (${res.skipped} skipped)`, 'success')
      if (source === 'custom') customURL = ''
      await reloadBlocked()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      importingSource = null
    }
  }

  async function toggleEntryDirection(entry) {
    const newDirection = entry.direction === 'inbound' ? 'both' : 'inbound'
    try {
      await apiPost(`/api/fw/entries/${entry.id}/toggle`, { direction: newDirection })
      const label = entry.entryType === 'country' ? entry.name || entry.value : entry.value
      toast(`${label} direction changed to ${newDirection}`, 'success')
      await loadBlocked()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // Toggle blocked entry selection
  function toggleBlockedEntrySelection(id) {
    if (selectedBlockedEntries.includes(id)) {
      selectedBlockedEntries = selectedBlockedEntries.filter(e => e !== id)
    } else {
      selectedBlockedEntries = [...selectedBlockedEntries, id]
    }
  }

  // Select/deselect all blocked entries
  function toggleAllBlockedEntries() {
    if (selectedBlockedEntries.length === blockedEntries.length) {
      selectedBlockedEntries = []
    } else {
      selectedBlockedEntries = blockedEntries.map(e => e.id)
    }
  }

  // Delete selected blocked entries
  async function deleteSelectedBlockedEntries() {
    if (selectedBlockedEntries.length === 0) return
    deletingSelectedEntries = true
    const toDelete = [...selectedBlockedEntries]

    try {
      const result = await apiPost('/api/fw/entries/bulk', {
        action: 'delete',
        ids: toDelete
      })
      selectedBlockedEntries = []
      await loadBlocked()
      toast(`Deleted ${result.affected} entries`, 'success')
    } catch (e) {
      toast(`Failed to delete entries: ${e.message}`, 'error')
    } finally {
      deletingSelectedEntries = false
    }
  }

  // Set direction for selected entries
  async function setSelectedDirection(direction) {
    if (selectedBlockedEntries.length === 0) return
    try {
      const result = await apiPost('/api/fw/entries/bulk', {
        action: `set_${direction}`,
        ids: [...selectedBlockedEntries]
      })
      selectedBlockedEntries = []
      await loadBlocked()
      toast(`Updated ${result.affected} entries to ${direction}`, 'success')
    } catch (e) {
      toast(`Failed to update entries: ${e.message}`, 'error')
    }
  }

  // Delete all entries
  async function confirmDeleteAll() {
    const confirmed = await confirm({
      title: 'Delete All Entries',
      message: `This will permanently delete ${blockedTotal} blocked entries.`,
      description: 'All IPs, ranges, and countries will be removed. Essential entries (system ports) will not be deleted.',
      warning: 'This action cannot be undone!',
      confirmText: 'Delete All'
    })
    if (!confirmed) return

    setConfirmLoading(true)
    try {
      const result = await apiDelete('/api/fw/entries/all')
      await loadBlocked()
      toast(`Deleted ${result.deleted} entries`, 'success')
    } catch (e) {
      toast(`Failed to delete entries: ${e.message}`, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }

  async function refreshZones() {
    refreshingZones = true
    try {
      const res = await apiPost('/api/geo/zones/refresh')
      toast(`Refreshed ${res.updated} countries${res.errors > 0 ? ` (${res.errors} errors)` : ''}`, res.errors > 0 ? 'warning' : 'success')
      await loadBlocked()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      refreshingZones = false
    }
  }

  // Country blocking functions
  async function loadCountries() {
    try {
      const res = await apiGet('/api/geo/countries')
      availableCountries = res.countries || res || []
    } catch (e) {
      toast('Failed to load countries: ' + e.message, 'error')
    }
  }

  function openBlockCountriesModal() {
    loadCountries()
    showBlockCountriesModal = true
  }

  // Get list of blocked country codes from blocked entries
  const blockedCountryCodes = $derived(
    blockedEntries
      .filter(e => e.entryType === 'country')
      .map(e => e.value)
  )

  // Filter out already blocked countries
  const unblockedCountries = $derived(
    availableCountries.filter(c => !blockedCountryCodes.includes(c.code))
  )

  // Filtered by search
  const filteredUnblockedCountries = $derived(
    countrySearch
      ? unblockedCountries.filter(c =>
          c.name.toLowerCase().includes(countrySearch.toLowerCase()) ||
          c.code.toLowerCase().includes(countrySearch.toLowerCase())
        )
      : unblockedCountries
  )

  // Group by continent
  const countriesByContinent = $derived.by(() => {
    const groups = {}
    for (const country of filteredUnblockedCountries) {
      const continent = country.continent || 'Other'
      if (!groups[continent]) groups[continent] = []
      groups[continent].push(country)
    }
    return groups
  })

  const sortedContinents = $derived(
    Object.keys(countriesByContinent).sort()
  )

  function toggleCountrySelection(code) {
    if (selectedCountries.includes(code)) {
      selectedCountries = selectedCountries.filter(c => c !== code)
    } else {
      selectedCountries = [...selectedCountries, code]
    }
  }

  function selectAllFilteredCountries() {
    selectedCountries = filteredUnblockedCountries.map(c => c.code)
  }

  function clearCountrySelection() {
    selectedCountries = []
  }

  function toggleContinentSelection(continent) {
    const continentCountries = countriesByContinent[continent] || []
    const continentCodes = continentCountries.map(c => c.code)
    const allSelected = continentCodes.every(c => selectedCountries.includes(c))

    if (allSelected) {
      selectedCountries = selectedCountries.filter(c => !continentCodes.includes(c))
    } else {
      const newSelection = new Set([...selectedCountries, ...continentCodes])
      selectedCountries = [...newSelection]
    }
  }

  function isContinentFullySelected(continent) {
    const continentCountries = countriesByContinent[continent] || []
    return continentCountries.length > 0 && continentCountries.every(c => selectedCountries.includes(c.code))
  }

  function isContinentPartiallySelected(continent) {
    const continentCountries = countriesByContinent[continent] || []
    const selectedCount = continentCountries.filter(c => selectedCountries.includes(c.code)).length
    return selectedCount > 0 && selectedCount < continentCountries.length
  }

  async function blockSelectedCountries() {
    if (selectedCountries.length === 0) return
    blockingCountries = true
    try {
      // Create country entries via the entries API
      for (const code of selectedCountries) {
        const country = availableCountries.find(c => c.code === code)
        await apiPost('/api/fw/entries', {
          type: 'country',
          value: code,
          name: country?.name || code,
          action: 'block',
          direction: 'inbound',
          reason: 'Country block'
        })
      }
      toast(`Blocking ${selectedCountries.length} countries...`, 'info')
      showBlockCountriesModal = false
      selectedCountries = []
      countrySearch = ''
      // Reload blocked entries to show new countries
      await loadBlocked()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      blockingCountries = false
    }
  }

  // Helpers
  function formatTimeRemaining(expiresAt) {
    if (!expiresAt) return 'Permanent'
    const expStr = typeof expiresAt === 'string' ? expiresAt : expiresAt.toISOString?.() || String(expiresAt)
    if (expStr.startsWith('0001-')) return 'Permanent'
    const expires = new Date(expiresAt)
    const now = new Date()
    const diff = expires - now

    if (diff <= 0) return 'Expired'

    const hours = Math.floor(diff / (1000 * 60 * 60))
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))

    if (hours > 24) {
      const days = Math.floor(hours / 24)
      return `${days}d ${hours % 24}h`
    }
    if (hours > 0) return `${hours}h ${minutes}m`
    return `${minutes}m`
  }

  onMount(async () => {
    await loadBlocked()
    loading = false
  })

  onDestroy(() => {
    cleanupBlockedSearch()
  })
</script>

{#if loading}
  <div class="flex flex-col items-center justify-center py-12">
    <div class="w-8 h-8 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
    <p class="mt-3 text-sm text-muted-foreground">Loading firewall...</p>
  </div>
{:else}
  <div class="space-y-4">
    <!-- Info Card -->
    <div class="bg-gradient-to-r from-primary/5 to-info/5 border border-primary/20 rounded-lg p-4">
      <div class="flex items-start gap-3">
        <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
          <Icon name="shield" size={18} class="text-primary" />
        </div>
        <div class="flex-1 min-w-0">
          <h3 class="text-sm font-medium text-foreground mb-1">
            Blocked IPs & Countries
          </h3>
          <p class="text-xs text-muted-foreground leading-relaxed">
            Manage blocked IP addresses, ranges, and country-level blocking.
          </p>
        </div>
        <div class="hidden sm:flex items-center gap-3 text-center">
          <div class="text-lg font-bold text-foreground">{blockedTotal}</div>
          <div class="text-[10px] text-muted-foreground">Blocked</div>
        </div>
      </div>
    </div>

    <!-- Blocked Entries -->
    <div class="data-table">
            <!-- Header -->
            <div class="data-table-header">
              <div class="data-table-header-start">
                <Input
                  type="search"
                  value={blockedSearchQuery}
                  oninput={handleBlockedSearchInput}
                  placeholder="Search IP, country, reason..."
                  prefixIcon="search"
                  class="sm:w-64"
                />
                {#if blockedTypes.length > 1}
                  <Select
                    value={blocked.filters.type}
                    onchange={(e) => setBlockedTypeFilter(e.target.value)}
                    class="sm:w-32"
                  >
                    <option value="">All types</option>
                    {#each blockedTypes as type}
                      <option value={type}>{type}</option>
                    {/each}
                  </Select>
                {/if}
                {#if blockedSources.length > 1}
                  <Select
                    value={blocked.filters.source}
                    onchange={(e) => setBlockedSourceFilter(e.target.value)}
                    class="sm:w-36"
                  >
                    <option value="">All sources</option>
                    {#each blockedSources as source}
                      <option value={source}>{source}</option>
                    {/each}
                  </Select>
                {/if}
              </div>
              <div class="data-table-header-end">
                <div class="kt-btn-group">
                  <!-- Block dropdown -->
                  <DropdownButton
                    label="Block"
                    icon="plus"
                    items={[
                      { label: 'IP / Range', icon: 'ban', onclick: () => showBlockModal = true },
                      { label: 'Import Blocklist', icon: 'download', onclick: openImportModal },
                      { divider: true },
                      { label: 'Countries', icon: 'world', onclick: openBlockCountriesModal }
                    ]}
                  />

                  <!-- Actions dropdown -->
                  <DropdownButton
                    label="Actions"
                    icon="settings"
                    variant="outline"
                    items={[
                      { label: refreshingZones ? 'Refreshing...' : 'Refresh Zones', icon: 'refresh', iconClass: refreshingZones ? 'animate-spin' : '', onclick: refreshZones, disabled: refreshingZones },
                      { label: checkingSyncStatus ? 'Checking...' : 'Check Sync', icon: 'circle-check', onclick: checkSyncStatus, disabled: checkingSyncStatus },
                      { divider: true },
                      { label: 'Delete All...', icon: 'trash', variant: 'destructive', onclick: confirmDeleteAll, disabled: blockedTotal === 0 }
                    ]}
                  />

                  <!-- Bulk dropdown (when items selected) -->
                  {#if selectedBlockedEntries.length > 0}
                    <DropdownButton
                      label="Bulk ({selectedBlockedEntries.length})"
                      icon="layers-subtract"
                      variant="destructive"
                      items={[
                        { label: 'Delete', icon: 'trash', variant: 'destructive', onclick: deleteSelectedBlockedEntries },
                        { divider: true },
                        { label: 'Set Inbound', icon: 'arrow-down', onclick: () => setSelectedDirection('inbound') },
                        { label: 'Set Both', icon: 'arrows-vertical', onclick: () => setSelectedDirection('both') }
                      ]}
                    />
                  {/if}
                </div>
              </div>
            </div>

            <!-- Content -->
            {#if loadingBlocked && blockedEntries.length === 0}
              <div class="data-table-loading">
                <LoadingSpinner size="lg" />
              </div>
            {:else if blockedEntries.length === 0}
              <div class="data-table-empty">
                <EmptyState
                  icon="shield-check"
                  title="No blocked entries"
                  description={blocked.search || blocked.filters.type || blocked.filters.source ? 'No results match your filters' : 'IPs, ranges, and countries will appear here when blocked'}
                />
              </div>
            {:else}
              <div class="data-table-content">
                <table>
                  <thead>
                    <tr>
                      <th class="w-8">
                        <Checkbox
                          checked={blockedEntries.length > 0 && selectedBlockedEntries.length === blockedEntries.length}
                          indeterminate={selectedBlockedEntries.length > 0 && selectedBlockedEntries.length < blockedEntries.length}
                          onchange={() => toggleAllBlockedEntries()}
                        />
                      </th>
                      <th>Added / Source</th>
                      <th>Value</th>
                      <th>Direction</th>
                      <th>Expires</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each blockedEntries as entry}
                      <tr class="{removingEntryId === entry.id ? 'opacity-50' : ''} {selectedBlockedEntries.includes(entry.id) ? 'bg-primary/5' : ''}">
                        <td>
                          <Checkbox
                            checked={selectedBlockedEntries.includes(entry.id)}
                            onchange={() => toggleBlockedEntrySelection(entry.id)}
                            disabled={removingEntryId === entry.id}
                          />
                        </td>
                        <td class="data-table-cell-nowrap">
                          <div class="flex items-center gap-1.5">
                            <Icon name="clock" size={14} class="text-muted-foreground" />
                            <div>
                              <div class="text-xs font-medium">{formatRelativeDate(entry.createdAt)}, {formatTime(entry.createdAt)}</div>
                              <button onclick={() => setBlockedSourceFilter(entry.source)} class="text-[10px] text-muted-foreground hover:text-foreground">
                                {entry.source || 'manual'}
                              </button>
                            </div>
                          </div>
                        </td>
                        <td>
                          <div class="flex items-center gap-2">
                            {#if entry.entryType === 'country'}
                              <img
                                src="https://flagcdn.com/{entry.value.toLowerCase()}.svg"
                                width="18"
                                alt={entry.value}
                                class="rounded-sm shadow-sm"
                                loading="lazy"
                              />
                              <span class="text-sm font-medium">{entry.name || entry.value}</span>
                              <Badge variant="secondary" size="sm" title="{entry.hitCount || 0} IP ranges">
                                <Icon name="network" size={10} class="mr-0.5" />
                                {(entry.hitCount || 0).toLocaleString()}
                              </Badge>
                            {:else}
                              <Icon name={entry.entryType === 'range' ? 'network' : 'globe'} size={14} class="text-muted-foreground" />
                              <code class="text-xs font-mono">{entry.value}</code>
                              {#if entry.entryType === 'range'}
                                <Badge variant="info" size="sm">Range</Badge>
                              {/if}
                            {/if}
                          </div>
                          {#if entry.reason && entry.entryType !== 'country'}
                            <div class="text-[10px] text-muted-foreground mt-0.5 ml-5 truncate max-w-48" title={entry.reason}>
                              {entry.reason}
                            </div>
                          {/if}
                        </td>
                        <td class="data-table-cell-nowrap">
                          <button
                            onclick={() => toggleEntryDirection(entry)}
                            class="cursor-pointer hover:opacity-80 transition-opacity"
                            disabled={removingEntryId === entry.id}
                          >
                            <Badge variant={entry.direction === 'both' ? 'warning' : 'secondary'} size="sm">
                              {#if entry.direction === 'both'}
                                <Icon name="arrow-left" size={10} class="mr-0.5" />
                                <Icon name="arrow-right" size={10} class="mr-1" />
                                Both
                              {:else if entry.direction === 'outbound'}
                                <Icon name="arrow-right" size={10} class="mr-1" />
                                Out
                              {:else}
                                <Icon name="arrow-left" size={10} class="mr-1" />
                                In
                              {/if}
                            </Badge>
                          </button>
                        </td>
                        <td class="data-table-cell-nowrap">
                          {#if entry.expiresAt}
                            <Badge variant="warning" size="sm">
                              {formatTimeRemaining(entry.expiresAt)}
                            </Badge>
                          {:else}
                            <Badge variant="mono" size="sm">Permanent</Badge>
                          {/if}
                        </td>
                        <td class="data-table-cell-actions">
                          {#if removingEntryId === entry.id}
                            <div class="w-4 h-4 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
                          {:else if entry.essential}
                            <span class="p-1.5 text-dim" title="Essential entry">
                              <Icon name="lock" size={14} />
                            </span>
                          {:else}
                            <button onclick={() => confirmUnblock(entry)} class="icon-btn" title="Unblock">
                              <Icon name="lock-open" size={14} />
                            </button>
                          {/if}
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>

              <!-- Footer -->
              <div class="data-table-footer">
                <Pagination
                  page={blocked.page}
                  perPage={blocked.perPage}
                  total={blockedTotal}
                  onPageChange={(p) => { blocked.setPage(p); loadBlocked() }}
                  onPerPageChange={(pp) => { blocked.setPerPage(pp); loadBlocked() }}
                />
              </div>
            {/if}
    </div>
  </div>
{/if}

<!-- Block IP Modal -->
<Modal bind:open={showBlockModal} title="Block IP or Range" size="sm">
  <div class="space-y-4">
    <Input
      label="IP Address or CIDR Range"
      bind:value={blockForm.ip}
      placeholder="e.g. 192.168.1.100 or 192.168.1.0/24"
      helperText="Use CIDR notation (e.g., /24) to block an entire range"
    />
    <Input
      label="Reason"
      bind:value={blockForm.reason}
      placeholder="Manual block (optional)"
    />
    <Select
      label="Duration"
      bind:value={blockForm.duration}
      options={[
        { value: '1h', label: '1 hour' },
        { value: '24h', label: '24 hours' },
        { value: '7d', label: '7 days' },
        { value: '30d', label: '30 days' },
        { value: '90d', label: '90 days' },
        { value: 'permanent', label: 'Permanent' }
      ]}
    />
  </div>

  {#snippet footer()}
    <Button onclick={() => showBlockModal = false} variant="secondary">Cancel</Button>
    <Button onclick={blockIP} variant="destructive" icon="ban">Block</Button>
  {/snippet}
</Modal>


<!-- Blocklist Import Modal -->
<Modal bind:open={showImportModal} title="Import Blocklist" size="md">
  <div class="space-y-5">
    {#if loadingBlocklists}
      <div class="flex flex-col items-center justify-center py-8">
        <div class="w-6 h-6 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
        <p class="mt-2 text-sm text-muted-foreground">Loading sources...</p>
      </div>
    {:else}
      <!-- Internet Scanners -->
      <div class="pb-4 border-b border-dashed border-border">
        <h4 class="text-sm font-medium text-foreground mb-2">Internet Scanners</h4>
        <p class="text-xs text-muted-foreground mb-3">Block known scanning services like Censys, Shodan</p>
        <div class="flex flex-wrap gap-2">
          {#each blocklists.filter(b => b.id === 'censys' || b.id === 'shodan') as source}
            <Button
              onclick={() => importBlocklist(source.id)}
              variant="outline"
              size="sm"
              disabled={importingSource === source.id}
            >
              {#if importingSource === source.id}
                <div class="w-3 h-3 border-2 border-muted border-t-primary rounded-full animate-spin mr-1"></div>
              {/if}
              {source.name}
              <span class="text-xs text-muted-foreground ml-1">(~{source.count})</span>
            </Button>
          {/each}
        </div>
      </div>

      <!-- Threat Intelligence -->
      <div class="pb-4 border-b border-dashed border-border">
        <h4 class="text-sm font-medium text-foreground mb-2">Threat Intelligence</h4>
        <p class="text-xs text-muted-foreground mb-3">IP addresses flagged as malicious by multiple sources</p>
        <div class="flex flex-wrap gap-2">
          {#each blocklists.filter(b => b.id.startsWith('ipsum') || b.id.startsWith('firehol')) as source}
            <Button
              onclick={() => importBlocklist(source.id)}
              variant="outline"
              size="sm"
              disabled={importingSource === source.id}
            >
              {#if importingSource === source.id}
                <div class="w-3 h-3 border-2 border-muted border-t-primary rounded-full animate-spin mr-1"></div>
              {/if}
              {source.name}
              <span class="text-xs text-muted-foreground ml-1">(~{source.count?.toLocaleString()})</span>
            </Button>
          {/each}
        </div>
      </div>

      <!-- Custom URL -->
      <div>
        <h4 class="text-sm font-medium text-foreground mb-2">Custom URL</h4>
        <p class="text-xs text-muted-foreground mb-3">Import from any IP/CIDR list URL</p>
        <Input
          bind:value={customURL}
          placeholder="https://example.com/blocklist.txt"
          prefixIcon="link"
          suffixAddonBtn={{
            icon: "download",
            label: importingSource === 'custom' ? 'Importing...' : 'Import',
            onclick: () => importBlocklist('custom'),
            disabled: !customURL || importingSource === 'custom',
            loading: importingSource === 'custom'
          }}
          onkeydown={(e) => e.key === 'Enter' && customURL && importBlocklist('custom')}
        />
        <p class="text-xs text-muted-foreground mt-2">Supports: plain IP lists, CIDR notation, ipsum format, FireHOL netset</p>
      </div>
    {/if}
  </div>

  {#snippet footer()}
    <Button onclick={() => showImportModal = false} variant="secondary">Close</Button>
  {/snippet}
</Modal>

<!-- Block Countries Modal -->
<Modal bind:open={showBlockCountriesModal} title="Block Countries" size="lg">
  <div class="space-y-4">
    <!-- Search and actions -->
    <div class="flex flex-wrap items-center gap-3">
      <Input
        type="search"
        bind:value={countrySearch}
        placeholder="Search countries..."
        prefixIcon="search"
        class="w-48"
      />
      <div class="flex items-center gap-2">
        <button
          onclick={selectAllFilteredCountries}
          class="text-xs text-primary hover:text-primary/80 font-medium"
        >
          Select all{countrySearch ? ' filtered' : ''}
        </button>
        {#if selectedCountries.length > 0}
          <span class="text-dim">|</span>
          <button
            onclick={clearCountrySelection}
            class="text-xs text-muted-foreground hover:text-foreground"
          >
            Clear selection
          </button>
        {/if}
      </div>
      <div class="ml-auto text-sm text-muted-foreground">
        {unblockedCountries.length} available
      </div>
    </div>

    <!-- Countries grouped by continent -->
    <div class="max-h-96 overflow-y-auto border border-border rounded-lg">
      {#if sortedContinents.length > 0}
        <div class="divide-y divide-border">
          {#each sortedContinents as continent}
            <div class="bg-card">
              <!-- Continent header -->
              <button
                onclick={() => toggleContinentSelection(continent)}
                class="w-full flex items-center gap-3 px-3 py-2 bg-muted hover:bg-muted/80 transition-colors sticky top-0 z-10"
              >
                <Checkbox
                  checked={isContinentFullySelected(continent)}
                  indeterminate={isContinentPartiallySelected(continent)}
                  class="pointer-events-none"
                  tabindex="-1"
                />
                <span class="font-medium text-sm text-foreground">{continent}</span>
                <span class="text-xs text-muted-foreground">
                  ({countriesByContinent[continent]?.length || 0} countries)
                </span>
              </button>
              <!-- Countries in continent -->
              <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1 p-2">
                {#each countriesByContinent[continent] || [] as country}
                  <Checkbox
                    checked={selectedCountries.includes(country.code)}
                    onchange={() => toggleCountrySelection(country.code)}
                    class="px-2 py-1.5 rounded-md hover:bg-muted transition-colors {selectedCountries.includes(country.code) ? 'bg-primary/10' : ''}"
                  >
                    <img
                      use:lazyLoad={"https://flagcdn.com/" + country.code.toLowerCase() + ".svg"}
                      width="16"
                      alt={country.code}
                      class="rounded-sm"
                    />
                    <span class="text-xs text-foreground truncate">{country.name}</span>
                  </Checkbox>
                {/each}
              </div>
            </div>
          {/each}
        </div>
      {:else if countrySearch}
        <div class="text-center py-8 text-sm text-muted-foreground">
          No countries match "{countrySearch}"
        </div>
      {:else}
        <div class="text-center py-8 text-sm text-muted-foreground">
          <Icon name="circle-check" size={24} class="mx-auto text-success mb-2" />
          All available countries are blocked
        </div>
      {/if}
    </div>
  </div>

  {#snippet footer()}
    <Button onclick={() => { showBlockCountriesModal = false; selectedCountries = []; countrySearch = '' }} variant="secondary">
      Cancel
    </Button>
    <Button
      onclick={blockSelectedCountries}
      icon="ban"
      disabled={selectedCountries.length === 0 || blockingCountries}
    >
      {#if blockingCountries}
        <div class="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin mr-1"></div>
        Blocking...
      {:else}
        Block {selectedCountries.length > 0 ? `${selectedCountries.length} Countries` : 'Countries'}
      {/if}
    </Button>
  {/snippet}
</Modal>

