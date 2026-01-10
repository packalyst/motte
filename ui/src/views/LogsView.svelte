<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet } from '../stores/app.js'
  import { lookupIPs } from '../stores/geo.js'
  import { createDebouncedSearch } from '../stores/helpers.js'
  import { usePaginatedState } from '$lib/composables/index.js'
  import { formatTime, formatRelativeDate } from '../lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Pagination from '../components/Pagination.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import Input from '../components/Input.svelte'
  import Select from '../components/Select.svelte'
  import Button from '../components/Button.svelte'
  import CountryFlag from '../components/CountryFlag.svelte'

  let { loading = $bindable(true) } = $props()

  // ============ Logs State ============
  let logs = $state([])
  let total = $state(0)
  let types = $state([])
  let statuses = $state([])
  let isLoading = $state(false)
  let geoData = $state({})

  // Pagination with persistent state
  const pagination = usePaginatedState('logs', { type: '', status: '' })

  let autoRefresh = $state(false)
  let refreshInterval = null
  let searchQuery = $state(pagination.search)

  // Debounced search
  const { search: debouncedSearch, cleanup: cleanupSearch } = createDebouncedSearch((value) => {
    pagination.setSearch(value)
    loadData()
  })

  function handleSearchInput(e) {
    searchQuery = e.target.value
    debouncedSearch(searchQuery)
  }

  async function loadData() {
    isLoading = true
    try {
      const params = new URLSearchParams({
        limit: pagination.perPage.toString(),
        offset: pagination.offset.toString()
      })
      if (pagination.search) params.set('search', pagination.search)
      if (pagination.filters.type) params.set('type', pagination.filters.type)
      if (pagination.filters.status) params.set('status', pagination.filters.status)

      const res = await apiGet(`/api/logs?${params}`)
      logs = res.logs || []
      total = res.total || 0
      types = res.types || []
      statuses = res.statuses || []

      // Enrich with geo data - only lookup relevant IPs per log type
      if (logs.length > 0) {
        const ips = logs.flatMap(l => {
          if (l.logs_type === 'inbound') return [l.logs_src_ip]
          return [l.logs_dest_ip] // dns, outbound: lookup dest IP
        }).filter(Boolean)
        geoData = await lookupIPs(ips)
      }
    } catch (e) {
      toast('Failed to load logs: ' + e.message, 'error')
    } finally {
      isLoading = false
      loading = false
    }
  }

  function toggleAutoRefresh() {
    autoRefresh = !autoRefresh
    if (autoRefresh) {
      refreshInterval = setInterval(loadData, 5000)
    } else {
      clearInterval(refreshInterval)
      refreshInterval = null
    }
  }

  function getTypeInfo(type) {
    switch (type) {
      case 'dns': return { icon: 'world-share', label: 'DNS', color: 'text-info' }
      case 'outbound': return { icon: 'arrow-up-right', label: 'Out', color: 'text-warning' }
      case 'inbound': return { icon: 'arrow-down-left', label: 'In', color: 'text-success' }
      case 'fw': return { icon: 'shield', label: 'FW', color: 'text-danger' }
      default: return { icon: 'question-mark', label: type, color: 'text-muted-foreground' }
    }
  }

  function getStatusInfo(status) {
    switch (status) {
      case 'allowed': return { label: 'Allowed', variant: 'success' }
      case 'blocked': return { label: 'Blocked', variant: 'danger' }
      case 'filtered': return { label: 'Filtered', variant: 'warning' }
      case 'rewritten': return { label: 'Rewritten', variant: 'info' }
      case 'cached': return { label: 'Cached', variant: 'muted' }
      default: return { label: status || '—', variant: 'secondary' }
    }
  }

  onMount(() => {
    loadData()
  })

  onDestroy(() => {
    if (refreshInterval) clearInterval(refreshInterval)
    cleanupSearch()
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="file-text"
    title="Logs"
    description="Unified view of DNS queries, VPN outbound traffic, and HTTP inbound requests."
  />

  <div class="kt-panel">
    <!-- Header -->
    <div class="kt-panel-header flex-col sm:flex-row gap-2">
      <div class="contents sm:flex sm:items-center sm:gap-2">
        <Input
          type="search"
          value={searchQuery}
          oninput={handleSearchInput}
          placeholder="Search domain or IP..."
          prefixIcon="search"
          class="w-full sm:w-64"
        />
        <div class="flex items-center gap-2 w-full sm:w-auto">
          <Select
            value={pagination.filters.type}
            onchange={(e) => { pagination.setFilter('type', e.target.value); loadData() }}
            class="flex-1 sm:flex-none sm:w-28"
          >
            <option value="">Type</option>
            {#each types as t}
              <option value={t.value}>{t.label}</option>
            {/each}
          </Select>
          <Select
            value={pagination.filters.status}
            onchange={(e) => { pagination.setFilter('status', e.target.value); loadData() }}
            class="flex-1 sm:flex-none sm:w-28"
          >
            <option value="">Status</option>
            {#each statuses as s}
              <option value={s.value}>{s.label}</option>
            {/each}
          </Select>
        </div>
      </div>
      <div class="w-full border-t border-border sm:hidden"></div>
      <div class="kt-btn-group self-end sm:self-auto">
        <Button
          variant={autoRefresh ? 'mono' : 'outline'}
          size="sm"
          icon={autoRefresh ? 'player-pause' : 'player-play'}
          onclick={toggleAutoRefresh}
        >
          {autoRefresh ? 'Pause' : 'Auto'}
        </Button>
        <Button variant="outline" size="sm" icon="refresh" onclick={loadData}>
          Refresh
        </Button>
      </div>
    </div>

    <!-- Content -->
    {#if isLoading && logs.length === 0}
      <div class="kt-panel-body flex items-center justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    {:else if logs.length === 0}
      <div class="kt-panel-body">
        <EmptyState
          icon="list-details"
          title="No logs yet"
          description={pagination.search || pagination.filters.type || pagination.filters.status ? 'No results match your filters' : 'Logs will appear as traffic flows through the system'}
        />
      </div>
    {:else}
      <div class="kt-panel-body">
        <div class="border border-border rounded-lg overflow-hidden">
          <div class="overflow-x-auto">
            <table class="data-table-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Type</th>
              <th>Source</th>
              <th>Domain / Dest</th>
              <th>Country</th>
              <th class="text-right">Status</th>
            </tr>
          </thead>
          <tbody>
            {#each logs as log}
              {@const typeInfo = getTypeInfo(log.logs_type)}
              {@const statusInfo = getStatusInfo(log.logs_status)}
              {@const srcGeo = geoData[log.logs_src_ip]}
              {@const destGeo = geoData[log.logs_dest_ip]}
              <tr class="even:bg-muted/50">
                <td class="data-table-cell-nowrap">
                  <div class="space-y-1">
                    <div class="flex items-center gap-2">
                      <Icon name="calendar" size={14} class="text-muted-foreground" />
                      <span class="text-xs font-medium">{formatRelativeDate(log.logs_timestamp)}</span>
                    </div>
                    <div class="border-t border-dashed border-border pt-1">
                      <div class="flex items-center gap-2">
                        <Icon name="clock" size={14} class="text-muted-foreground opacity-50" />
                        <span class="text-[10px] text-muted-foreground">{formatTime(log.logs_timestamp)}</span>
                      </div>
                    </div>
                  </div>
                </td>
                <td>
                  <div class="space-y-1">
                    <div class="flex items-center gap-2">
                      <Icon name={typeInfo.icon} size={14} class={typeInfo.color} />
                      <span class="text-xs font-medium {typeInfo.color}">{typeInfo.label}</span>
                    </div>
                    {#if log.logs_protocol || log.logs_query_type}
                      <div class="border-t border-dashed border-border pt-1">
                        <div class="flex items-center gap-2">
                          <Icon name="switch-horizontal" size={14} class="text-muted-foreground opacity-50" />
                          <span class="text-[10px] text-muted-foreground">{log.logs_protocol?.toUpperCase() || log.logs_query_type}</span>
                        </div>
                      </div>
                    {/if}
                  </div>
                </td>
                <td class="data-table-cell-mono">
                  {#if log.logs_src_client_name}
                    <div class="space-y-1">
                      <div class="flex items-center gap-2">
                        <Icon name="device-laptop" size={14} class="text-primary" />
                        <span class="text-xs font-medium">{log.logs_src_client_name}</span>
                      </div>
                      <div class="border-t border-dashed border-border pt-1">
                        <div class="flex items-center gap-2">
                          <Icon name="network" size={14} class="text-muted-foreground opacity-50" />
                          <span class="text-[10px] text-muted-foreground">{log.logs_src_ip}</span>
                        </div>
                      </div>
                    </div>
                  {:else}
                    <div class="flex items-center gap-2">
                      <Icon name="device-laptop" size={14} class="text-primary" />
                      <span class="text-xs">{log.logs_src_ip}</span>
                    </div>
                  {/if}
                </td>
                <td class="data-table-cell-mono">
                  {#if log.logs_domain}
                    <div class="space-y-1">
                      <div class="flex items-center gap-2">
                        <Icon name="world" size={14} class="text-muted-foreground" />
                        <span class="text-xs truncate max-w-[200px]" title={log.logs_domain}>{log.logs_domain}</span>
                      </div>
                      {#if log.logs_type === 'dns' && log.logs_dest_ip && log.logs_dest_ip !== '0.0.0.0'}
                        <div class="border-t border-dashed border-border pt-1">
                          <div class="flex items-center gap-2">
                            <Icon name="network" size={14} class="text-muted-foreground opacity-50" />
                            <span class="text-[10px] text-muted-foreground">{log.logs_dest_ip}</span>
                          </div>
                        </div>
                      {/if}
                    </div>
                  {:else if log.logs_dest_ip}
                    <div class="flex items-center gap-2">
                      <Icon name="server" size={14} class="text-muted-foreground" />
                      <span class="text-xs">{log.logs_dest_ip}{log.logs_dest_port ? `:${log.logs_dest_port}` : ''}</span>
                    </div>
                  {:else}
                    <span class="text-muted-foreground">—</span>
                  {/if}
                </td>
                <td>
                  {#if log.logs_type === 'outbound' || log.logs_type === 'dns'}
                    {@const geo = destGeo}
                    {@const country = geo?.country_code || log.logs_dest_country}
                    {#if country}
                      <div class="flex items-center gap-2">
                        <CountryFlag code={country} />
                        <div class="hidden sm:flex items-center gap-2">
                          <div class="border-l border-dashed border-border h-6"></div>
                          <div>
                            <div class="text-[11px] text-foreground">{geo?.country_name || country}</div>
                            {#if geo?.extra?.city || geo?.extra?.region}
                              <div class="text-[10px] text-muted-foreground">{geo?.extra?.city}{geo?.extra?.city && geo?.extra?.region ? ', ' : ''}{geo?.extra?.region}</div>
                            {/if}
                          </div>
                        </div>
                      </div>
                    {:else}
                      <span class="text-muted-foreground">—</span>
                    {/if}
                  {:else}
                    {@const geo = srcGeo}
                    {@const country = geo?.country_code || log.logs_src_country}
                    {#if country}
                      <div class="flex items-center gap-2">
                        <CountryFlag code={country} />
                        <div class="hidden sm:flex items-center gap-2">
                          <div class="border-l border-dashed border-border h-6"></div>
                          <div>
                            <div class="text-[11px] text-foreground">{geo?.country_name || country}</div>
                            {#if geo?.extra?.city || geo?.extra?.region}
                              <div class="text-[10px] text-muted-foreground">{geo?.extra?.city}{geo?.extra?.city && geo?.extra?.region ? ', ' : ''}{geo?.extra?.region}</div>
                            {/if}
                          </div>
                        </div>
                      </div>
                    {:else}
                      <span class="text-muted-foreground">—</span>
                    {/if}
                  {/if}
                </td>
                <td class="text-right">
                  {#if log.logs_status}
                    <Badge variant={statusInfo.variant} size="sm">{statusInfo.label}</Badge>
                  {:else}
                    <span class="text-muted-foreground">—</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Footer -->
      <div class="kt-panel-footer">
        <Pagination
          page={pagination.page}
          perPage={pagination.perPage}
          total={total}
          onPageChange={(p) => { pagination.setPage(p); loadData() }}
          onPerPageChange={(pp) => { pagination.setPerPage(pp); loadData() }}
        />
      </div>
    {/if}
  </div>
</div>
