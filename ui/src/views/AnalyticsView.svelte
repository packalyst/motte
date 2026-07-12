<script>
  import { onMount } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import { usePersistentState } from '$lib/composables/index.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Select from '../components/Select.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import StatCard from '../components/StatCard.svelte'
  import CountryFlag from '../components/CountryFlag.svelte'
  import Sparkline from '../components/Sparkline.svelte'
  import AreaChart from '../components/AreaChart.svelte'
  import BarList from '../components/BarList.svelte'

  let { loading = $bindable(true) } = $props()

  // Persist selectedType + period across refresh / navigation
  const persisted = usePersistentState('analytics_ui', {
    selectedType: null,
    period: 'day',
  })

  // Bindable proxies over the persistent store
  let selectedType = $derived(persisted.value.selectedType)
  let period = $derived(persisted.value.period)

  function setType(t) {
    persisted.value = { ...persisted.value, selectedType: t }
    // Push a history entry when drilling in, so the browser Back button
    // returns to the overview instead of leaving the Analytics page.
    if (typeof window !== 'undefined') {
      if (t) {
        history.pushState({ analyticsType: t }, '', window.location.href)
      } else if (history.state?.analyticsType) {
        history.back()
      }
    }
  }
  function setPeriod(p) {
    persisted.value = { ...persisted.value, period: p }
  }

  // Browser Back button: pop out of drill-in → overview.
  onMount(() => {
    function onPop(e) {
      const t = e.state?.analyticsType ?? null
      if (t !== persisted.value.selectedType) {
        persisted.value = { ...persisted.value, selectedType: t }
      }
    }
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  })

  let data = $state({
    inbound: null,
    dns: null,
    outbound: null,
    fw: null,
  })

  // Semantic app colors + verified tabler icons (all present in existing views)
  const typeMeta = {
    inbound:  { label: 'Inbound',  icon: 'arrow-down', color: 'primary',     bar: 'bg-primary',     text: 'text-primary',     border: 'border-primary/30',     bg: 'bg-primary/10' },
    dns:      { label: 'DNS',      icon: 'globe',      color: 'success',     bar: 'bg-success',     text: 'text-success',     border: 'border-success/30',     bg: 'bg-success/10' },
    outbound: { label: 'Outbound', icon: 'arrow-up',   color: 'info',        bar: 'bg-info',        text: 'text-info',        border: 'border-info/30',        bg: 'bg-info/10' },
    fw:       { label: 'Firewall', icon: 'shield',     color: 'destructive', bar: 'bg-destructive', text: 'text-destructive', border: 'border-destructive/30', bg: 'bg-destructive/10' },
  }

  async function loadType(type) {
    try {
      const res = await apiGet(`/api/logs/stats?type=${type}&period=${period}`)
      data[type] = res
    } catch (e) {
      data[type] = { error: e.message }
    }
  }

  async function loadAll() {
    loading = true
    await Promise.all(Object.keys(typeMeta).map(loadType))
    loading = false
  }

  $effect(() => {
    period                        // dep
    loadAll()
  })

  onMount(loadAll)

  // ── Per-node outbound breakdown (conntrack byte accounting) ──
  let peerList = $state([])
  let selectedPeer = $state('')
  let peerUsage = $state(null)
  let peerUsageLoading = $state(false)

  async function loadPeers() {
    try {
      const clients = await apiGet('/api/vpn/clients')
      peerList = (Array.isArray(clients) ? clients : [])
        .filter(c => c.ip)
        .map(c => ({ value: c.ip, label: `${c.name || c.ip} (${c.ip})` }))
    } catch { peerList = [] }
  }
  onMount(loadPeers)

  async function loadPeerUsage() {
    if (!selectedPeer) { peerUsage = null; return }
    peerUsageLoading = true
    try {
      peerUsage = await apiGet(`/api/logs/peer-usage?peer=${encodeURIComponent(selectedPeer)}&period=${period}`)
    } catch (e) {
      peerUsage = { destinations: [], series: [], error: e.message }
    } finally {
      peerUsageLoading = false
    }
  }

  // Reload the per-node breakdown when the node or period changes.
  $effect(() => {
    selectedPeer; period
    if (selectedType === 'outbound' && selectedPeer) loadPeerUsage()
  })

  function trend(cur, prev) {
    if (!prev || prev === 0) return null
    const p = ((cur - prev) / prev) * 100
    return { pct: p, dir: p >= 0 ? 'up' : 'down' }
  }

  function fmtNumber(n) {
    if (n == null) return '—'
    if (n < 1000) return n.toString()
    if (n < 1_000_000) return (n / 1000).toFixed(1) + 'K'
    return (n / 1_000_000).toFixed(1) + 'M'
  }

  function fmtBytes(b) {
    if (!b) return '0 B'
    const units = ['B', 'KB', 'MB', 'GB', 'TB']
    let i = 0
    while (b >= 1024 && i < units.length - 1) { b /= 1024; i++ }
    return b.toFixed(i === 0 ? 0 : 1) + ' ' + units[i]
  }

  function pct(part, total) {
    if (!total) return 0
    return Math.round((part / total) * 100)
  }

  function maxOf(arr, key = 'count') {
    return arr && arr.length ? Math.max(...arr.map(x => x[key] || 0)) : 1
  }

  const httpColor = {
    '2xx': 'bg-success',
    '3xx': 'bg-primary',
    '4xx': 'bg-warning',
    '5xx': 'bg-destructive',
    'other': 'bg-muted-foreground',
  }
  function httpColorFor(row) {
    return httpColor[row.status] || 'bg-primary'
  }

  const infoTitle = $derived(selectedType ? typeMeta[selectedType].label : 'Analytics')
  const infoDesc = $derived(selectedType
    ? {
        inbound:  'Traefik-observed HTTP requests to your domain routes and catchall.',
        dns:      'AdGuard DNS queries from clients connected to your VPN.',
        outbound: 'Outbound connections VPN peers made to the internet.',
        fw:       'Firewall drops — attempted connections that did not pass any rule.',
      }[selectedType]
    : 'Traffic overview across all log sources — inbound, DNS, outbound, firewall.')
</script>

<div class="space-y-4">
  <InfoCard
    icon={selectedType ? typeMeta[selectedType].icon : 'chart-bar'}
    title={infoTitle}
    description={infoDesc}
  />

  <div class="kt-panel">
    <div class="kt-panel-header flex-col sm:flex-row gap-2">
      <div class="contents sm:flex sm:items-center sm:gap-2">
        {#if selectedType}
          <Button variant="outline" size="sm" icon="arrow-left" onclick={() => setType(null)}>
            Back
          </Button>
        {/if}
        <Select value={period} onchange={(e) => setPeriod(e.target.value)} class="flex-1 sm:flex-none sm:w-40">
          <option value="hour">Last hour</option>
          <option value="day">Last 24 hours</option>
          <option value="week">Last 7 days</option>
        </Select>
      </div>
      <div class="w-full border-t border-border sm:hidden"></div>
      <div class="kt-btn-group self-end sm:self-auto">
        <Button variant="outline" size="sm" icon="refresh" onclick={loadAll}>
          Refresh
        </Button>
      </div>
    </div>

    <div class="p-4 space-y-4">
      {#if loading}
        <div class="flex justify-center py-12">
          <LoadingSpinner />
        </div>
      {:else if !selectedType}
        <!-- ═════════ OVERVIEW ═════════ -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {#each Object.entries(typeMeta) as [type, meta]}
            {@const d = data[type]}
            {@const tr = d && !d.error ? trend(d.total_count, d.previous_total) : null}
            <button
              type="button"
              onclick={() => setType(type)}
              class="group flex cursor-pointer flex-col rounded-lg border shadow-sm transition hover:shadow-md bg-card text-left {d && d.total_count > 0 ? meta.border : 'border-border'}"
            >
              <div class="flex items-center gap-2.5 p-3">
                <div class="flex h-9 w-9 items-center justify-center rounded-lg shrink-0 {meta.bg} {meta.text}">
                  <Icon name={meta.icon} size={18} />
                </div>
                <div class="flex-1 min-w-0">
                  <h2 class="text-sm font-semibold text-foreground">{meta.label}</h2>
                  <p class="text-[11px] text-muted-foreground truncate">
                    {d && d.total_count > 0 ? 'Click for details' : 'no events'}
                  </p>
                </div>
                <Icon name="chevron-right" size={14} class="text-muted-foreground shrink-0" />
              </div>

              <div class="px-3 pb-1">
                <div class="text-3xl font-bold tabular-nums {meta.text}">
                  {d ? fmtNumber(d.total_count) : '—'}
                </div>
                {#if tr}
                  <div class="flex items-center gap-1 text-[11px] mt-0.5 {tr.dir === 'up' ? 'text-success' : 'text-destructive'}">
                    <Icon name={tr.dir === 'up' ? 'arrow-up' : 'arrow-down'} size={11} />
                    <span class="font-medium">{Math.abs(tr.pct).toFixed(1)}%</span>
                    <span class="text-muted-foreground font-normal">vs previous</span>
                  </div>
                {:else}
                  <div class="text-[11px] text-muted-foreground mt-0.5">no previous data</div>
                {/if}
              </div>

              {#if d?.time_series?.length > 1}
                <div class="{meta.text} h-8 px-3">
                  <Sparkline data={d.time_series} width={220} height={32} />
                </div>
              {/if}

              {#if d && !d.error && d.total_count > 0}
                <div class="mt-2 border-t border-border p-3 flex items-center justify-between gap-3 text-[11px]">
                  {#if type === 'inbound'}
                    <div class="flex items-center gap-1.5 min-w-0">
                      <Icon name="user" size={13} class="shrink-0 text-muted-foreground" />
                      <div class="min-w-0">
                        <div class="font-semibold tabular-nums text-foreground">{fmtNumber(d.unique_visitors)}</div>
                        <div class="text-muted-foreground text-[10px]">visitors</div>
                      </div>
                    </div>
                    <div class="flex items-center gap-1.5 min-w-0">
                      <Icon name="activity" size={13} class="shrink-0 text-muted-foreground" />
                      <div class="min-w-0">
                        <div class="font-semibold tabular-nums text-foreground">{fmtBytes(d.total_bytes)}</div>
                        <div class="text-muted-foreground text-[10px]">bandwidth</div>
                      </div>
                    </div>
                  {:else if type === 'dns'}
                    <div class="flex items-center gap-1.5 min-w-0">
                      <Icon name="check" size={13} class="shrink-0 text-success" />
                      <div class="min-w-0">
                        <div class="font-semibold tabular-nums text-foreground">{pct(d.cached_count, d.total_count)}%</div>
                        <div class="text-muted-foreground text-[10px]">cached</div>
                      </div>
                    </div>
                    <div class="flex items-center gap-1.5 min-w-0">
                      <Icon name="ban" size={13} class="shrink-0 text-destructive" />
                      <div class="min-w-0">
                        <div class="font-semibold tabular-nums text-foreground">{pct(d.blocked_count, d.total_count)}%</div>
                        <div class="text-muted-foreground text-[10px]">blocked</div>
                      </div>
                    </div>
                  {:else if type === 'outbound'}
                    <div class="flex items-center gap-1.5 min-w-0">
                      <Icon name="globe" size={13} class="shrink-0 text-muted-foreground" />
                      <div class="min-w-0">
                        <div class="font-semibold tabular-nums text-foreground">{fmtNumber(d.top_dest_ips?.length || 0)}</div>
                        <div class="text-muted-foreground text-[10px]">destinations</div>
                      </div>
                    </div>
                    <div class="flex items-center gap-1.5 min-w-0">
                      <Icon name="activity" size={13} class="shrink-0 text-muted-foreground" />
                      <div class="min-w-0">
                        <div class="font-semibold tabular-nums text-foreground">{fmtBytes(d.total_bytes)}</div>
                        <div class="text-muted-foreground text-[10px]">bandwidth</div>
                      </div>
                    </div>
                  {:else if type === 'fw'}
                    <div class="flex items-center gap-1.5 min-w-0">
                      <Icon name="alert-triangle" size={13} class="shrink-0 text-destructive" />
                      <div class="min-w-0">
                        <div class="font-semibold tabular-nums text-foreground">{fmtNumber(d.unique_visitors)}</div>
                        <div class="text-muted-foreground text-[10px]">attackers</div>
                      </div>
                    </div>
                    <div class="flex items-center gap-1.5 min-w-0">
                      <Icon name="plug" size={13} class="shrink-0 text-muted-foreground" />
                      <div class="min-w-0">
                        <div class="font-semibold tabular-nums text-foreground">:{d.top_dest_ports?.[0]?.status || '—'}</div>
                        <div class="text-muted-foreground text-[10px]">top port</div>
                      </div>
                    </div>
                  {/if}
                </div>
              {/if}
            </button>
          {/each}
        </div>

        {#if Object.values(data).every(d => !d || d.error || d.total_count === 0)}
          <EmptyState
            icon="chart-bar"
            title="No log data in this period"
            description="Check that log watchers are enabled and that Traefik/AdGuard are producing log output."
          />
        {/if}

      {:else}
        <!-- ═════════ DRILL-IN ═════════ -->
        {@const d = data[selectedType]}
        {@const tr = d && !d.error ? trend(d.total_count, d.previous_total) : null}
        {@const maxCountry = d?.top_countries ? maxOf(d.top_countries) : 1}
        {@const maxClient = d?.top_clients ? maxOf(d.top_clients) : 1}
        {@const maxDest = d?.top_dest_ips ? maxOf(d.top_dest_ips) : 1}

        {#if !d}
          <div class="flex justify-center py-12"><LoadingSpinner /></div>
        {:else if d.error}
          <div class="rounded-lg border border-destructive/30 bg-destructive/5 p-4 text-sm text-destructive">
            {d.error}
          </div>
        {:else if d.total_count === 0}
          <EmptyState
            icon="inbox"
            title="No {typeMeta[selectedType].label.toLowerCase()} events yet"
            description={selectedType === 'inbound' ? 'Traefik has not logged requests to any user domain or catchall route yet.' :
                         selectedType === 'outbound' ? 'The outbound watcher has not observed any peer traffic.' :
                         selectedType === 'fw' ? 'No firewall drops in this period.' :
                         'AdGuard has not logged any queries.'}
          />
        {:else}

          <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <StatCard icon={typeMeta[selectedType].icon} color={typeMeta[selectedType].color} value={fmtNumber(d.total_count)} label="Total events" />
            <StatCard icon="user" color="info" value={fmtNumber(d.unique_visitors)} label={selectedType === 'fw' ? 'Unique attackers' : 'Unique sources'} />
            <StatCard icon="activity" color="warning" value={fmtBytes(d.total_bytes)} label="Bandwidth" />
            {#if selectedType === 'dns'}
              <StatCard icon="check" color="success" value="{pct(d.cached_count, d.total_count)}%" label="Cache rate" />
            {:else if selectedType === 'inbound'}
              <StatCard icon="check" color="success" value="{pct((d.http_status?.find(s => s.status === '2xx')?.count || 0), (d.http_status?.reduce((s,x)=>s+x.count,0) || 1))}%" label="Success rate" />
            {:else if selectedType === 'fw'}
              <StatCard icon="filter" color="destructive" value={d.top_rules?.length || 0} label="Rules fired" />
            {:else}
              <StatCard icon="world" color="primary" value={d.top_countries?.length || 0} label="Countries" />
            {/if}
          </div>

          {#if tr}
            <div class="flex items-center gap-1 text-xs {tr.dir === 'up' ? 'text-success' : 'text-destructive'}">
              <Icon name={tr.dir === 'up' ? 'arrow-up' : 'arrow-down'} size={14} />
              <span class="font-medium">{Math.abs(tr.pct).toFixed(1)}%</span>
              <span class="text-muted-foreground">vs previous {period}</span>
            </div>
          {/if}

          {#if d.time_series?.length}
            <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
              <div class="flex items-center justify-between mb-3">
                <div class="text-sm font-semibold">Events over time</div>
                <Badge variant="muted" size="sm">{period}</Badge>
              </div>
              <div class={typeMeta[selectedType].text}>
                <AreaChart data={d.time_series} valueKey="count" labelKey="time" height={160} />
              </div>
            </div>
          {/if}

          {#if selectedType === 'outbound'}
            <!-- Per-node traffic breakdown (bytes, from conntrack) -->
            <div class="bg-card border border-border rounded-lg p-4 shadow-sm space-y-3">
              <div class="flex items-center justify-between gap-2 flex-wrap">
                <div class="text-sm font-semibold">Per-node traffic (bytes)</div>
                <Select value={selectedPeer} onchange={(e) => selectedPeer = e.target.value} class="w-full sm:w-64">
                  <option value="">Select a node…</option>
                  {#each peerList as p}<option value={p.value}>{p.label}</option>{/each}
                </Select>
              </div>

              {#if peerUsageLoading}
                <div class="text-xs text-muted-foreground py-6 text-center">Loading…</div>
              {:else if !selectedPeer}
                <div class="text-xs text-muted-foreground py-4 text-center">Select a node to see where its traffic went, by bytes.</div>
              {:else if peerUsage}
                <div class="grid grid-cols-2 lg:grid-cols-3 gap-3">
                  <StatCard icon="upload" color="info" value={fmtBytes(peerUsage.total_up)} label="Uploaded" />
                  <StatCard icon="download" color="success" value={fmtBytes(peerUsage.total_down)} label="Downloaded" />
                  <StatCard icon="globe" color="primary" value={peerUsage.destinations?.length || 0} label="Destinations" />
                </div>

                {#if peerUsage.series?.length}
                  <div class="text-info">
                    <AreaChart data={peerUsage.series} valueKey="total" labelKey="time" height={160} format={fmtBytes} />
                  </div>
                {/if}

                {#if peerUsage.destinations?.length}
                  <div>
                    <div class="text-sm font-semibold mb-3">Top destinations</div>
                    <BarList
                      data={peerUsage.destinations.map(x => ({ ...x, _label: x.domain || x.dest_ip }))}
                      labelKey="_label"
                      valueKey="bytes_total"
                      format={fmtBytes}
                      labelWidth="w-44"
                      barClass="bg-info"
                    />
                  </div>
                {:else}
                  <div class="text-xs text-muted-foreground py-2">No per-destination data for this node yet — enable the conntrack watcher in Settings → Logs Watchers.</div>
                {/if}
              {/if}
            </div>
          {/if}

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">

            <!-- Countries: use CountryFlag (real images) with inline bars -->
            {#if d.top_countries?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">
                  Top countries {selectedType === 'outbound' ? '(destination)' : ''}
                </div>
                <div class="space-y-2.5">
                  {#each d.top_countries as row}
                    <div class="flex items-center gap-3 text-sm">
                      <span class="shrink-0"><CountryFlag code={row.country} size="sm" /></span>
                      <span class="w-8 shrink-0 text-xs font-mono uppercase">{row.country || '—'}</span>
                      <div class="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                        <div class="h-full {typeMeta[selectedType].bar}" style="width: {(row.count / maxCountry) * 100}%"></div>
                      </div>
                      <span class="font-mono text-xs w-14 text-right tabular-nums">{fmtNumber(row.count)}</span>
                    </div>
                  {/each}
                </div>
              </div>
            {/if}

            {#if selectedType === 'inbound' && d.http_status?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">HTTP status</div>
                <BarList data={d.http_status} labelKey="status" colorFor={httpColorFor} percent labelWidth="w-12" />
              </div>
            {:else if selectedType === 'dns' && d.status_counts?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">DNS response codes</div>
                <BarList data={d.status_counts} labelKey="status" barClass="bg-success" percent labelWidth="w-28" />
              </div>
            {:else if selectedType === 'outbound' && d.protocols?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">Protocols</div>
                <BarList data={d.protocols} labelKey="status" barClass="bg-info" percent labelWidth="w-16" />
              </div>
            {:else if selectedType === 'fw' && d.top_dest_ports?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">Top probed ports</div>
                <BarList data={d.top_dest_ports} labelKey="status" barClass="bg-destructive" format={fmtNumber} labelWidth="w-14" />
              </div>
            {/if}

            <!-- Source IPs: real flag + IP + bar -->
            {#if d.top_clients?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">Top source IPs</div>
                <div class="space-y-2.5">
                  {#each d.top_clients as row}
                    <div class="flex items-center gap-3 text-sm">
                      <span class="shrink-0"><CountryFlag code={row.country} size="sm" /></span>
                      <span class="w-32 shrink-0 truncate text-xs font-mono">{row.ip}</span>
                      <div class="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                        <div class="h-full {typeMeta[selectedType].bar}" style="width: {(row.count / maxClient) * 100}%"></div>
                      </div>
                      <span class="font-mono text-xs w-14 text-right tabular-nums">{fmtNumber(row.count)}</span>
                    </div>
                  {/each}
                </div>
              </div>
            {/if}

            <!-- Inbound: show BOTH top domains and top paths as independent widgets -->
            {#if selectedType === 'inbound' && d.top_domains?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">Top domains</div>
                <BarList data={d.top_domains} labelKey="domain" barClass="bg-primary" format={fmtNumber} labelWidth="w-40" />
              </div>
            {/if}
            {#if selectedType === 'inbound' && d.top_paths?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">Top paths</div>
                <BarList
                  data={d.top_paths.map(p => ({ ...p, _label: (p.domain || '') + (p.path || '') }))}
                  labelKey="_label"
                  barClass="bg-primary"
                  format={fmtNumber}
                  labelWidth="w-64"
                />
              </div>
            {/if}
            {#if selectedType === 'dns' && d.top_blocked?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">Top blocked domains</div>
                <BarList data={d.top_blocked} labelKey="domain" barClass="bg-destructive" format={fmtNumber} labelWidth="w-40" />
              </div>
            {/if}
            {#if selectedType === 'dns' && d.query_types?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">Query types</div>
                <BarList data={d.query_types} labelKey="status" barClass="bg-success" percent labelWidth="w-16" />
              </div>
            {/if}
            {#if selectedType === 'outbound' && d.top_dest_ips?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">Top destinations</div>
                <div class="space-y-2.5">
                  {#each d.top_dest_ips as row}
                    <div class="flex items-center gap-3 text-sm">
                      <span class="shrink-0"><CountryFlag code={row.country} size="sm" /></span>
                      <span class="w-32 shrink-0 truncate text-xs font-mono">{row.ip}</span>
                      <div class="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                        <div class="h-full bg-info" style="width: {(row.count / maxDest) * 100}%"></div>
                      </div>
                      <span class="font-mono text-xs w-14 text-right tabular-nums">{fmtNumber(row.count)}</span>
                    </div>
                  {/each}
                </div>
              </div>
            {/if}
            {#if selectedType === 'fw' && d.top_rules?.length}
              <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
                <div class="text-sm font-semibold mb-4">Top firewall rules</div>
                <BarList data={d.top_rules} labelKey="status" barClass="bg-destructive" format={fmtNumber} labelWidth="w-40" />
              </div>
            {/if}
          </div>

          <!-- Sanity check: are we actually getting top_paths in the response? -->
          {#if selectedType === 'inbound' && d.top_paths?.length === 0}
            <div class="text-xs text-muted-foreground">
              No path data collected yet — check that the backend has been rebuilt with the extended handleGetStats.
            </div>
          {/if}
        {/if}
      {/if}
    </div>
  </div>
</div>
