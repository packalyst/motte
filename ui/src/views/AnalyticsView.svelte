<script>
  import { onMount } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Select from '../components/Select.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import Sparkline from '../components/Sparkline.svelte'
  import AreaChart from '../components/AreaChart.svelte'
  import BarList from '../components/BarList.svelte'

  let { loading = $bindable(true) } = $props()

  let selectedType = $state(null)
  let period = $state('day')

  let data = $state({
    inbound: null,
    dns: null,
    outbound: null,
    fw: null,
  })

  const typeMeta = {
    inbound:  { label: 'Inbound',  icon: 'arrow-down-right', accent: 'text-sky-600',     dot: 'bg-sky-500',     ring: 'ring-sky-500/20' },
    dns:      { label: 'DNS',      icon: 'world-www',        accent: 'text-emerald-600', dot: 'bg-emerald-500', ring: 'ring-emerald-500/20' },
    outbound: { label: 'Outbound', icon: 'arrow-up-right',   accent: 'text-violet-600',  dot: 'bg-violet-500',  ring: 'ring-violet-500/20' },
    fw:       { label: 'Firewall', icon: 'shield',           accent: 'text-rose-600',    dot: 'bg-rose-500',    ring: 'ring-rose-500/20' },
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
    period
    loadAll()
  })

  onMount(loadAll)

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

  function flag(cc) {
    if (!cc || cc.length !== 2) return ''
    return String.fromCodePoint(...cc.toUpperCase().split('').map(c => 0x1f1a5 + c.charCodeAt(0)))
  }

  // Enrich country rows with a flag emoji for BarList prefixKey
  function withFlags(arr) {
    if (!arr) return []
    return arr.map(r => ({ ...r, _flag: flag(r.country) }))
  }

  // Enrich source-IP rows: prefix flag + label = country/ip
  function ipRows(arr) {
    if (!arr) return []
    return arr.map(r => ({ ...r, _flag: flag(r.country), _label: r.ip }))
  }

  const httpColor = {
    '2xx': 'bg-emerald-500',
    '3xx': 'bg-sky-500',
    '4xx': 'bg-amber-500',
    '5xx': 'bg-rose-500',
    'other': 'bg-gray-500',
  }
  function httpColorFor(row) {
    return httpColor[row.status] || 'bg-primary'
  }
</script>

<div class="p-4 sm:p-6 space-y-4 sm:space-y-6 max-w-7xl mx-auto">

  <!-- ═════════ HEADER ═════════ -->
  <div class="flex items-center justify-between gap-3 flex-wrap">
    <div class="flex items-center gap-3 min-w-0">
      {#if selectedType}
        <Button size="sm" variant="ghost" onclick={() => selectedType = null}>
          <Icon name="arrow-left" size={16} />
          <span class="ml-1">Back</span>
        </Button>
        <span class="w-1 h-6 rounded {typeMeta[selectedType].dot}"></span>
        <div class="min-w-0">
          <h1 class="text-xl font-semibold truncate {typeMeta[selectedType].accent}">
            {typeMeta[selectedType].label}
          </h1>
        </div>
      {:else}
        <div class="p-2 rounded-lg bg-primary/10">
          <Icon name="chart-bar" size={20} class_="text-primary" />
        </div>
        <div>
          <h1 class="text-xl font-semibold">Analytics</h1>
          <p class="text-xs text-muted-foreground">Traffic overview across all log sources</p>
        </div>
      {/if}
    </div>

    <div class="flex items-center gap-2">
      <Select bind:value={period} class="w-36">
        <option value="hour">Last hour</option>
        <option value="day">Last 24 hours</option>
        <option value="week">Last 7 days</option>
      </Select>
      <Button size="sm" variant="ghost" onclick={loadAll} title="Refresh">
        <Icon name="refresh" size={16} />
      </Button>
    </div>
  </div>

  {#if loading}
    <div class="flex justify-center py-12">
      <LoadingSpinner />
    </div>
  {:else if !selectedType}
    <!-- ═════════ OVERVIEW ═════════ -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
      {#each Object.entries(typeMeta) as [type, meta]}
        {@const d = data[type]}
        {@const tr = d && !d.error ? trend(d.total_count, d.previous_total) : null}
        <button
          type="button"
          onclick={() => selectedType = type}
          class="group text-left rounded-xl border bg-card hover:ring-4 hover:{meta.ring} hover:border-primary/40 transition-all p-4 sm:p-5 flex flex-col gap-3"
        >
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full {meta.dot}"></span>
              <span class="font-medium text-sm">{meta.label}</span>
            </div>
            <Icon name="arrow-right" size={14} />
          </div>

          <div>
            <div class="text-3xl font-bold tabular-nums {meta.accent}">
              {d ? fmtNumber(d.total_count) : '—'}
            </div>
            {#if tr}
              <div class="flex items-center gap-1 text-xs mt-1 {tr.dir === 'up' ? 'text-emerald-600' : 'text-rose-600'}">
                <Icon name={tr.dir === 'up' ? 'trending-up' : 'trending-down'} size={12} />
                <span class="font-medium">{Math.abs(tr.pct).toFixed(1)}%</span>
                <span class="text-muted-foreground font-normal">vs previous</span>
              </div>
            {:else}
              <div class="text-xs text-muted-foreground mt-1">no previous data</div>
            {/if}
          </div>

          <!-- Mini sparkline -->
          {#if d?.time_series?.length > 1}
            <div class="{meta.accent} h-8 -mx-1">
              <Sparkline data={d.time_series} width={200} height={32} />
            </div>
          {/if}

          {#if d && !d.error && d.total_count > 0}
            <div class="pt-3 border-t border-border/50 grid grid-cols-2 gap-2 text-xs">
              {#if type === 'inbound'}
                <div><div class="text-muted-foreground">Visitors</div><div class="font-mono">{fmtNumber(d.unique_visitors)}</div></div>
                <div><div class="text-muted-foreground">Bytes</div><div class="font-mono">{fmtBytes(d.total_bytes)}</div></div>
              {:else if type === 'dns'}
                <div><div class="text-muted-foreground">Cached</div><div class="font-mono">{pct(d.cached_count, d.total_count)}%</div></div>
                <div><div class="text-muted-foreground">Blocked</div><div class="font-mono">{pct(d.blocked_count, d.total_count)}%</div></div>
              {:else if type === 'outbound'}
                <div><div class="text-muted-foreground">Dests</div><div class="font-mono">{fmtNumber(d.top_dest_ips?.length || 0)}</div></div>
                <div><div class="text-muted-foreground">Bytes</div><div class="font-mono">{fmtBytes(d.total_bytes)}</div></div>
              {:else if type === 'fw'}
                <div><div class="text-muted-foreground">Attackers</div><div class="font-mono">{fmtNumber(d.unique_visitors)}</div></div>
                <div><div class="text-muted-foreground">Top port</div><div class="font-mono">{d.top_dest_ports?.[0]?.status || '—'}</div></div>
              {/if}
            </div>
          {/if}
        </button>
      {/each}
    </div>

    <!-- All-empty hint -->
    {#if Object.values(data).every(d => !d || d.error || d.total_count === 0)}
      <EmptyState
        icon="chart-bar"
        title="No log data in this period"
        description="Check that log watchers are enabled in Settings, and that Traefik/AdGuard are producing log output."
      />
    {/if}

  {:else}
    <!-- ═════════ DRILL-IN ═════════ -->
    {@const d = data[selectedType]}
    {@const tr = d && !d.error ? trend(d.total_count, d.previous_total) : null}

    {#if !d}
      <div class="flex justify-center py-12"><LoadingSpinner /></div>
    {:else if d.error}
      <div class="rounded-xl border border-rose-500/30 bg-rose-500/5 p-4 text-sm text-rose-600">
        {d.error}
      </div>
    {:else if d.total_count === 0}
      <EmptyState
        icon="inbox"
        title="No {typeMeta[selectedType].label.toLowerCase()} events yet"
        description={selectedType === 'inbound' ? 'Traefik hasn\'t logged requests to any user domain or catchall route yet.' :
                     selectedType === 'outbound' ? 'The outbound watcher hasn\'t observed any peer traffic. Enable it in Settings if disabled.' :
                     selectedType === 'fw' ? 'No firewall drops in this period. That\'s a good thing.' :
                     'AdGuard hasn\'t logged any queries. Check that DNS is being routed through it.'}
      />
    {:else}

      <!-- KPI row -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div class="rounded-xl border bg-card p-4">
          <div class="text-xs text-muted-foreground">Total events</div>
          <div class="text-2xl font-bold tabular-nums mt-1">{fmtNumber(d.total_count)}</div>
          {#if tr}
            <div class="text-xs mt-1 flex items-center gap-1 {tr.dir === 'up' ? 'text-emerald-600' : 'text-rose-600'}">
              <Icon name={tr.dir === 'up' ? 'trending-up' : 'trending-down'} size={12} />
              {Math.abs(tr.pct).toFixed(1)}% vs prev
            </div>
          {/if}
        </div>
        <div class="rounded-xl border bg-card p-4">
          <div class="text-xs text-muted-foreground">Unique {selectedType === 'fw' ? 'attackers' : 'sources'}</div>
          <div class="text-2xl font-bold tabular-nums mt-1">{fmtNumber(d.unique_visitors)}</div>
        </div>
        <div class="rounded-xl border bg-card p-4">
          <div class="text-xs text-muted-foreground">Bandwidth</div>
          <div class="text-2xl font-bold tabular-nums mt-1">{fmtBytes(d.total_bytes)}</div>
        </div>
        <div class="rounded-xl border bg-card p-4">
          <div class="text-xs text-muted-foreground">
            {selectedType === 'dns' ? 'Cache rate' : selectedType === 'inbound' ? 'Success rate' : selectedType === 'fw' ? 'Rules fired' : 'Countries'}
          </div>
          <div class="text-2xl font-bold tabular-nums mt-1">
            {#if selectedType === 'dns'}
              {pct(d.cached_count, d.total_count)}%
            {:else if selectedType === 'inbound'}
              {pct((d.http_status?.find(s => s.status === '2xx')?.count || 0), (d.http_status?.reduce((s,x)=>s+x.count,0) || 1))}%
            {:else if selectedType === 'fw'}
              {d.top_rules?.length || 0}
            {:else}
              {d.top_countries?.length || 0}
            {/if}
          </div>
        </div>
      </div>

      <!-- Time series -->
      {#if d.time_series?.length}
        <div class="rounded-xl border bg-card p-4 sm:p-5">
          <div class="flex items-center justify-between mb-3">
            <div class="text-sm font-semibold">Events over time</div>
            <Badge variant="muted" size="sm">{period}</Badge>
          </div>
          <div class="{typeMeta[selectedType].accent}">
            <AreaChart data={d.time_series} valueKey="count" labelKey="time" height={200} />
          </div>
        </div>
      {/if}

      <!-- Widgets grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3 sm:gap-4">

        <!-- Top countries -->
        {#if d.top_countries?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">
              Top countries {selectedType === 'outbound' ? '(destination)' : ''}
            </div>
            <BarList
              data={withFlags(d.top_countries)}
              labelKey="country"
              prefixKey="_flag"
              barClass={typeMeta[selectedType].dot}
              format={fmtNumber}
              labelWidth="w-10"
            />
          </div>
        {/if}

        <!-- Type-specific: status/protocol/ports -->
        {#if selectedType === 'inbound' && d.http_status?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">HTTP status</div>
            <BarList data={d.http_status} labelKey="status" colorFor={httpColorFor} percent labelWidth="w-12" />
          </div>
        {:else if selectedType === 'dns' && d.status_counts?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">DNS response codes</div>
            <BarList data={d.status_counts} labelKey="status" barClass="bg-emerald-500" percent labelWidth="w-28" />
          </div>
        {:else if selectedType === 'outbound' && d.protocols?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">Protocols</div>
            <BarList data={d.protocols} labelKey="status" barClass="bg-violet-500" percent labelWidth="w-16" />
          </div>
        {:else if selectedType === 'fw' && d.top_dest_ports?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">Top probed ports</div>
            <BarList data={d.top_dest_ports} labelKey="status" barClass="bg-rose-500" format={fmtNumber} labelWidth="w-14" />
          </div>
        {/if}

        <!-- Top source IPs -->
        {#if d.top_clients?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">Top source IPs</div>
            <BarList
              data={ipRows(d.top_clients)}
              labelKey="_label"
              prefixKey="_flag"
              barClass={typeMeta[selectedType].dot}
              format={fmtNumber}
              labelWidth="w-32"
            />
          </div>
        {/if}

        <!-- Secondary widget -->
        {#if selectedType === 'inbound' && d.top_domains?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">Top domains</div>
            <BarList data={d.top_domains} labelKey="domain" barClass="bg-sky-500" format={fmtNumber} labelWidth="w-40" />
          </div>
        {:else if selectedType === 'inbound' && d.top_paths?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">Top paths</div>
            <BarList data={d.top_paths} labelKey="path" barClass="bg-sky-500" format={fmtNumber} labelWidth="w-40" />
          </div>
        {:else if selectedType === 'dns' && d.top_blocked?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">Top blocked domains</div>
            <BarList data={d.top_blocked} labelKey="domain" barClass="bg-rose-500" format={fmtNumber} labelWidth="w-40" />
          </div>
        {:else if selectedType === 'dns' && d.query_types?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">Query types</div>
            <BarList data={d.query_types} labelKey="status" barClass="bg-emerald-500" percent labelWidth="w-16" />
          </div>
        {:else if selectedType === 'outbound' && d.top_dest_ips?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">Top destinations</div>
            <BarList
              data={ipRows(d.top_dest_ips)}
              labelKey="_label"
              prefixKey="_flag"
              barClass="bg-violet-500"
              format={fmtNumber}
              labelWidth="w-32"
            />
          </div>
        {:else if selectedType === 'fw' && d.top_rules?.length}
          <div class="rounded-xl border bg-card p-4 sm:p-5">
            <div class="text-sm font-semibold mb-4">Top firewall rules</div>
            <BarList data={d.top_rules} labelKey="status" barClass="bg-rose-500" format={fmtNumber} labelWidth="w-40" />
          </div>
        {/if}
      </div>
    {/if}
  {/if}
</div>
