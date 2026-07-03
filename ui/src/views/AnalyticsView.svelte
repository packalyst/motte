<script>
  import { onMount } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'

  let { loading = $bindable(true) } = $props()

  let selectedType = $state(null)  // null = overview, or 'inbound'|'dns'|'outbound'|'fw'
  let period = $state('day')

  let data = $state({
    inbound: null,
    dns: null,
    outbound: null,
    fw: null,
  })

  const typeMeta = {
    inbound:  { label: 'Inbound',  icon: 'arrow-down-right', accent: 'text-sky-600',    dot: 'bg-sky-500',    subtitle: 'Traefik requests to your domains' },
    dns:      { label: 'DNS',      icon: 'world-www',        accent: 'text-emerald-600',dot: 'bg-emerald-500',subtitle: 'AdGuard queries from clients' },
    outbound: { label: 'Outbound', icon: 'arrow-up-right',   accent: 'text-violet-600', dot: 'bg-violet-500', subtitle: 'Connections VPN peers made' },
    fw:       { label: 'Firewall', icon: 'shield',           accent: 'text-rose-600',   dot: 'bg-rose-500',   subtitle: 'Dropped connections' },
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

  function goBack() {
    selectedType = null
  }

  // Helpers
  function trend(cur, prev) {
    if (!prev || prev === 0) return null
    const pct = ((cur - prev) / prev) * 100
    return { pct, dir: pct >= 0 ? 'up' : 'down' }
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

  function maxOf(arr, key = 'count') {
    return arr && arr.length ? Math.max(...arr.map(x => x[key] || 0)) : 1
  }

  function totalOf(arr, key = 'count') {
    return arr && arr.length ? arr.reduce((s, x) => s + (x[key] || 0), 0) : 1
  }

  const statusColor = {
    '2xx': 'bg-emerald-500',
    '3xx': 'bg-sky-500',
    '4xx': 'bg-amber-500',
    '5xx': 'bg-rose-500',
    'other': 'bg-gray-500',
  }
</script>

<div class="p-6 max-w-7xl mx-auto space-y-6">
  <!-- ═════════ HEADER ═════════ -->
  <div class="flex items-center justify-between gap-4 flex-wrap">
    <div class="flex items-center gap-3">
      {#if selectedType}
        <button
          type="button"
          onclick={goBack}
          class="inline-flex items-center gap-1 px-3 py-1.5 rounded-md border hover:bg-muted transition-colors text-sm"
        >
          <Icon name="arrow-left" size={16} />
          <span>Back</span>
        </button>
        <span class="w-1.5 h-6 rounded {typeMeta[selectedType].dot}"></span>
        <h1 class="text-2xl font-semibold {typeMeta[selectedType].accent}">
          {typeMeta[selectedType].label}
        </h1>
      {:else}
        <h1 class="text-2xl font-semibold">Analytics</h1>
      {/if}
    </div>

    <div class="flex items-center gap-2">
      <select
        bind:value={period}
        class="border rounded-md px-3 py-1.5 bg-background text-sm"
      >
        <option value="hour">Last hour</option>
        <option value="day">Last 24 hours</option>
        <option value="week">Last 7 days</option>
      </select>
      <button
        type="button"
        onclick={loadAll}
        class="p-2 rounded-md border hover:bg-muted transition-colors"
        title="Refresh"
      >
        <Icon name="refresh" size={16} />
      </button>
    </div>
  </div>

  {#if !selectedType}
    <!-- ═════════ OVERVIEW ═════════ -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {#each Object.entries(typeMeta) as [type, meta]}
        {@const d = data[type]}
        {@const tr = d && !d.error ? trend(d.total_count, d.previous_total) : null}
        <button
          type="button"
          onclick={() => selectedType = type}
          class="group text-left rounded-xl border bg-card hover:shadow-md hover:border-primary/50 transition-all p-5 flex flex-col gap-4"
        >
          <!-- Header row -->
          <div class="flex items-start justify-between">
            <div class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full {meta.dot}"></span>
              <span class="font-medium text-sm">{meta.label}</span>
            </div>
            <Icon name="arrow-right" size={16} class_="text-muted-foreground group-hover:text-foreground transition-colors" />
          </div>

          <!-- Big number -->
          <div>
            <div class="text-4xl font-bold tabular-nums {meta.accent}">
              {d ? fmtNumber(d.total_count) : '—'}
            </div>
            <div class="text-xs text-muted-foreground mt-1">{meta.subtitle}</div>
          </div>

          <!-- Trend + metrics -->
          <div class="mt-auto space-y-2">
            {#if tr}
              <div class="flex items-center gap-1 text-xs font-medium {tr.dir === 'up' ? 'text-emerald-600' : 'text-rose-600'}">
                <Icon name={tr.dir === 'up' ? 'trending-up' : 'trending-down'} size={12} />
                <span>{Math.abs(tr.pct).toFixed(1)}%</span>
                <span class="text-muted-foreground font-normal">vs previous</span>
              </div>
            {:else if d && !d.error && d.total_count === 0}
              <div class="text-xs text-muted-foreground italic">no events yet</div>
            {:else}
              <div class="text-xs text-muted-foreground">—</div>
            {/if}

            {#if d && !d.error && d.total_count > 0}
              <div class="pt-2 border-t border-border/50 grid grid-cols-2 gap-2 text-xs">
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
          </div>
        </button>
      {/each}
    </div>

    <!-- Empty state hint -->
    {#if !loading && Object.values(data).every(d => !d || d.total_count === 0)}
      <div class="text-center text-muted-foreground py-8">
        <p class="text-sm">No logs recorded in this period.</p>
        <p class="text-xs mt-1">Check that log watchers are enabled (Settings → Logs)</p>
      </div>
    {/if}

  {:else}
    <!-- ═════════ DRILL-IN ═════════ -->
    {@const d = data[selectedType]}
    {@const tr = d && !d.error ? trend(d.total_count, d.previous_total) : null}
    {@const maxBucket = d?.time_series ? maxOf(d.time_series) : 1}
    {@const maxCountry = d?.top_countries ? maxOf(d.top_countries) : 1}
    {@const totalHTTP = d?.http_status ? totalOf(d.http_status) : 1}
    {@const totalDNS = d?.status_counts ? totalOf(d.status_counts) : 1}
    {@const totalProto = d?.protocols ? totalOf(d.protocols) : 1}
    {@const maxPort = d?.top_dest_ports ? maxOf(d.top_dest_ports) : 1}
    {@const totalQuery = d?.query_types ? totalOf(d.query_types) : 1}

    {#if !d}
      <div class="text-center py-16 text-muted-foreground">Loading…</div>
    {:else if d.error}
      <div class="text-center py-16 text-rose-600">Error: {d.error}</div>
    {:else if d.total_count === 0}
      <div class="rounded-xl border bg-card p-12 text-center space-y-2">
        <Icon name="inbox" size={40} class_="mx-auto text-muted-foreground" />
        <h3 class="font-semibold">No {typeMeta[selectedType].label.toLowerCase()} events yet</h3>
        <p class="text-sm text-muted-foreground">
          {#if selectedType === 'inbound'}
            The Traefik watcher hasn't logged any requests. Verify Traefik access-log is enabled and points at the right file.
          {:else if selectedType === 'outbound'}
            The outbound watcher hasn't seen any peer traffic. Enable it in Settings if disabled.
          {:else if selectedType === 'fw'}
            No firewall drops in this period. That's a good thing.
          {:else}
            AdGuard hasn't logged any queries. Check that AdGuard is receiving DNS traffic from your clients.
          {/if}
        </p>
      </div>
    {:else}

      <!-- KPI row -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div class="rounded-xl border bg-card p-4">
          <div class="text-xs text-muted-foreground">Total events</div>
          <div class="text-3xl font-bold tabular-nums mt-1">{fmtNumber(d.total_count)}</div>
          {#if tr}
            <div class="text-xs mt-1 {tr.dir === 'up' ? 'text-emerald-600' : 'text-rose-600'}">
              {tr.dir === 'up' ? '↑' : '↓'} {Math.abs(tr.pct).toFixed(1)}%
            </div>
          {/if}
        </div>
        <div class="rounded-xl border bg-card p-4">
          <div class="text-xs text-muted-foreground">Unique {selectedType === 'fw' ? 'attackers' : 'sources'}</div>
          <div class="text-3xl font-bold tabular-nums mt-1">{fmtNumber(d.unique_visitors)}</div>
        </div>
        <div class="rounded-xl border bg-card p-4">
          <div class="text-xs text-muted-foreground">Bandwidth</div>
          <div class="text-3xl font-bold tabular-nums mt-1">{fmtBytes(d.total_bytes)}</div>
        </div>
        <div class="rounded-xl border bg-card p-4">
          <div class="text-xs text-muted-foreground">
            {selectedType === 'dns' ? 'Cache rate' : selectedType === 'fw' ? 'Rules fired' : selectedType === 'inbound' ? 'Success rate' : 'Countries'}
          </div>
          <div class="text-3xl font-bold tabular-nums mt-1">
            {#if selectedType === 'dns'}
              {pct(d.cached_count, d.total_count)}%
            {:else if selectedType === 'fw'}
              {d.top_rules?.length || 0}
            {:else if selectedType === 'inbound'}
              {pct((d.http_status?.find(s => s.status === '2xx')?.count || 0), totalHTTP)}%
            {:else}
              {d.top_countries?.length || 0}
            {/if}
          </div>
        </div>
      </div>

      <!-- Time series -->
      {#if d.time_series?.length}
        <div class="rounded-xl border bg-card p-5">
          <div class="text-sm font-semibold mb-4">Events over time</div>
          <div class="flex items-end gap-0.5 h-32">
            {#each d.time_series as b}
              <div
                class="flex-1 min-w-1 {typeMeta[selectedType].dot} opacity-60 hover:opacity-100 rounded-t transition-opacity"
                style="height: {Math.max((b.count / maxBucket) * 100, 2)}%"
                title={`${b.time}: ${b.count} events`}
              ></div>
            {/each}
          </div>
          <div class="flex justify-between mt-2 text-xs text-muted-foreground font-mono">
            <span>{d.time_series[0]?.time}</span>
            <span>{d.time_series[d.time_series.length - 1]?.time}</span>
          </div>
        </div>
      {/if}

      <!-- Widgets grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">

        <!-- Countries -->
        {#if d.top_countries?.length}
          <div class="rounded-xl border bg-card p-5">
            <div class="text-sm font-semibold mb-4">
              Top countries {selectedType === 'outbound' ? '(dest)' : ''}
            </div>
            <div class="space-y-2.5">
              {#each d.top_countries as c}
                <div class="flex items-center gap-3 text-sm">
                  <span class="w-6 shrink-0 text-base leading-none">{flag(c.country)}</span>
                  <span class="w-10 shrink-0 font-mono text-xs">{c.country || '??'}</span>
                  <div class="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                    <div class="h-full {typeMeta[selectedType].dot}" style="width: {(c.count / maxCountry) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right tabular-nums">{fmtNumber(c.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Status / Protocol / Ports -->
        {#if selectedType === 'inbound' && d.http_status?.length}
          <div class="rounded-xl border bg-card p-5">
            <div class="text-sm font-semibold mb-4">HTTP status</div>
            <div class="space-y-2.5">
              {#each d.http_status as s}
                <div class="flex items-center gap-3 text-sm">
                  <span class="w-10 font-mono text-xs">{s.status}</span>
                  <div class="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                    <div class="h-full {statusColor[s.status] || 'bg-primary'}" style="width: {(s.count / totalHTTP) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right tabular-nums">{pct(s.count, totalHTTP)}%</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'dns' && d.status_counts?.length}
          <div class="rounded-xl border bg-card p-5">
            <div class="text-sm font-semibold mb-4">DNS response codes</div>
            <div class="space-y-2.5">
              {#each d.status_counts as s}
                <div class="flex items-center gap-3 text-sm">
                  <span class="w-24 truncate text-xs">{s.status}</span>
                  <div class="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                    <div class="h-full bg-emerald-500" style="width: {(s.count / totalDNS) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right tabular-nums">{pct(s.count, totalDNS)}%</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'outbound' && d.protocols?.length}
          <div class="rounded-xl border bg-card p-5">
            <div class="text-sm font-semibold mb-4">Protocols</div>
            <div class="space-y-2.5">
              {#each d.protocols as p}
                <div class="flex items-center gap-3 text-sm">
                  <span class="w-16 font-mono text-xs">{p.status}</span>
                  <div class="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                    <div class="h-full bg-violet-500" style="width: {(p.count / totalProto) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right tabular-nums">{pct(p.count, totalProto)}%</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'fw' && d.top_dest_ports?.length}
          <div class="rounded-xl border bg-card p-5">
            <div class="text-sm font-semibold mb-4">Top probed ports</div>
            <div class="space-y-2.5">
              {#each d.top_dest_ports as p}
                <div class="flex items-center gap-3 text-sm">
                  <span class="w-14 font-mono text-xs">:{p.status}</span>
                  <div class="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                    <div class="h-full bg-rose-500" style="width: {(p.count / maxPort) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right tabular-nums">{fmtNumber(p.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Top source IPs -->
        {#if d.top_clients?.length}
          <div class="rounded-xl border bg-card p-5">
            <div class="text-sm font-semibold mb-4">Top source IPs</div>
            <div class="space-y-2">
              {#each d.top_clients as c}
                <div class="flex items-center justify-between gap-2 text-sm">
                  <div class="flex items-center gap-2 min-w-0">
                    <span class="shrink-0">{flag(c.country)}</span>
                    <span class="font-mono text-xs truncate">{c.ip}</span>
                  </div>
                  <span class="font-mono text-xs tabular-nums shrink-0">{fmtNumber(c.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Secondary widget -->
        {#if selectedType === 'inbound' && d.top_domains?.length}
          <div class="rounded-xl border bg-card p-5">
            <div class="text-sm font-semibold mb-4">Top domains</div>
            <div class="space-y-2 text-sm">
              {#each d.top_domains as x}
                <div class="flex justify-between gap-2">
                  <span class="text-xs truncate">{x.domain}</span>
                  <span class="font-mono text-xs tabular-nums">{fmtNumber(x.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'dns' && d.top_blocked?.length}
          <div class="rounded-xl border bg-card p-5">
            <div class="text-sm font-semibold mb-4">Top blocked domains</div>
            <div class="space-y-2 text-sm">
              {#each d.top_blocked as x}
                <div class="flex justify-between gap-2">
                  <span class="text-xs truncate">{x.domain}</span>
                  <span class="font-mono text-xs tabular-nums text-rose-600">{fmtNumber(x.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'dns' && d.query_types?.length}
          <div class="rounded-xl border bg-card p-5">
            <div class="text-sm font-semibold mb-4">Query types</div>
            <div class="space-y-2.5">
              {#each d.query_types as q}
                <div class="flex items-center gap-3 text-sm">
                  <span class="w-16 font-mono text-xs">{q.status}</span>
                  <div class="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                    <div class="h-full bg-emerald-500" style="width: {(q.count / totalQuery) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right tabular-nums">{pct(q.count, totalQuery)}%</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'outbound' && d.top_dest_ips?.length}
          <div class="rounded-xl border bg-card p-5">
            <div class="text-sm font-semibold mb-4">Top destinations</div>
            <div class="space-y-2 text-sm">
              {#each d.top_dest_ips as x}
                <div class="flex items-center justify-between gap-2">
                  <div class="flex items-center gap-2 min-w-0">
                    <span class="shrink-0">{flag(x.country)}</span>
                    <span class="font-mono text-xs truncate">{x.ip}</span>
                  </div>
                  <span class="font-mono text-xs tabular-nums shrink-0">{fmtNumber(x.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'fw' && d.top_rules?.length}
          <div class="rounded-xl border bg-card p-5">
            <div class="text-sm font-semibold mb-4">Top firewall rules</div>
            <div class="space-y-2 text-sm">
              {#each d.top_rules as r}
                <div class="flex justify-between gap-2">
                  <span class="text-xs truncate">{r.status}</span>
                  <span class="font-mono text-xs tabular-nums">{fmtNumber(r.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {/if}
      </div>
    {/if}
  {/if}
</div>
