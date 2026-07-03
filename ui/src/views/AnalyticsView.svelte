<script>
  import { onMount } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Toolbar from '../components/Toolbar.svelte'

  let { loading = $bindable(true) } = $props()

  // View mode: null = overview (4 cards); or a type string for drill-in
  let selectedType = $state(null)

  // Period selector — applies to both overview and detail views
  let period = $state('day')

  // Data buckets — one per type; loaded on demand
  let data = $state({
    inbound: null,
    dns: null,
    outbound: null,
    fw: null,
  })

  const typeMeta = {
    inbound:  { label: 'Inbound',  icon: 'arrow-down-right', color: 'blue',   subtitle: 'Traefik requests to your domains' },
    dns:      { label: 'DNS',      icon: 'world-www',        color: 'green',  subtitle: 'AdGuard queries from clients' },
    outbound: { label: 'Outbound', icon: 'arrow-up-right',   color: 'purple', subtitle: 'Connections VPN peers made' },
    fw:       { label: 'Firewall', icon: 'shield',           color: 'red',    subtitle: 'Dropped connections' },
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
    await Promise.all(['inbound', 'dns', 'outbound', 'fw'].map(loadType))
    loading = false
  }

  // Reload when period changes
  $effect(() => {
    // read `period` to establish dependency
    period
    loadAll()
  })

  onMount(loadAll)

  // Trend arrow calc
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

  // Country flag emoji from 2-letter code
  function flag(cc) {
    if (!cc || cc.length !== 2) return ''
    return String.fromCodePoint(...cc.toUpperCase().split('').map(c => 0x1f1a5 + c.charCodeAt(0)))
  }

  // Max value in a series (for scaling bars)
  function maxOf(arr, key = 'count') {
    return arr && arr.length ? Math.max(...arr.map(x => x[key] || 0)) : 1
  }
</script>

<div class="p-4 space-y-4">
  <Toolbar>
    <div slot="left" class="flex items-center gap-3">
      {#if selectedType}
        <Button size="sm" variant="ghost" onclick={() => selectedType = null}>
          <Icon name="arrow-left" size={16} /> Back
        </Button>
      {/if}
      <h1 class="text-xl font-semibold">
        {selectedType ? typeMeta[selectedType].label : 'Analytics'}
      </h1>
    </div>
    <div slot="right" class="flex items-center gap-2">
      <select bind:value={period} class="border rounded px-2 py-1 bg-transparent text-sm">
        <option value="hour">Last hour</option>
        <option value="day">Last 24h</option>
        <option value="week">Last 7 days</option>
      </select>
      <Button size="sm" variant="ghost" onclick={loadAll} title="Refresh">
        <Icon name="refresh" size={16} />
      </Button>
    </div>
  </Toolbar>

  {#if !selectedType}
    <!-- ═════════ OVERVIEW ═════════ -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {#each Object.entries(typeMeta) as [type, meta]}
        {@const d = data[type]}
        {@const tr = d && trend(d.total_count, d.previous_total)}
        <button
          class="text-left p-4 rounded-lg border hover:border-primary transition-colors bg-card"
          onclick={() => selectedType = type}
        >
          <div class="flex items-center justify-between mb-3">
            <div class="flex items-center gap-2">
              <Icon name={meta.icon} size={20} />
              <span class="font-semibold">{meta.label}</span>
            </div>
            <Icon name="arrow-right" size={16} class_="text-muted-foreground" />
          </div>
          <div class="text-3xl font-bold mb-1">
            {d ? fmtNumber(d.total_count) : '—'}
          </div>
          <div class="text-xs text-muted-foreground mb-2">{meta.subtitle}</div>
          {#if tr}
            <div class="flex items-center gap-1 text-xs {tr.dir === 'up' ? 'text-green-600' : 'text-red-600'}">
              <Icon name={tr.dir === 'up' ? 'trending-up' : 'trending-down'} size={12} />
              {tr.pct.toFixed(1)}% vs previous {period}
            </div>
          {:else}
            <div class="text-xs text-muted-foreground">no previous data</div>
          {/if}

          <!-- Type-specific mini KPI -->
          {#if d && !d.error}
            <div class="mt-3 pt-3 border-t text-xs space-y-1">
              {#if type === 'inbound'}
                <div class="flex justify-between"><span>Unique visitors</span><span class="font-mono">{fmtNumber(d.unique_visitors)}</span></div>
                <div class="flex justify-between"><span>Bandwidth</span><span class="font-mono">{fmtBytes(d.total_bytes)}</span></div>
              {:else if type === 'dns'}
                <div class="flex justify-between"><span>Cached</span><span class="font-mono">{pct(d.cached_count, d.total_count)}%</span></div>
                <div class="flex justify-between"><span>Blocked</span><span class="font-mono">{pct(d.blocked_count, d.total_count)}%</span></div>
              {:else if type === 'outbound'}
                <div class="flex justify-between"><span>Unique dests</span><span class="font-mono">{fmtNumber(d.top_dest_ips?.length || 0)}</span></div>
                <div class="flex justify-between"><span>Bandwidth</span><span class="font-mono">{fmtBytes(d.total_bytes)}</span></div>
              {:else if type === 'fw'}
                <div class="flex justify-between"><span>Unique attackers</span><span class="font-mono">{fmtNumber(d.unique_visitors)}</span></div>
                <div class="flex justify-between"><span>Top port</span><span class="font-mono">{d.top_dest_ports?.[0]?.status || '—'}</span></div>
              {/if}
            </div>
          {/if}
        </button>
      {/each}
    </div>

  {:else}
    <!-- ═════════ DRILL-IN ═════════ -->
    {@const d = data[selectedType]}

    {#if !d}
      <div class="text-center py-8 text-muted-foreground">Loading…</div>
    {:else if d.error}
      <div class="text-center py-8 text-red-600">Error: {d.error}</div>
    {:else}

      <!-- KPI row -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div class="p-4 rounded-lg border bg-card">
          <div class="text-xs text-muted-foreground">Total events</div>
          <div class="text-2xl font-bold">{fmtNumber(d.total_count)}</div>
          {@const tr = trend(d.total_count, d.previous_total)}
          {#if tr}
            <div class="text-xs {tr.dir === 'up' ? 'text-green-600' : 'text-red-600'}">
              {tr.pct.toFixed(1)}% vs prev
            </div>
          {/if}
        </div>
        <div class="p-4 rounded-lg border bg-card">
          <div class="text-xs text-muted-foreground">Unique source IPs</div>
          <div class="text-2xl font-bold">{fmtNumber(d.unique_visitors)}</div>
        </div>
        <div class="p-4 rounded-lg border bg-card">
          <div class="text-xs text-muted-foreground">Total bytes</div>
          <div class="text-2xl font-bold">{fmtBytes(d.total_bytes)}</div>
        </div>
        <div class="p-4 rounded-lg border bg-card">
          <div class="text-xs text-muted-foreground">
            {selectedType === 'dns' ? 'Cached' : selectedType === 'fw' ? 'Rules fired' : 'Countries'}
          </div>
          <div class="text-2xl font-bold">
            {#if selectedType === 'dns'}
              {pct(d.cached_count, d.total_count)}%
            {:else if selectedType === 'fw'}
              {d.top_rules?.length || 0}
            {:else}
              {d.top_countries?.length || 0}
            {/if}
          </div>
        </div>
      </div>

      <!-- Time series (SVG bar sparkline) -->
      {#if d.time_series?.length}
        {@const maxBucket = maxOf(d.time_series)}
        <div class="p-4 rounded-lg border bg-card">
          <div class="text-sm font-semibold mb-3">Events over time ({period})</div>
          <div class="flex items-end gap-0.5 h-24">
            {#each d.time_series as b}
              <div
                class="flex-1 min-w-0.5 bg-primary/60 hover:bg-primary transition-colors rounded-t"
                style="height: {(b.count / maxBucket) * 100}%"
                title={`${b.time}: ${b.count} events`}
              ></div>
            {/each}
          </div>
          <div class="flex justify-between mt-1 text-xs text-muted-foreground">
            <span>{d.time_series[0]?.time}</span>
            <span>{d.time_series[d.time_series.length - 1]?.time}</span>
          </div>
        </div>
      {/if}

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">

        <!-- Top countries -->
        {#if d.top_countries?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">
              Top countries {selectedType === 'outbound' ? '(destination)' : ''}
            </div>
            {@const max = maxOf(d.top_countries)}
            <div class="space-y-2">
              {#each d.top_countries as c}
                <div class="flex items-center gap-2 text-sm">
                  <span class="w-8 shrink-0">{flag(c.country)}</span>
                  <span class="w-10 shrink-0 font-mono text-xs">{c.country}</span>
                  <div class="flex-1 h-4 bg-muted rounded overflow-hidden">
                    <div class="h-full bg-primary" style="width: {(c.count / max) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right">{fmtNumber(c.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Type-specific main widget: HTTP status / DNS status / Protocols / Ports -->
        {#if selectedType === 'inbound' && d.http_status?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">HTTP status</div>
            {@const total = d.http_status.reduce((s, x) => s + x.count, 0)}
            <div class="space-y-2">
              {#each d.http_status as s}
                {@const colors = { '2xx': 'bg-green-500', '3xx': 'bg-blue-500', '4xx': 'bg-yellow-500', '5xx': 'bg-red-500', 'other': 'bg-gray-500' }}
                <div class="flex items-center gap-2 text-sm">
                  <span class="w-10 font-mono">{s.status}</span>
                  <div class="flex-1 h-4 bg-muted rounded overflow-hidden">
                    <div class="h-full {colors[s.status] || 'bg-primary'}" style="width: {(s.count / total) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right">{pct(s.count, total)}%</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'dns' && d.status_counts?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">DNS status</div>
            {@const total = d.status_counts.reduce((s, x) => s + x.count, 0)}
            <div class="space-y-2">
              {#each d.status_counts as s}
                <div class="flex items-center gap-2 text-sm">
                  <span class="w-24 truncate">{s.status}</span>
                  <div class="flex-1 h-4 bg-muted rounded overflow-hidden">
                    <div class="h-full bg-primary" style="width: {(s.count / total) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right">{pct(s.count, total)}%</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'outbound' && d.protocols?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">Protocols</div>
            {@const total = d.protocols.reduce((s, x) => s + x.count, 0)}
            <div class="space-y-2">
              {#each d.protocols as p}
                <div class="flex items-center gap-2 text-sm">
                  <span class="w-16 font-mono">{p.status}</span>
                  <div class="flex-1 h-4 bg-muted rounded overflow-hidden">
                    <div class="h-full bg-primary" style="width: {(p.count / total) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right">{pct(p.count, total)}%</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'fw' && d.top_dest_ports?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">Top probed ports</div>
            {@const max = maxOf(d.top_dest_ports)}
            <div class="space-y-2">
              {#each d.top_dest_ports as p}
                <div class="flex items-center gap-2 text-sm">
                  <span class="w-12 font-mono">{p.status}</span>
                  <div class="flex-1 h-4 bg-muted rounded overflow-hidden">
                    <div class="h-full bg-red-500" style="width: {(p.count / max) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right">{fmtNumber(p.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Top clients / IPs -->
        {#if d.top_clients?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">Top source IPs</div>
            <div class="space-y-1 text-sm">
              {#each d.top_clients as c}
                <div class="flex justify-between font-mono text-xs">
                  <span class="truncate">{flag(c.country)} {c.ip}</span>
                  <span>{fmtNumber(c.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <!-- Type-specific secondary widget -->
        {#if selectedType === 'inbound' && d.top_domains?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">Top domains</div>
            <div class="space-y-1 text-sm">
              {#each d.top_domains as x}
                <div class="flex justify-between text-xs">
                  <span class="truncate">{x.domain}</span>
                  <span class="font-mono">{fmtNumber(x.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'inbound' && d.top_paths?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">Top paths</div>
            <div class="space-y-1 text-sm">
              {#each d.top_paths as x}
                <div class="flex justify-between text-xs">
                  <span class="truncate font-mono">{x.path}</span>
                  <span class="font-mono">{fmtNumber(x.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'dns' && d.top_blocked?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">Top blocked domains</div>
            <div class="space-y-1 text-sm">
              {#each d.top_blocked as x}
                <div class="flex justify-between text-xs">
                  <span class="truncate">{x.domain}</span>
                  <span class="font-mono text-red-600">{fmtNumber(x.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'dns' && d.query_types?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">Query types</div>
            {@const total = d.query_types.reduce((s, x) => s + x.count, 0)}
            <div class="space-y-2">
              {#each d.query_types as q}
                <div class="flex items-center gap-2 text-sm">
                  <span class="w-16 font-mono">{q.status}</span>
                  <div class="flex-1 h-4 bg-muted rounded overflow-hidden">
                    <div class="h-full bg-primary" style="width: {(q.count / total) * 100}%"></div>
                  </div>
                  <span class="font-mono text-xs w-14 text-right">{pct(q.count, total)}%</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'outbound' && d.top_dest_ips?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">Top destination IPs</div>
            <div class="space-y-1 text-sm">
              {#each d.top_dest_ips as x}
                <div class="flex justify-between text-xs font-mono">
                  <span class="truncate">{flag(x.country)} {x.ip}</span>
                  <span>{fmtNumber(x.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {:else if selectedType === 'fw' && d.top_rules?.length}
          <div class="p-4 rounded-lg border bg-card">
            <div class="text-sm font-semibold mb-3">Top firewall rules</div>
            <div class="space-y-1 text-sm">
              {#each d.top_rules as r}
                <div class="flex justify-between text-xs">
                  <span class="truncate">{r.status}</span>
                  <span class="font-mono">{fmtNumber(r.count)}</span>
                </div>
              {/each}
            </div>
          </div>
        {/if}
      </div>

    {/if}
  {/if}
</div>
