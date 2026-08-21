<script>
  import { onMount } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import { usePersistentState } from '$lib/composables/index.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import Select from '../components/Select.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import CountryFlag from '../components/CountryFlag.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import BlockedByLayer from '../components/BlockedByLayer.svelte'
  import UPlotChart from '../components/UPlotChart.svelte'
  import Donut from '../components/Donut.svelte'
  import WorldMap from '../components/WorldMap.svelte'

  let { loading = $bindable(true) } = $props()

  // Persist selectedType + period across refresh / navigation
  const persisted = usePersistentState('analytics_ui', { selectedType: null, period: 'day' })
  let selectedType = $derived(persisted.value.selectedType)
  let period = $derived(persisted.value.period)
  const periodLabelFull = $derived({ hour: '1 hour', day: '24 hours', week: '7 days', month: '30 days', all: 'all time' }[period] || period)

  function setType(t) { persisted.value = { ...persisted.value, selectedType: t } }
  function setPeriod(p) { persisted.value = { ...persisted.value, period: p } }

  const TABS = [
    { id: null, label: 'Overview', icon: 'chart-bar' },
    { id: 'inbound', label: 'Inbound' },
    { id: 'dns', label: 'DNS' },
    { id: 'outbound', label: 'Outbound' },
    { id: 'fw', label: 'Firewall' },
    { id: 'client', label: 'Per client', icon: 'user' },
  ]
  const PERIODS = [
    { id: 'hour', label: '1h' }, { id: 'day', label: '24h' },
    { id: 'week', label: '7d' }, { id: 'month', label: '30d' }, { id: 'all', label: 'All' },
  ]

  let data = $state({ inbound: null, dns: null, outbound: null, fw: null })

  // Per-type identity: label, plain-English subtitle, icon, a CSS colour var for
  // inline styles (`cvar`), and a `stroke` token for UPlotChart.
  const typeMeta = {
    inbound:  { label: 'Inbound',  plain: 'Visits to your services', icon: 'arrow-down', cvar: 'var(--primary)',     stroke: '--primary' },
    dns:      { label: 'DNS',      plain: 'Domain lookups',          icon: 'globe',      cvar: 'var(--success)',     stroke: '--success' },
    outbound: { label: 'Outbound', plain: 'Traffic leaving',         icon: 'arrow-up',   cvar: 'var(--tx)',          stroke: '--tx' },
    fw:       { label: 'Firewall', plain: 'Blocked attacks',         icon: 'shield',     cvar: 'var(--destructive)', stroke: '--destructive' },
  }
  const typeDesc = {
    inbound: 'HTTP requests that reached your self-hosted services through the reverse proxy.',
    dns: 'Domain-name lookups made by devices on your VPN, including ad & tracker blocking.',
    outbound: 'Connections your devices made out to the internet.',
    fw: 'Connection attempts that were dropped before they reached anything.',
  }

  // Overview + per-type stats are NEVER client-filtered — they show all traffic.
  // A client is only ever scoped inside the "Per client" tab (via peer-usage).
  async function loadType(type) {
    try {
      data[type] = await apiGet(`/api/logs/stats?type=${type}&period=${period}`)
    } catch (e) { data[type] = { error: e.message } }
  }
  async function loadAll() {
    loading = true
    await Promise.all([...Object.keys(typeMeta).map(loadType), loadTopTalkers()])
    loading = false
  }
  $effect(() => { period; loadAll() })
  onMount(loadAll)

  // ── Per-client (conntrack byte accounting) ──
  let peerList = $state([])
  let selectedPeer = $state('')
  let peerUsage = $state(null)
  let peerUsageLoading = $state(false)
  let topTalkers = $state([])

  async function loadTopTalkers() {
    try { topTalkers = (await apiGet(`/api/logs/top-talkers?period=${period}`)).talkers || [] } catch { topTalkers = [] }
  }
  async function loadPeers() {
    try {
      const clients = await apiGet('/api/vpn/clients')
      peerList = (Array.isArray(clients) ? clients : []).filter((c) => c.ip).map((c) => ({ value: c.ip, label: `${c.name || c.ip} (${c.ip})` }))
    } catch { peerList = [] }
  }
  onMount(loadPeers)
  async function loadPeerUsage() {
    if (!selectedPeer) { peerUsage = null; return }
    peerUsageLoading = true
    try { peerUsage = await apiGet(`/api/logs/peer-usage?peer=${encodeURIComponent(selectedPeer)}&period=${period}`) }
    catch (e) { peerUsage = { destinations: [], series: [], error: e.message } }
    finally { peerUsageLoading = false }
  }
  $effect(() => {
    selectedPeer; period; selectedType
    if (selectedType === 'client' && selectedPeer) loadPeerUsage()
  })
  // Default the client picker to the first peer when the tab opens with none chosen.
  $effect(() => {
    if (selectedType === 'client' && !selectedPeer && peerList.length) selectedPeer = peerList[0].value
  })

  function openClient(ip) { selectedPeer = ip; setType('client') }

  const clientCountries = $derived.by(() => {
    const agg = {}
    for (const d of peerUsage?.destinations || []) if (d.country) agg[d.country] = (agg[d.country] || 0) + (d.bytes_total || 0)
    return Object.entries(agg).map(([country, count]) => ({ country, count })).sort((a, b) => b.count - a.count).slice(0, 10)
  })

  // Overview world map: source (attackers, fw) vs destination (outbound). Persisted UI.
  let mapKind = $state('src')
  const mapData = $derived(mapKind === 'src' ? (data.fw?.top_countries || []) : (data.outbound?.top_countries || []))

  // Plain-English one-liner summarizing the period.
  const summary = $derived.by(() => {
    const fw = data.fw, inb = data.inbound, dns = data.dns
    const parts = []
    if (fw && !fw.error && fw.total_count != null) {
      const topC = fw.top_countries?.[0]?.country
      parts.push({ n: fmtNumber(fw.total_count), t: `attacks blocked${fw.unique_visitors ? ` from ${fmtNumber(fw.unique_visitors)} IPs` : ''}`, code: topC })
    }
    if (inb && !inb.error && inb.unique_visitors != null) parts.push({ n: fmtNumber(inb.unique_visitors), t: 'visitors to your services' })
    if (dns && !dns.error && dns.total_count) parts.push({ n: fmtNumber(dns.total_count), t: `DNS lookups, ${pct(dns.blocked_count, dns.total_count)}% blocked` })
    return parts
  })

  // ── CSV export of the current type view ──
  function csvCell(v) { const s = String(v ?? ''); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s }
  function downloadCsv() {
    const d = data[selectedType]
    if (!d) return
    const lines = []
    const section = (title, rows, cols) => { if (!rows?.length) return; lines.push(title, cols.join(',')); for (const r of rows) lines.push(cols.map((c) => csvCell(r[c])).join(',')); lines.push('') }
    section('Top source IPs', d.top_clients, ['ip', 'country', 'count'])
    section('Top countries', d.top_countries, ['country', 'count'])
    if (selectedType === 'outbound') section('Top destinations', d.top_dest_ips, ['ip', 'country', 'count'])
    if (selectedType === 'inbound') { section('Top domains', d.top_domains, ['domain', 'count']); section('Top paths', d.top_paths, ['domain', 'path', 'count']) }
    if (selectedType === 'dns') section('Top blocked', d.top_blocked, ['domain', 'count'])
    if (selectedType === 'fw') { section('Top ports', d.top_dest_ports, ['status', 'count']); section('Top rules', d.top_rules, ['status', 'count']) }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `analytics-${selectedType || 'all'}-${period}.csv`; a.click()
    URL.revokeObjectURL(url)
  }

  // ── format + colour helpers ──
  function trend(cur, prev) { if (!prev) return null; const p = ((cur - prev) / prev) * 100; return { pct: p, dir: p >= 0 ? 'up' : 'down' } }
  function fmtNumber(n) { if (n == null) return '—'; n = Math.round(n); if (n < 1000) return String(n); if (n < 1e6) return (n / 1e3).toFixed(n < 1e4 ? 1 : 0) + 'K'; return (n / 1e6).toFixed(1) + 'M' }
  function fmtBytes(b) { if (!b) return '0 B'; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; let v = b; while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ } return v.toFixed(i === 0 ? 0 : 1) + ' ' + u[i] }
  function pct(part, total) { return total ? Math.round((part / total) * 100) : 0 }
  function maxOf(arr, key = 'count') { return arr && arr.length ? Math.max(...arr.map((x) => x[key] || 0)) : 1 }
  const trGood = (type, tr) => (tr ? (type === 'fw' ? tr.dir === 'down' : tr.dir === 'up') : true)

  // Donut segment colours: semantic where meaningful, else a stable cycle.
  const CYCLE = ['var(--primary)', 'var(--success)', 'var(--tx)', 'var(--info)', 'var(--mem)', 'var(--warning)']
  function httpColor(s) { const k = String(s)[0]; return { 2: 'var(--success)', 3: 'var(--primary)', 4: 'var(--warning)', 5: 'var(--destructive)' }[k] || 'var(--muted-foreground)' }
  function dnsColor(s) { const u = String(s).toUpperCase(); if (u.includes('BLOCK') || u.includes('FILTER') || u === 'SERVFAIL') return 'var(--destructive)'; if (u === 'NOERROR') return 'var(--success)'; if (u === 'NXDOMAIN') return 'var(--warning)'; return 'var(--primary)' }
  const donutSeg = (rows, colorFn) => (rows || []).map((r, i) => ({ label: r.status, count: r.count, color: colorFn(r.status, i) }))

  // Success rate for the inbound stat tile.
  const successRate = (d) => pct(d.http_status?.find((s) => String(s.status).startsWith('2'))?.count || 0, d.http_status?.reduce((s, x) => s + x.count, 0) || 1)
</script>

<div class="analytics">
  <InfoCard
    icon="chart-bar"
    title="Analytics"
    description="Everything your firewall, DNS resolver, and reverse proxy have seen — in plain language, with the raw numbers one click away."
  />

  <!-- toolbar: segmented tab menu + a kt-btn-group period control -->
  <div class="toolbar">
    <div class="tabs">
      {#each TABS as t}
        <button class="tab" class:active={selectedType === t.id} onclick={() => setType(t.id)}>
          {#if t.icon}<Icon name={t.icon} size={14} />{:else if t.id && typeMeta[t.id]}<span class="tdot" style="background:{typeMeta[t.id].cvar}"></span>{/if}
          {t.label}
        </button>
      {/each}
    </div>
    <div class="controls">
      <div class="kt-btn-group">
        {#each PERIODS as p}
          <Button variant={period === p.id ? 'mono' : 'outline'} size="sm" onclick={() => setPeriod(p.id)}>{p.label}</Button>
        {/each}
      </div>
      {#if selectedType && selectedType !== 'client'}<Button variant="outline" size="sm" icon="download" onclick={downloadCsv}>Export</Button>{/if}
      <Button variant="outline" size="sm" icon="refresh" onclick={loadAll}>Refresh</Button>
    </div>
  </div>

  {#if loading}
    <div class="center"><LoadingSpinner /></div>

  <!-- ═══════════ OVERVIEW ═══════════ -->
  {:else if !selectedType}
    {#if summary.length}
      <div class="banner">
        <span class="icon-badge sm"><Icon name="list-details" size={16} /></span>
        <div>
          <div class="eyebrow">Last {periodLabelFull} at a glance</div>
          <div class="line">
            {#each summary as s, i}{#if i > 0}<span class="sep">·</span>{/if}<b>{s.n}</b> {s.t}{#if s.code}&nbsp;(top <span class="inline-flag"><CountryFlag code={s.code} size="sm" /></span> {s.code}){/if}{/each}
          </div>
        </div>
      </div>
    {/if}

    <!-- KPI tiles -->
    <div class="grid cols-4 stack-gap">
      {#each Object.entries(typeMeta) as [type, meta]}
        {@const d = data[type]}
        {@const tr = d && !d.error ? trend(d.total_count, d.previous_total) : null}
        {@const good = trGood(type, tr)}
        <button class="kpi" onclick={() => setType(type)}>
          <div class="top">
            <span class="ic" style="background:color-mix(in oklch, {meta.cvar} 16%, var(--card)); color:{meta.cvar}"><Icon name={meta.icon} size={17} /></span>
            <div><div class="ttl">{meta.label}</div><div class="plain">{meta.plain}</div></div>
            <span class="chev"><Icon name="chevron-right" size={14} /></span>
          </div>
          <div class="num" style="color:{meta.cvar}">{d ? fmtNumber(d.total_count) : '—'}</div>
          <div class="trend" style="color:{tr ? (good ? 'var(--success)' : 'var(--destructive)') : 'var(--muted-foreground)'}">
            {#if tr}<Icon name={tr.dir === 'up' ? 'arrow-up' : 'arrow-down'} size={11} /><span>{Math.abs(tr.pct).toFixed(1)}%</span><span class="muted">vs previous</span>{:else}<span>no prior data</span>{/if}
          </div>
          {#if d && !d.error && d.total_count > 0}
            <div class="foot">
              {#if type === 'inbound'}
                {@render footCell('user', fmtNumber(d.unique_visitors), 'visitors')}{@render footCell('activity', fmtBytes(d.total_bytes), 'bandwidth')}
              {:else if type === 'dns'}
                {@render footCell('check', pct(d.cached_count, d.total_count) + '%', 'cached')}{@render footCell('ban', pct(d.blocked_count, d.total_count) + '%', 'blocked')}
              {:else if type === 'outbound'}
                {@render footCell('globe', fmtNumber(d.top_dest_ips?.length || 0), 'destinations')}{@render footCell('activity', fmtBytes(d.total_bytes), 'bandwidth')}
              {:else}
                {@render footCell('user', fmtNumber(d.unique_visitors), 'attackers')}{@render footCell('plug', d.top_dest_ports?.[0]?.status || '—', 'top port')}
              {/if}
            </div>
          {/if}
        </button>
      {/each}
    </div>

    <!-- traffic over time: one full-width chart per type, stacked -->
    <div class="section-title">Traffic over time<span class="line"></span></div>
    <div class="grid cols-4 stack-gap">
      {#each Object.entries(typeMeta) as [type, meta]}
        {@const d = data[type]}
        <div class="card">
          <div class="card-h compact"><h3><span class="tdot" style="background:{meta.cvar}"></span>{meta.label}</h3><span class="sub">{d && !d.error ? fmtNumber(d.total_count) : '—'}</span></div>
          {#if d?.time_series?.length > 1}
            <div class="card-body tight">
              <UPlotChart data={[d.time_series.map((b) => b.ts), d.time_series.map((b) => b.count)]} series={[{ label: meta.label, stroke: meta.stroke, fill: 0.18 }]} height={120} legend={false} />
            </div>
          {:else}
            <div class="card-body"><div class="nodata">Not enough data in this period.</div></div>
          {/if}
        </div>
      {/each}
    </div>

    <!-- enforcement (reuses BlockedByLayer, real /api/fw/layers) -->
    <div class="section-title">Enforcement — what your firewall is actually stopping<span class="line"></span></div>
    <div class="stack-gap"><BlockedByLayer {period} /></div>

    <!-- world map + top countries -->
    <div class="grid cols-2 stack-gap start">
      <div class="card">
        <div class="card-h">
          <h3><Icon name="world" size={15} />World map</h3>
          <div class="map-toggle">
            <button class:active={mapKind === 'src'} onclick={() => (mapKind = 'src')}>Who's hitting us</button>
            <button class:active={mapKind === 'dest'} onclick={() => (mapKind = 'dest')}>Where traffic goes</button>
          </div>
        </div>
        <div class="card-body tight">
          {#if mapData.length}<WorldMap dots={mapData} kind={mapKind} />{:else}<div class="nodata pad">No country data in this period.</div>{/if}
        </div>
      </div>
      <div class="card">
        <div class="card-h"><h3><Icon name="map-pin" size={15} />Top countries</h3><span class="sub">{mapKind === 'src' ? 'source of attacks' : 'destination of traffic'}</span></div>
        <div class="card-body">
          {#if mapData.length}
            {@const mx = maxOf(mapData)}
            <div class="rows">{#each mapData.slice(0, 10) as row}{@render cRow(row.country, row.count, mx, mapKind === 'src' ? 'var(--destructive)' : 'var(--info)', fmtNumber)}{/each}</div>
          {:else}<div class="nodata pad">No country data yet.</div>{/if}
        </div>
      </div>
    </div>

    <!-- devices -->
    <div class="section-title">Devices<span class="line"></span></div>
    <div class="card">
      <div class="card-h"><h3><Icon name="activity" size={15} />Top devices by data used</h3><span class="sub">click a device for full detail</span></div>
      <div class="card-body">
        {#if topTalkers.length}
          {@const mx = maxOf(topTalkers, 'total')}
          <div class="rows">
            {#each topTalkers as t}
              <button class="row clickable" onclick={() => openClient(t.peer)}>
                <span class="flag"><Icon name="device-desktop" size={15} /></span>
                <span class="label wide name">{t.name || t.peer}</span>
                <div class="track"><div class="fill" style="width:{(t.total / mx) * 100}%; background:var(--tx)"></div></div>
                <span class="val">{fmtBytes(t.total)}</span>
              </button>
            {/each}
          </div>
        {:else}<div class="nodata pad">No per-device byte data yet — enable the conntrack watcher in Settings → Logs Watchers.</div>{/if}
      </div>
    </div>

    {#if Object.values(data).every((d) => !d || d.error || d.total_count === 0)}
      <EmptyState icon="chart-bar" title="No log data in this period" description="Check that log watchers are enabled and Traefik/AdGuard are producing output." />
    {/if}

  <!-- ═══════════ PER CLIENT ═══════════ -->
  {:else if selectedType === 'client'}
    <div class="card stack-gap">
      <div class="card-h"><h3><Icon name="user" size={15} />Pick a device</h3>
        <Select value={selectedPeer} onchange={(e) => (selectedPeer = e.target.value)} class="w-full sm:w-64">
          <option value="">Choose a client…</option>
          {#each peerList as p}<option value={p.value}>{p.label}</option>{/each}
        </Select>
      </div>
      {#if selectedPeer}
        <div class="client-card">
          <span class="client-avatar"><Icon name="device-desktop" size={19} /></span>
          <div><div class="client-name">{peerList.find((p) => p.value === selectedPeer)?.label || selectedPeer}</div><div class="client-ip">{selectedPeer}</div></div>
        </div>
      {/if}
    </div>

    {#if !selectedPeer}
      <EmptyState icon="user" title="Pick a device" description="Choose a client above to see what it talked to, how much it sent and received, and which countries it reached." />
    {:else if peerUsageLoading}
      <div class="center"><LoadingSpinner /></div>
    {:else if peerUsage?.error}
      <div class="errbox">{peerUsage.error}</div>
    {:else if peerUsage}
      <div class="grid cols-4 stack-gap">
        {@render statTile('upload', 'var(--tx)', fmtBytes(peerUsage.total_up), 'Uploaded')}
        {@render statTile('download', 'var(--info)', fmtBytes(peerUsage.total_down), 'Downloaded')}
        {@render statTile('activity', 'var(--primary)', fmtBytes((peerUsage.total_up || 0) + (peerUsage.total_down || 0)), 'Total traffic')}
        {@render statTile('globe', 'var(--success)', String(peerUsage.destinations?.length || 0), 'Destinations')}
      </div>

      {#if peerUsage.series?.length}
        <div class="card stack-gap">
          <div class="card-h"><h3><Icon name="activity" size={15} />Data over time</h3><span class="sub">upload + download, this device</span></div>
          <div class="card-body"><UPlotChart data={[peerUsage.series.map((b) => b.ts), peerUsage.series.map((b) => b.total)]} series={[{ label: 'Traffic', stroke: '--primary', fill: 0.18 }]} height={160} yFormat={fmtBytes} legend={false} /></div>
        </div>
      {/if}

      <div class="grid cols-2">
        <div class="card">
          <div class="card-h"><h3><Icon name="globe" size={15} />Talked to</h3><span class="sub">by total bytes</span></div>
          <div class="card-body">
            <div class="ud-legend"><span><span class="sw" style="background:var(--info)"></span>download</span><span><span class="sw" style="background:var(--tx)"></span>upload</span></div>
            {#if peerUsage.destinations?.length}
              {@const mx = maxOf(peerUsage.destinations, 'bytes_total')}
              <div class="rows">
                {#each [...peerUsage.destinations].sort((a, b) => b.bytes_total - a.bytes_total).slice(0, 12) as dst}
                  {@const t = dst.bytes_total || 1}
                  <div class="row">
                    <span class="flag"><CountryFlag code={dst.country} size="sm" /></span>
                    <span class="label wide">{dst.domain || dst.dest_ip}</span>
                    <div class="track"><div class="split" style="width:{(dst.bytes_total / mx) * 100}%">
                      <span style="width:{((dst.bytes_down || 0) / t) * 100}%; background:var(--info)"></span>
                      <span style="width:{((dst.bytes_up || 0) / t) * 100}%; background:var(--tx)"></span>
                    </div></div>
                    <span class="val">{fmtBytes(dst.bytes_total)}</span>
                  </div>
                {/each}
              </div>
            {:else}<div class="nodata pad">No per-destination byte data yet.</div>{/if}
          </div>
        </div>
        <div class="card">
          <div class="card-h"><h3><Icon name="map-pin" size={15} />By country</h3></div>
          <div class="card-body">
            {#if clientCountries.length}
              {@const mx = clientCountries[0].count}
              <div class="rows">{#each clientCountries as row}{@render cRow(row.country, row.count, mx, 'var(--primary)', fmtBytes)}{/each}</div>
            {:else}<div class="nodata pad">No country data.</div>{/if}
          </div>
        </div>
      </div>
    {/if}

  <!-- ═══════════ TYPE PANELS ═══════════ -->
  {:else}
    {@const meta = typeMeta[selectedType]}
    {@const d = data[selectedType]}
    {@const tr = d && !d.error ? trend(d.total_count, d.previous_total) : null}
    {@const good = trGood(selectedType, tr)}

    {#if !d}
      <div class="center"><LoadingSpinner /></div>
    {:else if d.error}
      <div class="errbox">{d.error}</div>
    {:else if d.total_count === 0}
      <EmptyState icon="inbox" title="No {meta.label.toLowerCase()} events yet" description={typeDesc[selectedType]} />
    {:else}
      <div class="banner">
        <span class="icon-badge sm" style="background:color-mix(in oklch, {meta.cvar} 15%, var(--card)); color:{meta.cvar}"><Icon name={meta.icon} size={16} /></span>
        <div><div class="eyebrow">{meta.label} · {meta.plain}</div><div class="line">{typeDesc[selectedType]}</div></div>
      </div>

      <div class="grid cols-4 stack-gap">
        {#if selectedType === 'inbound'}
          {@render statTile('arrow-down', meta.cvar, fmtNumber(d.total_count), 'Total requests')}
          {@render statTile('user', 'var(--primary)', fmtNumber(d.unique_visitors), 'Unique visitors')}
          {@render statTile('activity', 'var(--warning)', fmtBytes(d.total_bytes), 'Bandwidth')}
          {@render statTile('check', 'var(--success)', successRate(d) + '%', 'Success rate')}
        {:else if selectedType === 'dns'}
          {@render statTile('globe', meta.cvar, fmtNumber(d.total_count), 'Total queries')}
          {@render statTile('user', 'var(--primary)', fmtNumber(d.unique_visitors), 'Unique clients')}
          {@render statTile('check', 'var(--success)', pct(d.cached_count, d.total_count) + '%', 'Cache rate')}
          {@render statTile('ban', 'var(--destructive)', pct(d.blocked_count, d.total_count) + '%', 'Blocked rate')}
        {:else if selectedType === 'outbound'}
          {@render statTile('arrow-up', meta.cvar, fmtNumber(d.total_count), 'Total connections')}
          {@render statTile('user', 'var(--primary)', fmtNumber(d.unique_visitors), 'Active sources')}
          {@render statTile('activity', 'var(--warning)', fmtBytes(d.total_bytes), 'Bandwidth')}
          {@render statTile('globe', 'var(--info)', fmtNumber(d.top_dest_ips?.length || 0), 'Destinations')}
        {:else}
          {@render statTile('shield', meta.cvar, fmtNumber(d.total_count), 'Total blocks')}
          {@render statTile('user', 'var(--primary)', fmtNumber(d.unique_visitors), 'Unique attackers')}
          {@render statTile('filter', 'var(--warning)', String(d.top_rules?.length || 0), 'Rules fired')}
          {@render statTile('plug', 'var(--info)', d.top_dest_ports?.[0]?.status || '—', 'Most-probed port')}
        {/if}
      </div>

      {#if tr && period !== 'all'}
        <div class="trend-badge" style="color:{good ? 'var(--success)' : 'var(--destructive)'}">
          <Icon name={tr.dir === 'up' ? 'arrow-up' : 'arrow-down'} size={13} /><span>{Math.abs(tr.pct).toFixed(1)}%</span>
          <span class="muted">vs previous {periodLabelFull}{selectedType === 'fw' ? (good ? ' — fewer attacks' : ' — more attacks') : ''}</span>
        </div>
      {/if}

      {#if d.time_series?.length}
        <div class="card stack-gap">
          <div class="card-h"><h3>Events over time</h3><span class="sub">{periodLabelFull}</span></div>
          <div class="card-body tight"><UPlotChart data={[d.time_series.map((b) => b.ts), d.time_series.map((b) => b.count)]} series={[{ label: meta.label, stroke: meta.stroke, fill: 0.18 }]} height={170} legend={false} /></div>
        </div>
      {/if}

      <!-- type-specific breakdowns -->
      {#if selectedType === 'inbound'}
        <div class="masonry stack-gap">
          <div class="mcol">
            {@render countriesCard('Top countries', 'who is visiting', d.top_countries, meta.cvar)}
            {@render listCard('Top domains', d.top_domains, 'domain', meta.cvar, {})}
            {@render ipCard('Top visitors', d.top_clients, meta.cvar)}
          </div>
          <div class="mcol">
            <div class="card"><div class="card-h"><h3>HTTP status</h3><span class="sub">how requests were answered</span></div><div class="card-body"><Donut segments={donutSeg(d.http_status, httpColor)} format={fmtNumber} /></div></div>
            {@render pathCard('Top paths', d.top_paths, meta.cvar)}
          </div>
        </div>
      {:else if selectedType === 'dns'}
        <div class="masonry stack-gap">
          <div class="mcol">
            <div class="card"><div class="card-h"><h3>Response codes</h3></div><div class="card-body"><Donut segments={donutSeg(d.status_counts, dnsColor)} format={fmtNumber} /></div></div>
            {@render listCard('Top allowed domains', d.top_allowed, 'domain', 'var(--success)', { sub: 'most resolved' })}
          </div>
          <div class="mcol">
            <div class="card"><div class="card-h"><h3>Query types</h3></div><div class="card-body"><Donut segments={donutSeg(d.query_types, (_, i) => CYCLE[i % CYCLE.length])} format={fmtNumber} /></div></div>
            {@render listCard('Top blocked domains', d.top_blocked, 'domain', 'var(--destructive)', { sub: 'ads & trackers' })}
          </div>
        </div>
      {:else if selectedType === 'outbound'}
        <div class="masonry stack-gap">
          <div class="mcol">
            {@render mapCard('World map', 'where your traffic goes', d.top_countries, 'dest')}
            {@render ipCard('Top destinations', d.top_dest_ips, meta.cvar, { dest: true })}
          </div>
          <div class="mcol">
            <div class="card"><div class="card-h"><h3>Protocol mix</h3></div><div class="card-body"><Donut segments={donutSeg(d.protocols, (_, i) => (i === 0 ? 'var(--tx)' : 'var(--info)'))} format={fmtNumber} /></div></div>
            {@render countriesCard('Top countries', 'destination', d.top_countries, 'var(--info)')}
          </div>
        </div>
      {:else}
        <div class="masonry stack-gap">
          <div class="mcol">
            <div class="card"><div class="card-h"><h3>Most-probed ports</h3></div><div class="card-body"><Donut segments={donutSeg(d.top_dest_ports, (_, i) => CYCLE[i % CYCLE.length])} format={fmtNumber} /></div></div>
            {@render ipCard('Top attacker IPs', d.top_clients, meta.cvar)}
          </div>
          <div class="mcol">
            {@render mapCard('World map', 'who is attacking', d.top_countries, 'src')}
            {@render countriesCard('Top countries', 'source of attacks', d.top_countries, meta.cvar)}
          </div>
        </div>
      {/if}
    {/if}
  {/if}
</div>

<!-- ─────────── reusable snippets ─────────── -->
{#snippet footCell(icon, v, l)}
  <span class="cell"><Icon name={icon} size={13} /><span><span class="v">{v}</span><span class="l">{l}</span></span></span>
{/snippet}

{#snippet statTile(icon, cvar, value, label)}
  <div class="stat-tile">
    <span class="ic" style="background:color-mix(in oklch, {cvar} 15%, var(--card)); color:{cvar}"><Icon name={icon} size={18} /></span>
    <div><div class="stat-val">{value}</div><div class="stat-lab">{label}</div></div>
  </div>
{/snippet}

{#snippet cRow(code, count, max, cvar, fmt)}
  <div class="row">
    <span class="flag"><CountryFlag {code} size="sm" /></span>
    <span class="label">{code || '—'}</span>
    <div class="track"><div class="fill" style="width:{max ? (count / max) * 100 : 0}%; background:{cvar}"></div></div>
    <span class="val">{fmt(count)}</span>
  </div>
{/snippet}

{#snippet listCard(title, rows, key, cvar, opts)}
  <div class="card">
    <div class="card-h"><h3>{title}</h3>{#if opts.sub}<span class="sub">{opts.sub}</span>{/if}</div>
    <div class="card-body">
      {#if rows?.length}
        {@const mx = maxOf(rows)}
        <div class="rows">{#each rows as r}
          <div class="row">
            <span class="label {opts.wide ? 'wide' : ''}">{r[key]}</span>
            <div class="track"><div class="fill" style="width:{(r.count / mx) * 100}%; background:{cvar}"></div></div>
            <span class="val">{fmtNumber(r.count)}</span>
          </div>
        {/each}</div>
      {:else}<div class="nodata pad">No data.</div>{/if}
    </div>
  </div>
{/snippet}

{#snippet pathCard(title, rows, cvar)}
  <div class="card">
    <div class="card-h"><h3>{title}</h3></div>
    <div class="card-body">
      {#if rows?.length}
        {@const mx = maxOf(rows)}
        <div class="rows">{#each rows as r}
          <div class="row">
            <span class="label wide">{(r.domain || '') + (r.path || '')}</span>
            <div class="track"><div class="fill" style="width:{(r.count / mx) * 100}%; background:{cvar}"></div></div>
            <span class="val">{fmtNumber(r.count)}</span>
          </div>
        {/each}</div>
      {:else}<div class="nodata pad">No data.</div>{/if}
    </div>
  </div>
{/snippet}

{#snippet ipCard(title, rows, cvar, opts = {})}
  <div class="card">
    <div class="card-h"><h3>{title}</h3>{#if !opts.dest}<span class="sub">by IP</span>{/if}</div>
    <div class="card-body">
      {#if rows?.length}
        {@const mx = maxOf(rows)}
        <div class="rows">{#each rows as r}
          <div class="row">
            <span class="flag"><CountryFlag code={r.country} size="sm" /></span>
            <span class="label {opts.wide ? 'wide' : ''}">{r.label || r.ip}</span>
            <div class="track"><div class="fill" style="width:{(r.count / mx) * 100}%; background:{cvar}"></div></div>
            <span class="val">{fmtNumber(r.count)}</span>
          </div>
        {/each}</div>
      {:else}<div class="nodata pad">No data.</div>{/if}
    </div>
  </div>
{/snippet}

{#snippet countriesCard(title, sub, rows, cvar)}
  <div class="card">
    <div class="card-h"><h3><Icon name="map-pin" size={15} />{title}</h3><span class="sub">{sub}</span></div>
    <div class="card-body">
      {#if rows?.length}
        {@const mx = maxOf(rows)}
        <div class="rows">{#each rows as r}{@render cRow(r.country, r.count, mx, cvar, fmtNumber)}{/each}</div>
      {:else}<div class="nodata pad">No country data.</div>{/if}
    </div>
  </div>
{/snippet}

{#snippet mapCard(title, sub, rows, kind)}
  <div class="card">
    <div class="card-h"><h3><Icon name="world" size={15} />{title}</h3><span class="sub">{sub}</span></div>
    <div class="card-body tight">{#if rows?.length}<WorldMap dots={rows} {kind} />{:else}<div class="nodata pad">No country data.</div>{/if}</div>
  </div>
{/snippet}

<style>
  .analytics {
    --acc: 250 20% 50%;
    --a-radius: 0.6rem;
    color: var(--foreground);
  }
  .center { display: flex; justify-content: center; padding: 48px 0; }
  .errbox { border: 1px solid color-mix(in oklch, var(--destructive) 30%, var(--border)); background: color-mix(in oklch, var(--destructive) 6%, var(--card)); color: var(--destructive); padding: 14px 16px; border-radius: var(--a-radius); font-size: 13px; }
  .muted { color: var(--muted-foreground); font-weight: 500; }
  .nodata { color: var(--muted-foreground); font-size: 12px; }
  .nodata.pad { padding: 18px 2px; }

  /* masthead */
  .icon-badge { width: 30px; height: 30px; border-radius: 8px; display: flex; align-items: center; justify-content: center; background: color-mix(in oklch, var(--primary) 12%, var(--card)); color: var(--primary); flex-shrink: 0; }
  .icon-badge.sm { width: 30px; height: 30px; border-radius: 8px; }

  /* toolbar: segmented tab menu (smaller) + period controls */
  .toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-top: 16px; margin-bottom: 18px; }
  .controls { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .tabs { display: flex; gap: 2px; background: var(--muted); padding: 3px; border-radius: calc(var(--a-radius) + 3px); flex-wrap: wrap; }
  .tab { display: inline-flex; align-items: center; gap: 5px; border: 0; background: transparent; cursor: pointer; padding: 5px 11px; border-radius: calc(var(--a-radius) - 1px); font-size: 11.5px; font-weight: 600; color: var(--muted-foreground); }
  .tab:hover { color: var(--foreground); }
  .tab.active { background: var(--card); color: var(--foreground); box-shadow: 0 1px 2px rgba(0, 0, 0, 0.08); }
  .tab .tdot { width: 6px; height: 6px; border-radius: 99px; flex-shrink: 0; }
  .map-toggle { display: flex; gap: 2px; background: var(--muted); padding: 3px; border-radius: 9px; }
  .map-toggle button { border: 0; background: transparent; padding: 5px 10px; font-size: 11px; font-weight: 700; border-radius: 6px; cursor: pointer; color: var(--muted-foreground); }
  .map-toggle button.active { background: var(--card); color: var(--foreground); }

  /* cards */
  .card { background: var(--card); border: 1px solid var(--border); border-radius: var(--a-radius); overflow: hidden; display: flex; flex-direction: column; }
  .card-h { padding: 13px 16px; border-bottom: 1px solid var(--border); background: color-mix(in oklch, var(--muted) 55%, transparent); display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
  .card-h h3 { margin: 0; font-size: 13px; font-weight: 700; display: flex; align-items: center; gap: 7px; }
  .card-h.compact { padding: 10px 12px; }
  .card-h.compact h3 { font-size: 12px; }
  .card-h .sub { font-size: 11.5px; color: var(--muted-foreground); font-weight: 600; }
  .card-body { padding: 16px; flex: 1; }
  .card-body.tight { padding: 0; }

  .grid { display: grid; gap: 14px; }
  .grid.cols-4 { grid-template-columns: repeat(4, 1fr); }
  .grid.cols-2 { grid-template-columns: repeat(2, 1fr); }
  /* masonry: two independent columns, each card at its natural height */
  .masonry { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; align-items: start; }
  .mcol { display: flex; flex-direction: column; gap: 14px; min-width: 0; }
  @media (max-width: 720px) { .masonry { grid-template-columns: 1fr; } }
  .grid.start { align-items: start; }
  .stack-gap { margin-bottom: 14px; }
  @media (max-width: 980px) { .grid.cols-4 { grid-template-columns: repeat(2, 1fr); } .grid.cols-2 { grid-template-columns: 1fr; } }
  @media (max-width: 620px) { .grid.cols-4 { grid-template-columns: 1fr; } }

  /* banner */
  .banner { border: 1px solid color-mix(in oklch, var(--primary) 25%, var(--border)); background: linear-gradient(90deg, color-mix(in oklch, var(--primary) 7%, var(--card)), color-mix(in oklch, var(--success) 6%, var(--card))); border-radius: var(--a-radius); padding: 14px 16px; display: flex; gap: 12px; align-items: flex-start; margin-bottom: 16px; }
  .banner .eyebrow { font-size: 10.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted-foreground); margin-bottom: 3px; }
  .banner .line { font-size: 13.5px; color: var(--muted-foreground); line-height: 1.6; }
  .banner .line b { color: var(--foreground); font-weight: 700; font-variant-numeric: tabular-nums; }
  .inline-flag { display: inline-flex; vertical-align: -2px; }
  .sep { margin: 0 7px; color: var(--muted-foreground); opacity: 0.4; }

  /* KPI */
  .kpi { border: 1px solid var(--border); border-radius: var(--a-radius); background: var(--card); cursor: pointer; text-align: left; display: flex; flex-direction: column; width: 100%; padding: 0; color: inherit; }
  .kpi:hover { box-shadow: 0 2px 10px rgba(0, 0, 0, 0.08); }
  .kpi .top { display: flex; align-items: center; gap: 10px; padding: 12px 12px 0; }
  .kpi .ic { width: 34px; height: 34px; border-radius: 9px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .kpi .ttl { font-size: 13px; font-weight: 700; }
  .kpi .plain { font-size: 11px; color: var(--muted-foreground); }
  .kpi .chev { color: var(--muted-foreground); margin-left: auto; flex-shrink: 0; display: flex; }
  .kpi .num { font-size: 27px; font-weight: 800; letter-spacing: -0.02em; padding: 8px 12px 0; font-variant-numeric: tabular-nums; }
  .kpi .trend { display: flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 600; padding: 2px 12px 8px; }
  .kpi .foot { display: flex; justify-content: space-between; gap: 10px; border-top: 1px solid var(--border); padding: 9px 12px; margin-top: auto; }
  .kpi .cell { display: flex; align-items: center; gap: 6px; min-width: 0; color: var(--muted-foreground); }
  .kpi .cell .v { font-size: 12px; font-weight: 700; font-variant-numeric: tabular-nums; color: var(--foreground); display: block; }
  .kpi .cell .l { font-size: 9.5px; color: var(--muted-foreground); text-transform: uppercase; letter-spacing: 0.03em; display: block; }

  /* rows */
  .rows { display: flex; flex-direction: column; gap: 9px; }
  .row { display: flex; align-items: center; gap: 10px; font-size: 12.5px; border-radius: 6px; padding: 3px 4px; margin: 0 -4px; width: 100%; border: 0; background: transparent; color: inherit; text-align: left; }
  button.row.clickable { cursor: pointer; }
  button.row.clickable:hover { background: var(--muted); }
  .row .flag { width: 18px; display: flex; justify-content: center; flex-shrink: 0; color: var(--muted-foreground); }
  .row .label { width: 118px; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; }
  .row .label.wide { width: 200px; }
  .row .label.name { font-family: inherit; font-weight: 600; }
  .row .track { flex: 1; height: 7px; border-radius: 99px; background: var(--muted); overflow: hidden; display: flex; }
  .row .fill { height: 100%; border-radius: 99px; }
  .row .split { display: flex; height: 100%; }
  .row .split span { height: 100%; }
  .row .val { width: 62px; text-align: right; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px; flex-shrink: 0; font-variant-numeric: tabular-nums; }
  @media (max-width: 720px) { .row .label { width: 92px; } .row .label.wide { width: 120px; } }

  /* section titles */
  .section-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted-foreground); margin: 22px 2px 10px; display: flex; align-items: center; gap: 8px; }
  .section-title .line { flex: 1; height: 1px; background: var(--border); }

  /* stat tiles */
  .stat-tile { background: var(--card); border: 1px solid var(--border); border-radius: var(--a-radius); display: flex; flex-direction: row; align-items: center; gap: 12px; padding: 14px; }
  .stat-tile .ic { width: 38px; height: 38px; border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .stat-tile .stat-val { font-size: 22px; font-weight: 800; font-variant-numeric: tabular-nums; }
  .stat-tile .stat-lab { font-size: 11px; color: var(--muted-foreground); }

  .trend-badge { display: flex; align-items: center; gap: 5px; font-size: 12px; font-weight: 600; margin-bottom: 14px; }

  /* map toggle */

  /* per client */
  .client-card { display: flex; align-items: center; gap: 12px; padding: 14px 16px; border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .client-avatar { width: 38px; height: 38px; border-radius: 10px; background: color-mix(in oklch, var(--primary) 14%, var(--card)); color: var(--primary); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .client-name { font-size: 14px; font-weight: 700; }
  .client-ip { font-size: 11.5px; color: var(--muted-foreground); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .ud-legend { display: flex; gap: 14px; font-size: 11.5px; color: var(--muted-foreground); margin-bottom: 10px; }
  .ud-legend span { display: inline-flex; align-items: center; gap: 6px; }
  .ud-legend .sw { width: 9px; height: 9px; border-radius: 2px; }
</style>
