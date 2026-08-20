<script>
  import { onMount, onDestroy } from 'svelte'
  import { apiGet, apiPost, apiDelete, toast, confirm } from '../stores/app.js'
  import { serverStatsStore, wsConnected, subscribe, unsubscribe } from '../stores/websocket.js'
  import Icon from '../components/Icon.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import StatCard from '../components/StatCard.svelte'
  import Button from '../components/Button.svelte'
  import UPlotChart from '../components/UPlotChart.svelte'
  import Gauge from '../components/Gauge.svelte'
  import { timeAgo, formatBytes } from '$lib/utils/format.js'

  let { loading = $bindable(true), onLogout } = $props()
  let data = $state(null)
  let error = $state(null)

  async function load() {
    try { data = await apiGet('/api/server/security'); error = null }
    catch (e) { error = e.message }
    finally { loading = false }
  }
  onMount(() => {
    load()
    const t = setInterval(load, 30000)
    subscribe('server_stats') // ref-counted; app-wide sub keeps it alive too
    return () => clearInterval(t)
  })
  onDestroy(() => unsubscribe('server_stats'))

  // --- Live host stats: keep a rolling window from the server_stats channel ---
  const N = 60
  let xs = $state([]), cpuH = $state([]), memH = $state([]), rxH = $state([]), txH = $state([])
  let latest = $state(null)
  let lastTs = 0
  $effect(() => {
    const s = $serverStatsStore
    if (!s || s.ts === lastTs) return
    lastTs = s.ts
    latest = s
    const push = (arr, v) => (arr.length >= N ? [...arr.slice(1), v] : [...arr, v])
    xs = push(xs, s.ts)
    cpuH = push(cpuH, s.cpu ?? 0)
    memH = push(memH, s.mem_pct ?? 0)
    rxH = push(rxH, s.net?.rx ?? 0)
    txH = push(txH, s.net?.tx ?? 0)
  })

  const netData = $derived([xs, rxH, txH])
  const cmData = $derived([xs, cpuH, memH])
  const netSeries = [{ label: 'RX', stroke: '--rx', fill: 0.22 }, { label: 'TX', stroke: '--tx', fill: 0.22 }]
  const cmSeries = [{ label: 'CPU', stroke: '--cpu' }, { label: 'Memory', stroke: '--mem' }]
  const fmtRate = (v) => formatBytes(v) + '/s'
  const live = $derived($wsConnected && !!latest)
  const coreColor = (v) => (v >= 85 ? 'var(--destructive)' : v >= 60 ? 'var(--warning)' : 'var(--success)')

  async function banIP(ip) {
    if (!ip) return
    const ok = await confirm({ title: `Block ${ip}`, message: `Add a firewall block rule for ${ip}? It came from a sudo-escalation attempt.`, confirmText: 'Block', variant: 'destructive' })
    if (!ok) return
    try {
      await apiPost('/api/fw/entries', { type: 'ip', value: ip, action: 'block', direction: 'inbound', reason: 'server escalation (manual)' })
      toast(`Blocked ${ip}`, 'success')
    } catch (e) { toast('Failed to block: ' + e.message, 'error') }
  }
  async function forget(id) {
    try {
      await apiDelete(`/api/server/sudo-failure/${id}`)
      if (data?.sudo?.failed) data.sudo.failed = data.sudo.failed.filter(f => f.id !== id)
    } catch (e) { toast('Failed: ' + e.message, 'error') }
  }

  function isLocal(ip) { return !ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.') }
  function methodIcon(m) { return m === 'publickey' ? 'key' : m === 'password' ? 'lock' : 'terminal-2' }
  function certColor(s) { return s === 'expired' || s === 'critical' ? 'text-destructive' : s === 'warning' ? 'text-warning' : 'text-success' }
  function fmtUptime(secs) {
    if (!secs) return '—'
    const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600)
    return d > 0 ? `${d}d ${h}h` : `${h}h ${Math.floor((secs % 3600) / 60)}m`
  }

  // Access & escalation: show only what needs eyes — sessions connected now,
  // plus any alarming closed session (unexpected remote root). The full recent
  // count lives in the header badge instead of a long scroll.
  const shownLogins = $derived.by(() => {
    const recent = data?.logins?.recent || []
    const active = recent.filter(l => l.active)
    const alarms = recent.filter(l => !l.active && l.root && l.ip && !isLocal(l.ip))
    return [...active, ...alarms]
  })

  // Exposure: group listening ports by the process that owns them.
  const portGroups = $derived.by(() => {
    const m = new Map()
    for (const p of data?.ports?.listening || []) {
      const key = p.process || 'unknown'
      if (!m.has(key)) m.set(key, { process: key, ports: [], public: false })
      const g = m.get(key)
      g.ports.push(p)
      if (p.public) g.public = true
    }
    const arr = [...m.values()]
    arr.forEach(g => g.ports.sort((a, b) => (b.public - a.public) || (a.port - b.port)))
    arr.sort((a, b) => (b.public - a.public) || (b.ports.length - a.ports.length) || a.process.localeCompare(b.process))
    return arr
  })

  const verdict = $derived.by(() => {
    const s = data?.status || 'calm'
    const m = {
      calm: { dot: 'bg-success', title: 'Host looks clean — no unauthorized access.' },
      elevated: { dot: 'bg-warning', title: 'Elevated — worth a look.' },
      under_attack: { dot: 'bg-destructive', title: 'Warning — possible intrusion. Check the access list below.' },
    }
    return m[s] || m.calm
  })
  const sectionH = 'text-xs uppercase tracking-wide text-muted-foreground font-semibold'
  const card = 'bg-card border border-border rounded-xl p-4'
  const av = 'w-8 h-8 rounded-lg bg-muted/60 border border-border grid place-items-center shrink-0'
  const chip = 'text-[10px] px-1.5 py-0.5 rounded-full font-medium whitespace-nowrap'
  const l2 = 'text-[11px] text-muted-foreground font-mono truncate'
  const badge = 'normal-case tracking-normal text-[10px] px-1.5 py-0.5 rounded-full font-semibold'
</script>

<div class="space-y-4">
  <InfoCard icon="shield-lock" title="Server" description="What's happening on the host itself: live load, who logged in, privilege use, what's exposed, and system health. Read-only, from the server's own logs." />

  {#if error && !data}
    <div class="bg-destructive/10 border border-destructive/30 rounded-xl p-4 text-sm text-destructive">Couldn't load server security data: {error}</div>
  {:else if data}
    <!-- Verdict -->
    <div class="{card} flex items-center gap-4">
      <span class="w-3 h-3 rounded-full {verdict.dot} shrink-0"></span>
      <div class="text-sm font-semibold text-foreground">{verdict.title}</div>
    </div>

    <!-- Live host stats -->
    <h2 class="{sectionH} mt-2 mb-2 flex items-center gap-2">Live
      <span class="{badge} {live ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'} flex items-center gap-1">
        {#if live}<span class="w-1.5 h-1.5 rounded-full bg-success"></span>streaming{:else}connecting…{/if}</span></h2>
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <!-- Current server load -->
      <div class="{card}">
        <h3 class="text-sm font-semibold mb-3 flex items-center gap-2"><Icon name="gauge" size={16} class="text-primary" />Current server load</h3>
        <div class="flex items-center gap-5">
          <Gauge value={latest?.cpu ?? 0} label="CPU utilization" />
          <div class="flex-1 min-w-0 space-y-1.5 text-sm">
            <div class="flex items-center justify-between"><span class="text-muted-foreground">Load 1m</span><b class="tabular-nums">{latest?.load?.[0]?.toFixed(2) ?? '—'}</b></div>
            <div class="flex items-center justify-between"><span class="text-muted-foreground">Load 5m</span><b class="tabular-nums">{latest?.load?.[1]?.toFixed(2) ?? '—'}</b></div>
            <div class="flex items-center justify-between"><span class="text-muted-foreground">Load 15m</span><b class="tabular-nums">{latest?.load?.[2]?.toFixed(2) ?? '—'}</b></div>
            <div class="flex items-center justify-between border-t border-border pt-1.5"><span class="text-muted-foreground">CPU cores</span><b class="tabular-nums">{latest?.cores_n ?? '—'}</b></div>
            <div class="flex items-center justify-between"><span class="text-muted-foreground">Uptime</span><b>{fmtUptime(latest?.uptime ?? data.host.uptime_seconds)}</b></div>
          </div>
        </div>
      </div>

      <!-- CPU cores -->
      <div class="{card}">
        <h3 class="text-sm font-semibold mb-3 flex items-center gap-2"><Icon name="cpu" size={16} class="text-primary" />CPU cores<span class="text-muted-foreground font-normal text-xs ml-auto">per-core %</span></h3>
        {#if latest?.cores?.length}
          <div class="flex items-end gap-1.5 h-[132px]">
            {#each latest.cores as v, i}
              <div class="flex-1 flex flex-col items-center justify-end gap-1 min-w-0" title="core {i}: {v.toFixed(1)}%">
                <span class="text-[9px] font-semibold tabular-nums text-muted-foreground">{Math.round(v)}</span>
                <div class="w-full rounded-t transition-[height] duration-300" style="height:{Math.max(2, v)}%; background:{coreColor(v)}"></div>
                <span class="text-[9px] text-muted-foreground">c{i}</span>
              </div>
            {/each}
          </div>
        {:else}
          <div class="h-[132px] grid place-items-center text-xs text-muted-foreground">waiting for first sample…</div>
        {/if}
      </div>

      <!-- Network I/O -->
      <div class="{card}">
        <h3 class="text-sm font-semibold mb-2 flex items-center gap-2"><Icon name="network" size={16} class="text-primary" />Network I/O
          <span class="ml-auto flex items-center gap-3 text-[11px] font-normal text-muted-foreground">
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-sm" style="background:var(--rx)"></span>RX {latest ? fmtRate(latest.net?.rx ?? 0) : '—'}</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-sm" style="background:var(--tx)"></span>TX {latest ? fmtRate(latest.net?.tx ?? 0) : '—'}</span>
          </span></h3>
        <UPlotChart data={netData} series={netSeries} height={150} yFormat={fmtRate} />
      </div>

      <!-- CPU / memory -->
      <div class="{card}">
        <h3 class="text-sm font-semibold mb-2 flex items-center gap-2"><Icon name="chart-line" size={16} class="text-primary" />CPU / memory
          <span class="ml-auto flex items-center gap-3 text-[11px] font-normal text-muted-foreground">
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-sm" style="background:var(--cpu)"></span>CPU {latest ? Math.round(latest.cpu) + '%' : '—'}</span>
            <span class="flex items-center gap-1"><span class="w-2 h-2 rounded-sm" style="background:var(--mem)"></span>Mem {latest ? Math.round(latest.mem_pct) + '%' : '—'}</span>
          </span></h3>
        <UPlotChart data={cmData} series={cmSeries} height={150} yRange={[0, 100]} yUnit="%" />
        {#if latest}<div class="text-[11px] text-muted-foreground mt-1">{formatBytes(latest.mem_used)} / {formatBytes(latest.mem_total)} used</div>{/if}
      </div>
    </div>

    <!-- Who touched the server: logins + sudo escalation, combined -->
    <h2 class="{sectionH} mt-2 mb-2 flex items-center gap-2">Who touched the server
      <span class="{badge} bg-destructive/10 text-destructive">breach watch</span></h2>
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div class="{card} lg:col-span-2">
        <h3 class="text-sm font-semibold mb-3 flex items-center gap-2"><Icon name="terminal-2" size={16} class="text-primary" />Access &amp; escalation
          <span class="{badge} bg-muted text-muted-foreground ml-auto">{data.logins.recent.length} login{data.logins.recent.length === 1 ? '' : 's'} recorded</span></h3>
        {#if !shownLogins.length && !data.sudo.failed?.length}
          <div class="flex flex-col items-center justify-center py-8 text-center text-muted-foreground">
            <Icon name="terminal-2" size={26} class="opacity-40 mb-2" />
            <div class="text-sm">No active sessions or sudo failures.</div>
            {#if data.logins.recent.length}<div class="text-[11px] mt-1">{data.logins.recent.length} past login{data.logins.recent.length === 1 ? '' : 's'} in history — none connected now.</div>{/if}
          </div>
        {:else}
          <div class="divide-y divide-border">
            <!-- connected-now sessions + alarming closed sessions -->
            {#each shownLogins as l}
              {@const alarm = l.root && l.ip && !isLocal(l.ip)}
              <div class="flex items-center gap-2.5 py-2 {alarm ? 'bg-destructive/10 -mx-2 px-2 rounded-lg' : ''}">
                <span class="{av} {alarm ? 'border-destructive/50 text-destructive' : 'text-muted-foreground'}"><Icon name={methodIcon(l.method)} size={15} /></span>
                <div class="flex-1 min-w-0">
                  <div class="text-[13px] font-medium flex items-center gap-1.5 {alarm ? 'text-destructive' : 'text-foreground'}">{l.user}
                    {#if l.active}<span class="{chip} bg-success/15 text-success flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-success"></span>active</span>{/if}
                    <span class="{chip} bg-muted text-muted-foreground">{l.method}</span>
                    {#if l.root}<span class="{chip} {alarm ? 'bg-destructive/15 text-destructive' : 'bg-muted text-muted-foreground'}">{alarm ? 'unexpected root' : 'root'}</span>{/if}
                    {#if isLocal(l.ip)}<span class="{chip} bg-success/15 text-success">local</span>{/if}</div>
                  <div class="{l2}">{isLocal(l.ip) ? 'local session' : l.ip}{l.country ? ' · ' + l.country : ''}{l.owner ? ' · ' + l.owner : ''} · {l.active ? 'connected now · since ' + timeAgo(l.when) : timeAgo(l.when)}</div>
                </div>
                {#if alarm}<Button variant="destructive" size="xs" icon="ban" onclick={() => banIP(l.ip)}>Ban</Button>{/if}
              </div>
            {/each}
            <!-- sudo failures (escalation) -->
            {#each data.sudo.failed || [] as f}
              {@const remote = f.ip && !isLocal(f.ip)}
              <div class="flex items-center gap-2.5 py-2 {remote ? 'bg-destructive/10 -mx-2 px-2 rounded-lg' : ''}">
                <span class="{av} {remote ? 'border-destructive/50 text-destructive' : 'text-warning'}"><Icon name="alert-triangle" size={15} /></span>
                <div class="flex-1 min-w-0">
                  <div class="text-[13px] font-medium flex items-center gap-1.5 text-foreground">{f.user || 'unknown'}
                    <span class="{chip} bg-warning/15 text-warning">sudo failed</span>
                    {#if f.command}<span class="text-muted-foreground font-normal text-xs truncate">→ {f.command}</span>{/if}</div>
                  <div class="{l2}">{f.tty || '—'} · {f.ip ? (isLocal(f.ip) ? 'local' : f.ip) : 'session closed'} · {timeAgo(f.when)}</div>
                </div>
                <div class="flex items-center gap-1.5 shrink-0">
                  {#if remote}<Button variant="destructive" size="xs" icon="ban" onclick={() => banIP(f.ip)}>Ban</Button>{/if}
                  <Button variant="ghost" size="xs" icon="x" onclick={() => forget(f.id)}>Forget</Button>
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>

      <div class="{card}">
        <h3 class="text-sm font-semibold mb-0.5 flex items-center gap-2"><Icon name="hammer" size={16} class="text-destructive" />Brute-force blocked</h3>
        <p class="text-[11px] text-muted-foreground mb-3">Failed SSH — last hour.</p>
        <div class="text-3xl font-bold tabular-nums text-destructive">{data.logins.failed_1h.toLocaleString()}</div>
        <div class="text-xs text-muted-foreground mt-1">from {data.logins.failed_ips_1h} IP{data.logins.failed_ips_1h === 1 ? '' : 's'}{#if data.logins.failed_prev_1h} · prev hour {data.logins.failed_prev_1h}{/if}</div>
        <div class="text-[11px] text-muted-foreground mt-3 pt-3 border-t border-dashed border-border">0 is normal if SSH is firewalled — attackers are dropped at L3 before sshd logs them.</div>
      </div>
    </div>

    <!-- Privilege & persistence -->
    <h2 class="{sectionH} mt-2 mb-2 flex items-center gap-2">Privilege &amp; persistence
      <span class="{badge} bg-success/10 text-success">from logs you already have</span></h2>
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div class="{card}">
        <h3 class="text-sm font-semibold mb-3 flex items-center gap-2"><Icon name="key" size={16} class="text-primary" />Privileged actions</h3>
        <div class="flex items-center justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Failed sudo (24h)</span><span class="tabular-nums font-medium {data.sudo.failures_24h > 0 ? 'text-warning' : 'text-success'}">{data.sudo.failures_24h}</span></div>
        <div class="flex items-center justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">New users / groups</span><span class="tabular-nums font-medium {(data.accounts.new_users.length + data.accounts.new_groups.length) > 0 ? 'text-warning' : 'text-success'}">{data.accounts.new_users.length + data.accounts.new_groups.length}</span></div>
        {#if data.sudo.recent.length}
          <div class="divide-y divide-border mt-1">
            {#each data.sudo.recent.slice().reverse().slice(0, 5) as sd}
              <div class="py-1.5"><div class="text-xs font-medium text-foreground">{sd.user}</div><div class="text-[11px] text-muted-foreground font-mono truncate">{sd.command}</div></div>
            {/each}
          </div>
        {:else}
          <div class="text-xs text-muted-foreground py-3 text-center">No sudo activity recorded.</div>
        {/if}
      </div>

      <div class="{card}">
        <h3 class="text-sm font-semibold mb-0.5 flex items-center gap-2"><Icon name="network" size={16} class="text-primary" />Phone-home watch</h3>
        <p class="text-[11px] text-muted-foreground mb-2">Where the server is reaching out — a reverse shell / beacon shows here.</p>
        <div class="flex items-baseline gap-2">
          <span class="text-2xl font-bold tabular-nums {data.phone_home.external > 0 ? 'text-foreground' : 'text-success'}">{data.phone_home.external}</span>
          <span class="text-xs text-muted-foreground">external destination{data.phone_home.external === 1 ? '' : 's'}</span>
        </div>
        {#if data.phone_home.destinations?.length}
          <div class="mt-2 pt-2 border-t border-dashed border-border divide-y divide-border/60">
            {#each data.phone_home.destinations.slice(0, 6) as d}
              <div class="flex items-center gap-2 py-1.5">
                <Icon name="arrow-up-right" size={13} class="text-muted-foreground shrink-0" />
                <div class="min-w-0 flex-1">
                  <div class="text-xs font-mono text-foreground truncate">{d.ip}{d.port ? ':' + d.port : ''}</div>
                  {#if d.process || d.owner || d.country}
                    <div class="text-[11px] text-muted-foreground truncate">{#if d.process}<span class="font-medium text-foreground/80">{d.process}</span>{/if}{#if d.owner}{d.process ? ' · ' : ''}{d.owner}{/if}{#if d.country} · {d.country}{/if}</div>
                  {/if}
                </div>
              </div>
            {/each}
          </div>
        {:else}
          <div class="text-xs text-muted-foreground py-2">No outbound connections to external hosts.</div>
        {/if}
      </div>

      <div class="{card}">
        <h3 class="text-sm font-semibold mb-3 flex items-center gap-2"><Icon name="clock" size={16} class="text-primary" />Persistence watch</h3>
        <div class="flex items-center justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Cron files changed (7d)</span><span class="tabular-nums font-medium {data.persistence.cron_recent > 0 ? 'text-warning' : 'text-success'}">{data.persistence.cron_recent}</span></div>
        <div class="flex items-center justify-between text-sm py-1.5"><span class="text-muted-foreground">Packages installed (7d)</span><span class="tabular-nums font-medium text-foreground">{data.persistence.packages_installed}</span></div>
        <div class="text-[11px] text-muted-foreground mt-2">footholds an intruder plants to survive a reboot · from dpkg.log + cron files</div>
      </div>
    </div>

    <!-- Package changes -->
    <h2 class="{sectionH} mt-2 mb-2">Package changes</h2>
    <div class="{card}">
      {#if data.packages.length}
        <div class="divide-y divide-border">
          {#each data.packages.slice().reverse() as p}
            <div class="flex items-center justify-between py-1.5 text-xs"><span class="font-mono text-foreground truncate">{p.package} <span class="text-muted-foreground">{p.version}</span></span><span class="text-muted-foreground shrink-0 ml-2">{p.action} · {timeAgo(p.when)}</span></div>
          {/each}
        </div>
      {:else}
        <div class="flex flex-col items-center justify-center py-6 text-center text-muted-foreground">
          <Icon name="package" size={24} class="opacity-40 mb-2" />
          <div class="text-sm">No packages installed, upgraded, or removed in the last 7 days.</div>
          <div class="text-[11px] mt-1">Rows appear here (from <span class="font-mono">dpkg.log</span>) when apt installs or updates something — a tripwire for an intruder installing tools.</div>
        </div>
      {/if}
    </div>

    <!-- Exposure: listening ports, grouped by the process that owns them -->
    <h2 class="{sectionH} mt-2 mb-2 flex items-center gap-2">Exposure — listening ports
      <span class="{badge} {data.ports.public > 0 ? 'bg-warning/10 text-warning' : 'bg-muted text-muted-foreground'} ml-auto">{data.ports.public} public · {data.ports.listening.length} total</span></h2>
    <div class="{card}">
      <p class="text-[11px] text-muted-foreground mb-3">Grouped by process. Public listeners are reachable from other machines — make sure each is intentional.</p>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        {#each portGroups as g}
          <div class="border border-border rounded-lg p-3 {g.public ? 'bg-warning/5' : ''}">
            <div class="flex items-center gap-2 mb-2">
              <Icon name={g.public ? 'world' : 'app-window'} size={15} class={g.public ? 'text-warning' : 'text-muted-foreground'} />
              <span class="text-[13px] font-semibold text-foreground truncate">{g.process}</span>
              <span class="{chip} bg-muted text-muted-foreground ml-auto">{g.ports.length} port{g.ports.length === 1 ? '' : 's'}</span>
              {#if g.public}<span class="{chip} bg-warning/15 text-warning">public</span>{/if}
            </div>
            <div class="flex flex-wrap gap-1.5">
              {#each g.ports as p}
                <span class="inline-flex items-center gap-1 text-[11px] font-mono px-1.5 py-0.5 rounded border {p.public ? 'border-warning/40 bg-warning/10 text-warning' : 'border-border bg-muted/50 text-muted-foreground'}"
                  title="{p.proto} · {p.address}">
                  {p.port}<span class="opacity-60">/{p.proto}</span>
                </span>
              {/each}
            </div>
          </div>
        {/each}
      </div>
    </div>

    <!-- Health & history -->
    <h2 class="{sectionH} mt-2 mb-2">Health &amp; history</h2>
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard icon="clock" color="primary" value={fmtUptime(data.host.uptime_seconds)} label="Host uptime" />
      <StatCard icon="refresh" color={data.host.reboot_recent ? 'warning' : 'info'} value={data.host.boot_time ? timeAgo(data.host.boot_time) : '—'} label="Last reboot" />
      <div class="{card}">
        <div class="text-xs text-muted-foreground mb-2 flex items-center gap-1.5"><Icon name="certificate" size={14} />TLS certificates</div>
        {#if !data.certs?.length}<div class="text-xs text-muted-foreground">None managed</div>
        {:else}{#each data.certs.slice(0, 4) as c}<div class="flex items-center justify-between text-xs py-0.5"><span class="truncate text-foreground">{c.domain}</span><span class="shrink-0 ml-2 tabular-nums {certColor(c.status)}">{c.daysLeft}d</span></div>{/each}{/if}
      </div>
      <StatCard icon="network" color={data.phone_home.external > 0 ? 'warning' : 'success'} value={data.phone_home.external} label="Outbound destinations" />
    </div>
  {/if}
</div>
