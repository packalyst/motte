<script>
  /**
   * MachineDetail — the structured view of one enrolled machine, laid out as the fleet
   * mockup: a grid of cards, each with an icon header, its data, and a plain-language
   * note explaining what it means. Sources (CrowdSec / osquery / Trivy) are labelled so
   * the detection split stays visible. Pulls the full report + polls it.
   */
  import { onMount } from 'svelte'
  import { get } from 'svelte/store'
  import { apiGet, apiPost, toast, confirm } from '../stores/app.js'
  import { subscribe, unsubscribe, fleetStore, wsConnected } from '../stores/websocket.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Badge from './Badge.svelte'
  import Input from './Input.svelte'
  import EmptyState from './EmptyState.svelte'
  import UPlotChart from './UPlotChart.svelte'
  import { timeAgo, formatBytes } from '$lib/utils/format.js'
  import { usageColor, sevVariant, statusInfo, round, fmtUptime } from '$lib/fleet.js'

  let { machine, latestAgent = null, onback, ondeleted, onviewcves } = $props()

  // Self-update landed in agent 0.1.20; older agents can't be updated from the panel.
  const MIN_SELFUPDATE = '0.1.20'
  // Compare dotted numeric versions ("0.1.20"): -1 a<b, 0 equal, 1 a>b.
  function cmpVer(a, b) {
    const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number)
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pa[i] || 0) - (pb[i] || 0)
      if (d) return d < 0 ? -1 : 1
    }
    return 0
  }
  // Agent-version state for the Agent & Host header: current vs latest published.
  const agentUpdate = $derived.by(() => {
    const cur = report?.agent
    if (!cur || !latestAgent) return { state: 'unknown', cur }        // no data / GitHub unreachable
    if (cmpVer(cur, latestAgent) >= 0) return { state: 'current', cur }
    if (cmpVer(cur, MIN_SELFUPDATE) < 0) return { state: 'reinstall', cur, latest: latestAgent }
    return { state: 'updatable', cur, latest: latestAgent }          // self-update will work
  })

  let report = $state(null)
  let loading = $state(true)
  let blockIP = $state('')

  const st = $derived(statusInfo(machine))
  const dryRun = $derived(report?.dry_run ?? true)
  const m = $derived(report?.metrics || {})
  const cves = $derived(report?.cves || null)
  const intr = $derived(report?.intrusion || null)
  const facts = $derived(report?.facts || null)

  // kernel-maintenance job status (absent unless a kernel update has run). Each phase
  // maps to a dot color + human label so a long, reboot-spanning job is legible.
  const kernel = $derived(report?.kernel || null)
  const kernelPhase = {
    installing:     { dot: 'bg-info',        label: 'Installing new kernel' },
    reboot_pending: { dot: 'bg-warning',     label: 'Reboot pending' },
    cleanup_pending:{ dot: 'bg-warning',     label: 'Rebooting & cleaning up' },
    done:           { dot: 'bg-success',     label: 'Kernel up to date' },
    failed:         { dot: 'bg-destructive', label: 'Kernel update failed' },
  }
  const kphase = $derived(kernel ? (kernelPhase[kernel.phase] || { dot: 'bg-muted-foreground', label: kernel.phase }) : null)

  // merged security feed: bans first (most severe), then FIM changes.
  const feed = $derived.by(() => {
    const out = []
    for (const d of intr?.decisions || []) {
      out.push({ tone: 'crit', body: `Banned ${d.value}`, meta: d.scenario || d.type || 'ban', src: 'crowdsec' })
    }
    for (const f of (facts?.fim || []).slice().reverse()) {
      out.push({ tone: f.action === 'DELETED' ? 'crit' : 'warn', body: `${f.action || 'changed'} ${f.path}`, meta: '', src: 'osquery' })
    }
    return out
  })

  let commands = $state([])
  // machine-level CVE roll-up (unique CVEs, affected packages, fixable) — the report's cves
  // summary only has raw findings + severity, so we pull the richer numbers from the panel.
  let cveSummary = $state(null)
  // One request returns { report, commands } (same shape as the live WS push).
  async function loadReport() {
    try {
      const res = await apiGet('/api/fleet/report?id=' + encodeURIComponent(machine.id))
      report = res?.report ?? null
      if (res?.commands) commands = res.commands
    } catch { report = null } finally { loading = false }
  }
  // CVE summary only changes on a rescan, so it's refetched only when a new scan lands (a
  // report arrives with a newer scanned_at) — never on a timer.
  async function loadCves() {
    try { cveSummary = (await apiGet('/api/fleet/cves/groups?machine_id=' + encodeURIComponent(machine.id)))?.summary || null } catch { /* keep last */ }
  }
  const load = () => loadReport()
  const refresh = () => { loadReport(); loadCves() }

  // Usage history — CPU/mem/disk over time, averaged into 5-min buckets on the panel
  // (the report only carries the live snapshot). `stat` flips the lines between the
  // bucket average and its peak; both come in one payload so the toggle never refetches.
  let histRange = $state('24h')
  let histStat = $state('avg')
  let histPoints = $state([])
  let histLoading = $state(false)
  async function loadHistory() {
    histLoading = true
    try {
      const res = await apiGet(`/api/fleet/metrics?id=${encodeURIComponent(machine.id)}&range=${histRange}`)
      histPoints = res?.points || []
    } catch { histPoints = [] } finally { histLoading = false }
  }
  // Refetch when the range (or the machine) changes; runs once on mount too.
  $effect(() => { histRange; machine.id; loadHistory() })

  const histSeries = [
    { label: 'CPU', stroke: '--cpu' },
    { label: 'Memory', stroke: '--mem' },
    { label: 'Disk', stroke: '--tx' },
  ]
  // uPlot columnar shape: [xs, cpu, mem, disk] pulled from the chosen stat (avg|max).
  const chartData = $derived.by(() => {
    const p = histPoints
    if (!p.length) return []
    const k = histStat === 'max' ? 'max' : 'avg'
    return [
      p.map((d) => d.t),
      p.map((d) => d[`cpu_${k}`]),
      p.map((d) => d[`mem_${k}`]),
      p.map((d) => d[`disk_${k}`]),
    ]
  })

  onMount(() => {
    refresh()             // initial HTTP populate
    subscribe('fleet')    // ask the panel to push this machine's reports over WS

    // Live updates: the panel broadcasts each agent check-in. Apply the pushed report for
    // THIS machine instantly (no polling while the socket is up); refresh the command log,
    // and refetch the CVE roll-up only when the scan timestamp changed.
    const unsub = fleetStore.subscribe((msg) => {
      if (!msg || msg.machine_id !== machine.id) return
      // Command log now rides the push (report broadcast + queue/ack broadcasts),
      // so no more polling /api/fleet/machine/commands on every check-in.
      if (msg.commands) commands = msg.commands
      if (!msg.report) return
      const prevScan = report?.cves?.scanned_at
      report = msg.report
      loading = false
      if (msg.report?.cves?.scanned_at && msg.report.cves.scanned_at !== prevScan) loadCves()
    })

    // Fallback poll ONLY while the WS is disconnected (much lighter than the old 10s timer).
    const t = setInterval(() => { if (!get(wsConnected)) load() }, 20000)
    return () => { unsub(); clearInterval(t); unsubscribe('fleet') }
  })

  const cmdStatus = { pending: 'text-warning', delivered: 'text-info', done: 'text-success', error: 'text-destructive' }

  async function cmd(type, payload = null, opts = {}) {
    const ok = await confirm({
      title: `${opts.title || type} · ${machine.name}`,
      message: opts.message || `Queue "${type}" for ${machine.name}? It runs on the machine's next check-in (~10s).`,
      confirmText: opts.confirmText || 'Queue',
      variant: opts.variant || 'primary',
      alert: opts.alert || false,
    })
    if (!ok) return
    try {
      const res = await apiPost(opts.endpoint || '/api/fleet/command',
        opts.endpoint ? { machine_id: machine.id } : { machine_id: machine.id, type, payload })
      toast(opts.done ? opts.done(res) : `${type} queued`, 'success')
      if (opts.after) opts.after()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function blockOn() {
    const ip = blockIP.trim()
    if (!ip) return
    await cmd('block', { ip }, { title: 'Block IP', message: `Block ${ip} on ${machine.name}?`, after: () => (blockIP = '') })
  }

  const pushBlocks = () => cmd('sync-blocks', null, {
    endpoint: '/api/fleet/push-blocks', title: 'Push panel blocklist',
    message: `Push the panel's current blocklist (its manually + auto-blocked IPs and ranges) onto ${machine.name}? It drops them in its own nftables. Country/ASN mega-lists are excluded.`,
    done: (r) => `Pushing ${r.count} blocks to ${machine.name}`,
  })
  const applyUpdates = () => cmd('apply-updates', null, { title: 'Apply updates', message: `Run system package updates on ${machine.name}? OS-package CVEs are fixed by this; a kernel CVE also needs a reboot.` })
  const setDryRun = (enabled) => cmd('set-dry-run', { enabled }, {
    title: enabled ? 'Switch to dry-run' : 'Go live',
    message: enabled
      ? `Put ${machine.name} in DRY-RUN? It will LOG firewall/update actions instead of applying them.`
      : `Take ${machine.name} LIVE? It will enforce firewall blocks and apply updates for real.`,
    confirmText: enabled ? 'Dry-run' : 'Go live', variant: enabled ? 'primary' : 'destructive',
  })
  const rescan = () => cmd('rescan', null, { title: 'Rescan', message: `Re-run the Trivy CVE scan on ${machine.name} now?` })
  const updateAgent = () => cmd('update-agent', null, {
    title: 'Update agent',
    message: `Update the wgscout agent on ${machine.name}${agentUpdate.cur && agentUpdate.latest ? ` from ${agentUpdate.cur} to ${agentUpdate.latest}` : ' to the latest release'}? It downloads the release binary, verifies its checksum, checks it runs, swaps it in (keeping a backup), and restarts the agent — a brief reconnect, no reboot.`,
    confirmText: 'Update agent',
  })

  // Unblock a single IP (the typed one, or a specific one from the enforced list).
  async function unblockOn(ip = null) {
    const t = (ip ?? blockIP).trim()
    if (!t) return
    await cmd('unblock', { ip: t }, { title: 'Unblock IP', message: `Unblock ${t} on ${machine.name}?`, after: () => { if (ip == null) blockIP = '' } })
  }
  const updateKernel = () => cmd('update-kernel', null, {
    title: 'Update kernel', variant: 'destructive', confirmText: 'Update & reboot', alert: true,
    message: `Run the full kernel update on ${machine.name}? It installs the newest kernel, AUTO-REBOOTS to activate, then purges old kernels and rescans. The host is briefly offline. Honors dry-run.`,
  })
  const restartAgents = () => cmd('restart', { target: 'tools' }, { title: 'Restart sub-agents', message: `Restart the CrowdSec / osquery sub-agents on ${machine.name}? Safe — no reboot.` })
  const rebootHost = () => cmd('restart', { target: 'host' }, {
    title: 'Reboot host', variant: 'destructive', confirmText: 'Reboot', alert: true,
    message: `REBOOT ${machine.name}? The whole host restarts and is offline for a bit.`,
  })
  const setLogLevel = (level) => cmd('set-log-level', { level }, {
    title: level === 'debug' ? 'Enable debug logs' : 'Return to quiet logs',
    message: level === 'debug'
      ? `Turn on verbose debug logging on ${machine.name}? CrowdSec and osquery go to info level and the agent logs more — useful for troubleshooting. It restarts the sub-agents. Switch back to quiet when you're done.`
      : `Return ${machine.name} to quiet logging (warnings & errors only)? It restarts the sub-agents.`,
    confirmText: level === 'debug' ? 'Enable debug' : 'Go quiet',
  })

  // WG cell: pubkey (shortened) + assigned IP when we have it — one combined "WG" fact.
  const wgVal = $derived(
    [machine.wg_pubkey ? (machine.wg_pubkey.length > 14 ? machine.wg_pubkey.slice(0, 14) + '…' : machine.wg_pubkey) : '', machine.wg_ip || '']
      .filter(Boolean).join(' · '),
  )
  // Host facts shown in the Agent & Host card (icon · label · value). 9 → a clean 3×3 grid.
  const hostFacts = $derived([
    ['device-desktop', 'OS', [facts?.os?.name, facts?.os?.version].filter(Boolean).join(' ')],
    ['box', 'Kernel', facts?.kernel || ''],
    ['cpu', 'CPU', facts?.system?.cpu_brand],
    ['clock', 'Uptime', m.uptime ? fmtUptime(m.uptime) : ''],
    ['server', 'Host', report?.host],
    ['activity', 'Last report', report?.time ? timeAgo(report.time) : ''],
    ['calendar', 'Enrolled', machine.enrolled_at ? timeAgo(machine.enrolled_at) : ''],
    ['certificate', 'Cert', (machine.cert_fp || '').replace('sha256:', '').slice(0, 12)],
    ['key', 'WG', wgVal],
  ])
  // IPs this host is currently enforcing a block on (from the live report).
  const blockedIPs = $derived(report?.blocked || [])

  // Live-usage rows. Memory/Disk get a tooltip with the absolute bytes (agent v0.1.17+);
  // CPU is inherently a % so it has none.
  const usageRows = $derived([
    { lbl: 'CPU', val: m.cpu, tip: '' },
    { lbl: 'Memory', val: m.mem, tip: m.mem_total ? `${formatBytes(m.mem_used)} / ${formatBytes(m.mem_total)} used` : '' },
    { lbl: 'Disk', val: m.disk, tip: m.disk_total ? `${formatBytes(m.disk_used)} / ${formatBytes(m.disk_total)} used` : '' },
  ])

  async function del() {
    await cmd(null, null, {
      endpoint: '/api/fleet/machine/delete', title: `Delete ${machine.name}`,
      message: `Delete ${machine.name} for good? Its certificate is invalidated immediately — the agent can no longer connect and must re-enroll with a fresh token to return. Queued commands are removed too.`,
      confirmText: 'Delete machine', variant: 'destructive', alert: true,
      done: () => `${machine.name} deleted`, after: () => ondeleted?.(),
    })
  }

  const toneDot = { crit: 'bg-destructive', warn: 'bg-warning', ok: 'bg-success' }

  // Well-known port → service label (client-side; the agent only sends addr/port/proto).
  const PORT_NAMES = {
    22: 'SSH', 53: 'DNS', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS', 123: 'NTP',
    3306: 'MySQL', 5432: 'Postgres', 6379: 'Redis', 27017: 'MongoDB', 11211: 'Memcached',
    9100: 'node_exporter', 8420: 'CrowdSec', 51820: 'WireGuard', 3000: 'app', 8080: 'HTTP-alt',
  }
  const proto = (p) => (p === '6' ? 'tcp' : p === '17' ? 'udp' : p || '')
  const scopeOf = (addr) =>
    !addr || addr === '0.0.0.0' || addr === '::' ? 'exposed'
    : addr === '127.0.0.1' || addr === '::1' ? 'local' : 'iface'
  // Group listening ports by exposure so "what's open to the world" reads at a glance.
  const portGroups = $derived.by(() => {
    const g = { exposed: [], iface: [], local: [] }
    for (const p of facts?.ports || []) (g[scopeOf(p.address)] ||= []).push(p)
    return g
  })
  const scopeMeta = {
    exposed: { label: 'Exposed (all interfaces)', tone: 'text-warning', dot: 'bg-warning' },
    iface: { label: 'Bound to an interface', tone: 'text-info', dot: 'bg-info' },
    local: { label: 'Local only', tone: 'text-success', dot: 'bg-success' },
  }
</script>

<!-- one listening-port pill with a service name when we know it -->
{#snippet portPill(p)}
  <span class="inline-flex items-center gap-1 font-mono text-[11px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
    <span class="text-foreground">{p.address || '*'}:{p.port}</span>
    <span class="opacity-60">/{proto(p.protocol)}</span>
    {#if PORT_NAMES[+p.port]}<span class="not-italic text-[9px] px-1 rounded bg-background text-muted-foreground">{PORT_NAMES[+p.port]}</span>{/if}
  </span>
{/snippet}

<!-- card header: icon tile + title + source subtitle -->
{#snippet head(icon, title, sub, tint = 'text-muted-foreground')}
  <div class="flex items-center gap-2.5 mb-3">
    <span class="w-9 h-9 rounded-lg grid place-items-center bg-muted border border-border shrink-0 {tint}"><Icon name={icon} size={17} /></span>
    <div class="min-w-0">
      <div class="text-[13px] font-semibold text-foreground">{title}</div>
      {#if sub}<div class="text-[11px] text-muted-foreground truncate">{sub}</div>{/if}
    </div>
  </div>
{/snippet}

<!-- persistent plain-language note (mockup's dashed footer) -->
{#snippet note(text)}
  <div class="text-[11px] text-muted-foreground mt-3 pt-3 border-t border-dashed border-border">{text}</div>
{/snippet}

<div class="space-y-4">
  <!-- Header -->
  <div class="flex items-center gap-3 flex-wrap">
    <button onclick={onback} title="Back to fleet"
      class="h-8 w-8 grid place-items-center rounded-lg border border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground transition cursor-pointer shrink-0">
      <Icon name="arrow-left" size={16} />
    </button>
    <span class="w-2.5 h-2.5 rounded-full shrink-0 {st.dot}"></span>
    <div class="min-w-0 flex-1">
      <div class="text-lg font-semibold text-foreground truncate leading-tight">{machine.name || machine.id}</div>
      <div class="text-[11px] text-muted-foreground font-mono truncate">
        {st.label}{machine.last_seen ? ` · seen ${timeAgo(machine.last_seen)}` : ''}{report?.agent ? ` · agent ${report.agent}` : ''}
      </div>
    </div>
    <!-- grouped actions -->
    <div class="flex items-center rounded-lg border border-border overflow-hidden shrink-0 divide-x divide-border">
      <button onclick={refresh} class="flex items-center gap-1.5 px-3 py-1.5 text-xs text-muted-foreground hover:bg-muted hover:text-foreground transition cursor-pointer">
        <Icon name="refresh" size={14} />Refresh
      </button>
      <button onclick={del} class="flex items-center gap-1.5 px-3 py-1.5 text-xs text-destructive hover:bg-destructive/10 transition cursor-pointer">
        <Icon name="trash" size={14} />Delete
      </button>
    </div>
  </div>

  {#if loading && !report}
    <div class="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">Loading report…</div>
  {:else if !report}
    <div class="bg-card border border-border rounded-xl p-8">
      <EmptyState icon="clock" title="No report yet"
        description="This machine hasn't checked in with a report. It appears once the agent's first metrics/scan cycle completes." />
    </div>
  {:else}
    <!-- AGENT & HOST (full width): header · Host | Actions inline · commands full-width -->
    <div class="bg-card border border-border rounded-xl mb-4">
      <div class="p-4 pb-3 flex items-center gap-2.5">
        <span class="w-9 h-9 rounded-lg grid place-items-center bg-muted border border-border shrink-0 text-muted-foreground"><Icon name="robot" size={17} /></span>
        <div class="min-w-0 flex-1">
          <div class="text-[13px] font-semibold text-foreground">Agent &amp; Host</div>
          <div class="text-[11px] text-muted-foreground flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
            <span>{report?.agent ? `wgscout ${report.agent}` : 'wgscout'}</span>
            {#if agentUpdate.state === 'current'}
              <span class="inline-flex items-center gap-1 text-success"><Icon name="circle-check" size={11} /> up to date</span>
            {:else if agentUpdate.state === 'updatable'}
              <button onclick={updateAgent} class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md bg-primary/10 text-primary hover:bg-primary/20 transition cursor-pointer font-medium">
                <Icon name="arrow-up" size={11} /> Update → {agentUpdate.latest}
              </button>
            {:else if agentUpdate.state === 'reinstall'}
              <span class="inline-flex items-center gap-1 text-warning cursor-help" data-kt-tooltip>
                <Icon name="alert-triangle" size={11} /> {agentUpdate.latest} available — reinstall
                <span data-kt-tooltip-content class="kt-tooltip hidden">This agent predates in-panel self-update (added in {MIN_SELFUPDATE}). Reinstall once via the install command to enable one-click updates.</span>
              </span>
            {/if}
          </div>
        </div>
        <span class="hidden sm:flex items-center gap-1.5 text-xs mr-1">
          <span class="w-2 h-2 rounded-full {dryRun ? 'bg-warning' : 'bg-success'}"></span>
          <span class="font-medium">{dryRun ? 'Dry-run' : 'Live'}</span>
          <span class="text-muted-foreground">{dryRun ? '— logs actions' : '— enforcing'}</span>
        </span>
        {#if dryRun}
          <Button variant="destructive" size="xs" icon="bolt" onclick={() => setDryRun(false)}>Go live</Button>
        {:else}
          <Button variant="outline" size="xs" icon="player-pause" onclick={() => setDryRun(true)}>Dry-run</Button>
        {/if}
      </div>

      {#if kernel && kphase}
        <div class="mx-4 mb-3 flex items-start gap-2 rounded-lg border border-border bg-muted/40 px-2.5 py-2">
          <span class="w-2 h-2 rounded-full mt-1.5 shrink-0 {kphase.dot} {kernel.phase === 'installing' || kernel.phase === 'cleanup_pending' ? 'animate-pulse' : ''}"></span>
          <div class="min-w-0">
            <div class="text-xs font-medium flex items-center gap-1.5"><Icon name="cpu" size={12} /> {kphase.label}{#if kernel.target}<span class="font-mono text-[10px] text-muted-foreground">{kernel.target}</span>{/if}</div>
            {#if kernel.message}<div class="text-[11px] text-muted-foreground mt-0.5 break-words">{kernel.message}</div>{/if}
            {#if kernel.removed?.length}<div class="text-[10px] text-muted-foreground mt-0.5">Removed {kernel.removed.length} old package(s)</div>{/if}
          </div>
        </div>
      {/if}

      <!-- Host | Actions inline -->
      <div class="flex flex-col md:flex-row border-t border-border">
        <div class="md:flex-[1.6] min-w-0 p-4">
          <div class="text-[10px] uppercase tracking-wide font-semibold text-muted-foreground mb-2">Host</div>
          <div class="grid grid-cols-2 sm:grid-cols-3 gap-px bg-border rounded-lg overflow-hidden border border-border">
            {#each hostFacts as [ic, k, v]}
              <div class="bg-card px-2.5 py-2 flex items-center gap-2 min-w-0">
                <Icon name={ic} size={14} class="text-muted-foreground shrink-0" />
                <div class="min-w-0">
                  <div class="text-[9px] uppercase tracking-wide text-muted-foreground leading-tight">{k}</div>
                  <div class="text-xs font-medium truncate {v ? '' : 'text-muted-foreground'}">{v || '—'}</div>
                </div>
              </div>
            {/each}
          </div>
          {#if facts?.users?.length}
            <div class="mt-2 text-[11px] text-muted-foreground">
              Sessions: {#each facts.users as u, i}{i > 0 ? ', ' : ''}<span class="font-mono text-foreground">{u.user}</span>{u.host ? ` (${u.host})` : ''}{/each}
            </div>
          {/if}
        </div>
        <div class="md:flex-1 min-w-0 p-4 border-t md:border-t-0 md:border-l border-border">
          <div class="text-[10px] uppercase tracking-wide font-semibold text-muted-foreground mb-2">Actions</div>
          <div class="space-y-2.5">
            <div>
              <div class="text-[10px] text-muted-foreground mb-1">Patching</div>
              <div class="flex flex-wrap gap-1.5">
                <Button variant="outline" size="xs" icon="download" onclick={applyUpdates}>Apply updates</Button>
                <Button variant="outline" size="xs" icon="cpu" onclick={updateKernel}>Update kernel</Button>
                <Button variant="outline" size="xs" icon="scan" onclick={rescan}>Rescan</Button>
              </div>
            </div>
            <div>
              <div class="text-[10px] text-muted-foreground mb-1">Lifecycle</div>
              <div class="flex flex-wrap gap-1.5">
                <Button variant="outline" size="xs" icon="refresh" onclick={restartAgents}>Restart agents</Button>
                {#if report?.log_level === 'debug'}
                  <Button variant="outline" size="xs" icon="file-text" onclick={() => setLogLevel('quiet')}>Quiet logs</Button>
                {:else if report?.log_level}
                  <Button variant="outline" size="xs" icon="file-text" onclick={() => setLogLevel('debug')}>Debug logs</Button>
                {/if}
                <Button variant="destructive" size="xs" icon="power" onclick={rebootHost}>Reboot host</Button>
              </div>
            </div>
          </div>
        </div>
      </div>

      {#if commands.length}
        <div class="p-4 border-t border-border">
          <div class="text-[10px] uppercase tracking-wide font-semibold text-muted-foreground mb-1">Recent commands</div>
          <div class="max-h-40 overflow-y-auto -mr-1 pr-1">
            {#each commands as c}
              <div class="flex items-center gap-2 py-1 border-t border-border first:border-t-0 text-xs">
                <span class="font-mono">{c.type}</span>
                {#if c.status === 'pending' || c.status === 'delivered'}<Icon name="loader-2" size={11} class="animate-spin {cmdStatus[c.status] || 'text-muted-foreground'}" />{/if}
                <span class="capitalize {cmdStatus[c.status] || 'text-muted-foreground'}">{c.status}</span>
                {#if c.result}<span class="text-muted-foreground truncate flex-1" title={c.result}>· {c.result}</span>{/if}
                <span class="text-[10px] text-muted-foreground ml-auto shrink-0">{timeAgo(c.done_at || c.created_at)}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}
    </div>

    <!-- USAGE HISTORY (full width — a time chart wants the room) -->
    <div class="bg-card border border-border rounded-xl p-4 mb-4">
      <div class="flex items-center gap-2.5 mb-3 flex-wrap">
        <span class="w-9 h-9 rounded-lg grid place-items-center bg-muted border border-border shrink-0 text-muted-foreground"><Icon name="chart-line" size={17} /></span>
        <div class="min-w-0 flex-1">
          <div class="text-[13px] font-semibold text-foreground">Usage history</div>
          <div class="text-[11px] text-muted-foreground truncate">CPU · memory · disk over time</div>
        </div>
        <!-- average vs peak (both stored; no refetch) -->
        <div class="inline-flex items-center gap-0.5 rounded-lg bg-muted/60 border border-border p-0.5 text-xs shrink-0">
          {#each [['avg', 'Avg'], ['max', 'Peak']] as [v, l]}
            <button onclick={() => histStat = v} class="px-2.5 py-1 rounded-md transition cursor-pointer {histStat === v ? 'bg-card shadow-sm text-foreground font-medium' : 'text-muted-foreground hover:text-foreground'}">{l}</button>
          {/each}
        </div>
        <!-- time range -->
        <div class="inline-flex items-center gap-0.5 rounded-lg bg-muted/60 border border-border p-0.5 text-xs shrink-0">
          {#each ['24h', '7d', '30d'] as r}
            <button onclick={() => histRange = r} class="px-2.5 py-1 rounded-md transition cursor-pointer {histRange === r ? 'bg-card shadow-sm text-foreground font-medium' : 'text-muted-foreground hover:text-foreground'}">{r}</button>
          {/each}
        </div>
      </div>
      {#if histLoading && histPoints.length === 0}
        <div class="h-[188px] grid place-items-center text-xs text-muted-foreground">Loading history…</div>
      {:else if histPoints.length < 2}
        <div class="h-[188px] grid place-items-center text-center text-xs text-muted-foreground px-4">
          Not enough history yet — usage is charted as the agent checks in (every&nbsp;~15s). Check back in a few minutes.
        </div>
      {:else}
        <UPlotChart data={chartData} series={histSeries} height={188} yRange={[0, 100]} yUnit="%" />
      {/if}
      {@render note('Averaged into 5-minute buckets, kept for 30 days. “Peak” shows the highest reading in each bucket — a brief CPU or disk spike the average smooths away.')}
    </div>

    <!-- rest of the cards in explicit 2 columns (each stacks independently) -->
    <div class="flex flex-col lg:flex-row gap-4 items-start">
      <!-- LEFT column -->
      <div class="flex-1 min-w-0 flex flex-col gap-4">

      <!-- LIVE USAGE -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('activity', 'Live usage', '')}
        <div class="space-y-2.5">
          {#each usageRows as r}
            <div class="flex items-center gap-3 text-xs {r.tip ? 'cursor-help' : ''}" data-kt-tooltip={r.tip ? '' : undefined}>
              <span class="w-14 text-muted-foreground">{r.lbl}</span>
              <span class="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                <span class="block h-full rounded-full {usageColor(round(r.val))}" style="width:{Math.min(round(r.val), 100)}%"></span>
              </span>
              <span class="w-10 text-right tabular-nums font-medium">{round(r.val)}%</span>
              {#if r.tip}<span data-kt-tooltip-content class="kt-tooltip hidden">{r.tip}</span>{/if}
            </div>
          {/each}
        </div>
        <div class="flex gap-6 mt-3 text-xs">
          <span class="text-muted-foreground">Uptime <span class="text-foreground font-medium">{fmtUptime(m.uptime)}</span></span>
          <span class="text-muted-foreground">Load <span class="text-foreground font-medium tabular-nums">{(m.load1 ?? 0).toFixed(2)}</span></span>
        </div>
        {@render note('Live resource use reported by the agent. A sustained CPU spike often tracks attack traffic.')}
      </div>

      <!-- VULNERABILITIES (summary — full list is the drill-down) -->
      <div class="bg-card border border-border rounded-xl p-4">
        <!-- header: title/subtitle left, total upper-right -->
        <div class="flex items-start gap-2.5 mb-3">
          <span class="w-9 h-9 rounded-lg grid place-items-center bg-muted border border-border shrink-0 text-warning"><Icon name="package" size={17} /></span>
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <span class="text-[13px] font-semibold text-foreground">Vulnerabilities</span>
              <span class="ml-auto text-[11px] text-muted-foreground shrink-0">
                {#if cveSummary}{cveSummary.unique_cves.toLocaleString()} CVEs · {cveSummary.packages.toLocaleString()} pkgs{:else}{(cves?.total ?? 0).toLocaleString()} findings{/if}{cves?.scanned_at ? ` · ${timeAgo(cves.scanned_at)}` : ''}
              </span>
            </div>
            <div class="text-[11px] text-muted-foreground">Trivy · OS packages + app lockfiles</div>
          </div>
        </div>
        <!-- lead with severity + what's actionable (fixable), not the noisy raw finding count -->
        {#if cves?.total}
          <div class="flex flex-wrap items-center gap-1.5">
            {#each ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as sev}
              {#if cves?.counts?.[sev]}<Badge variant={sevVariant(sev)} size="sm">{cves.counts[sev].toLocaleString()} {sev.toLowerCase()}</Badge>{/if}
            {/each}
            {#if cveSummary?.fixable}
              <span class="inline-flex items-center gap-1 text-xs ml-1"><Icon name="tool" size={13} class="text-success" /><span class="font-semibold text-foreground">{cveSummary.fixable.toLocaleString()}</span><span class="text-muted-foreground">fixable</span></span>
            {/if}
          </div>
          <!-- top preview (full list is the drill-down) -->
          {#if cves?.top?.length}
            <div class="mt-3 border-t border-border pt-1">
              {#each cves.top.slice(0, 12) as v}
                <div class="flex items-center gap-2.5 py-1 text-xs">
                  <Badge variant={sevVariant(v.severity)} size="sm">{(v.severity || '').toLowerCase()}</Badge>
                  <span class="font-mono whitespace-nowrap" title={v.title}>{v.id}</span>
                  <span class="text-muted-foreground truncate flex-1">{v.pkg}</span>
                  <span class="shrink-0 font-mono text-[11px]">{#if v.fixed}<span class="text-success">→ {v.fixed}</span>{:else}<span class="text-muted-foreground">no fix</span>{/if}</span>
                </div>
              {/each}
              {#if cves.total > 12}<div class="text-[11px] text-muted-foreground pt-1">+ {(cves.total - 12).toLocaleString()} more — “View all & fix”.</div>{/if}
            </div>
          {/if}
        {:else}
          <div class="text-sm text-success flex items-center gap-2 py-1"><Icon name="circle-check" size={15} />No known vulnerabilities found.</div>
        {/if}
        <div class="flex items-center gap-2 mt-3 flex-wrap">
          {#if cves?.total}<Button variant="primary" size="sm" icon="list-details" onclick={() => onviewcves?.(machine)}>View all & fix</Button>{/if}
        </div>
        {@render note('Fixable OS-package CVEs clear via “Apply updates” on the Agent card; kernel CVEs via “Update kernel”. “View all & fix” opens the full list grouped by OS/project to upgrade only selected packages.')}
      </div>
      </div><!-- /LEFT column -->

      <!-- RIGHT column -->
      <div class="flex-1 min-w-0 flex flex-col gap-4">

      <!-- EXPOSURE (listening ports only — host facts moved to the Agent & Host card) -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('network', 'Exposure', 'listening ports · osquery', 'text-info')}
        {#if facts?.ports?.length}
          <div class="space-y-2">
            {#each ['exposed', 'iface', 'local'] as scope}
              {#if portGroups[scope].length}
                <div>
                  <div class="flex items-center gap-1.5 mb-1">
                    <span class="w-1.5 h-1.5 rounded-full {scopeMeta[scope].dot}"></span>
                    <span class="text-[11px] font-medium {scopeMeta[scope].tone}">{scopeMeta[scope].label}</span>
                    <span class="text-[10px] text-muted-foreground">· {portGroups[scope].length}</span>
                  </div>
                  <div class="flex flex-wrap gap-1.5">
                    {#each portGroups[scope] as p}{@render portPill(p)}{/each}
                  </div>
                </div>
              {/if}
            {/each}
          </div>
        {:else}
          <div class="text-sm text-muted-foreground py-1">No listening ports reported.</div>
        {/if}
        {@render note('“Exposed” ports are open on all interfaces (reachable from the internet unless firewalled); “local” ones only from the box itself. An unexpected exposed port is worth a look.')}
      </div>

      <!-- BLOCKING -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('ban', 'Blocking', `${blockedIPs.length} IP${blockedIPs.length === 1 ? '' : 's'} blocked on this host`, 'text-destructive')}
        <div class="flex flex-wrap items-center gap-2">
          <div class="flex-1 min-w-[180px]">
            <Input bind:value={blockIP} prefixIcon="world" placeholder="IP to block / unblock" class="font-mono"
              onkeydown={(e) => e.key === 'Enter' && blockOn()} />
          </div>
          <Button variant="destructive" size="sm" icon="ban" onclick={blockOn} disabled={!blockIP.trim()}>Block</Button>
          <Button variant="outline" size="sm" icon="circle-check" onclick={() => unblockOn()} disabled={!blockIP.trim()}>Unblock</Button>
        </div>
        {#if blockedIPs.length}
          <div class="mt-3 max-h-48 overflow-y-auto -mr-1 pr-1">
            {#each blockedIPs as ip}
              <div class="flex items-center gap-2 py-1.5 border-t border-border first:border-t-0 text-sm">
                <Icon name="ban" size={13} class="text-destructive shrink-0" />
                <span class="font-mono truncate flex-1">{ip}</span>
                <button onclick={() => unblockOn(ip)} class="text-[11px] text-muted-foreground hover:text-foreground transition cursor-pointer shrink-0">unblock</button>
              </div>
            {/each}
          </div>
        {/if}
        <div class="mt-3"><Button variant="outline" size="sm" icon="arrow-down" onclick={pushBlocks}>Push panel blocklist</Button></div>
        {@render note("Block or unblock one IP, or push the panel's whole blocklist down so this host drops the same attackers the panel already knows about.")}
      </div>

      <!-- SECURITY EVENTS -->
      <div class="bg-card border rounded-xl p-4 {feed.some((e) => e.tone === 'crit') ? 'border-destructive/40' : 'border-border'}">
        {@render head('shield-lock', 'Security events', 'CrowdSec bans + osquery FIM', 'text-warning')}
        {#if feed.length}
          <div class="max-h-72 overflow-y-auto -mr-1 pr-1">
            {#each feed.slice(0, 100) as e}
              <div class="flex items-baseline gap-2.5 py-1.5 border-t border-border first:border-t-0 text-sm">
                <span class="w-1.5 h-1.5 rounded-full shrink-0 self-center {toneDot[e.tone]}"></span>
                <span class="flex-1 min-w-0 break-all"><span class="font-mono text-xs">{e.body}</span>{#if e.meta}<span class="text-muted-foreground text-xs"> — {e.meta}</span>{/if}</span>
                <span class="text-[9px] text-muted-foreground shrink-0">{e.src}</span>
              </div>
            {/each}
          </div>
        {:else}
          <div class="text-sm text-success flex items-center gap-2 py-2"><Icon name="circle-check" size={15} />No bans and no file-integrity changes.</div>
        {/if}
        {@render note('CrowdSec bans attackers on-host automatically. The FIM lines (a watched file changed) are the "someone got in" signals worth investigating.')}
      </div>
      </div><!-- /RIGHT column -->
    </div>
  {/if}
</div>
