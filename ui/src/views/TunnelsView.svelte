<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, confirm, setConfirmLoading } from '../stores/app.js'
  import { subscribeToLogs, unsubscribeFromLogs, dockerLogsStore } from '../stores/websocket.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import Input from '../components/Input.svelte'
  import Select from '../components/Select.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import ContentBlock from '../components/ContentBlock.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import StatCard from '../components/StatCard.svelte'

  let { loading = $bindable(true) } = $props()

  // Live container status (running/stopped/…) + per-tunnel display info.
  let status = $state(null)
  // The editable config (source of truth for tunnels), loaded from /config.
  let config = $state({ tunnels: [] })
  let stats = $state(null)
  let vpnClients = $state([])          // for the upstream-node selector
  let testResults = $state({})         // tunnel id -> { testing, ok, exitIp, latencyMs, error }
  let busy = $state(false)
  let refreshTimer = null

  // Logs viewer modal (live stream, reusing the Docker logs WS channel).
  let showLogsModal = $state(false)
  let logsAutoScroll = $state(true)
  let logsElement = $state(null)

  // Modal form state.
  let showModal = $state(false)
  let modalMode = $state('create') // create | edit
  let editIndex = $state(-1)
  let form = $state(blankForm())

  const running = $derived(status?.status === 'running')
  const drift = $derived(status?.drift === true)
  // Merge the running display info (host, example command) into each config
  // tunnel by id, so the card can show a copy-paste command when running.
  const infoById = $derived(
    Object.fromEntries((status?.tunnels || []).map((t) => [t.id, t]))
  )

  // Search / filter by tunnel name.
  let searchQuery = $state('')
  const filteredTunnels = $derived(
    config.tunnels.filter((t) => (t.name || '').toLowerCase().includes(searchQuery.toLowerCase()))
  )

  // Collapsible cards: expanded state keyed by tunnel id (collapsed by default).
  let expanded = $state({})
  function toggleExpand(id) {
    expanded = { ...expanded, [id]: !expanded[id] }
  }

  function blankForm() {
    return {
      id: '',
      name: '',
      protocols: ['http'],                 // create can pick multiple → one tunnel each
      ports: { http: '3128', socks5: '1080' },
      user: '',
      pass: '',
      chained: true, // manual "Add tunnel" defaults to chained; Quick-deploy is direct
      upstream: { host: '', user: '', pass: '', ports: { http: '', socks5: '' } },
      rotateUrl: '',
    }
  }

  // Toggle a protocol on the tunnel (one listener each). A tunnel can serve both.
  function toggleProto(p) {
    form.protocols = form.protocols.includes(p)
      ? form.protocols.filter((x) => x !== p)
      : [...form.protocols, p]
  }

  async function loadStatus() {
    try {
      status = await apiGet('/api/turbotunnels/status')
    } catch (e) {
      status = { status: 'error', error: e.message, tunnels: [] }
    }
  }

  async function loadConfig() {
    try {
      const cfg = await apiGet('/api/turbotunnels/config')
      config = { tunnels: cfg.tunnels || [] }
    } catch (e) {
      toast('Failed to load tunnel config: ' + e.message, 'error')
    }
  }

  async function loadStats() {
    try {
      stats = await apiGet('/api/turbotunnels/stats')
    } catch {
      // non-fatal — stats are best-effort
    }
  }

  function formatLastSeen(ts) {
    if (!ts) return ''
    // SQLite CURRENT_TIMESTAMP is UTC "YYYY-MM-DD HH:MM:SS"; render in local time.
    const d = new Date(String(ts).replace(' ', 'T') + 'Z')
    return isNaN(d.getTime()) ? '' : d.toLocaleString()
  }

  async function loadClients() {
    try {
      vpnClients = await apiGet('/api/vpn/clients')
    } catch {
      vpnClients = []
    }
  }

  // Fill the upstream host when a VPN node is picked from the dropdown.
  function onUpstreamNode(e) {
    const ip = e.target.value
    if (ip) form.upstream.host = ip
  }

  // Probe a tunnel end-to-end (through the proxy) and stash the result by id.
  // Probe one listener (protocol+port) of a tunnel; result keyed by id:protocol.
  async function testTunnel(t, l) {
    const key = `${t.id}:${l.protocol}`
    testResults = { ...testResults, [key]: { testing: true } }
    try {
      const res = await apiPost('/api/turbotunnels/test', { protocol: l.protocol, port: l.port, user: t.user, pass: t.pass })
      testResults = { ...testResults, [key]: res }
      toast(res.ok ? `${t.name} (${l.protocol}) is up — exit ${res.exitIp}` : `${t.name} (${l.protocol}) failed: ${res.error}`, res.ok ? 'success' : 'error')
    } catch (e) {
      testResults = { ...testResults, [key]: { error: e.message } }
      toast('Test failed: ' + e.message, 'error')
    }
  }

  // Regenerate a tunnel's rotation key (clears it → backend assigns a new one).
  // No restart needed: the key is used by the panel's rotation endpoint, not the
  // proxy container.
  async function regenerateRotationKey(t) {
    const idx = config.tunnels.indexOf(t)
    if (idx < 0) return
    const next = { tunnels: config.tunnels.map((x, k) => (k === idx ? { ...x, rotateKey: '' } : x)) }
    busy = true
    try {
      status = await apiPut('/api/turbotunnels/config', next)
      await loadConfig()
      toast('Rotation key regenerated', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      busy = false
    }
  }

  async function refresh() {
    await Promise.all([loadStatus(), loadConfig(), loadStats(), loadClients()])
    loading = false
  }

  // ---- Lifecycle actions -------------------------------------------------

  async function lifecycle(action, label) {
    busy = true
    try {
      status = await apiPost('/api/turbotunnels/' + action)
      toast(label, 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
      await loadStatus()
    } finally {
      busy = false
    }
  }

  const start = () => lifecycle('start', 'Proxy started')
  const stop = () => lifecycle('stop', 'Proxy stopped')
  async function restart() {
    // With no tunnels there is nothing to run — stop instead of a doomed
    // restart (the backend rejects starting with zero tunnels).
    if (config.tunnels.length === 0) return stop()
    return lifecycle('restart', 'Proxy restarted')
  }

  async function quickDeploy() {
    busy = true
    try {
      status = await apiPost('/api/turbotunnels/quick-deploy')
      await loadConfig()
      toast('Direct proxy deployed', 'success')
    } catch (e) {
      toast('Quick deploy failed: ' + e.message, 'error')
    } finally {
      busy = false
    }
  }

  // ---- Config editing ----------------------------------------------------

  async function generateCreds(target) {
    try {
      const c = await apiPost('/api/turbotunnels/credentials')
      target.user = c.user
      target.pass = c.pass
    } catch (e) {
      toast('Failed to generate credentials: ' + e.message, 'error')
    }
  }

  function openCreate() {
    modalMode = 'create'
    editIndex = -1
    form = blankForm()
    generateCreds(form) // start with strong auto-generated creds
    showModal = true
  }

  function openEdit(index) {
    const t = config.tunnels[index]
    modalMode = 'edit'
    editIndex = index
    const listeners = t.listeners || []
    const ports = { http: '3128', socks5: '1080' }
    const upPorts = { http: '', socks5: '' }
    for (const l of listeners) {
      ports[l.protocol] = String(l.port ?? '')
      if (l.upstreamPort) upPorts[l.protocol] = String(l.upstreamPort)
    }
    form = {
      id: t.id || '',
      name: t.name || '',
      protocols: listeners.length ? listeners.map((l) => l.protocol) : ['http'],
      ports,
      user: t.user || '',
      pass: t.pass || '',
      chained: !!(t.upstream && t.upstream.host),
      upstream: {
        host: t.upstream?.host || '',
        user: t.upstream?.user || '',
        pass: t.upstream?.pass || '',
        ports: upPorts,
      },
      rotateUrl: t.rotateUrl || '',
    }
    showModal = true
  }

  // Build one tunnel with a listener per selected protocol (shared identity).
  function buildTunnelFromForm() {
    return {
      id: form.id,
      name: form.name.trim(),
      listeners: form.protocols.map((proto) => ({
        protocol: proto,
        port: Number(form.ports[proto]),
        upstreamPort: form.chained ? Number(form.upstream.ports[proto]) : 0,
      })),
      user: form.user.trim(),
      pass: form.pass,
      upstream: form.chained
        ? { host: form.upstream.host.trim(), user: form.upstream.user.trim(), pass: form.upstream.pass }
        : { host: '', user: '', pass: '' },
      rotateUrl: form.rotateUrl.trim(),
    }
  }

  async function saveTunnel() {
    if (form.protocols.length === 0) {
      toast('Pick at least one protocol (HTTP and/or SOCKS5).', 'error')
      return
    }
    if (form.chained && !form.upstream.host.trim()) {
      toast('A chained tunnel needs an upstream host — pick a node or enter one.', 'error')
      return
    }
    // Build one tunnel (with a listener per protocol), then persist the document.
    const built = buildTunnelFromForm()
    const next = { tunnels: [...config.tunnels] }
    if (modalMode === 'create') next.tunnels.push(built)
    else next.tunnels[editIndex] = built

    busy = true
    try {
      status = await apiPut('/api/turbotunnels/config', next)
      await loadConfig() // pull back with server-assigned IDs
      showModal = false
      toast(modalMode === 'create' ? 'Tunnel added' : 'Tunnel updated', 'success')
      const applied = await maybeOfferRestart()
      // Test-on-add: once the proxy is running, verify each of its listeners.
      if (applied) {
        const saved = config.tunnels.find((x) => x.name === built.name)
        if (saved) for (const l of saved.listeners || []) testTunnel(saved, l)
      }
    } catch (e) {
      // Validation errors come back as the message — show them inline.
      toast(e.message, 'error')
    } finally {
      busy = false
    }
  }

  async function deleteTunnel(index) {
    const t = config.tunnels[index]
    const confirmed = await confirm({
      title: 'Delete tunnel',
      message: `Delete "${t.name}" (${(t.listeners || []).map((l) => `${l.protocol}:${l.port}`).join(', ')})?`,
      description: 'These proxies will stop being served after a restart.',
    })
    if (!confirmed) return
    setConfirmLoading(true)
    const next = { tunnels: config.tunnels.filter((_, i) => i !== index) }
    try {
      status = await apiPut('/api/turbotunnels/config', next)
      config = next
      toast('Tunnel deleted', 'success')
      await maybeOfferRestart()
    } catch (e) {
      toast('Failed to delete: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }

  // After a config change, if the proxy is running the change isn't live until
  // a restart — offer it explicitly so the user understands connections drop.
  // Returns true if the proxy ended up (re)started with the new config.
  async function maybeOfferRestart() {
    if (!running) return false
    // No tunnels left → the running proxy has nothing to serve; offer to stop.
    if (config.tunnels.length === 0) {
      const ok = await confirm({
        title: 'Stop the proxy?',
        message: 'No tunnels are configured anymore, so the running proxy has nothing left to serve.',
        description: 'Stopping ends the running container.',
        confirmText: 'Stop now',
        cancelText: 'Later',
      })
      if (ok) await stop()
      return false
    }
    const ok = await confirm({
      title: 'Restart proxy to apply?',
      message: 'The proxy is running. Applying this change restarts it and briefly drops active connections.',
      description: 'You can also restart later from the toolbar.',
      confirmText: 'Restart now',
      cancelText: 'Later',
    })
    if (ok) {
      await restart()
      return true
    }
    return false
  }

  function openLogs() {
    showLogsModal = true
    subscribeToLogs('turbotunnels')
  }

  function closeLogs() {
    showLogsModal = false
    unsubscribeFromLogs()
  }

  // Log line styling + timestamp formatting (matches the Docker logs viewer).
  function getLogLevel(message) {
    const lower = (message || '').toLowerCase()
    if (lower.includes('error') || lower.includes('fatal') || lower.includes('panic')) return 'error'
    if (lower.includes('warn')) return 'warn'
    if (lower.includes('debug') || lower.includes('trace')) return 'debug'
    if (lower.includes('info')) return 'info'
    return 'default'
  }

  function getLogClass(log) {
    if (log.stream === 'stderr') return 'text-destructive'
    const level = getLogLevel(log.message)
    if (level === 'error') return 'text-destructive'
    if (level === 'warn') return 'text-warning'
    if (level === 'debug') return 'text-muted-foreground'
    if (level === 'info') return 'text-info'
    return 'text-foreground'
  }

  function formatTimestamp(ts) {
    if (!ts) return ''
    try {
      const d = new Date(ts)
      const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
      return `${months[d.getMonth()]} ${String(d.getDate()).padStart(2,'0')} ${ts.substring(11,19)}`
    } catch {
      return ts.substring(11, 19)
    }
  }

  // Auto-scroll the log view as new lines stream in.
  $effect(() => {
    const logs = $dockerLogsStore
    if (logsAutoScroll && logsElement && logs.length > 0) {
      logsElement.scrollTop = logsElement.scrollHeight
    }
  })

  onMount(() => {
    refresh()
    // Light polling so running/stopped state stays fresh while the page is open.
    refreshTimer = setInterval(() => { loadStatus(); loadStats() }, 5000)
  })
  onDestroy(() => {
    clearInterval(refreshTimer)
    unsubscribeFromLogs()
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="arrows-right-left"
    title="Tunnels"
    description="Authenticated HTTP forward proxies. Direct tunnels exit from this server; chained tunnels forward through another proxy. Config is stored encrypted and applied by (re)starting the proxy."
    descriptionClass="hidden sm:block"
  >
    {#if status}
      <div class="mt-3 flex items-center gap-2 text-xs">
        <span class="text-muted-foreground">Proxy status:</span>
        {#if running}
          <Badge variant="success" size="sm">Running</Badge>
        {:else if status.status === 'stopped'}
          <Badge variant="warning" size="sm">Stopped</Badge>
        {:else if status.status === 'error'}
          <Badge variant="destructive" size="sm">Error</Badge>
        {:else}
          <Badge variant="muted" size="sm">Not running</Badge>
        {/if}
        {#if config.tunnels.length}
          <span class="text-muted-foreground">· {config.tunnels.length} tunnel{config.tunnels.length === 1 ? '' : 's'}</span>
        {/if}
      </div>
    {/if}
  </InfoCard>

  <Toolbar bind:search={searchQuery} placeholder="Search tunnels...">
    <div class="kt-btn-group">
      {#if running}
        <Button size="xs" variant="secondary" icon="refresh" onclick={restart} disabled={busy}>Restart</Button>
        <Button size="xs" variant="destructive" icon="player-stop" onclick={stop} disabled={busy}>Stop</Button>
      {:else}
        <Button size="xs" variant="secondary" icon="play" onclick={start} disabled={busy || config.tunnels.length === 0}>Start</Button>
      {/if}
      <Button size="xs" variant="outline" icon="file-text" onclick={openLogs}>Logs</Button>
      <Button size="xs" icon="plus" onclick={openCreate}>Add tunnel</Button>
    </div>
  </Toolbar>

  <!-- Overall proxy usage (last 24h) -->
  {#if stats}
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <StatCard icon="activity" color="success" value={stats.requests ?? 0} label="Requests (24h)" />
      <StatCard icon="ban" color="destructive" value={stats.failed ?? 0} label="Failed (24h)" />
      <!-- Secondary stats: hidden on mobile to keep the header compact -->
      <div class="hidden sm:block"><StatCard icon="users" color="info" value={stats.clients ?? 0} label="Unique clients" /></div>
      <div class="hidden sm:block"><StatCard icon="world" color="primary" value={stats.topDest || '—'} label="Top destination" /></div>
    </div>
  {/if}

  <!-- Drift banner: saved config differs from what's running -->
  {#if drift && running}
    <div class="flex items-center justify-between gap-3 p-3 rounded-lg bg-warning/10 border border-warning/30">
      <div class="flex items-center gap-2 text-sm">
        <Icon name="alert-triangle" size={16} class="text-warning shrink-0" />
        <span>Saved changes aren't live yet — restart to apply.</span>
      </div>
      <Button size="sm" variant="secondary" icon="refresh" onclick={restart} disabled={busy}>Restart</Button>
    </div>
  {/if}

  <!-- Error surface (e.g. failed start) -->
  {#if status?.status === 'error' && status.error}
    <div class="flex items-start gap-2 p-3 bg-destructive/10 border border-destructive/30 rounded-lg">
      <Icon name="alert-triangle" size={16} class="text-destructive mt-0.5 shrink-0" />
      <div class="text-xs text-foreground break-all">{status.error}</div>
    </div>
  {/if}

  <!-- Tunnels list -->
  {#if config.tunnels.length === 0}
    <EmptyState
      icon="arrows-right-left"
      title="No tunnels yet"
      description="Deploy a one-click direct proxy on this server, or add a custom tunnel.">
      <div class="flex items-center gap-2 justify-center">
        <Button icon="bolt" onclick={quickDeploy} disabled={busy}>Quick deploy direct proxy</Button>
        <Button variant="outline" icon="plus" onclick={openCreate}>Add tunnel</Button>
      </div>
    </EmptyState>
  {:else if filteredTunnels.length === 0}
    <EmptyState
      icon="search"
      title="No matching tunnels"
      description="No tunnel names match your search." />
  {:else}
    <div class="space-y-2">
      {#each filteredTunnels as t (t.id || t.name)}
        {@const i = config.tunnels.indexOf(t)}
        {@const info = infoById[t.id]}
        {@const chained = !!(t.upstream && t.upstream.host)}
        {@const isOpen = !!expanded[t.id]}
        <div class="bg-card border border-border rounded-lg border-l-4 {running ? 'border-l-success' : 'border-l-muted-foreground/30'}">
          <!-- Header: tap toggles. Row 1 = icon + name + grouped actions;
               row 2 = badges (from the left edge) with 'via' inline. -->
          <div
            class="px-3 py-2.5 sm:px-4 sm:py-3 cursor-pointer select-none"
            role="button" tabindex="0" aria-expanded={isOpen}
            onclick={() => toggleExpand(t.id)}
            onkeydown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleExpand(t.id) } }}
          >
            <div class="flex items-center gap-2">
              <div class="w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0 {running ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                <Icon name="arrows-right-left" size={16} />
              </div>
              <span class="font-medium truncate min-w-0">{t.name}</span>
              <!-- Regenerate: inline right after the title (only when rotating). -->
              {#if info?.rotateTrigger}
                <span class="shrink-0" onclick={(e) => e.stopPropagation()} role="presentation">
                  <Button size="xs" variant="outline" icon="refresh" onclick={() => regenerateRotationKey(t)} disabled={busy} title="Regenerate rotation key"><span class="hidden sm:inline">Regenerate</span></Button>
                </span>
              {/if}
              <!-- Edit/Delete + chevron pushed to the far right. Don't toggle. -->
              <div class="flex items-center gap-2 shrink-0 ml-auto" onclick={(e) => e.stopPropagation()} role="presentation">
                <div class="kt-btn-group">
                  <Button size="xs" variant="outline" icon="pencil" onclick={() => openEdit(i)}><span class="hidden sm:inline">Edit</span></Button>
                  <Button size="xs" variant="outline" icon="trash" onclick={() => deleteTunnel(i)}><span class="hidden sm:inline">Delete</span></Button>
                </div>
                <Icon name="chevron-down" size={18} class="text-muted-foreground transition-transform {isOpen ? 'rotate-180' : ''}" />
              </div>
            </div>
            <!-- Badges start from the left edge (under the icon); 'via' inline (right on mobile). -->
            <div class="flex items-center gap-1 flex-wrap mt-2">
              {#each (t.listeners || []) as l}
                <Badge variant="info" size="sm">{l.protocol.toUpperCase()}</Badge>
              {/each}
              <Badge variant={chained ? 'warning' : 'muted'} size="sm">{chained ? 'Chained' : 'Direct'}</Badge>
              {#if t.rotateUrl}<Badge variant="secondary" size="sm">Rotating</Badge>{/if}
              {#if chained}
                <span class="text-[11px] text-muted-foreground font-mono truncate ml-auto sm:ml-1">via {t.upstream.host}</span>
              {/if}
            </div>
          </div>

          <!-- Expanded body: usage, endpoints, credentials, rotation URL -->
          {#if isOpen}
            <div class="px-3 pb-3 sm:px-4 sm:pb-4 pt-3 border-t border-border/50 space-y-3">
              {#if stats?.perUser?.[t.user]}
                {@const ts = stats.perUser[t.user]}
                <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                  <span class="flex items-center gap-1"><Icon name="activity" size={12} /> {ts.requests} req</span>
                  <span class="flex items-center gap-1 {ts.failed ? 'text-destructive' : ''}"><Icon name="ban" size={12} /> {ts.failed} failed</span>
                  <span class="flex items-center gap-1"><Icon name="users" size={12} /> {ts.clients} clients</span>
                  {#if formatLastSeen(ts.lastSeen)}<span class="flex items-center gap-1"><Icon name="clock" size={12} /> {formatLastSeen(ts.lastSeen)}</span>{/if}
                </div>
              {/if}

              <!-- Endpoints (one per protocol) -->
              <div class="space-y-2">
                {#each (t.listeners || []) as l}
                  {@const ep = (info?.endpoints || []).find((e) => e.protocol === l.protocol)}
                  {@const tr = testResults[`${t.id}:${l.protocol}`]}
                  <div class="rounded-md bg-muted/30 border border-border/50 p-2 space-y-1.5">
                    <div class="flex items-center justify-between gap-2">
                      <div class="flex items-center gap-2 min-w-0">
                        <Badge variant="info" size="sm">{l.protocol.toUpperCase()}</Badge>
                        <span class="font-mono text-xs truncate">{(info?.host || 'server')}:{l.port}</span>
                        {#if tr && !tr.testing}
                          <span class="text-[11px] flex items-center gap-1 shrink-0 {tr.ok ? 'text-success' : 'text-destructive'}">
                            <Icon name={tr.ok ? 'circle-check' : 'alert-triangle'} size={12} />
                            {tr.ok ? `${tr.exitIp} · ${tr.latencyMs}ms` : tr.error}
                          </span>
                        {/if}
                      </div>
                      <Button size="xs" variant="outline" icon="activity" onclick={() => testTunnel(t, l)}
                        disabled={!running || tr?.testing} title={running ? 'Test' : 'Start the proxy to test'}>
                        {tr?.testing ? '...' : 'Test'}
                      </Button>
                    </div>
                    {#if ep?.command}
                      <ContentBlock variant="data" label="Command" value={ep.command} mono copyable padding="sm" />
                    {/if}
                  </div>
                {/each}
              </div>

              <!-- Shared credentials -->
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <ContentBlock variant="data" label="User" value={t.user} mono copyable padding="sm" />
                <ContentBlock variant="data" label="Password" value={t.pass} mono copyable padding="sm" />
              </div>

              {#if info?.rotateTrigger}
                <ContentBlock variant="data" label="Rotation URL (secret)" value={info.rotateTrigger} mono copyable padding="sm" />
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<!-- Add / edit modal -->
<Modal bind:open={showModal} title={modalMode === 'create' ? 'Add tunnel' : 'Edit tunnel'} size="md">
  <div class="space-y-4">
    <Input label="Name" placeholder="My proxy" bind:value={form.name} prefixIcon="tag" />

    <!-- Protocol(s): create can pick both → one tunnel each -->
    <div>
      <span class="text-sm font-medium text-foreground">Protocol{modalMode === 'create' ? 's' : ''}</span>
      <p class="text-xs text-muted-foreground mb-2">
        {modalMode === 'create' ? 'Pick one or both — selecting both creates two tunnels (one per port).' : 'HTTP or SOCKS5.'}
      </p>
      <div class="flex gap-2">
        <Checkbox variant="chip" icon="world" checked={form.protocols.includes('http')} onchange={() => toggleProto('http')} label="HTTP" />
        <Checkbox variant="chip" icon="plug-connected" checked={form.protocols.includes('socks5')} onchange={() => toggleProto('socks5')} label="SOCKS5" />
      </div>
    </div>

    <!-- One port per selected protocol -->
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
      {#if form.protocols.includes('http')}
        <Input label="HTTP port" type="number" placeholder="3128" bind:value={form.ports.http} prefixIcon="plug" />
      {/if}
      {#if form.protocols.includes('socks5')}
        <Input label="SOCKS5 port" type="number" placeholder="1080" bind:value={form.ports.socks5} prefixIcon="plug" />
      {/if}
    </div>

    <!-- Mode: direct vs chained (chosen first — it drives the rest) -->
    <div>
      <span class="text-sm font-medium text-foreground">Mode</span>
      <p class="text-xs text-muted-foreground mb-2">
        <b>Direct</b> exits from this server's IP. <b>Chained</b> forwards through another proxy (e.g. a VPN node) and exits from <i>its</i> IP.
      </p>
      <div class="flex gap-2">
        <Checkbox variant="chip" icon="arrow-up-right" checked={!form.chained}
          onchange={() => form.chained = false} label="Direct" />
        <Checkbox variant="chip" color="warning" icon="link" checked={form.chained}
          onchange={() => form.chained = true} label="Chained" />
      </div>
    </div>

    {#if form.chained}
      <div class="space-y-3 border-l-2 border-warning/40 pl-3">
        <Select label="Upstream node" value={form.upstream.host} onchange={onUpstreamNode}>
          <option value="">Custom / external proxy…</option>
          {#each vpnClients as c}
            <option value={c.ip}>{c.name} ({c.ip})</option>
          {/each}
        </Select>
        <p class="text-[11px] text-muted-foreground -mt-1">Pick a VPN node to reach it by its WG IP, or choose Custom and type any proxy host.</p>
        <Input label="Upstream host" placeholder="1.2.3.4 or node IP" bind:value={form.upstream.host} prefixIcon="server" />
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {#if form.protocols.includes('http')}
            <Input label="Upstream HTTP port" type="number" placeholder="3128" bind:value={form.upstream.ports.http} prefixIcon="plug" />
          {/if}
          {#if form.protocols.includes('socks5')}
            <Input label="Upstream SOCKS5 port" type="number" placeholder="1080" bind:value={form.upstream.ports.socks5} prefixIcon="plug" />
          {/if}
          <Input label="Upstream user (optional)" bind:value={form.upstream.user} prefixIcon="user" />
          <Input label="Upstream password (optional)" bind:value={form.upstream.pass} prefixIcon="key" />
        </div>
      </div>
    {/if}

    <!-- Proxy credentials (what clients use to connect TO this proxy) -->
    <div class="border-t border-border pt-4">
      <span class="text-sm font-medium text-foreground">Proxy credentials</span>
      <p class="text-xs text-muted-foreground mb-2">What clients use to connect to this proxy. Every tunnel is internet-facing, so a strong password is required.</p>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Input label="Username" bind:value={form.user} prefixIcon="user" />
        <Input label="Password" bind:value={form.pass} prefixIcon="key" />
      </div>
      <div class="mt-2">
        <Button size="sm" variant="outline" icon="refresh" onclick={() => generateCreds(form)}>Regenerate</Button>
      </div>
    </div>

    <!-- Rotating IP URL -->
    <div class="border-t border-border pt-4">
      <Input label="Provider rotate URL (optional)" placeholder="https://provider.com/changeip?token=…" bind:value={form.rotateUrl} prefixIcon="refresh" />
      <p class="text-xs text-muted-foreground mt-1">The provider's "change IP" endpoint. We never expose it — we call it via a generated secret rotation URL shown on the tunnel card.</p>
    </div>
  </div>

  {#snippet footer()}
    <div class="flex justify-between w-full">
      <Button variant="outline" onclick={() => showModal = false}>Cancel</Button>
      <Button variant="primary" onclick={saveTunnel} disabled={busy}>
        {modalMode === 'create' ? 'Add tunnel' : 'Save changes'}
      </Button>
    </div>
  {/snippet}
</Modal>

<!-- Logs viewer (live stream over the Docker logs WS channel) -->
<Modal bind:open={showLogsModal} title="Proxy logs" size="lg" onclose={closeLogs}>
  <div class="space-y-3">
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-2">
        <div class="w-2 h-2 rounded-full bg-success animate-pulse"></div>
        <span class="text-sm text-muted-foreground">Live streaming</span>
        <Badge variant="muted" size="sm">{$dockerLogsStore.length} lines</Badge>
      </div>
      <Checkbox bind:checked={logsAutoScroll} label="Auto-scroll" />
    </div>

    <div bind:this={logsElement} class="bg-secondary border border-border rounded-lg max-h-[400px] overflow-auto">
      {#if $dockerLogsStore.length === 0}
        <div class="flex items-center justify-center py-12 text-muted-foreground">
          <div class="w-5 h-5 border-2 border-muted-foreground border-t-transparent rounded-full animate-spin mr-2"></div>
          Waiting for logs...
        </div>
      {:else}
        <table class="w-full text-xs font-mono">
          <thead class="sticky top-0 bg-secondary border-b border-border">
            <tr class="text-muted-foreground text-left">
              <th class="px-2 py-1.5 w-10 text-right">#</th>
              <th class="px-2 py-1.5 w-32">Timestamp</th>
              <th class="px-2 py-1.5">Message</th>
            </tr>
          </thead>
          <tbody>
            {#each $dockerLogsStore as log, i}
              <tr class="hover:bg-muted/30 border-b border-border/20 last:border-0">
                <td class="px-2 py-1 text-muted-foreground/40 text-right align-top select-none">{i + 1}</td>
                <td class="px-2 py-1 text-muted-foreground/60 align-top whitespace-nowrap">{formatTimestamp(log.timestamp)}</td>
                <td class="px-2 py-1 align-top break-all {getLogClass(log)}">{log.message}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  </div>

  {#snippet footer()}
    <Button onclick={closeLogs} variant="secondary">Close</Button>
  {/snippet}
</Modal>
