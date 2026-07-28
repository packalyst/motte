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
  import Checkbox from '../components/Checkbox.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import ContentBlock from '../components/ContentBlock.svelte'
  import InfoCard from '../components/InfoCard.svelte'

  let { loading = $bindable(true) } = $props()

  // Live container status (running/stopped/…) + per-tunnel display info.
  let status = $state(null)
  // The editable config (source of truth for tunnels), loaded from /config.
  let config = $state({ tunnels: [] })
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

  function blankForm() {
    return {
      id: '',
      name: '',
      listenPort: '',
      user: '',
      pass: '',
      chained: false,
      upstream: { host: '', port: '', user: '', pass: '' },
    }
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

  async function refresh() {
    await Promise.all([loadStatus(), loadConfig()])
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
  const restart = () => lifecycle('restart', 'Proxy restarted')

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
    form = {
      id: t.id || '',
      name: t.name || '',
      listenPort: t.listenPort ?? '',
      user: t.user || '',
      pass: t.pass || '',
      chained: !!(t.upstream && t.upstream.host),
      upstream: {
        host: t.upstream?.host || '',
        port: t.upstream?.port ?? '',
        user: t.upstream?.user || '',
        pass: t.upstream?.pass || '',
      },
    }
    showModal = true
  }

  function buildTunnelFromForm() {
    const t = {
      id: form.id,
      name: form.name.trim(),
      listenPort: Number(form.listenPort),
      user: form.user.trim(),
      pass: form.pass,
      upstream: { host: '', port: 0, user: '', pass: '' },
    }
    if (form.chained) {
      t.upstream = {
        host: form.upstream.host.trim(),
        port: Number(form.upstream.port),
        user: form.upstream.user.trim(),
        pass: form.upstream.pass,
      }
    }
    return t
  }

  async function saveTunnel() {
    // Build the next config, then persist the whole document.
    const next = { tunnels: [...config.tunnels] }
    const tunnel = buildTunnelFromForm()
    if (modalMode === 'create') next.tunnels.push(tunnel)
    else next.tunnels[editIndex] = tunnel

    busy = true
    try {
      status = await apiPut('/api/turbotunnels/config', next)
      config = next
      showModal = false
      toast(modalMode === 'create' ? 'Tunnel added' : 'Tunnel updated', 'success')
      await maybeOfferRestart()
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
      message: `Delete "${t.name}" (port ${t.listenPort})?`,
      description: 'The proxy on this port will stop being served after a restart.',
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
  async function maybeOfferRestart() {
    if (!running) return
    const ok = await confirm({
      title: 'Restart proxy to apply?',
      message: 'The proxy is running. Applying this change restarts it and briefly drops active connections.',
      description: 'You can also restart later from the toolbar.',
      confirmText: 'Restart now',
      cancelText: 'Later',
    })
    if (ok) await restart()
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
    refreshTimer = setInterval(loadStatus, 5000)
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
        <Button size="sm" variant="secondary" icon="refresh" onclick={restart} disabled={busy}>Restart</Button>
        <Button size="sm" variant="destructive" icon="player-stop" onclick={stop} disabled={busy}>Stop</Button>
      {:else}
        <Button size="sm" variant="secondary" icon="play" onclick={start} disabled={busy || config.tunnels.length === 0}>Start</Button>
      {/if}
    </div>
    <Button size="sm" variant="outline" icon="file-text" onclick={openLogs}>Logs</Button>
    <Button size="sm" icon="plus" onclick={openCreate}>Add tunnel</Button>
  </Toolbar>

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
        <div class="bg-card border border-border rounded-lg px-4 py-3">
          <div class="flex flex-wrap sm:flex-nowrap items-center gap-3">
            <div class="flex items-center gap-3 min-w-0 flex-1">
              <div class="w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0 {running ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                <Icon name="arrows-right-left" size={16} />
              </div>
              <div class="min-w-0">
                <div class="flex items-center gap-2">
                  <span class="font-medium truncate">{t.name}</span>
                  <Badge variant="info" size="sm">HTTP</Badge>
                  <Badge variant={chained ? 'warning' : 'muted'} size="sm">{chained ? 'Chained' : 'Direct'}</Badge>
                </div>
                <p class="text-[11px] text-muted-foreground font-mono truncate">
                  {(info?.host || 'server')}:{t.listenPort}
                  {#if chained}· via {t.upstream.host}:{t.upstream.port}{/if}
                </p>
              </div>
            </div>
            <div class="kt-btn-group">
              <Button size="sm" variant="outline" icon="pencil" onclick={() => openEdit(i)}>Edit</Button>
              <Button size="sm" variant="outline" icon="trash" onclick={() => deleteTunnel(i)}>Delete</Button>
            </div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2 mt-3">
            <ContentBlock variant="data" label="User" value={t.user} mono copyable padding="sm" />
            <ContentBlock variant="data" label="Password" value={t.pass} mono copyable padding="sm" />
            <ContentBlock variant="data" label="Port" value={String(t.listenPort)} mono copyable padding="sm" />
          </div>
          {#if info?.command}
            <div class="mt-2">
              <ContentBlock variant="data" label="Example command" value={info.command} mono copyable padding="sm" />
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
    <Input label="Listen port" type="number" placeholder="3128" bind:value={form.listenPort} prefixIcon="plug" />

    <div>
      <span class="text-sm font-medium text-foreground">Credentials</span>
      <p class="text-xs text-muted-foreground mb-2">Every tunnel is internet-facing, so a strong password is required.</p>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Input label="Username" bind:value={form.user} prefixIcon="user" />
        <Input label="Password" bind:value={form.pass} prefixIcon="key" />
      </div>
      <div class="mt-2">
        <Button size="sm" variant="outline" icon="refresh" onclick={() => generateCreds(form)}>Regenerate</Button>
      </div>
    </div>

    <div class="border-t border-border pt-4">
      <div class="flex items-center justify-between">
        <div>
          <span class="text-sm font-medium text-foreground">Chain through an upstream proxy</span>
          <p class="text-xs text-muted-foreground">Off = direct (exits this server). On = forward through another proxy.</p>
        </div>
        <Checkbox variant="chip" icon="link" checked={form.chained}
          onchange={() => form.chained = !form.chained}
          label={form.chained ? 'Chained' : 'Direct'} />
      </div>

      {#if form.chained}
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
          <Input label="Upstream host" placeholder="1.2.3.4" bind:value={form.upstream.host} prefixIcon="server" />
          <Input label="Upstream port" type="number" placeholder="8080" bind:value={form.upstream.port} prefixIcon="plug" />
          <Input label="Upstream user (optional)" bind:value={form.upstream.user} prefixIcon="user" />
          <Input label="Upstream password (optional)" bind:value={form.upstream.pass} prefixIcon="key" />
        </div>
      {/if}
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
