<script>
  // DockerSettings — the panel's containers (Settings → Docker): state, live stats, restart/stop/start,
  // logs and image analysis. Live list over the "docker" WS channel.
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiPost, apiGet, confirm, stepUpConfirm } from '../stores/app.js'
  import { subscribe, unsubscribe, subscribeToLogs, unsubscribeFromLogs, dockerStore, dockerLogsStore, containerStatsStore } from '../stores/websocket.js'
  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import StatStrip from './StatStrip.svelte'
  import Button from './Button.svelte'
  import Modal from './Modal.svelte'
  import Checkbox from './Checkbox.svelte'
  import LoadingSpinner from './LoadingSpinner.svelte'
  import EmptyState from './EmptyState.svelte'

  let loading = $state(true) // until the first container list arrives

  let containers = $state([])

  // Logs modal state
  let showLogsModal = $state(false)
  let logsContainer = $state(null)
  let logsAutoScroll = $state(true)
  let logsElement = $state(null)

  // Image analysis modal state
  let showAnalyzeModal = $state(false)
  let analyzeContainer = $state(null)
  let imageAnalysis = $state(null)
  let analyzingImage = $state(false)

  // Action states
  let actionInProgress = $state(null)

  // React to WebSocket docker updates
  $effect(() => {
    const data = $dockerStore
    if (data?.containers) {
      containers = data.containers
      loading = false
    }
  })

  // Live per-container stats, keyed by container id.
  let statsById = $state({})
  $effect(() => {
    const d = $containerStatsStore
    if (d?.containers) {
      const m = {}
      for (const st of d.containers) m[st.id] = st
      statsById = m
    }
  })

  onMount(() => {
    subscribe('docker')
    subscribe('container_stats')
  })

  onDestroy(() => {
    unsubscribe('docker')
    unsubscribe('container_stats')
  })

  // Get state color
  function getStateVariant(state) {
    if (state === 'running') return 'success'
    if (state === 'exited') return 'danger'
    if (state === 'restarting') return 'warning'
    return 'muted'
  }

  // Get icon for container
  function getContainerIcon(name) {
    const icons = {
      'traefik': 'route',
      'headscale': 'network',
      'api': 'server',
      'adguard': 'shield',
      'ui-dev': 'layout'
    }
    return icons[name] || 'box'
  }

  // Format uptime
  function formatUptime(status) {
    return status || 'Unknown'
  }

  // Actions - the WebSocket pushes the new state when a container changes
  const DONE = { restart: 'restarted', stop: 'stopped', start: 'started' }
  async function containerAction(name, verb, body) {
    actionInProgress = name + '-' + verb
    try {
      await apiPost(`/api/docker/containers/${name}/${verb}`, body)
      toast(`Container ${name} ${DONE[verb]}`, 'success')
    } catch (e) {
      toast(`Failed to ${verb} ${name}: ${e.message}`, 'error')
    } finally {
      actionInProgress = null
    }
  }

  async function restartContainer(name) {
    const ok = await confirm({ title: 'Restart container', message: `Restart ${name}?`, description: "It's offline for a few seconds while it restarts.", confirmText: 'Restart', variant: 'primary' })
    if (ok) containerAction(name, 'restart')
  }

  // Stopping can take the panel, Traefik or the VPN offline: the server asks for the password.
  async function stopContainer(name) {
    const su = await stepUpConfirm({ title: 'Stop container', message: `Stop ${name}?`,
      description: 'It stays offline until you start it again. Stopping the panel, Traefik or the VPN containers can cut off your own access.',
      confirmText: 'Stop', variant: 'destructive' })
    if (su?.confirmed && su.password) containerAction(name, 'stop', { currentPassword: su.password, totpCode: su.totp || '' })
  }

  const startContainer = (name) => containerAction(name, 'start')

  function viewLogs(container) {
    logsContainer = container
    showLogsModal = true
    subscribeToLogs(container.name)
  }

  function closeLogs() {
    showLogsModal = false
    unsubscribeFromLogs()
    logsContainer = null
  }

  // Image analysis
  async function analyzeImage(container) {
    analyzeContainer = container
    showAnalyzeModal = true
    analyzingImage = true
    imageAnalysis = null

    try {
      // Use imageId (short sha256 hash) to avoid URL encoding issues with image names
      imageAnalysis = await apiGet(`/api/docker/images/${container.imageId}/analyze`)
    } catch (e) {
      toast('Failed to analyze image: ' + e.message, 'error')
    } finally {
      analyzingImage = false
    }
  }

  function closeAnalyze() {
    showAnalyzeModal = false
    analyzeContainer = null
    imageAnalysis = null
  }

  // Auto-scroll logs when new entries arrive
  $effect(() => {
    const logs = $dockerLogsStore
    if (logsAutoScroll && logsElement && logs.length > 0) {
      logsElement.scrollTop = logsElement.scrollHeight
    }
  })

  // Get log level from message for styling
  function getLogLevel(message) {
    const lower = message.toLowerCase()
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

  // Format timestamp: "2024-01-02T15:04:05.123Z" -> "Jan 02 15:04:05"
  function formatTimestamp(ts) {
    if (!ts) return ''
    try {
      const d = new Date(ts)
      const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
      const month = months[d.getMonth()]
      const day = String(d.getDate()).padStart(2, '0')
      const time = ts.substring(11, 19)
      return `${month} ${day} ${time}`
    } catch {
      return ts.substring(11, 19)
    }
  }

  // Stats
  const runningCount = $derived(containers.filter(c => c.state === 'running').length)
  const stoppedCount = $derived(containers.filter(c => c.state !== 'running').length)
</script>

<div class="space-y-4">
  {#if loading}
    <LoadingSpinner centered size="lg" />
  {:else}
    <StatStrip label="Containers" items={[
      { icon: 'box', value: containers.length, label: 'containers', tone: 'info' },
      { icon: 'player-play', value: runningCount, of: containers.length, label: 'running', tone: 'success' },
      { icon: 'player-stop', value: stoppedCount, label: 'stopped', tone: stoppedCount ? 'destructive' : undefined },
    ]} />

    <!-- Containers List -->
    {#if containers.length > 0}
      <div class="space-y-2">
        <!-- a container's actions: one copy for the phone layout and the desktop row -->
        {#snippet containerActions(container)}
          {@const busy = (what) => actionInProgress === container.name + '-' + what}
          <div class="kt-btn-group shrink-0">
            <Button variant="outline" size="xs" icon="file-text" tooltip="Logs" aria-label={`Logs of ${container.name}`} onclick={() => viewLogs(container)} />
            <Button variant="outline" size="xs" icon="chart-pie" tooltip="Analyze size" aria-label={`Analyze the size of ${container.name}`} onclick={() => analyzeImage(container)} />
            {#if container.state === 'running'}
              <Button variant="outline" size="xs" icon="refresh" class="text-primary hover:bg-primary/10" loading={busy('restart')} disabled={busy('restart')}
                tooltip="Restart" aria-label={`Restart ${container.name}`} onclick={() => restartContainer(container.name)} />
              <Button variant="outline" size="xs" icon="player-stop" class="text-destructive hover:bg-destructive/10" loading={busy('stop')} disabled={busy('stop')}
                tooltip="Stop" aria-label={`Stop ${container.name}`} onclick={() => stopContainer(container.name)} />
            {:else}
              <Button variant="outline" size="xs" icon="player-play" class="text-success hover:bg-success/10" loading={busy('start')} disabled={busy('start')}
                tooltip="Start" aria-label={`Start ${container.name}`} onclick={() => startContainer(container.name)} />
            {/if}
          </div>
        {/snippet}
        {#each containers as container}
          <div class="bg-card border border-border rounded-lg px-4 py-3 hover:border-primary/30 transition-colors">
            <div class="flex flex-wrap sm:flex-nowrap items-center gap-3 sm:gap-4">
              <!-- Icon + Name -->
              <div class="flex items-center gap-3 min-w-0 flex-1 sm:flex-none sm:min-w-[200px]">
                <div class="w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0 {container.state === 'running' ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                  <Icon name={getContainerIcon(container.name)} size={16} />
                </div>
                <div class="min-w-0">
                  <h3 class="font-medium text-sm text-foreground">{container.name}</h3>
                  <p class="text-[11px] text-muted-foreground truncate">{container.image.split(':')[0].split('/').pop()}</p>
                </div>
              </div>

              <!-- Mobile: Status + Actions aligned right -->
              <div class="flex flex-col items-end gap-1.5 sm:hidden">
                <Badge variant={getStateVariant(container.state)} size="sm">
                  {container.state}
                </Badge>
                {@render containerActions(container)}
              </div>

              <!-- Desktop: Inline layout -->
              <div class="hidden sm:contents">
                <!-- Status -->
                <Badge variant={getStateVariant(container.state)} size="sm">
                  {container.state}
                </Badge>

                <!-- Uptime -->
                <span class="text-xs text-muted-foreground">
                  {formatUptime(container.status)}
                </span>

                <!-- Ports -->
                {#if container.ports?.length > 0}
                  {@const visiblePorts = container.ports.filter(p => p.publicPort)}
                  <div class="hidden md:flex items-center gap-1">
                    {#each visiblePorts.slice(0, 2) as port}
                      <span class="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-mono">
                        :{port.publicPort}
                      </span>
                    {/each}
                    {#if visiblePorts.length > 2}
                      <span class="text-[10px] text-muted-foreground cursor-help" data-kt-tooltip>
                        +{visiblePorts.length - 2}
                        <span data-kt-tooltip-content class="kt-tooltip hidden">
                          {visiblePorts.slice(2).map(p => `:${p.publicPort}`).join(', ')}
                        </span>
                      </span>
                    {/if}
                  </div>
                {/if}

                <!-- Live resource stats -->
                {#if container.state === 'running' && statsById[container.id]}
                  {@const st = statsById[container.id]}
                  <div class="hidden lg:flex items-center gap-3 text-[11px]" data-kt-tooltip>
                    <span class="flex items-center gap-1 text-muted-foreground"><Icon name="cpu" size={12} /><b class="text-foreground tabular-nums">{st.cpuPercent.toFixed(1)}%</b></span>
                    <span class="flex items-center gap-1 text-muted-foreground"><Icon name="database" size={12} /><b class="text-foreground tabular-nums">{st.memUsageHR}</b><span class="opacity-70"> · {st.memPercent.toFixed(0)}%</span></span>
                    <span data-kt-tooltip-content class="kt-tooltip hidden">CPU {st.cpuPercent.toFixed(1)}% · Mem {st.memUsageHR} / {st.memLimitHR} ({st.memPercent.toFixed(0)}%) · Net ↓{st.netRxHR} ↑{st.netTxHR}</span>
                  </div>
                {/if}

                <!-- Spacer -->
                <div class="flex-1"></div>

                <!-- Actions -->
                {@render containerActions(container)}
              </div>
            </div>
          </div>
        {/each}
      </div>
    {:else}
      <EmptyState
        icon="box"
        title="No containers"
        description="No project containers found"
      />
    {/if}
  {/if}
</div>

<!-- Logs Modal -->
<Modal bind:open={showLogsModal} title="{logsContainer?.name} Logs" size="lg" onclose={closeLogs}>
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

<!-- Image Analysis Modal -->
<Modal bind:open={showAnalyzeModal} title="Image Size Analysis" size="lg" onclose={closeAnalyze}>
  <div class="space-y-4">
    {#if analyzingImage}
      <div class="flex items-center justify-center py-12">
        <div class="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mr-3"></div>
        <span class="text-muted-foreground">Analyzing image layers...</span>
      </div>
    {:else if imageAnalysis}
      <!-- Header with total size -->
      <div class="flex items-center justify-between p-3 bg-muted/50 rounded-lg border border-border">
        <div>
          <div class="text-sm font-medium text-foreground">{analyzeContainer?.image}</div>
          <div class="text-xs text-muted-foreground">Container: {analyzeContainer?.name}</div>
        </div>
        <div class="text-right">
          <div class="text-2xl font-bold text-primary">{imageAnalysis.totalHR}</div>
          <div class="text-[10px] text-muted-foreground">Total Size</div>
        </div>
      </div>

      <!-- Layers table -->
      <div class="bg-secondary border border-border rounded-lg overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-muted/50 border-b border-border">
            <tr class="text-muted-foreground text-left text-xs">
              <th class="px-3 py-2 font-medium">Layer</th>
              <th class="px-3 py-2 font-medium text-right w-24">Size</th>
              <th class="px-3 py-2 font-medium">Purpose</th>
            </tr>
          </thead>
          <tbody>
            {#each imageAnalysis.layers as layer, i}
              {@const percent = Math.round((layer.size / imageAnalysis.totalSize) * 100)}
              <tr class="border-b border-border/50 last:border-0 hover:bg-muted/30">
                <td class="px-3 py-2">
                  <div class="flex items-center gap-2">
                    <div class="w-2 h-2 rounded-full {
                      layer.category === 'Base OS' ? 'bg-info' :
                      layer.category === 'System packages' ? 'bg-warning' :
                      layer.category === 'Binary' ? 'bg-success' :
                      layer.category === 'Static files' ? 'bg-primary' :
                      layer.category === 'Config' ? 'bg-muted-foreground' :
                      layer.category === 'Nginx' ? 'bg-orange-500' :
                      'bg-muted-foreground'
                    }"></div>
                    <span class="font-medium text-foreground">{layer.category}</span>
                  </div>
                </td>
                <td class="px-3 py-2 text-right">
                  <span class="font-mono text-foreground">{layer.sizeHR}</span>
                  <span class="text-[10px] text-muted-foreground ml-1">({percent}%)</span>
                </td>
                <td class="px-3 py-2 text-muted-foreground text-xs">{layer.purpose}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      <!-- Size visualization bar -->
      <div class="space-y-2">
        <div class="text-xs font-medium text-muted-foreground">Size Distribution</div>
        <div class="h-4 rounded-full overflow-hidden flex bg-muted">
          {#each imageAnalysis.layers as layer}
            {@const percent = (layer.size / imageAnalysis.totalSize) * 100}
            {#if percent > 1}
              <div
                class="h-full {
                  layer.category === 'Base OS' ? 'bg-info' :
                  layer.category === 'System packages' ? 'bg-warning' :
                  layer.category === 'Binary' ? 'bg-success' :
                  layer.category === 'Static files' ? 'bg-primary' :
                  layer.category === 'Config' ? 'bg-muted-foreground' :
                  layer.category === 'Nginx' ? 'bg-orange-500' :
                  'bg-muted-foreground/50'
                }"
                style="width: {percent}%"
                data-kt-tooltip
              >
                <span data-kt-tooltip-content class="kt-tooltip hidden">{layer.category}: {layer.sizeHR}</span>
              </div>
            {/if}
          {/each}
        </div>
      </div>
    {:else}
      <div class="text-center py-8 text-muted-foreground">
        <Icon name="alert-circle" size={24} class="mx-auto mb-2" />
        <p>Failed to analyze image</p>
      </div>
    {/if}
  </div>

  {#snippet footer()}
    <Button onclick={closeAnalyze} variant="secondary">Close</Button>
  {/snippet}
</Modal>
