<script>
  import { onMount, onDestroy } from 'svelte'
  import { toast, apiPost, apiGet } from '../stores/app.js'
  import { subscribe, unsubscribe, subscribeToLogs, unsubscribeFromLogs, dockerStore, dockerLogsStore } from '../stores/websocket.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import InfoCard from '../components/InfoCard.svelte'

  let { loading = $bindable(true) } = $props()

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

  onMount(() => {
    subscribe('docker')
  })

  onDestroy(() => {
    unsubscribe('docker')
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

  // Actions - WebSocket will push updates when container state changes
  async function restartContainer(name) {
    actionInProgress = name + '-restart'
    try {
      await apiPost(`/api/docker/containers/${name}/restart`)
      toast(`Container ${name} restarted`, 'success')
    } catch (e) {
      toast('Failed to restart: ' + e.message, 'error')
    } finally {
      actionInProgress = null
    }
  }

  async function stopContainer(name) {
    actionInProgress = name + '-stop'
    try {
      await apiPost(`/api/docker/containers/${name}/stop`)
      toast(`Container ${name} stopped`, 'success')
    } catch (e) {
      toast('Failed to stop: ' + e.message, 'error')
    } finally {
      actionInProgress = null
    }
  }

  async function startContainer(name) {
    actionInProgress = name + '-start'
    try {
      await apiPost(`/api/docker/containers/${name}/start`)
      toast(`Container ${name} started`, 'success')
    } catch (e) {
      toast('Failed to start: ' + e.message, 'error')
    } finally {
      actionInProgress = null
    }
  }

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
  <InfoCard
    icon="box"
    title="Container Management"
    description="Monitor and manage Docker containers. Restart services, view logs, and check container health."
  />

  {#if loading}
    <LoadingSpinner centered size="lg" />
  {:else}
    <!-- Stats -->
    <div class="grid grid-cols-3 gap-3">
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-info/10 flex items-center justify-center flex-shrink-0">
          <Icon name="box" size={20} class="text-info" />
        </div>
        <div>
          <div class="text-2xl font-bold text-foreground">{containers.length}</div>
          <div class="text-[11px] text-muted-foreground">Total</div>
        </div>
      </div>
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-success/10 flex items-center justify-center flex-shrink-0">
          <Icon name="check" size={20} class="text-success" />
        </div>
        <div>
          <div class="text-2xl font-bold text-success">{runningCount}</div>
          <div class="text-[11px] text-muted-foreground">Running</div>
        </div>
      </div>
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-danger/10 flex items-center justify-center flex-shrink-0">
          <Icon name="x" size={20} class="text-danger" />
        </div>
        <div>
          <div class="text-2xl font-bold text-danger">{stoppedCount}</div>
          <div class="text-[11px] text-muted-foreground">Stopped</div>
        </div>
      </div>
    </div>

    <!-- Containers List -->
    {#if containers.length > 0}
      <div class="space-y-2">
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
                <div class="btn-group">
                  <button onclick={() => viewLogs(container)} class="custom_btns" data-kt-tooltip>
                    <Icon name="file-text" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Logs</span>
                  </button>
                  <button onclick={() => analyzeImage(container)} class="custom_btns" data-kt-tooltip>
                    <Icon name="chart-pie" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Analyze Size</span>
                  </button>
                  {#if container.state === 'running'}
                    <button onclick={() => restartContainer(container.name)} disabled={actionInProgress === container.name + '-restart'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-restart'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="refresh" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Restart</span>
                    </button>
                    <button onclick={() => stopContainer(container.name)} disabled={actionInProgress === container.name + '-stop'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-stop'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="player-stop" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Stop</span>
                    </button>
                  {:else}
                    <button onclick={() => startContainer(container.name)} disabled={actionInProgress === container.name + '-start'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-start'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="player-play" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Start</span>
                    </button>
                  {/if}
                </div>
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

                <!-- Spacer -->
                <div class="flex-1"></div>

                <!-- Actions -->
                <div class="btn-group">
                  <button onclick={() => viewLogs(container)} class="custom_btns" data-kt-tooltip>
                    <Icon name="file-text" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Logs</span>
                  </button>
                  <button onclick={() => analyzeImage(container)} class="custom_btns" data-kt-tooltip>
                    <Icon name="chart-pie" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Analyze Size</span>
                  </button>
                  {#if container.state === 'running'}
                    <button onclick={() => restartContainer(container.name)} disabled={actionInProgress === container.name + '-restart'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-restart'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="refresh" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Restart</span>
                    </button>
                    <button onclick={() => stopContainer(container.name)} disabled={actionInProgress === container.name + '-stop'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-stop'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="player-stop" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Stop</span>
                    </button>
                  {:else}
                    <button onclick={() => startContainer(container.name)} disabled={actionInProgress === container.name + '-start'} class="custom_btns" data-kt-tooltip>
                      {#if actionInProgress === container.name + '-start'}
                        <div class="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <Icon name="player-play" size={14} />
                      {/if}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">Start</span>
                    </button>
                  {/if}
                </div>
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
