<script>
  import { onMount, onDestroy } from 'svelte'
  import { subscribe, unsubscribe, statsStore } from '../stores/websocket.js'
  import Icon from '../components/Icon.svelte'
  import InfoCard from '../components/InfoCard.svelte'

  let { loading = $bindable(true) } = $props()

  // Format bytes to human readable
  function formatBytes(bytes, decimals = 1) {
    if (!bytes || bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i]
  }

  // Format uptime to human readable
  function formatUptime(seconds) {
    if (!seconds) return '0s'
    const days = Math.floor(seconds / 86400)
    const hours = Math.floor((seconds % 86400) / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    if (days > 0) return `${days}d ${hours}h`
    if (hours > 0) return `${hours}h ${mins}m`
    return `${mins}m ${seconds % 60}s`
  }

  // Format rate to human readable
  function formatRate(bytesPerSec) {
    return formatBytes(bytesPerSec) + '/s'
  }

  $effect(() => {
    if ($statsStore) {
      loading = false
    }
  })

  onMount(() => {
    subscribe('stats')
    loading = false
  })

  onDestroy(() => {
    unsubscribe('stats')
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="dashboard"
    title="Overview"
    description="System status, VPN traffic, and resource usage at a glance."
  />

  <!-- System Stats - Row 1 -->
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-primary/10">
            <Icon name="clock" size={20} class="text-primary" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Uptime</div>
            <div class="text-lg font-semibold">{formatUptime($statsStore?.system?.uptime)}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-info/10">
            <Icon name="cpu" size={20} class="text-info" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Memory</div>
            <div class="text-lg font-semibold">{formatBytes($statsStore?.system?.mem_alloc)}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-success/10">
            <Icon name="users" size={20} class="text-success" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Nodes Online</div>
            <div class="text-lg font-semibold">{$statsStore?.nodes?.online || 0}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-destructive/10">
            <Icon name="user-off" size={20} class="text-destructive" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Nodes Offline</div>
            <div class="text-lg font-semibold">{$statsStore?.nodes?.offline || 0}</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Traffic Stats - Row 2 -->
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-success/10">
            <Icon name="arrow-up" size={20} class="text-success" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Upload</div>
            <div class="text-lg font-semibold">{formatRate($statsStore?.traffic?.rate_tx)}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-info/10">
            <Icon name="arrow-down" size={20} class="text-info" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Download</div>
            <div class="text-lg font-semibold">{formatRate($statsStore?.traffic?.rate_rx)}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-warning/10">
            <Icon name="activity" size={20} class="text-warning" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">Goroutines</div>
            <div class="text-lg font-semibold">{$statsStore?.system?.num_goroutine || 0}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="kt-panel">
      <div class="kt-panel-body p-4">
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-secondary/10">
            <Icon name="plug-connected" size={20} class="text-muted-foreground" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">WS Clients</div>
            <div class="text-lg font-semibold">{$statsStore?.system?.ws_clients || 0}</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Traffic Totals & Top Peers -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <!-- Traffic Totals -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">Total Transfer</h3>
      </div>
      <div class="kt-panel-body">
        <div class="grid grid-cols-2 gap-4">
          <div class="p-4 rounded-lg bg-success/10 border border-success/20">
            <div class="flex items-center gap-2 mb-2">
              <Icon name="arrow-up" size={18} class="text-success" />
              <span class="text-sm text-muted-foreground">Uploaded</span>
            </div>
            <div class="text-2xl font-bold text-success">{formatBytes($statsStore?.traffic?.total_tx)}</div>
          </div>
          <div class="p-4 rounded-lg bg-info/10 border border-info/20">
            <div class="flex items-center gap-2 mb-2">
              <Icon name="arrow-down" size={18} class="text-info" />
              <span class="text-sm text-muted-foreground">Downloaded</span>
            </div>
            <div class="text-2xl font-bold text-info">{formatBytes($statsStore?.traffic?.total_rx)}</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Top Peers by Traffic -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">Top Peers by Traffic</h3>
      </div>
      <div class="kt-panel-body">
        {#if $statsStore?.traffic?.by_peer?.length > 0}
          <div class="space-y-2">
            {#each $statsStore.traffic.by_peer.slice(0, 5) as peer}
              <div class="flex items-center justify-between p-2 rounded-lg bg-muted/50">
                <div class="flex items-center gap-3">
                  <Icon name="device-laptop" size={18} class="text-primary" />
                  <div>
                    <div class="font-medium text-sm">{peer.name}</div>
                    <div class="text-xs text-muted-foreground">{peer.ip}</div>
                  </div>
                </div>
                <div class="text-right">
                  <div class="text-xs">
                    <span class="text-success">{formatBytes(peer.tx)}</span>
                    <span class="text-muted-foreground"> / </span>
                    <span class="text-info">{formatBytes(peer.rx)}</span>
                  </div>
                </div>
              </div>
            {/each}
          </div>
        {:else}
          <div class="text-center text-muted-foreground py-8">
            <Icon name="chart-bar" size={32} class="mx-auto mb-2 opacity-50" />
            <p class="text-sm">No traffic data yet</p>
          </div>
        {/if}
      </div>
    </div>
  </div>

  <!-- Docker Stats -->
  {#if $statsStore?.dockerInfo}
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <!-- Docker Info -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">Docker</h3>
        <span class="text-sm text-muted-foreground">{$statsStore.dockerInfo.operatingSystem}</span>
      </div>
      <div class="kt-panel-body">
        <div class="grid grid-cols-2 sm:grid-cols-3 gap-4">
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-lg bg-info/10">
              <Icon name="server" size={20} class="text-info" />
            </div>
            <div>
              <div class="text-xs text-muted-foreground">Version</div>
              <div class="font-semibold">{$statsStore.dockerInfo.serverVersion}</div>
            </div>
          </div>
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-lg bg-primary/10">
              <Icon name="cpu" size={20} class="text-primary" />
            </div>
            <div>
              <div class="text-xs text-muted-foreground">CPUs</div>
              <div class="font-semibold">{$statsStore.dockerInfo.ncpu}</div>
            </div>
          </div>
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-lg bg-warning/10">
              <Icon name="device-floppy" size={20} class="text-warning" />
            </div>
            <div>
              <div class="text-xs text-muted-foreground">Memory</div>
              <div class="font-semibold">{$statsStore.dockerInfo.memTotalHR}</div>
            </div>
          </div>
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-lg bg-success/10">
              <Icon name="box" size={20} class="text-success" />
            </div>
            <div>
              <div class="text-xs text-muted-foreground">Containers</div>
              <div class="font-semibold">
                <span class="text-success">{$statsStore.dockerInfo.containersRunning}</span>
                <span class="text-muted-foreground">/</span>
                {$statsStore.dockerInfo.containers}
              </div>
            </div>
          </div>
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-lg bg-secondary/10">
              <Icon name="layers-subtract" size={20} class="text-muted-foreground" />
            </div>
            <div>
              <div class="text-xs text-muted-foreground">Images</div>
              <div class="font-semibold">{$statsStore.dockerInfo.images}</div>
            </div>
          </div>
          <div class="flex items-center gap-3">
            <div class="p-2 rounded-lg bg-secondary/10">
              <Icon name="layout" size={20} class="text-muted-foreground" />
            </div>
            <div>
              <div class="text-xs text-muted-foreground">Storage</div>
              <div class="font-semibold">{$statsStore.dockerInfo.storageDriver}</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Disk Usage -->
    {#if $statsStore?.diskUsage}
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">Disk Usage</h3>
        <span class="text-sm text-muted-foreground">{$statsStore.diskUsage.totalSizeHR} total</span>
      </div>
      <div class="kt-panel-body">
        <div class="space-y-3">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <Icon name="layers-subtract" size={16} class="text-info" />
              <span class="text-sm">Images ({$statsStore.diskUsage.imagesCount})</span>
            </div>
            <span class="text-sm font-medium">{$statsStore.diskUsage.imagesSizeHR}</span>
          </div>
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <Icon name="box" size={16} class="text-success" />
              <span class="text-sm">Containers ({$statsStore.diskUsage.containersCount})</span>
            </div>
            <span class="text-sm font-medium">{$statsStore.diskUsage.containersSizeHR}</span>
          </div>
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <Icon name="server" size={16} class="text-warning" />
              <span class="text-sm">Volumes ({$statsStore.diskUsage.volumesCount})</span>
            </div>
            <span class="text-sm font-medium">{$statsStore.diskUsage.volumesSizeHR}</span>
          </div>
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <Icon name="code" size={16} class="text-muted-foreground" />
              <span class="text-sm">Build Cache</span>
            </div>
            <span class="text-sm font-medium">{$statsStore.diskUsage.buildCacheSizeHR}</span>
          </div>
        </div>
      </div>
    </div>
    {/if}
  </div>
  {/if}
</div>
