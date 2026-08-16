<script>
  import { onMount, onDestroy, untrack } from 'svelte'
  import { subscribe, unsubscribe, statsStore } from '../stores/websocket.js'
  import Icon from '../components/Icon.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import AreaChart from '../components/AreaChart.svelte'
  import SecurityGlance from '../components/SecurityGlance.svelte'
  import BlockedByLayer from '../components/BlockedByLayer.svelte'
  import PublicVisitors from '../components/PublicVisitors.svelte'
  import WorstOffender from '../components/WorstOffender.svelte'
  import ActivityFeed from '../components/ActivityFeed.svelte'
  import PeersCard from '../components/PeersCard.svelte'
  import { currentView } from '../stores/app.js'

  let { loading = $bindable(true) } = $props()

  // Rolling buffer of live traffic samples for the real-time chart. Each WebSocket
  // stats push appends one point (server-computed bytes/sec); the server pushes on
  // its status-checker tick (~10s), so MAX_SAMPLES points is a moving ~10-min window.
  const MAX_SAMPLES = 60
  let samples = $state([])

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

  // Append a live-traffic sample on each stats push. Only $statsStore may be a
  // dependency; the sample mutation is wrapped in untrack() because push/shift read
  // `samples` internally, which would otherwise make the effect depend on its own
  // write and loop (effect_update_depth_exceeded).
  $effect(() => {
    const s = $statsStore
    if (!s?.traffic) return
    untrack(() => {
      const label = new Date().toTimeString().slice(0, 8) // HH:MM:SS
      samples.push({ t: label, up: s.traffic.rate_tx ?? 0, down: s.traffic.rate_rx ?? 0 })
      if (samples.length > MAX_SAMPLES) samples.shift()
    })
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

  <!-- Security lead: verdict + "did anyone get in?" glance -->
  <SecurityGlance />

  <!-- Is my defense working — blocked by layer (last hour) -->
  <div>
    <h2 class="text-xs uppercase tracking-wide text-muted-foreground font-semibold mb-2">Is my defense working — blocked by layer</h2>
    <BlockedByLayer live />
  </div>

  <!-- Threats & visitors right now -->
  <div>
    <h2 class="text-xs uppercase tracking-wide text-muted-foreground font-semibold mb-2">Threats &amp; visitors right now</h2>
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <WorstOffender />
      <PublicVisitors />
    </div>
  </div>

  <!-- Service health -->
  {#if $statsStore?.services?.length}
    <div>
      <h2 class="text-xs uppercase tracking-wide text-muted-foreground font-semibold mb-2">Service health</h2>
      <div class="bg-card border border-border rounded-xl p-4 flex flex-wrap gap-2">
        {#each $statsStore.services as svc (svc.key)}
          <span class="inline-flex items-center gap-1.5 text-xs bg-muted/40 border border-border rounded-full px-2.5 py-1">
            <span class="h-1.5 w-1.5 rounded-full {svc.status === 'up' ? 'bg-success' : 'bg-destructive animate-pulse'}"></span>
            <span class="{svc.status === 'up' ? 'text-muted-foreground' : 'text-destructive font-medium'}">{svc.name}</span>
          </span>
        {/each}
      </div>
    </div>
  {/if}

  <!-- Traffic: live chart + cumulative totals -->
  <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
  <!-- Live Traffic -->
  <div class="bg-card border border-border rounded-xl p-4 lg:col-span-2">
    <h3 class="text-sm font-semibold mb-3">Live Traffic</h3>
    <div>
      {#if samples.length > 1}
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="rounded-lg border border-border bg-muted/20 p-3 overflow-hidden">
            <div class="text-xs text-muted-foreground mb-2 flex items-center justify-between">
              <span class="flex items-center gap-1.5"><Icon name="arrow-up" size={14} class="text-success" />Upload</span>
              <span class="text-success font-medium tabular-nums">{formatRate($statsStore?.traffic?.rate_tx)}</span>
            </div>
            <div class="text-success">
              <AreaChart data={samples} valueKey="up" labelKey="t" height={120} format={formatRate} />
            </div>
          </div>
          <div class="rounded-lg border border-border bg-muted/20 p-3 overflow-hidden">
            <div class="text-xs text-muted-foreground mb-2 flex items-center justify-between">
              <span class="flex items-center gap-1.5"><Icon name="arrow-down" size={14} class="text-info" />Download</span>
              <span class="text-info font-medium tabular-nums">{formatRate($statsStore?.traffic?.rate_rx)}</span>
            </div>
            <div class="text-info">
              <AreaChart data={samples} valueKey="down" labelKey="t" height={120} format={formatRate} />
            </div>
          </div>
        </div>
      {:else}
        <div class="text-center text-muted-foreground py-8">
          <Icon name="activity" size={32} class="mx-auto mb-2 opacity-50" />
          <p class="text-sm">Collecting live traffic…</p>
        </div>
      {/if}
    </div>
  </div>

    <!-- Total Transfer -->
    <div class="bg-card border border-border rounded-xl p-4">
      <h3 class="text-sm font-semibold mb-3">Total Transfer</h3>
      <div class="space-y-3">
        <div class="p-4 rounded-lg bg-success/10 border border-success/20">
          <div class="flex items-center gap-2 mb-1">
            <Icon name="arrow-up" size={16} class="text-success" />
            <span class="text-xs text-muted-foreground">Uploaded</span>
          </div>
          <div class="text-2xl font-bold text-success">{formatBytes($statsStore?.traffic?.total_tx)}</div>
        </div>
        <div class="p-4 rounded-lg bg-info/10 border border-info/20">
          <div class="flex items-center gap-2 mb-1">
            <Icon name="arrow-down" size={16} class="text-info" />
            <span class="text-xs text-muted-foreground">Downloaded</span>
          </div>
          <div class="text-2xl font-bold text-info">{formatBytes($statsStore?.traffic?.total_rx)}</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Key Stats -->
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
    <div class="bg-card border border-border rounded-xl p-4">
      <div>
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

    <div class="bg-card border border-border rounded-xl p-4">
      <div>
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

    <div class="bg-card border border-border rounded-xl p-4">
      <div>
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

    <div class="bg-card border border-border rounded-xl p-4">
      <div>
        <div class="flex items-center gap-3">
          <div class="p-2 rounded-lg bg-info/10">
            <Icon name="plug-connected" size={20} class="text-info" />
          </div>
          <div>
            <div class="text-xs text-muted-foreground">WG Peers</div>
            <div class="text-lg font-semibold">{$statsStore?.nodes?.wgPeers || 0}</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Who's here · recent activity -->
  <h2 class="text-xs uppercase tracking-wide text-muted-foreground font-semibold mb-2">Who's here · recent activity</h2>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <PeersCard />

    <!-- Recent activity (compact feed; full history on the Activity page) -->
    <div class="bg-card border border-border rounded-xl p-4">
      <div class="flex items-center justify-between mb-2">
        <h3 class="text-sm font-semibold text-foreground flex items-center gap-2"><Icon name="clock" size={16} class="text-muted-foreground" />Recent activity</h3>
        <button class="text-xs text-primary font-medium hover:underline cursor-pointer" onclick={() => currentView.set('activity')}>View all →</button>
      </div>
      <p class="text-[11px] text-muted-foreground -mt-1 mb-2">Latest events — full history on Activity.</p>
      <ActivityFeed limit={8} compact />
    </div>
  </div>

  <!-- Docker Stats -->
  {#if $statsStore?.dockerInfo}
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    <!-- Docker Info -->
    <div class="bg-card border border-border rounded-xl p-4">
      <div class="flex items-center justify-between mb-3">
        <h3 class="text-sm font-semibold">Docker</h3>
        <span class="text-xs text-muted-foreground">{$statsStore.dockerInfo.operatingSystem}</span>
      </div>
      <div>
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
      {@const du = $statsStore.diskUsage}
      {@const parts = [
        { label: 'Images', size: du.imagesSize || 0, hr: du.imagesSizeHR, color: 'bg-info' },
        { label: 'Containers', size: du.containersSize || 0, hr: du.containersSizeHR, color: 'bg-success' },
        { label: 'Volumes', size: du.volumesSize || 0, hr: du.volumesSizeHR, color: 'bg-warning' },
        { label: 'Build cache', size: du.buildCacheSize || 0, hr: du.buildCacheSizeHR, color: 'bg-muted-foreground/40' },
      ].filter(p => p.size > 0)}
      {@const total = parts.reduce((s, p) => s + p.size, 0) || 1}
      <div class="bg-card border border-border rounded-xl p-4">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-semibold">Disk usage</h3>
          <span class="text-xs text-muted-foreground">{du.totalSizeHR} total</span>
        </div>
        <div class="flex h-3 rounded-full overflow-hidden bg-muted border border-border">
          {#each parts as p}
            <div class="{p.color}" style="width:{(p.size / total * 100).toFixed(1)}%" title="{p.label} {p.hr}"></div>
          {/each}
        </div>
        <div class="flex flex-wrap gap-x-4 gap-y-1.5 mt-3 text-[11px] text-muted-foreground">
          {#each parts as p}
            <span class="inline-flex items-center gap-1.5"><i class="h-2.5 w-2.5 rounded-sm {p.color} inline-block"></i>{p.label} <span class="text-foreground font-medium tabular-nums">{p.hr}</span></span>
          {/each}
        </div>
      </div>
    {/if}
  </div>
  {/if}

  <!-- System internals (muted) -->
  <div class="flex flex-wrap items-center gap-x-6 gap-y-1 text-xs text-muted-foreground pt-1">
    <span class="flex items-center gap-1.5"><Icon name="cpu" size={14} />Memory {formatBytes($statsStore?.system?.mem_alloc)}</span>
    <span class="flex items-center gap-1.5"><Icon name="activity" size={14} />Goroutines {$statsStore?.system?.num_goroutine || 0}</span>
    <span class="flex items-center gap-1.5"><Icon name="plug-connected" size={14} />WS Clients {$statsStore?.system?.ws_clients || 0}</span>
  </div>
</div>
