<script>
  /**
   * PeersCard - one panel for peers, two views:
   *  • Online now — live WireGuard sessions (where-from, transfer, isolate)
   *  • Top traffic — cumulative transfer ranking from the stats stream
   * Replaces the two separate peer cards that used to stack on the Overview.
   */
  import { onMount, onDestroy } from 'svelte'
  import { apiGet, apiPost } from '../stores/app.js'
  import { statsStore } from '../stores/websocket.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Tabs from './Tabs.svelte'
  import CountryFlag from './CountryFlag.svelte'
  import IpBadge from './IpBadge.svelte'
  import EmptyState from './EmptyState.svelte'
  import { lookupIPs, getGeoData } from '../stores/geo.js'
  import { formatBytes, timeAgo } from '$lib/utils/format.js'

  let sessions = $state([])
  let geoData = $state({})
  let isolating = $state('')
  let timer

  let activeTab = $state('online')
  const tabs = $derived([
    { id: 'online', label: 'Online now', badge: sessions.length },
    { id: 'traffic', label: 'Top traffic' },
  ])

  const byPeer = $derived($statsStore?.traffic?.by_peer?.slice(0, 6) || [])

  async function load() {
    try {
      const res = await apiGet('/api/wg/sessions')
      sessions = res.sessions || []
      const ips = sessions.map(s => s.endpointIp).filter(Boolean)
      if (ips.length) {
        await lookupIPs(ips)
        const next = {}
        for (const ip of ips) { const g = getGeoData(ip); if (g) next[ip] = g }
        geoData = next
      }
    } catch {
      sessions = []
    }
  }

  async function isolate(s) {
    if (!confirm(`Isolate "${s.name}"? This disables the peer and disconnects it immediately.`)) return
    isolating = s.id
    try {
      await apiPost(`/api/wg/peers/${s.id}/disable`, {})
      await load()
    } finally {
      isolating = ''
    }
  }

  onMount(() => {
    load()
    timer = setInterval(load, 15000)
  })
  onDestroy(() => clearInterval(timer))
</script>

<div class="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
  <div class="flex items-center justify-between gap-2 px-4 pt-3 pb-2">
    <div class="flex items-center gap-2">
      <Icon name="users" size={16} class="text-muted-foreground" />
      <h3 class="text-sm font-semibold">Peers</h3>
    </div>
    <div class="inline-flex items-center gap-0.5 rounded-lg bg-muted/60 border border-border p-0.5 text-xs shrink-0">
      <button onclick={() => activeTab = 'online'} class="px-2.5 py-1 rounded-md transition cursor-pointer {activeTab === 'online' ? 'bg-card shadow-sm text-foreground font-medium' : 'text-muted-foreground hover:text-foreground'}">
        Online now{#if sessions.length} <span class="tabular-nums text-muted-foreground">{sessions.length}</span>{/if}
      </button>
      <button onclick={() => activeTab = 'traffic'} class="px-2.5 py-1 rounded-md transition cursor-pointer {activeTab === 'traffic' ? 'bg-card shadow-sm text-foreground font-medium' : 'text-muted-foreground hover:text-foreground'}">
        Top traffic
      </button>
    </div>
  </div>

  <div class="p-2 sm:p-3">
    {#if activeTab === 'online'}
      {#if sessions.length === 0}
        <EmptyState icon="plug-connected" title="No peers connected" description="Peers with a recent handshake appear here." compact />
      {:else}
        <ul class="divide-y divide-border">
          {#each sessions as s (s.id)}
            {@const geo = geoData[s.endpointIp]}
            <li class="flex items-center gap-3 px-2 py-2">
              <span class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted/60 border border-border">
                {#if geo?.country_code}<CountryFlag code={geo.country_code} size="sm" />{:else}<Icon name="device-laptop" size={15} class="text-muted-foreground" />{/if}
              </span>
              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2 min-w-0">
                  <span class="text-sm font-medium truncate">{s.name}</span>
                  <IpBadge {geo} compact />
                </div>
                <div class="text-[11px] text-muted-foreground truncate font-mono">
                  {s.ip}{#if s.endpointIp} · from {s.endpointIp}{/if} · {timeAgo(s.lastHandshake)}
                </div>
              </div>
              <div class="hidden sm:block text-right text-[11px] text-muted-foreground tabular-nums shrink-0">
                <div>↓ {formatBytes(s.rx)}</div>
                <div>↑ {formatBytes(s.tx)}</div>
              </div>
              <div class="shrink-0">
                <Button variant="outline" size="xs" onclick={() => isolate(s)} loading={isolating === s.id} title="Disable this peer and disconnect it">Isolate</Button>
              </div>
            </li>
          {/each}
        </ul>
      {/if}
    {:else if byPeer.length === 0}
      <EmptyState icon="chart-bar" title="No traffic yet" description="Per-peer transfer totals appear here." compact />
    {:else}
      <ul class="divide-y divide-border">
        {#each byPeer as peer}
          <li class="flex items-center gap-3 px-2 py-2.5">
            <span class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <Icon name="device-laptop" size={16} />
            </span>
            <div class="min-w-0 flex-1">
              <div class="text-sm font-medium truncate">{peer.name}</div>
              <div class="text-[11px] text-muted-foreground truncate font-mono">{peer.ip}</div>
            </div>
            <div class="text-right text-[11px] tabular-nums shrink-0">
              <div class="text-success">↑ {formatBytes(peer.tx)}</div>
              <div class="text-info">↓ {formatBytes(peer.rx)}</div>
            </div>
          </li>
        {/each}
      </ul>
    {/if}
  </div>
</div>
