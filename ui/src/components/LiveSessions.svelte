<script>
  /**
   * LiveSessions - "who's on my VPN right now": peers that handshaked recently,
   * where they dial in from (geo), transfer, and one-click isolate.
   */
  import { onMount, onDestroy } from 'svelte'
  import { apiGet, apiPost } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import CountryFlag from './CountryFlag.svelte'
  import IpBadge from './IpBadge.svelte'
  import { lookupIPs, getGeoData } from '../stores/geo.js'
  import { formatBytes, timeAgo } from '$lib/utils/format.js'

  let sessions = $state([])
  let geoData = $state({})
  let loaded = $state(false)
  let isolating = $state('')
  let timer

  async function load() {
    try {
      const res = await apiGet('/api/wg/sessions')
      sessions = res.sessions || []
      // Enrich the public endpoints with geo (where-from + reputation).
      const ips = sessions.map(s => s.endpointIp).filter(Boolean)
      if (ips.length) {
        await lookupIPs(ips)
        const next = {}
        for (const ip of ips) { const g = getGeoData(ip); if (g) next[ip] = g }
        geoData = next
      }
    } catch {
      sessions = []
    } finally {
      loaded = true
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

{#if loaded}
  <div class="kt-panel">
    <div class="kt-panel-header flex items-center justify-between">
      <h3 class="kt-panel-title">On your VPN now</h3>
      <span class="text-xs text-muted-foreground">{sessions.length} online</span>
    </div>
    <div class="kt-panel-body">
      {#if sessions.length === 0}
        <div class="text-sm text-muted-foreground py-2">No peers connected right now.</div>
      {:else}
        <ul class="divide-y divide-border">
          {#each sessions as s (s.id)}
            {@const geo = geoData[s.endpointIp]}
            <li class="flex items-center gap-3 py-2.5">
              <span class="shrink-0">
                {#if geo?.country_code}<CountryFlag code={geo.country_code} size="sm" />{:else}<Icon name="world" size={16} class="text-muted-foreground" />{/if}
              </span>
              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2 min-w-0">
                  <span class="text-sm font-medium truncate">{s.name}</span>
                  <IpBadge {geo} compact />
                </div>
                <div class="text-[11px] text-muted-foreground truncate">
                  {s.ip}{#if s.endpointIp} · from {s.endpointIp}{/if} · {timeAgo(s.lastHandshake)}
                </div>
              </div>
              <div class="hidden sm:block text-right text-[11px] text-muted-foreground tabular-nums shrink-0">
                <div>↓ {formatBytes(s.rx)}</div>
                <div>↑ {formatBytes(s.tx)}</div>
              </div>
              <button
                class="shrink-0 text-xs px-2 py-1 rounded border border-border text-muted-foreground hover:border-destructive/50 hover:text-destructive transition disabled:opacity-50"
                onclick={() => isolate(s)}
                disabled={isolating === s.id}
                title="Disable this peer and disconnect it"
              >
                {isolating === s.id ? '…' : 'Isolate'}
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  </div>
{/if}
