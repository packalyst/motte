<script>
  import { onMount } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import { statsStore } from '../stores/websocket.js'
  import Icon from './Icon.svelte'

  // period: hour | day | week | month | all. live=true reads the WS stats stream
  // (Overview, fixed last hour); otherwise poll by period (Analytics).
  let { period = 'hour', live = false } = $props()

  let d = $state(null)

  async function load() {
    try { d = await apiGet(`/api/fw/layers?period=${period}`) } catch {}
  }
  $effect(() => {
    if (live) { d = $statsStore?.security?.layers }
    else { period; load() }
  })
  onMount(() => {
    if (live) return
    const t = setInterval(load, 30000); return () => clearInterval(t)
  })

  const fmt = (n) => (n ?? 0).toLocaleString()
</script>

<div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
  <!-- L3 firewall -->
  <div class="bg-card border border-border rounded-xl p-3.5">
    <div class="text-xs font-semibold text-muted-foreground flex items-center gap-1.5 mb-1.5"><Icon name="wall" size={14} class="text-destructive" />Firewall (L3)</div>
    <div class="text-2xl font-bold tabular-nums text-destructive">{fmt(d?.l3?.blocked)}</div>
    <div class="text-[11px] text-muted-foreground mt-1">packets dropped</div>
  </div>

  <!-- DNS -->
  <div class="bg-card border border-border rounded-xl p-3.5">
    <div class="text-xs font-semibold text-muted-foreground flex items-center gap-1.5 mb-1.5"><Icon name="ban" size={14} class="text-warning" />DNS blocked</div>
    <div class="text-2xl font-bold tabular-nums text-warning">{fmt(d?.dns?.blocked)}</div>
    <div class="text-[11px] text-muted-foreground mt-1">of {fmt(d?.dns?.total)} queries</div>
  </div>

  <!-- L7 proxy -->
  <div class="bg-card border border-border rounded-xl p-3.5">
    <div class="text-xs font-semibold text-muted-foreground flex items-center gap-1.5 mb-1.5"><Icon name="world" size={14} class="text-primary" />Proxy (L7)</div>
    <div class="text-2xl font-bold tabular-nums text-primary">{fmt(d?.l7?.blocked)}</div>
    <div class="text-[11px] text-muted-foreground mt-1">requests blocked (Cloudflare)</div>
  </div>

  <!-- Allowed web requests -->
  <div class="bg-card border border-border rounded-xl p-3.5">
    <div class="text-xs font-semibold text-muted-foreground flex items-center gap-1.5 mb-1.5"><Icon name="check" size={14} class="text-success" />Web requests</div>
    <div class="text-2xl font-bold tabular-nums text-success">{fmt(d?.allowed?.requests)}</div>
    <div class="text-[11px] text-muted-foreground mt-1">served (allowed)</div>
  </div>
</div>
