<script>
  import { onMount } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import Icon from './Icon.svelte'

  // period: hour | day | week | month | all
  let { period = 'hour' } = $props()

  let d = $state(null)
  let loaded = $state(false)

  async function load() {
    try {
      d = await apiGet(`/api/fw/layers?period=${period}`)
    } catch {
      // leave last-known data on error
    } finally {
      loaded = true
    }
  }

  // Reload on mount and whenever the period changes; refresh on a timer.
  $effect(() => { period; load() })
  onMount(() => {
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  })

  const fmt = (n) => (n ?? 0).toLocaleString()
  const pct = (a, b) => (b > 0 ? Math.min(100, Math.round((a / b) * 100)) : 0)
</script>

<div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
  <!-- L3 firewall -->
  <div class="bg-card border border-border rounded-xl p-3.5">
    <div class="flex items-center justify-between mb-1.5">
      <span class="text-xs font-semibold text-muted-foreground flex items-center gap-1.5"><Icon name="bricks" size={14} />Firewall (L3)</span>
    </div>
    <div class="text-xl font-bold tabular-nums text-destructive">{fmt(d?.l3?.blocked)}</div>
    <div class="text-[11px] text-muted-foreground mt-1">packets dropped</div>
  </div>

  <!-- DNS -->
  <div class="bg-card border border-border rounded-xl p-3.5">
    <div class="flex items-center justify-between mb-1.5">
      <span class="text-xs font-semibold text-muted-foreground flex items-center gap-1.5"><Icon name="ban" size={14} />DNS</span>
      <span class="text-[10px] text-muted-foreground">of {fmt(d?.dns?.total)}</span>
    </div>
    <div class="text-xl font-bold tabular-nums text-warning">{fmt(d?.dns?.blocked)}</div>
    <div class="h-1.5 rounded-full bg-muted mt-2 overflow-hidden"><div class="h-full bg-warning rounded-full" style="width:{pct(d?.dns?.blocked, d?.dns?.total)}%"></div></div>
  </div>

  <!-- L7 proxy -->
  <div class="bg-card border border-border rounded-xl p-3.5">
    <div class="flex items-center justify-between mb-1.5">
      <span class="text-xs font-semibold text-muted-foreground flex items-center gap-1.5"><Icon name="world" size={14} />Proxy (L7)</span>
    </div>
    <div class="text-xl font-bold tabular-nums text-primary">{fmt(d?.l7?.blocked)}</div>
    <div class="text-[11px] text-muted-foreground mt-1">blocked behind Cloudflare</div>
  </div>

  <!-- Allowed -->
  <div class="bg-card border border-border rounded-xl p-3.5">
    <div class="flex items-center justify-between mb-1.5">
      <span class="text-xs font-semibold text-muted-foreground flex items-center gap-1.5"><Icon name="check" size={14} />Allowed</span>
    </div>
    <div class="text-xl font-bold tabular-nums text-success">{d?.allowed?.percent != null ? Math.round(d.allowed.percent) + '%' : '—'}</div>
    <div class="h-1.5 rounded-full bg-muted mt-2 overflow-hidden"><div class="h-full bg-success rounded-full" style="width:{Math.round(d?.allowed?.percent ?? 0)}%"></div></div>
  </div>
</div>
