<script>
  /**
   * SecurityHero - one-glance "am I under attack?" banner for the Overview.
   * Reads /api/fw/overview (last hour) and renders a status light + plain-language
   * counts + the worst offender with owner/reputation.
   */
  import { onMount, onDestroy } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import CountryFlag from './CountryFlag.svelte'
  import IpBadge from './IpBadge.svelte'

  let data = $state(null)
  let error = $state('')
  let timer

  const STATUS = {
    calm:         { label: 'Calm',         icon: 'shield-check',   text: 'text-success',     ring: 'border-success/30 bg-success/5',         dot: 'bg-success' },
    elevated:     { label: 'Elevated',     icon: 'alert-triangle', text: 'text-warning',     ring: 'border-warning/40 bg-warning/5',         dot: 'bg-warning' },
    under_attack: { label: 'Under attack', icon: 'alert-triangle', text: 'text-destructive', ring: 'border-destructive/50 bg-destructive/5',  dot: 'bg-destructive animate-pulse' },
  }
  const meta = $derived(STATUS[data?.status] || STATUS.calm)
  // Adapt the endpoint's top_attacker (owner + reputation) to the IpBadge shape.
  const attackerGeo = $derived(data?.top_attacker
    ? { as_name: data.top_attacker.owner, reputation: data.top_attacker.reputation }
    : null)

  async function load() {
    try {
      data = await apiGet('/api/fw/overview')
      error = ''
    } catch (e) {
      error = e?.message || ''
    }
  }

  onMount(() => {
    load()
    timer = setInterval(load, 60000) // refresh hourly-window stats each minute
  })
  onDestroy(() => clearInterval(timer))
</script>

{#if data && !error}
  <div class="rounded-lg border {meta.ring} p-4 shadow-sm">
    <div class="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center sm:gap-x-6">
      <!-- Status light -->
      <div class="flex items-center gap-2.5">
        <span class="flex h-9 w-9 items-center justify-center rounded-lg {meta.text} shrink-0">
          <Icon name={meta.icon} size={22} />
        </span>
        <div>
          <div class="flex items-center gap-1.5">
            <span class="h-2 w-2 rounded-full {meta.dot}"></span>
            <span class="text-sm font-semibold {meta.text}">{meta.label}</span>
          </div>
          <div class="text-[11px] text-muted-foreground">last hour</div>
        </div>
      </div>

      <!-- Counts -->
      <div class="flex flex-wrap items-center gap-x-5 gap-y-1 text-sm">
        <span><span class="font-semibold tabular-nums">{data.blocked}</span> <span class="text-muted-foreground">blocked</span></span>
        <span><span class="font-semibold tabular-nums">{data.attackers}</span> <span class="text-muted-foreground">attackers</span></span>
        <span><span class="font-semibold tabular-nums">{data.countries}</span> <span class="text-muted-foreground">countries</span></span>
        <span><span class="font-semibold tabular-nums">{data.auto_bans}</span> <span class="text-muted-foreground">auto-bans</span></span>
      </div>

      <!-- Top offender -->
      {#if data.top_attacker}
        <div class="flex items-center gap-2 text-xs min-w-0 sm:ml-auto pt-2 border-t border-border/40 sm:pt-0 sm:border-0">
          <span class="text-muted-foreground shrink-0">Top:</span>
          {#if data.top_attacker.country}<CountryFlag code={data.top_attacker.country} size="sm" />{/if}
          <span class="font-mono truncate">{data.top_attacker.ip}</span>
          <IpBadge geo={attackerGeo} />
          <span class="text-muted-foreground tabular-nums shrink-0">×{data.top_attacker.count}</span>
        </div>
      {/if}
    </div>
  </div>
{/if}
