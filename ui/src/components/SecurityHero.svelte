<script>
  /**
   * SecurityHero - one-glance "am I under attack?" banner for the Overview.
   * Reads /api/fw/overview (last hour): a status strip, four stat tiles, and the
   * worst offender. Designed to read cleanly on both desktop and mobile.
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
    calm:         { label: 'Calm',         icon: 'shield-check',   text: 'text-success',     iconBg: 'bg-success/10',     strip: 'bg-success/5',     dot: 'bg-success' },
    elevated:     { label: 'Elevated',     icon: 'alert-triangle', text: 'text-warning',     iconBg: 'bg-warning/10',     strip: 'bg-warning/5',     dot: 'bg-warning' },
    under_attack: { label: 'Under attack', icon: 'alert-triangle', text: 'text-destructive', iconBg: 'bg-destructive/10', strip: 'bg-destructive/5', dot: 'bg-destructive animate-pulse' },
  }
  const meta = $derived(STATUS[data?.status] || STATUS.calm)

  // Stat tiles. "blocked" carries the status color; the rest stay neutral.
  const tiles = $derived(data ? [
    { value: data.blocked,   label: 'blocked',   color: meta.text },
    { value: data.attackers, label: 'attackers', color: 'text-foreground' },
    { value: data.countries, label: 'countries', color: 'text-foreground' },
    { value: data.auto_bans, label: 'auto-bans', color: 'text-foreground' },
  ] : [])

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
    timer = setInterval(load, 60000) // refresh the hourly window each minute
  })
  onDestroy(() => clearInterval(timer))
</script>

{#if data && !error}
  <div class="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
    <!-- Status strip -->
    <div class="flex items-center gap-3 px-4 py-3 {meta.strip} border-b border-border">
      <div class="flex h-11 w-11 items-center justify-center rounded-xl shrink-0 {meta.iconBg} {meta.text}">
        <Icon name={meta.icon} size={24} />
      </div>
      <div class="min-w-0">
        <div class="flex items-center gap-2">
          <span class="text-base font-semibold {meta.text}">{meta.label}</span>
          <span class="h-2 w-2 rounded-full {meta.dot}"></span>
        </div>
        <div class="text-xs text-muted-foreground">Security · last hour</div>
      </div>
    </div>

    <!-- Stat tiles -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4">
      {#each tiles as t}
        <div class="rounded-lg bg-muted/40 px-3 py-2.5">
          <div class="text-2xl font-bold tabular-nums {t.color}">{t.value}</div>
          <div class="text-[11px] text-muted-foreground">{t.label}</div>
        </div>
      {/each}
    </div>

    <!-- Top offender -->
    {#if data.top_attacker}
      <div class="flex items-center gap-2 border-t border-border px-4 py-2.5 text-xs">
        <span class="text-muted-foreground shrink-0">Top offender</span>
        {#if data.top_attacker.country}<CountryFlag code={data.top_attacker.country} size="sm" />{/if}
        <span class="font-mono truncate">{data.top_attacker.ip}</span>
        <IpBadge geo={attackerGeo} />
        <span class="ml-auto text-muted-foreground tabular-nums shrink-0">×{data.top_attacker.count} hits</span>
      </div>
    {/if}
  </div>
{/if}
