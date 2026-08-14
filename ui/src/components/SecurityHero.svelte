<script>
  /**
   * SecurityHero - one-glance "am I under attack?" card for the Overview:
   * a status strip, four stat tiles, the worst offender, and (folded in) the
   * service-health chips. Reads cleanly on desktop and mobile.
   *
   * Props:
   * - services: array of {key, name, status} from the stats stream (optional)
   */
  import { onMount, onDestroy } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import CountryFlag from './CountryFlag.svelte'
  import IpBadge from './IpBadge.svelte'

  let { services = [] } = $props()

  let data = $state(null)
  let error = $state('')
  let timer

  const STATUS = {
    calm:         { label: 'Calm',         icon: 'shield-check',   text: 'text-success',     iconBg: 'bg-success/10',     strip: 'bg-success/5',     dot: 'bg-success' },
    elevated:     { label: 'Elevated',     icon: 'alert-triangle', text: 'text-warning',     iconBg: 'bg-warning/10',     strip: 'bg-warning/5',     dot: 'bg-warning' },
    under_attack: { label: 'Under attack', icon: 'alert-triangle', text: 'text-destructive', iconBg: 'bg-destructive/10', strip: 'bg-destructive/5', dot: 'bg-destructive animate-pulse' },
  }
  const meta = $derived(STATUS[data?.status] || STATUS.calm)

  // Stat tiles: each with an icon. "blocked" carries the status color.
  const tiles = $derived(data ? [
    { icon: 'ban',      value: data.blocked,   label: 'blocked',   color: meta.text,          iconColor: meta.text },
    { icon: 'user-off', value: data.attackers, label: 'attackers', color: 'text-foreground',  iconColor: 'text-muted-foreground' },
    { icon: 'map-pin',  value: data.countries, label: 'countries', color: 'text-foreground',  iconColor: 'text-muted-foreground' },
    { icon: 'lock',     value: data.auto_bans, label: 'auto-bans', color: 'text-foreground',  iconColor: 'text-muted-foreground' },
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
    timer = setInterval(load, 60000)
  })
  onDestroy(() => clearInterval(timer))
</script>

{#if data && !error}
  <div class="bg-card border border-border rounded-xl shadow-sm overflow-hidden">
    <!-- Status strip -->
    <div class="flex items-center gap-3 px-4 py-3 {meta.strip} border-b border-border">
      <div class="flex h-9 w-9 items-center justify-center rounded-lg shrink-0 {meta.iconBg} {meta.text}">
        <Icon name={meta.icon} size={20} />
      </div>
      <div class="min-w-0 flex items-center gap-2">
        <span class="text-sm font-semibold {meta.text}">{meta.label}</span>
        <span class="h-1.5 w-1.5 rounded-full {meta.dot}"></span>
      </div>
      <span class="ml-auto text-[11px] text-muted-foreground">last hour</span>
    </div>

    <!-- Stat tiles -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5 p-3">
      {#each tiles as t}
        <div class="rounded-lg bg-muted/40 px-3 py-2.5">
          <div class="flex items-center gap-1.5 text-[11px] text-muted-foreground mb-1">
            <Icon name={t.icon} size={13} class={t.iconColor} />{t.label}
          </div>
          <div class="text-2xl font-bold tabular-nums {t.color}">{t.value}</div>
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

    <!-- Service health (folded in) -->
    {#if services?.length}
      <div class="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-border px-4 py-2.5">
        {#each services as svc (svc.key)}
          <span class="flex items-center gap-1.5 text-xs" title="{svc.name}: {svc.status === 'up' ? 'running' : 'not running'}">
            <span class="h-1.5 w-1.5 rounded-full {svc.status === 'up' ? 'bg-success' : 'bg-destructive animate-pulse'}"></span>
            <span class="{svc.status === 'up' ? 'text-muted-foreground' : 'text-destructive font-medium'}">{svc.name}</span>
          </span>
        {/each}
      </div>
    {/if}
  </div>
{/if}
