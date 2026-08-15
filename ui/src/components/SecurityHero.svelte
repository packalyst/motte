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
    calm:         { label: 'Calm',         icon: 'shield-check',   text: 'text-success',     dot: 'bg-success' },
    elevated:     { label: 'Elevated',     icon: 'alert-triangle', text: 'text-warning',     dot: 'bg-warning' },
    under_attack: { label: 'Under attack', icon: 'alert-triangle', text: 'text-destructive', dot: 'bg-destructive animate-pulse' },
  }
  // When the overview fetch fails we still render the shell (for the service-health
  // chips below) but must not imply "Calm" — show a neutral, non-committal header.
  const UNKNOWN = { label: 'Security', icon: 'shield', text: 'text-muted-foreground', dot: 'bg-muted-foreground' }
  const meta = $derived(!data ? UNKNOWN : (STATUS[data.status] || STATUS.calm))

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

<!-- Render whenever we have stats OR services: the service-health chips must survive
     an overview fetch failure, since that's exactly when a subsystem may be down. -->
{#if data || services?.length}
  <div class="kt-panel">
    <!-- Status as the panel title (reuses kt-panel-title sizing) -->
    <div class="kt-panel-header">
      <h3 class="kt-panel-title">
        <Icon name={meta.icon} size={16} class={meta.text} />
        <span class={meta.text}>{meta.label}</span>
        <span class="h-1.5 w-1.5 rounded-full {meta.dot}"></span>
      </h3>
      <span class="text-[11px] text-muted-foreground">last hour</span>
    </div>

    <div class="kt-panel-body space-y-3">
      {#if data && !error}
        <!-- Stat tiles -->
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
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
          <div class="flex items-center gap-2 border-t border-border pt-2.5 text-xs">
            <span class="text-muted-foreground shrink-0">Top offender</span>
            {#if data.top_attacker.country}<CountryFlag code={data.top_attacker.country} size="sm" />{/if}
            <span class="font-mono truncate">{data.top_attacker.ip}</span>
            <IpBadge geo={attackerGeo} />
            <span class="ml-auto text-muted-foreground tabular-nums shrink-0">×{data.top_attacker.count} hits</span>
          </div>
        {/if}
      {:else}
        <!-- Overview unavailable — keep the shell so the health chips below still show -->
        <div class="text-xs text-muted-foreground">Security stats unavailable{error ? ` — ${error}` : ''}.</div>
      {/if}

      <!-- Service health (folded in) — always rendered when present -->
      {#if services?.length}
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-border pt-2.5">
          {#each services as svc (svc.key)}
            <span class="flex items-center gap-1.5 text-xs" title="{svc.name}: {svc.status === 'up' ? 'running' : 'not running'}">
              <span class="h-1.5 w-1.5 rounded-full {svc.status === 'up' ? 'bg-success' : 'bg-destructive animate-pulse'}"></span>
              <span class="{svc.status === 'up' ? 'text-muted-foreground' : 'text-destructive font-medium'}">{svc.name}</span>
            </span>
          {/each}
        </div>
      {/if}
    </div>
  </div>
{/if}
