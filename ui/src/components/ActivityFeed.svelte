<script>
  /**
   * ActivityFeed - chronological cross-subsystem event feed.
   * Reusable: a compact widget on the Overview, or the full grouped list on the
   * Activity page (day headers + severity accents when not compact).
   *
   * Props:
   * - limit: max events to fetch (default 50)
   * - compact: tighter rows, no subsystem label, no day grouping
   */
  import { onMount } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import EmptyState from './EmptyState.svelte'
  import LoadingSpinner from './LoadingSpinner.svelte'
  import { timeAgo, parseDate } from '$lib/utils/format.js'

  let { limit = 50, compact = false, subsystem = '' } = $props()

  let events = $state([])
  let loading = $state(true)
  let error = $state('')

  // Icon per subsystem (all verified allowlisted in app.css).
  const SUBSYSTEM_ICON = {
    firewall: 'shield',
    wireguard: 'server',
    settings: 'settings',
    adguard: 'shield-check',
    docker: 'box',
    geolocation: 'world',
  }
  // Color per severity.
  const SEVERITY = {
    info:     { icon: 'text-muted-foreground', bg: 'bg-muted',            accent: 'border-transparent' },
    warning:  { icon: 'text-warning',          bg: 'bg-warning/10',       accent: 'border-warning/60' },
    critical: { icon: 'text-destructive',      bg: 'bg-destructive/10',   accent: 'border-destructive/60' },
  }

  const iconFor = e => SUBSYSTEM_ICON[e.subsystem] || 'activity'
  const sevFor = e => SEVERITY[e.severity] || SEVERITY.info

  // Apply the optional subsystem filter.
  const filtered = $derived(subsystem ? events.filter(e => e.subsystem === subsystem) : events)

  // Group events by day (full view only).
  const groups = $derived.by(() => {
    if (compact) return [{ day: '', items: filtered }]
    const out = []
    let cur = null
    for (const e of filtered) {
      const day = dayLabel(e.created_at)
      if (!cur || cur.day !== day) { cur = { day, items: [] }; out.push(cur) }
      cur.items.push(e)
    }
    return out
  })

  function dayLabel(ts) {
    const d = parseDate(ts)
    if (!d || isNaN(d.getTime())) return ''
    const startOfDay = x => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime()
    const diff = Math.round((startOfDay(new Date()) - startOfDay(d)) / 86400000)
    if (diff <= 0) return 'Today'
    if (diff === 1) return 'Yesterday'
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: diff > 300 ? 'numeric' : undefined })
  }

  export async function reload() {
    try {
      const res = await apiGet(`/api/events?limit=${limit}`)
      events = res.events || []
      error = ''
    } catch (e) {
      error = e?.message || 'Failed to load activity'
    } finally {
      loading = false
    }
  }

  onMount(reload)
</script>

{#if loading}
  <div class="flex justify-center py-8"><LoadingSpinner /></div>
{:else if error}
  <div class="text-xs text-warning flex items-center gap-1.5 py-4">
    <Icon name="alert-triangle" size={13} />{error}
  </div>
{:else if filtered.length === 0}
  <EmptyState icon="activity" title={subsystem ? 'No activity for this filter' : 'No activity yet'} description={subsystem ? 'Try a different source or clear the filter.' : 'Blocks, peer changes and config edits will appear here.'} compact />
{:else}
  <div class="space-y-3">
    {#each groups as group}
      <div>
        {#if group.day}
          <div class="flex items-center gap-2 px-1 pb-1.5">
            <span class="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{group.day}</span>
            <span class="h-px flex-1 bg-border"></span>
          </div>
        {/if}
        <ul class="space-y-0.5">
          {#each group.items as e (e.id)}
            {@const sev = sevFor(e)}
            <li class="group flex items-center gap-2.5 rounded-md px-2 hover:bg-muted/40 transition {compact ? 'py-1.5' : 'py-2 border-l-2 ' + sev.accent}">
              <span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg {sev.bg} {sev.icon}">
                <Icon name={iconFor(e)} size={14} />
              </span>
              <span class="min-w-0 flex-1 text-[13px] leading-tight text-foreground truncate">{e.message}</span>
              {#if !compact}
                <span class="hidden sm:inline-flex shrink-0 items-center rounded bg-muted/70 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{e.subsystem}</span>
              {/if}
              <span class="shrink-0 w-14 text-right text-[11px] text-muted-foreground tabular-nums" title={e.created_at}>{timeAgo(e.created_at)}</span>
            </li>
          {/each}
        </ul>
      </div>
    {/each}
  </div>
{/if}
