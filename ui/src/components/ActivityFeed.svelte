<script>
  /**
   * ActivityFeed - chronological cross-subsystem event feed.
   * Reusable: a compact widget on Overview or a full list on the Activity page.
   *
   * Props:
   * - limit: max events to fetch (default 50)
   * - compact: tighter rows, no subsystem label column
   */
  import { onMount } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import EmptyState from './EmptyState.svelte'
  import LoadingSpinner from './LoadingSpinner.svelte'
  import { timeAgo } from '$lib/utils/format.js'

  let { limit = 50, compact = false } = $props()

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
    info:     { icon: 'text-muted-foreground', bg: 'bg-muted' },
    warning:  { icon: 'text-warning',          bg: 'bg-warning/10' },
    critical: { icon: 'text-destructive',      bg: 'bg-destructive/10' },
  }

  function iconFor(e) { return SUBSYSTEM_ICON[e.subsystem] || 'activity' }
  function sevFor(e) { return SEVERITY[e.severity] || SEVERITY.info }

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
{:else if events.length === 0}
  <EmptyState icon="activity" title="No activity yet" description="Blocks, peer changes and config edits will appear here." />
{:else}
  <ul class="divide-y divide-border">
    {#each events as e (e.id)}
      {@const sev = sevFor(e)}
      <li class="flex items-center gap-3 {compact ? 'py-1.5' : 'py-2.5'}">
        <span class="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg {sev.bg} {sev.icon}">
          <Icon name={iconFor(e)} size={15} />
        </span>
        <div class="min-w-0 flex-1">
          <div class="text-sm text-foreground truncate">{e.message}</div>
          {#if !compact}
            <div class="text-[11px] text-muted-foreground capitalize">{e.subsystem}</div>
          {/if}
        </div>
        <span class="shrink-0 text-[11px] text-muted-foreground tabular-nums" title={e.created_at}>{timeAgo(e.created_at)}</span>
      </li>
    {/each}
  </ul>
{/if}
