<script module>
  // How each subsystem is shown (icons verified allowlisted in app.css).
  export const SOURCES = {
    auth: { icon: 'shield-lock', label: 'Sign-in & accounts' },
    fleet: { icon: 'device-desktop', label: 'Machines' },
    firewall: { icon: 'wall', label: 'Firewall' },
    wireguard: { icon: 'shield', label: 'WireGuard' },
    headscale: { icon: 'cloud', label: 'Headscale' },
    dhcp: { icon: 'router', label: 'LAN networks' },
    adguard: { icon: 'shield-check', label: 'AdGuard' },
    backup: { icon: 'database', label: 'Backups' },
    alerts: { icon: 'bell', label: 'Alerts' },
    pwa: { icon: 'device-mobile', label: 'Notifications' },
    security: { icon: 'shield-lock', label: 'Security' },
    docker: { icon: 'box', label: 'Docker' },
    settings: { icon: 'settings', label: 'Settings' },
    geolocation: { icon: 'world', label: 'Geolocation' },
  }
</script>

<script>
  /**
   * ActivityFeed - chronological cross-subsystem event feed (the panel's activity and audit trail).
   * Compact: the Overview widget (one line per event, newest few). Full: the Activity page — day
   * groups, whole messages, who/where, and "Load older" paging. Filters are applied on the server.
   *
   * Props:
   * - limit: events per page (default 50)
   * - compact: the one-line widget
   * - subsystem / severity / search: filters
   * - sources (bindable, full only): subsystems that have events, with counts, for a filter
   */
  import { apiGet } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import EmptyState from './EmptyState.svelte'
  import LoadingSpinner from './LoadingSpinner.svelte'
  import { timeAgo, formatTime, formatDate, parseDate, withTz } from '$lib/utils/format.js'

  let { limit = 50, compact = false, subsystem = '', severity = '', search = '', sources = $bindable([]) } = $props()

  let events = $state([])
  let next = $state(null) // cursor for older events; null when there are none
  let loading = $state(true)
  let loadingOlder = $state(false)
  let error = $state('')

  const filtering = $derived(!!(subsystem || severity || search))

  const sourceOf = (e) => SOURCES[e.subsystem] || { icon: 'activity', label: e.subsystem || 'Other' }

  const SEVERITY = {
    info:     { tile: 'bg-muted text-muted-foreground' },
    warning:  { tile: 'bg-warning/10 text-warning', badge: 'bg-warning/10 text-warning', label: 'Warning' },
    critical: { tile: 'bg-destructive/10 text-destructive', badge: 'bg-destructive/10 text-destructive', label: 'Critical' },
  }
  const sevFor = (e) => SEVERITY[e.severity] || SEVERITY.info

  // Full-view row columns, shared by the header and every row (literal for Tailwind).
  const ROW = 'grid-cols-[1.75rem_minmax(0,1fr)] sm:grid-cols-[4.5rem_1.75rem_minmax(0,1fr)] lg:grid-cols-[4.5rem_1.75rem_minmax(0,1fr)_10rem_7rem_8.5rem]'

  // Day groups (full view only).
  const groups = $derived.by(() => {
    if (compact) return [{ day: '', items: events }]
    const out = []
    let cur = null
    for (const e of events) {
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
    return d.toLocaleDateString(undefined, withTz({ weekday: 'long', month: 'short', day: 'numeric', year: diff > 300 ? 'numeric' : undefined }))
  }

  function fetchPage(before) {
    const params = new URLSearchParams({ limit: String(limit) })
    if (subsystem) params.set('subsystem', subsystem)
    if (severity) params.set('severity', severity)
    if (search) params.set('q', search)
    if (before) params.set('before', String(before))
    else if (!compact) params.set('facets', '1')
    return apiGet(`/api/events?${params}`)
  }

  export async function reload() {
    loading = true
    try {
      const res = await fetchPage(null)
      events = res.events || []
      next = res.next || null
      if (res.sources) sources = res.sources
      error = ''
    } catch (e) {
      error = e?.message || 'Failed to load activity'
    } finally {
      loading = false
    }
  }

  async function loadOlder() {
    loadingOlder = true
    try {
      const res = await fetchPage(next)
      events = [...events, ...(res.events || [])]
      next = res.next || null
    } catch (e) {
      error = e?.message || 'Failed to load older activity'
    } finally {
      loadingOlder = false
    }
  }

  // Refetch whenever a filter (or limit) changes; runs on mount too.
  $effect(() => {
    subsystem; severity; search; limit
    reload()
  })
</script>

{#if loading && !events.length}
  <div class="flex justify-center py-8"><LoadingSpinner /></div>
{:else if error && !events.length}
  <div class="text-xs text-warning flex items-center gap-1.5 py-4">
    <Icon name="alert-triangle" size={13} />{error}
  </div>
{:else if events.length === 0}
  <EmptyState icon="activity" title={filtering ? 'Nothing matches' : 'No activity yet'}
    description={filtering ? 'Try another search, source or severity.' : 'Sign-ins, peer changes, blocks and config edits appear here.'} compact />
{:else if compact}
  <ul class="divide-y divide-border">
    {#each events as e (e.id)}
      <li class="flex items-center gap-2.5 rounded-md px-2 py-1.5 transition hover:bg-muted/40">
        <span class="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg {sevFor(e).tile}"><Icon name={sourceOf(e).icon} size={12} /></span>
        <span class="min-w-0 flex-1 truncate text-[13px] leading-tight text-foreground">{e.message}</span>
        <span class="w-14 shrink-0 text-right text-[11px] tabular-nums text-muted-foreground" title={e.created_at}>{timeAgo(e.created_at)}</span>
      </li>
    {/each}
  </ul>
{:else}
  <!-- Wide screens: one row per event in columns (time, event, source, user, IP). Narrower: the
       source, user and IP move under the message; on phones the time joins them. -->
  <div class="{loading ? 'opacity-60' : ''}">
    <div class="hidden gap-x-3 px-2 pb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground lg:grid {ROW}">
      <span>Time</span><span class="col-span-2">Event</span><span>Source</span><span>User</span><span>From</span>
    </div>
    {#each groups as group (group.day)}
      <section>
        <h3 class="sticky top-0 z-10 flex items-center gap-2 bg-card px-2 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground after:h-px after:flex-1 after:bg-border">
          {group.day}<span class="font-normal normal-case tracking-normal">{group.items.length}</span>
        </h3>
        <ul>
          {#each group.items as e (e.id)}
            {@const sev = sevFor(e)}
            {@const src = sourceOf(e)}
            <li class="grid items-start gap-x-3 rounded-md px-2 py-1.5 transition hover:bg-muted/40 lg:items-center {ROW}">
              <span class="hidden pt-1 text-[11px] tabular-nums text-muted-foreground sm:block lg:pt-0" title={formatDate(e.created_at)}>{formatTime(e.created_at)}</span>
              <span class="grid h-7 w-7 place-items-center rounded-lg {sev.tile}"><Icon name={src.icon} size={14} /></span>
              <div class="min-w-0 py-0.5">
                <p class="break-words text-[13px] leading-snug text-foreground">
                  {#if sev.label}<span class="me-1.5 inline-block rounded px-1.5 py-px align-[1px] text-[10px] font-semibold {sev.badge}">{sev.label}</span>{/if}{e.message}
                </p>
                <div class="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-muted-foreground lg:hidden">
                  <span class="tabular-nums sm:hidden" title={formatDate(e.created_at)}>{formatTime(e.created_at)}</span>
                  <span>{src.label}</span>
                  {#if e.actor}<span class="inline-flex items-center gap-1"><Icon name="user" size={11} />{e.actor}</span>{/if}
                  {#if e.ip}<span class="inline-flex items-center gap-1 font-mono tabular-nums"><Icon name="map-pin" size={11} />{e.ip}</span>{/if}
                </div>
              </div>
              <span class="hidden truncate text-xs text-muted-foreground lg:block">{src.label}</span>
              <span class="hidden truncate text-xs text-muted-foreground lg:block">{e.actor || '—'}</span>
              <span class="hidden truncate font-mono text-[11px] tabular-nums text-muted-foreground lg:block">{e.ip || '—'}</span>
            </li>
          {/each}
        </ul>
      </section>
    {/each}

    <div class="mt-3 flex items-center justify-center gap-3 border-t border-dashed border-border pt-3 text-[11px] text-muted-foreground">
      <span>{events.length} {events.length === 1 ? 'event' : 'events'} shown</span>
      {#if next}
        <Button variant="outline" size="sm" icon="arrow-down" onclick={loadOlder} disabled={loadingOlder}>{loadingOlder ? 'Loading…' : 'Load older'}</Button>
      {:else}
        <span>· that's everything kept</span>
      {/if}
    </div>
  </div>
{/if}
