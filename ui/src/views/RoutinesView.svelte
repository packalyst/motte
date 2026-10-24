<script>
  import InfoCard from '../components/InfoCard.svelte'
  import Button from '../components/Button.svelte'
  import Badge from '../components/Badge.svelte'
  import Icon from '../components/Icon.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import { apiGet, apiPost, toast } from '../stores/app.js'
  import { subscribe, unsubscribe, routinesStore } from '../stores/websocket.js'
  import { relativeShort } from '../lib/utils/format.js'

  let { loading = $bindable(true) } = $props()

  let routines = $state([])
  let error = $state('')
  let busy = $state('') // name currently being acted on

  async function load() {
    try {
      const res = await apiGet('/api/routines')
      routines = res?.routines || []
      error = ''
    } catch (e) {
      error = e.message || 'Failed to load routines'
    } finally {
      loading = false
    }
  }

  // Initial fetch, then live updates over WebSocket (the supervisor broadcasts
  // the full list on every state change — no polling).
  $effect(() => {
    load()
    subscribe(['routines'])
    return () => unsubscribe(['routines'])
  })

  $effect(() => {
    const s = $routinesStore
    if (s?.routines) {
      routines = s.routines
      loading = false
    }
  })

  async function act(name, action, label) {
    busy = name
    try {
      await apiPost(`/api/routines/${name}/${action}`)
      toast(label, 'success')
      await load()
    } catch (e) {
      toast(e.message || `Failed to ${action} ${name}`, 'error')
    } finally {
      busy = ''
    }
  }

  const run = (n) => act(n, 'run', 'Run triggered')
  const pause = (n) => act(n, 'pause', 'Routine paused')
  const resume = (n) => act(n, 'resume', 'Routine resumed')

  const when = (ts) => (ts ? relativeShort(new Date(ts * 1000)) : '—')

  function statusBadge(r) {
    if (r.status === 'running') return { variant: 'info', label: 'Running' }
    if (r.status === 'error') return { variant: 'destructive', label: 'Error' }
    if (r.status === 'paused' || r.paused) return { variant: 'warning', label: 'Paused' }
    if (r.kind === 'daemon') return { variant: 'success', label: 'Running' }
    return { variant: 'muted', label: 'Idle' }
  }

  const ms = (v) => (v < 1 ? '<1' : Math.round(v)) + ' ms'
  // Scheduled jobs first (they have controls), always-on loops after.
  const groups = $derived([
    { id: 'jobs', title: 'Scheduled jobs', sub: 'Run on a timer; run now or pause any of them', icon: 'clock', items: routines.filter((r) => r.kind !== 'daemon') },
    { id: 'daemons', title: 'Always on', sub: 'Background loops that run continuously; status only', icon: 'activity-heartbeat', items: routines.filter((r) => r.kind === 'daemon') },
  ].filter((g) => g.items.length))
</script>

<div class="space-y-4">
  <InfoCard
    icon="clock"
    title="Routines"
    description="Background jobs the panel runs on a schedule — status, last/next run, and manual controls."
  />

  {#if error}
    <div class="rounded-md border border-destructive/20 bg-destructive/10 p-3 text-sm text-destructive">{error}</div>
  {:else if !loading && routines.length === 0}
    <EmptyState icon="clock" title="No routines registered" description="Background routines appear here as they register with the supervisor." />
  {:else}
    {#each groups as g (g.id)}
      <section class="space-y-2" aria-label={g.title}>
        <div class="px-0.5">
          <h2 class="text-[13px] font-semibold text-foreground">{g.title} <span class="font-normal text-muted-foreground">({g.items.length})</span></h2>
          <p class="text-[11px] text-muted-foreground">{g.sub}</p>
        </div>
        <div class="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
          {#each g.items as r (r.name)}
            {@const b = statusBadge(r)}
            {@const daemon = r.kind === 'daemon'}
            <article class="panel flex min-w-0 flex-col">
              <div class="panel-head">
                <span class="panel-icon {r.status === 'error' || r.last_error ? 'text-destructive' : r.status === 'running' || daemon ? 'text-success' : ''}">
                  {#if r.status === 'running'}
                    <span class="h-3.5 w-3.5 animate-spin rounded-full border-2 border-info border-t-transparent"></span>
                  {:else}
                    <Icon name={g.icon} size={17} />
                  {/if}
                </span>
                <div class="min-w-0 flex-1">
                  <div class="panel-title truncate font-mono">{r.name}</div>
                  <div class="panel-sub">{r.description}</div>
                </div>
                <Badge variant={b.variant} size="sm">{b.label}</Badge>
              </div>

              <dl class="grid grid-cols-3 gap-3 text-[11px]">
                <div class="min-w-0">
                  <dt class="text-muted-foreground">Schedule</dt>
                  <dd class="mt-0.5 truncate font-medium text-foreground">{r.schedule}</dd>
                </div>
                <div class="min-w-0">
                  <dt class="text-muted-foreground">Last run</dt>
                  <dd class="mt-0.5 truncate font-medium text-foreground">{daemon ? '—' : when(r.last_run)}{#if !daemon && r.last_duration_ms != null && !r.last_error}<span class="font-normal text-muted-foreground">&nbsp;· {ms(r.last_duration_ms)}</span>{/if}</dd>
                </div>
                <div class="min-w-0">
                  <dt class="text-muted-foreground">Next</dt>
                  <dd class="mt-0.5 truncate font-medium text-foreground">{daemon ? '—' : when(r.next_run)}</dd>
                </div>
              </dl>

              {#if !daemon && r.history?.length}
                <!-- recent runs, oldest to newest: green ok, red failed (hover one for details) -->
                <div class="mt-3 flex items-center gap-2">
                  <div class="flex h-4 flex-1 items-end gap-[3px]" aria-label="Recent runs">
                    {#each r.history as h, i (i)}
                      <span data-kt-tooltip class="h-full max-w-2.5 flex-1 rounded-sm {h.error ? 'bg-destructive' : 'bg-success/70'}">
                        <span data-kt-tooltip-content class="kt-tooltip hidden">{when(h.at)} · {h.error ? 'failed' : 'ok'}{h.duration_ms != null ? ` · ${ms(h.duration_ms)}` : ''}</span>
                      </span>
                    {/each}
                  </div>
                  <span class="shrink-0 text-[11px] tabular-nums text-muted-foreground">{r.runs} {r.runs === 1 ? 'run' : 'runs'}</span>
                </div>
              {/if}

              {#if r.last_error}
                <p class="mt-3 line-clamp-2 break-words rounded-md bg-destructive/10 px-2.5 py-1.5 text-[11px] text-destructive">Last run failed: {r.last_error}</p>
              {/if}

              {#if !daemon}
                <div class="grow"></div><!-- footers line up across a row of cards -->
                <div class="panel-foot">
                  <Button size="xs" variant="secondary" icon="player-play" onclick={() => run(r.name)} disabled={busy === r.name}>Run now</Button>
                  {#if r.paused}
                    <Button size="xs" variant="outline" icon="player-play" onclick={() => resume(r.name)} disabled={busy === r.name}>Resume</Button>
                  {:else}
                    <Button size="xs" variant="outline" icon="player-pause" onclick={() => pause(r.name)} disabled={busy === r.name}>Pause</Button>
                  {/if}
                </div>
              {/if}
            </article>
          {/each}
        </div>
      </section>
    {/each}
  {/if}
</div>
