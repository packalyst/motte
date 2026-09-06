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
</script>

<div class="space-y-4">
  <InfoCard
    icon="clock"
    title="Routines"
    description="Background jobs the panel runs on a schedule — status, last/next run, and manual controls."
  />

  {#if error}
    <div class="p-3 rounded-md bg-destructive/10 border border-destructive/20 text-destructive text-sm">{error}</div>
  {:else if !loading && routines.length === 0}
    <EmptyState icon="clock" title="No routines registered" description="Background routines appear here as they register with the supervisor." />
  {:else}
    <div class="border border-border rounded-lg overflow-hidden">
      <div class="overflow-x-auto">
        <table class="data-table-table">
          <thead>
            <tr>
              <th>Routine</th>
              <th>Status</th>
              <th class="hidden md:table-cell">Schedule</th>
              <th class="hidden sm:table-cell">Last run</th>
              <th class="hidden lg:table-cell">Next</th>
              <th class="hidden lg:table-cell text-right">Runs</th>
              <th class="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each routines as r (r.name)}
              {@const b = statusBadge(r)}
              <tr class="even:bg-muted/50 align-top">
                <td>
                  <div class="flex items-center gap-1.5">
                    <span class="font-medium text-foreground font-mono text-xs">{r.name}</span>
                    <!-- Mobile: description behind an info tooltip to save space -->
                    <span class="sm:hidden inline-flex" data-kt-tooltip>
                      <Icon name="info-circle" size={13} class="text-muted-foreground" />
                      <span data-kt-tooltip-content class="kt-tooltip hidden">{r.description}</span>
                    </span>
                  </div>
                  <div class="hidden sm:block text-xs text-muted-foreground">{r.description}</div>
                  <!-- Mobile: fold the hidden columns (schedule/last/next) into one line -->
                  <div class="sm:hidden text-[11px] text-muted-foreground mt-0.5">
                    {r.schedule}{#if r.kind !== 'daemon'} · last {when(r.last_run)} · next {when(r.next_run)}{/if}
                    {#if r.last_error}<span class="text-destructive"> · failed</span>{/if}
                  </div>
                </td>
                <td>
                  <div class="flex items-center gap-1.5">
                    {#if r.status === 'running'}
                      <span class="w-2.5 h-2.5 border-2 border-info border-t-transparent rounded-full animate-spin"></span>
                    {/if}
                    <Badge variant={b.variant} size="sm">{b.label}</Badge>
                  </div>
                </td>
                <td class="hidden md:table-cell text-muted-foreground">{r.schedule}</td>
                <td class="hidden sm:table-cell">
                  {#if r.kind === 'daemon'}
                    <span class="text-muted-foreground">—</span>
                  {:else}
                    <div>{when(r.last_run)}</div>
                    {#if r.last_error}
                      <div class="text-xs text-destructive truncate max-w-[16rem]" title={r.last_error}>failed: {r.last_error}</div>
                    {:else if r.last_duration_ms != null}
                      <div class="text-xs text-muted-foreground">{r.last_duration_ms < 1 ? '<1' : Math.round(r.last_duration_ms)} ms</div>
                    {/if}
                  {/if}
                </td>
                <td class="hidden lg:table-cell text-muted-foreground">{r.kind === 'daemon' ? '—' : when(r.next_run)}</td>
                <td class="hidden lg:table-cell text-right">
                  {#if r.kind === 'daemon' || !r.history?.length}
                    <span class="font-mono text-muted-foreground">{r.kind === 'daemon' ? '—' : r.runs}</span>
                  {:else}
                    <!-- Run count; hover shows the recent-run history (replaces the dots) -->
                    <span class="font-mono text-muted-foreground cursor-help underline decoration-dotted" data-kt-tooltip>
                      {r.runs}
                      <span data-kt-tooltip-content class="kt-tooltip hidden text-left">
                        {#each [...r.history].reverse() as h}
                          <div class={h.error ? 'text-destructive' : ''}>{when(h.at)} · {h.error ? 'failed' : 'ok'}{h.duration_ms != null ? ` · ${h.duration_ms < 1 ? '<1' : Math.round(h.duration_ms)}ms` : ''}</div>
                        {/each}
                      </span>
                    </span>
                  {/if}
                </td>
                <td class="text-right">
                  {#if r.kind === 'daemon'}
                    <span class="text-xs text-muted-foreground">read-only</span>
                  {:else}
                    <div class="flex justify-end">
                      <div class="kt-btn-group">
                        <Button size="xs" variant="secondary" icon="player-play" onclick={() => run(r.name)} disabled={busy === r.name}>Run</Button>
                        {#if r.paused}
                          <Button size="xs" variant="outline" icon="player-play" onclick={() => resume(r.name)} disabled={busy === r.name}>Resume</Button>
                        {:else}
                          <Button size="xs" variant="outline" icon="player-pause" onclick={() => pause(r.name)} disabled={busy === r.name}>Pause</Button>
                        {/if}
                      </div>
                    </div>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>

    <p class="text-xs text-muted-foreground px-1">
      Hover a run count to see recent-run history. Daemons are always-on loops — status only.
    </p>
  {/if}
</div>
