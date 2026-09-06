<script>
  import InfoCard from '../components/InfoCard.svelte'
  import Button from '../components/Button.svelte'
  import Badge from '../components/Badge.svelte'
  import Icon from '../components/Icon.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import { apiGet, apiPost, toast } from '../stores/app.js'
  import { formatRelativeDate } from '../lib/utils/format.js'

  let { loading = $bindable(true) } = $props()

  let routines = $state([])
  let error = $state('')
  let busy = $state('') // name currently being acted on
  let timer = null

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

  // Poll every 5s so a "running" state and last/next-run stay fresh.
  $effect(() => {
    load()
    timer = setInterval(load, 5000)
    return () => clearInterval(timer)
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

  function intervalLabel(sec) {
    if (!sec || sec <= 0) return '—'
    if (sec % 86400 === 0) return `${sec / 86400}d`
    if (sec % 3600 === 0) return `${sec / 3600}h`
    if (sec % 60 === 0) return `${sec / 60}m`
    return `${sec}s`
  }

  const when = (ts) => (ts ? formatRelativeDate(new Date(ts * 1000)) : '—')

  function statusBadge(r) {
    if (r.status === 'running') return { variant: 'info', label: 'Running' }
    if (r.status === 'error') return { variant: 'destructive', label: 'Error' }
    if (r.status === 'paused' || r.paused) return { variant: 'warning', label: 'Paused' }
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
  {/if}

  {#if !loading && routines.length === 0 && !error}
    <EmptyState icon="clock" title="No routines registered" description="Background routines will appear here as they register with the supervisor." />
  {:else}
    <div class="rounded-lg border border-border overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="text-xs text-muted-foreground border-b border-border">
          <tr>
            <th class="text-left font-medium px-3 py-2">Routine</th>
            <th class="text-left font-medium px-3 py-2">Status</th>
            <th class="text-left font-medium px-3 py-2">Every</th>
            <th class="text-left font-medium px-3 py-2">Last run</th>
            <th class="text-left font-medium px-3 py-2">Next run</th>
            <th class="text-right font-medium px-3 py-2">Runs</th>
            <th class="text-right font-medium px-3 py-2">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each routines as r (r.name)}
            {@const b = statusBadge(r)}
            <tr class="border-b border-border last:border-0 align-top">
              <td class="px-3 py-2.5">
                <div class="font-medium text-foreground font-mono">{r.name}</div>
                <div class="text-xs text-muted-foreground">{r.description}</div>
              </td>
              <td class="px-3 py-2.5">
                <div class="flex items-center gap-1.5">
                  {#if r.status === 'running'}
                    <span class="w-2.5 h-2.5 border-2 border-info border-t-transparent rounded-full animate-spin"></span>
                  {/if}
                  <Badge variant={b.variant} size="sm">{b.label}</Badge>
                </div>
              </td>
              <td class="px-3 py-2.5 font-mono text-muted-foreground">{intervalLabel(r.interval_sec)}</td>
              <td class="px-3 py-2.5">
                <div>{when(r.last_run)}</div>
                {#if r.last_error}
                  <div class="text-xs text-destructive" title={r.last_error}>failed: {r.last_error}</div>
                {:else if r.last_duration_ms != null}
                  <div class="text-xs text-muted-foreground">{r.last_duration_ms < 1 ? '<1' : Math.round(r.last_duration_ms)} ms</div>
                {/if}
              </td>
              <td class="px-3 py-2.5 text-muted-foreground">{r.paused ? '—' : when(r.next_run)}</td>
              <td class="px-3 py-2.5 text-right font-mono text-muted-foreground">{r.runs}</td>
              <td class="px-3 py-2.5">
                <div class="flex items-center justify-end gap-1">
                  <Button size="xs" variant="secondary" icon="player-play" onclick={() => run(r.name)} disabled={busy === r.name}>Run</Button>
                  {#if r.paused}
                    <Button size="xs" variant="outline" icon="player-play" onclick={() => resume(r.name)} disabled={busy === r.name}>Resume</Button>
                  {:else}
                    <Button size="xs" variant="outline" icon="player-pause" onclick={() => pause(r.name)} disabled={busy === r.name}>Pause</Button>
                  {/if}
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>
