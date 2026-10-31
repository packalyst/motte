<script>
  /**
   * RecordingList — console session recordings: one machine's (machineId) or every machine in the
   * caller's scope (no machineId, the Sessions page), grouped by day. Operators see their own, admins
   * everyone's; the server enforces both. Play opens the in-app player, download fetches the .cast
   * (each fetch is audited), delete is admin-only and re-authenticates every time. Reloads whenever
   * `live` changes — a session starting or ending flips its recording's "live" state.
   */
  import { apiGet, apiPost, toast, stepUpConfirm, currentUser, hasRole } from '../stores/app.js'
  import { formatBytes } from '$lib/utils/format.js'
  import { fmtUptime } from '$lib/fleet.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Select from './Select.svelte'
  import RecordingPlayer from './RecordingPlayer.svelte'
  import EmptyState from './EmptyState.svelte'

  let {
    machineId = '', live = 0, hideEmpty = false, emptyText = '', class: cls = '',
    recordings = $bindable([]),
  } = $props()

  const isAdmin = $derived(hasRole($currentUser, 'admin'))
  let retentionDays = $state(30)
  let playing = $state(null)
  let machineFilter = $state('') // the list across machines can narrow to one

  async function load() {
    try {
      const res = await apiGet('/api/fleet/console/recordings' + (machineId ? '?machine_id=' + encodeURIComponent(machineId) : ''))
      recordings = res.recordings || []
      retentionDays = res.retentionDays || retentionDays
    } catch {
      recordings = []
    }
  }
  // A derived only changes when the count does: the session list is re-pushed (a new array, same
  // length) when the page opens and on every update, which must not refetch the recordings.
  const liveCount = $derived(live)
  $effect(() => {
    machineId
    liveCount
    load()
  })

  const machineOptions = $derived.by(() => {
    const names = new Map(recordings.map((r) => [r.machine_id, r.machine_name || r.machine_id]))
    return [{ value: '', label: 'All machines' }, ...[...names].map(([value, label]) => ({ value, label }))]
  })
  const shown = $derived(machineFilter ? recordings.filter((r) => r.machine_id === machineFilter) : recordings)

  // Newest first (the server's order), bucketed by the day each recording started.
  function dayLabel(ts) {
    const d = new Date(ts * 1000)
    const today = new Date()
    const yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1)
    if (d.toDateString() === today.toDateString()) return 'Today'
    if (d.toDateString() === yesterday.toDateString()) return 'Yesterday'
    return d.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' })
  }
  const days = $derived.by(() => {
    const out = []
    for (const r of shown) {
      const label = dayLabel(r.started)
      if (out.at(-1)?.label !== label) out.push({ label, items: [] })
      out.at(-1).items.push(r)
    }
    return out
  })

  function download(rec) {
    const a = document.createElement('a') // same-origin GET: the session cookie authenticates it
    a.href = `/api/fleet/console/recording?machine_id=${encodeURIComponent(rec.machine_id)}&name=${encodeURIComponent(rec.name)}`
    a.download = rec.name
    a.click()
  }

  // One prompt is both the confirmation and the re-authentication (the server asks every time — no
  // grace window for erasing a recording); the deletion itself is audited.
  const DELETE_URL = '/api/fleet/console/recording/delete'
  async function remove(rec) {
    const r = await stepUpConfirm({
      title: 'Delete recording',
      message: `Delete ${rec.title} by ${rec.user} on ${rec.machine_name}?`,
      description: 'It is gone for good — copies of the file left anywhere become unreadable. The deletion is kept in the audit log. Re-authenticate to confirm.',
      confirmText: 'Delete', variant: 'destructive',
      action: { method: 'POST', url: DELETE_URL },
    })
    if (!r?.proof) return
    try {
      await apiPost(DELETE_URL, { machine_id: rec.machine_id, name: rec.name, ...r.proof })
      recordings = recordings.filter((x) => x.name !== rec.name)
      toast('Recording deleted', 'success')
    } catch (e) {
      toast(e.message || 'Could not delete the recording', 'error')
    }
  }

  const time = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
</script>

{#if recordings.length || !hideEmpty}
  <section aria-label="Recordings" class="space-y-3 {cls}">
    <div class="flex items-center gap-3">
      <h2 class="flex min-w-0 flex-1 items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground after:h-px after:flex-1 after:bg-border">
        <Icon name="player-record" size={13} class="text-destructive" />
        <span class="inline-flex cursor-help items-center gap-1" data-kt-tooltip>
          Recordings<Icon name="info-circle" size={12} />
          <span data-kt-tooltip-content class="kt-tooltip hidden normal-case tracking-normal font-normal">Only screen output is recorded, never keystrokes. Every playback is logged.</span>
        </span>
        <span class="font-normal normal-case tracking-normal">{shown.length} · kept {retentionDays} days</span>
      </h2>
      {#if !machineId && machineOptions.length > 2}
        <Select bind:value={machineFilter} size="sm" aria-label="Machine" class="w-40" options={machineOptions} />
      {/if}
      <Button variant="ghost" size="xs" iconOnly icon="refresh" onclick={load} tooltip="Refresh" />
    </div>

    {#if shown.length}
      {#each days as day (day.label)}
        <div class="space-y-2">
          <div class="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{day.label}</div>
          <div class="grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-4">
            {#each day.items as rec (rec.machine_id + '/' + rec.name)}
              <div class="group overflow-hidden rounded-xl border border-border bg-card transition hover:border-primary/40">
                <!-- thumbnail: a terminal-coloured tile; the recording itself is only fetched on play (audited) -->
                <button type="button" onclick={() => (playing = rec)} aria-label="Play {rec.title} on {rec.machine_name}"
                  class="relative block h-24 w-full cursor-pointer bg-[#0f1419] text-left">
                  <span class="absolute left-2.5 top-2 font-mono text-[10px] text-white/25">{rec.user}@{rec.machine_name}:~$ ▍</span>
                  <span class="absolute inset-0 grid place-items-center">
                    <span class="grid h-10 w-10 place-items-center rounded-full bg-white/10 text-white transition group-hover:bg-primary group-hover:text-primary-foreground">
                      <Icon name="player-play" size={18} />
                    </span>
                  </span>
                  {#if rec.live}
                    <span class="absolute bottom-2 left-2.5 inline-flex items-center gap-1 rounded bg-destructive px-1.5 py-0.5 text-[10px] font-semibold text-white"><span class="h-1.5 w-1.5 rounded-full bg-white"></span>REC</span>
                  {:else if rec.capped}
                    <span class="absolute bottom-2 left-2.5 rounded bg-warning px-1.5 py-0.5 text-[10px] font-semibold text-black">size limit</span>
                  {/if}
                  <span class="absolute bottom-2 right-2.5 rounded bg-black/60 px-1.5 py-0.5 font-mono text-[10px] text-white tabular-nums">{fmtUptime(Math.max(0, rec.ended - rec.started))} · {formatBytes(rec.size)}</span>
                </button>
                <div class="flex items-center gap-2 px-3 py-2">
                  <div class="min-w-0 flex-1">
                    <div class="truncate text-sm font-medium text-foreground">{machineId ? rec.title : rec.machine_name}</div>
                    <div class="truncate text-[11px] text-muted-foreground tabular-nums">
                      {machineId ? '' : rec.title + ' · '}{rec.user} · {time(rec.started)}
                    </div>
                  </div>
                  <div class="kt-btn-group shrink-0">
                    <Button variant="outline" size="xs" icon="download" tooltip="Download .cast" aria-label={`Download ${rec.title} on ${rec.machine_name}`} onclick={() => download(rec)} />
                    {#if isAdmin}
                      <Button variant="outline" size="xs" icon="trash" class="text-destructive hover:bg-destructive/10" disabled={rec.live} onclick={() => remove(rec)}
                        tooltip={rec.live ? 'Still recording — stop the session first' : 'Delete recording'} aria-label={`Delete ${rec.title} on ${rec.machine_name}`} />
                    {/if}
                  </div>
                </div>
              </div>
            {/each}
          </div>
        </div>
      {/each}
    {:else}
      <EmptyState inline icon="player-record" color="var(--destructive)" title="No recordings yet" description={emptyText} />
    {/if}
  </section>
{/if}

{#if playing}
  <RecordingPlayer machineId={playing.machine_id} rec={playing} onclose={() => (playing = null)} />
{/if}
