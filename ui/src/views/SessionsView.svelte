<script>
  /**
   * SessionsView — console work across every machine in your scope: your live sessions (resume or
   * close them), a new session on any console-enabled machine, the session recordings, and running
   * one allowlisted command on several machines. Operator+; the server scopes every list and action.
   * The live list comes from the shared console-events WS (pushed, no polling).
   */
  import { onMount, onDestroy } from 'svelte'
  import { apiGet, currentUser, hasRole } from '../stores/app.js'
  import { consoleSessions, openConsoleEvents, refreshSessions, closeSession, openConsoleAt } from '../lib/consoleEvents.js'
  import { formatBytes } from '$lib/utils/format.js'
  import { statusInfo } from '$lib/fleet.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Modal from '../components/Modal.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import SessionCard from '../components/SessionCard.svelte'
  import RecordingList from '../components/RecordingList.svelte'
  import BulkRun from '../components/BulkRun.svelte'
  import StatStrip from '../components/StatStrip.svelte'

  let { loading = $bindable(true) } = $props()

  const canUse = $derived(hasRole($currentUser, 'operator'))
  const BACK = { view: 'sessions' }

  let machines = $state([]) // fleet machines in scope
  let recordings = $state([])
  let target = $state('') // machine for a new session
  let newOpen = $state(false)
  let bulkOpen = $state(false)
  const active = $derived(machines.filter((m) => !m.revoked))
  const consoleMachines = $derived(active.filter((m) => m.console_enabled))
  const recordingOn = $derived(consoleMachines.filter((m) => m.console_record).length)
  const watched = $derived($consoleSessions.filter((s) => s.attached).length)

  async function loadMachines() {
    try {
      machines = (await apiGet('/api/fleet/machines')) || []
    } catch {
      machines = []
    }
  }

  // The console needs the agent connected, so the picker preselects the first online machine.
  function startNew() {
    target = consoleMachines.find((m) => statusInfo(m).online)?.id || ''
    newOpen = true
  }

  function newSession() {
    const m = consoleMachines.find((x) => x.id === target)
    if (!m) return
    newOpen = false
    openConsoleAt({ machine_id: m.id, machine_name: m.name, session: null, fresh: true }, BACK)
  }
  const resume = (s) => openConsoleAt({ machine_id: s.machine_id, machine_name: s.machine_name, session: s.id, label: s.label }, BACK)
  const kill = (s) => closeSession(s, s.machine_name)

  const stats = $derived([
    { icon: 'terminal-2', color: 'var(--success)', value: $consoleSessions.length, label: 'live sessions', sub: watched ? `${watched} open now` : '' },
    { icon: 'server', color: 'var(--client-mc)', value: consoleMachines.length, of: active.length, label: 'console on' },
    { icon: 'player-play', color: 'var(--destructive)', value: recordingOn, of: consoleMachines.length, label: 'recording' },
    { icon: 'history', color: 'var(--info)', value: recordings.length, label: 'recordings', sub: recordings.length ? formatBytes(recordings.reduce((n, r) => n + r.size, 0)) : '' },
  ])

  let release
  onMount(async () => {
    if (canUse) {
      release = openConsoleEvents()
      refreshSessions()
      await loadMachines()
    }
    loading = false
  })
  onDestroy(() => release?.())
</script>

{#if !canUse}
  <EmptyState icon="lock" title="Operator access needed" description="Console sessions and recordings are available to operators and admins." large />
{:else}
<div class="space-y-5">
  <InfoCard icon="terminal-2" title="Sessions"
    description="Your console sessions on every machine, what they recorded, and commands run on several machines at once.">
    <div class="flex shrink-0 gap-2">
      {#if active.length}
        <Button variant="outline" icon="player-play" onclick={() => (bulkOpen = true)} tooltip="Run one command on several machines">
          <span class="hidden sm:inline">Run on multiple</span>
        </Button>
      {/if}
      {#if consoleMachines.length}
        <Button icon="plus" onclick={startNew} tooltip="New session"><span class="hidden sm:inline">New session</span></Button>
      {/if}
    </div>
  </InfoCard>

  <StatStrip items={stats} label="Summary" />

  <section aria-label="Live sessions" class="space-y-2">
    <div class="flex items-center gap-3">
      <h2 class="flex min-w-0 flex-1 items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground after:h-px after:flex-1 after:bg-border">
        <span class="h-2 w-2 rounded-sm bg-success"></span>
        Live sessions
        <span class="font-normal normal-case tracking-normal">{$consoleSessions.length}</span>
      </h2>
      {#if consoleMachines.length}
        <button type="button" onclick={startNew}
          class="link-action">
          <Icon name="plus" size={12} />New session
        </button>
      {/if}
    </div>
    {#if $consoleSessions.length}
      <div class="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {#each $consoleSessions as s (s.machine_id + '/' + s.id)}
          <SessionCard session={s} machine={{ id: s.machine_id, name: s.machine_name }} onresume={resume} onkill={kill} />
        {/each}
      </div>
    {:else}
      {#if consoleMachines.length}
        <EmptyState inline icon="terminal-2" color="var(--success)" title="No live sessions"
          description="Open a shell on any machine with the console on. It keeps running after you close the browser, so you can come back to it here." />
      {:else}
        <EmptyState inline icon="terminal-2" title="The console is off on every machine"
          description="An admin turns it on for a machine under Clients, in that machine's Sessions tab." />
      {/if}
    {/if}
  </section>

  <RecordingList bind:recordings live={$consoleSessions.length}
    emptyText="Machines set to record keep every console session here, to play back or download." />
</div>

<BulkRun bind:open={bulkOpen} machines={active} />

<Modal bind:open={newOpen} title="New session" size="md">
  <div class="space-y-3">
    <p class="text-sm text-muted-foreground">Pick a machine. The session keeps running if you close the browser, so you can come back to it.</p>
    <div role="radiogroup" aria-label="Machine" class="max-h-72 divide-y divide-border overflow-y-auto rounded-lg border border-border">
      {#each consoleMachines as m (m.id)}
        {@const st = statusInfo(m)}
        {@const on = target === m.id}
        <button type="button" role="radio" aria-checked={on} disabled={!st.online} onclick={() => (target = m.id)}
          class="flex w-full items-center gap-3 px-3 py-2.5 text-left transition-colors
            {on ? 'bg-primary/10' : 'hover:bg-muted/50'} {st.online ? 'cursor-pointer' : 'cursor-not-allowed opacity-50'}">
          <span class="grid h-4 w-4 shrink-0 place-items-center rounded-full border {on ? 'border-primary' : 'border-muted-foreground/40'}">
            {#if on}<span class="h-2 w-2 rounded-full bg-primary"></span>{/if}
          </span>
          <span class="min-w-0 flex-1">
            <span class="block truncate text-sm font-medium text-foreground">{m.name || m.id}</span>
            <span class="flex items-center gap-1.5 text-[11px] text-muted-foreground"><span class="h-1.5 w-1.5 rounded-full {st.dot}"></span>{st.label}</span>
          </span>
          {#if m.console_record}
            <span class="inline-flex items-center gap-1 text-[11px] text-destructive" title="Every session on this machine is recorded"><Icon name="player-record" size={12} />recorded</span>
          {/if}
        </button>
      {/each}
    </div>
  </div>
  {#snippet footer()}
    <Button variant="secondary" onclick={() => (newOpen = false)}>Cancel</Button>
    <Button icon="terminal-2" onclick={newSession} disabled={!target}>Open session</Button>
  {/snippet}
</Modal>
{/if}
