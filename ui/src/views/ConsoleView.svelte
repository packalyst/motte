<script>
  // The standalone GLOBAL console: one workspace showing the caller's live sessions across EVERY
  // accessible, console-enabled machine. A left rail lists sessions to resume + machines to start a
  // new session on; the terminal (embedded Console) holds tabs that can span different hosts and
  // split across them. Fixed overlay inset past the app sidebar, so the sidebar stays usable.
  import { onMount, onDestroy } from 'svelte'
  import { apiGet, apiPost, confirm, toast, currentView, currentUser } from '../stores/app.js'
  import Console from '../components/Console.svelte'
  import Icon from '../components/Icon.svelte'

  let { loading = $bindable() } = $props()

  const ROLE_RANK = { viewer: 1, operator: 2, admin: 3, owner: 4 }
  const canOpen = $derived((ROLE_RANK[$currentUser?.role] || 0) >= ROLE_RANK.operator)

  let consoleRef = $state(null)
  let sessions = $state([]) // global list: [{id,label,attached,viewers,machine_id,machine_name}]
  let machines = $state([]) // console-enabled accessible machines
  let poll

  async function loadMachines() {
    try {
      const res = await apiGet('/api/fleet/machines')
      machines = (res || []).filter((m) => m.console_enabled)
    } catch {
      machines = []
    }
  }
  async function loadSessions() {
    try {
      const res = await apiGet('/api/fleet/console/sessions') // no machine_id → all machines
      sessions = res?.sessions || []
    } catch {
      sessions = []
    }
  }
  function resume(s) {
    consoleRef?.openSession(s)
  }
  function newOn(m) {
    consoleRef?.openNew({ id: m.id, name: m.name, console_record: m.console_record })
  }
  async function kill(s) {
    const ok = await confirm({
      title: 'Close session',
      message: `Close Session ${s.label || ''} on ${s.machine_name}? Anything running in it is terminated.`,
      variant: 'destructive', confirmText: 'Close',
    })
    if (!ok) return
    try {
      await apiPost('/api/fleet/console/kill', { machine_id: s.machine_id, session: s.id })
      sessions = sessions.filter((x) => !(x.id === s.id && x.machine_id === s.machine_id))
      loadSessions()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  onMount(async () => {
    loading = false // this view paints its own full-height overlay; release the shell spinner
    if (!canOpen) return
    await Promise.all([loadMachines(), loadSessions()])
    poll = setInterval(loadSessions, 5000)
  })
  onDestroy(() => clearInterval(poll))
</script>

{#if !canOpen}
  <div class="flex h-64 items-center justify-center text-sm text-muted-foreground">
    You need operator access to use the console.
  </div>
{:else}
  <div class="fixed inset-0 lg:left-60 z-40 flex bg-[#0f1419] text-[#d7dce2]">
    <!-- Session rail -->
    <aside class="w-56 lg:w-60 shrink-0 border-r border-white/10 bg-[#12161d] flex flex-col">
      <div class="flex items-center gap-2 px-3 py-2.5 border-b border-white/10">
        <button onclick={() => currentView.set('fleet')} title="Back" class="p-1 text-white/60 hover:text-white lg:hidden">
          <Icon name="arrow-left" size={16} />
        </button>
        <Icon name="terminal-2" size={16} class="text-[#58a6ff]" />
        <span class="font-semibold text-sm">Console</span>
        <span class="ml-auto text-[10px] text-white/40">{sessions.length} active</span>
      </div>

      <div class="flex-1 overflow-y-auto">
        <div class="px-3 pt-3 pb-1 text-[10px] uppercase tracking-wide text-white/40">New session</div>
        {#if machines.length}
          {#each machines as m (m.id)}
            <button onclick={() => newOn(m)}
              class="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-white/70 hover:bg-white/5 hover:text-white transition">
              <Icon name="plus" size={13} class="text-[#58a6ff] shrink-0" />
              <span class="truncate">{m.name || m.id}</span>
            </button>
          {/each}
        {:else}
          <div class="px-3 py-1.5 text-xs text-white/40">No console-enabled machines.</div>
        {/if}

        <div class="px-3 pt-4 pb-1 text-[10px] uppercase tracking-wide text-white/40">Active sessions</div>
        {#if sessions.length}
          {#each sessions as s (s.machine_id + '|' + s.id)}
            <div class="group flex items-center gap-2 px-3 py-1.5 hover:bg-white/5 transition">
              <span class="w-1.5 h-1.5 rounded-full shrink-0 {s.attached ? 'bg-green-400' : 'bg-white/30'}"
                title={s.attached ? 'attached' : 'detached'}></span>
              <button onclick={() => resume(s)} class="min-w-0 flex-1 text-left">
                <div class="text-xs text-white/80 truncate">Session {s.label}</div>
                <div class="text-[10px] text-white/40 truncate">{s.machine_name}</div>
              </button>
              {#if s.viewers > 0}
                <span class="text-[10px] text-white/40 flex items-center gap-0.5 shrink-0"><Icon name="eye" size={10} />{s.viewers}</span>
              {/if}
              <button onclick={() => kill(s)} title="Close session"
                class="opacity-0 group-hover:opacity-100 p-0.5 text-white/50 hover:text-red-300 shrink-0"><Icon name="x" size={12} /></button>
            </div>
          {/each}
        {:else}
          <div class="px-3 py-1.5 text-xs text-white/40">No active sessions. Start one above.</div>
        {/if}
      </div>
    </aside>

    <!-- Terminal (tabs span machines; split mixes hosts) -->
    <Console embedded machines={machines.map((m) => ({ id: m.id, name: m.name, console_record: m.console_record }))} bind:this={consoleRef} />
  </div>
{/if}
