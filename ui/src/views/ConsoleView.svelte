<script>
  // The standalone GLOBAL console page. No left rail (the app sidebar already is the menu): the
  // console chrome (tabs, all-sessions menu, new-session picker, split, close) lives in Console
  // itself. This view just supplies the machine list, drives the one-shot open target from a
  // machine's session card, mirrors open tabs into the URL hash (refresh/deep-link), and sends the
  // close button back to the page you came from. Live data arrives over the console-events WS.
  import { onMount, onDestroy, tick } from 'svelte'
  import { get } from 'svelte/store'
  import { apiGet, currentView, previousView, consoleTarget, currentUser } from '../stores/app.js'
  import { consoleSessions, openConsoleEvents } from '../lib/consoleEvents.js'
  import Console from '../components/Console.svelte'

  let { loading = $bindable() } = $props()

  const ROLE_RANK = { viewer: 1, operator: 2, admin: 3, owner: 4 }
  const canOpen = $derived((ROLE_RANK[$currentUser?.role] || 0) >= ROLE_RANK.operator)

  let consoleRef = $state(null)
  let machines = $state([])
  let release
  let restored = false

  async function loadMachines() {
    try {
      const res = await apiGet('/api/fleet/machines')
      machines = (res || []).filter((m) => m.console_enabled)
    } catch {
      machines = []
    }
  }

  // URL hash <-> open tabs, so a refresh reopens (reattaches) them. Format: #t=machineId|session,…
  function readHashTabs() {
    const h = new URLSearchParams(location.hash.slice(1)).get('t')
    if (!h) return []
    return h
      .split(',')
      .map((x) => { const [machine_id, session] = x.split('|'); return { machine_id, session } })
      .filter((x) => x.machine_id && x.session)
  }
  function onTabs(list) {
    const h = list.map((t) => `${t.machine_id}|${t.session}`).join(',')
    const url = new URL(location.href)
    url.hash = h ? 't=' + h : ''
    history.replaceState(history.state, '', url)
  }

  function goBack() {
    const prev = get(previousView)
    currentView.set(prev && prev !== 'console' ? prev : 'fleet')
  }

  onMount(async () => {
    loading = false // this view paints its own full-height overlay; release the shell spinner
    if (!canOpen) return
    release = openConsoleEvents()
    await loadMachines()
    await tick()
    // A machine's session card set a one-shot target before navigating here — honor it.
    const target = get(consoleTarget)
    if (target) {
      consoleTarget.set(null)
      restored = true // the target replaces any hash restore
      if (target.session) {
        consoleRef?.openSession({ id: target.session, machine_id: target.machine_id, machine_name: target.machine_name, label: target.label })
      } else {
        consoleRef?.openNew({ id: target.machine_id, name: target.machine_name })
      }
    }
  })
  onDestroy(() => release?.())

  // Restore tabs from the URL hash once the live list is known (to recover each session's label).
  $effect(() => {
    if (restored || !consoleRef) return
    const want = readHashTabs()
    if (!want.length) { restored = true; return }
    const list = $consoleSessions
    if (!list.length) return // wait for the first push
    restored = true
    for (const w of want) {
      const s = list.find((x) => x.machine_id === w.machine_id && x.id === w.session)
      if (s) consoleRef.openSession(s)
    }
  })
</script>

{#if !canOpen}
  <div class="flex h-64 items-center justify-center text-sm text-muted-foreground">
    You need operator access to use the console.
  </div>
{:else}
  <div class="fixed inset-0 lg:left-60 z-40 flex bg-[#0f1419] text-[#d7dce2]">
    <Console
      embedded
      machines={machines.map((m) => ({ id: m.id, name: m.name, console_record: m.console_record }))}
      ontabs={onTabs}
      onclose={goBack}
      bind:this={consoleRef}
    />
  </div>
{/if}
