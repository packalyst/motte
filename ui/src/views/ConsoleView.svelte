<script>
  // The standalone GLOBAL console page. Not in the sidebar — you reach it by resuming a session (or
  // starting one) from a machine. On arrival it opens EVERY live session across all your machines as
  // tabs (one step-up covers them all via grant-all), focuses the one you resumed, and tabs/split can
  // span hosts. Close returns to exactly where you came from. Live data is pushed over the WS.
  import { onMount, onDestroy, tick } from 'svelte'
  import { get } from 'svelte/store'
  import {
    apiGet, apiPost, stepUpConfirm, currentView, previousView, consoleTarget, consoleReturn, currentUser, hasRole,
  } from '../stores/app.js'
  import { consoleSessions, openConsoleEvents } from '../lib/consoleEvents.js'
  import Console from '../components/Console.svelte'
  import { keyboardAware } from '../lib/utils/viewport.js'

  let { loading = $bindable() } = $props()

  const canOpen = $derived(hasRole($currentUser, 'operator'))

  let consoleRef = $state(null)
  let machines = $state([])
  let release

  async function loadMachines() {
    try {
      const res = await apiGet('/api/fleet/machines')
      machines = (res || []).filter((m) => m.console_enabled)
    } catch {
      machines = []
    }
  }

  // Resolve with the live session list: use it if already pushed, else wait briefly for the first push.
  function firstSessions() {
    const cur = get(consoleSessions)
    if (cur.length) return Promise.resolve(cur)
    return new Promise((resolve) => {
      let settled = false
      const done = (v) => { if (!settled) { settled = true; resolve(v || []) } }
      const unsub = consoleSessions.subscribe((v) => { if (v && v.length) { unsub(); done(v) } })
      setTimeout(() => { try { unsub() } catch { /* noop */ } done(get(consoleSessions)) }, 1500)
    })
  }

  // One step-up mints grants for every machine we're about to attach, so auto-opening all sessions
  // never prompts per machine. Returns the {machineId: grant} map, or null if the user cancelled.
  async function bulkGrants(machineIds) {
    if (!machineIds.length) return {}
    // Try silently first: the server honours a step-up grace window, so re-opening the console
    // within it needs no prompt. Only a 428 (grace lapsed) pops the re-auth dialog.
    try {
      const res = await apiPost('/api/fleet/console/grant-all', { machine_ids: machineIds })
      return res?.grants || {}
    } catch (e) {
      if (e?.status !== 428) throw e
    }
    const r = await stepUpConfirm({ title: 'Open console', description: 'Re-authenticate to open your sessions.' })
    if (!r?.confirmed) return null
    const res = await apiPost('/api/fleet/console/grant-all', { machine_ids: machineIds, currentPassword: r.password, totpCode: r.totp })
    return res?.grants || {}
  }

  // URL hash <-> open tabs so a refresh reopens (reattaches) them. Format: #t=machineId|session,…
  function readHashTabs() {
    const h = new URLSearchParams(location.hash.slice(1)).get('t')
    if (!h) return []
    return h.split(',').map((x) => { const [machine_id, session] = x.split('|'); return { machine_id, session } }).filter((x) => x.machine_id && x.session)
  }
  function onTabs(list) {
    const h = list.map((t) => `${t.machine_id}|${t.session}`).join(',')
    const url = new URL(location.href)
    url.hash = h ? 't=' + h : ''
    history.replaceState(history.state, '', url)
  }

  function goBack() {
    const ret = get(consoleReturn)
    consoleReturn.set(null)
    const view = ret?.view && ret.view !== 'console' ? ret.view : get(previousView) || 'clients'
    currentView.set(view)
    // Apply the deep-link hash on a macrotask: closing clears the tabs, which fires Console's
    // hash-writer with an empty list during teardown — doing it now would let that wipe this one.
    if (ret?.hash) setTimeout(() => { location.hash = ret.hash }, 0)
  }

  async function enter() {
    const sessions = await firstSessions()
    const target = get(consoleTarget)
    consoleTarget.set(null)
    const hashWanted = readHashTabs()

    // Which machines to grant: everything with a live session + the target (and any hash entries).
    const ids = new Set(sessions.map((s) => s.machine_id))
    if (target?.machine_id) ids.add(target.machine_id)
    for (const w of hashWanted) ids.add(w.machine_id)
    const grants = await bulkGrants([...ids])
    if (grants === null) { goBack(); return } // cancelled the step-up → leave
    consoleRef?.seedGrants(grants)

    // Open every live session as a tab (the target one LAST so it ends up active).
    const targetS = target?.session ? sessions.find((s) => s.machine_id === target.machine_id && s.id === target.session) : null
    for (const s of sessions) { if (s !== targetS) consoleRef?.openSession(s) }
    if (target?.fresh && target.machine_id) await consoleRef?.openNew({ id: target.machine_id, name: target.machine_name })
    if (targetS) await consoleRef?.openSession(targetS)
  }

  onMount(async () => {
    loading = false // this view paints its own full-height overlay; release the shell spinner
    if (!canOpen) return
    release = openConsoleEvents()
    await loadMachines()
    await tick()
    await enter()
  })
  onDestroy(() => release?.())
</script>

{#if !canOpen}
  <div class="flex h-64 items-center justify-center text-sm text-muted-foreground">
    You need operator access to use the console.
  </div>
{:else}
  <div use:keyboardAware class="safe-inset fixed inset-0 lg:left-60 z-40 flex bg-[#0f1419] text-[#d7dce2]">
    <Console
      embedded
      machines={machines.map((m) => ({ id: m.id, name: m.name, console_record: m.console_record }))}
      ontabs={onTabs}
      onclose={goBack}
      bind:this={consoleRef}
    />
  </div>
{/if}
