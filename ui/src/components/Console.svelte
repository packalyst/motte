<script>
  // Full-screen interactive console for a fleet machine. Opens one step-up-granted WebSocket per
  // tab (session), rendered with xterm.js. Supports multiple tabs, reattach to a resumable session
  // (tmux survives a disconnect), resize, copy/paste (xterm), scrollback search, file
  // upload/download, a read-only share link, and shows a recording badge.
  import { onMount, onDestroy, tick } from 'svelte'
  import { Terminal } from '@xterm/xterm'
  import { FitAddon } from '@xterm/addon-fit'
  import { SearchAddon } from '@xterm/addon-search'
  import { WebLinksAddon } from '@xterm/addon-web-links'
  import '@xterm/xterm/css/xterm.css'
  import { apiPost, stepUpConfirm, toast, confirm } from '../stores/app.js'
  import { consoleSessions } from '../lib/consoleEvents.js'
  import { ConsoleSocket } from '../lib/console.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'

  // The console is machine-agnostic: every tab carries its OWN machine, so one console can hold
  // sessions from different hosts (the global console). Grants are cached per machine.
  //   machines        — accessible, console-enabled machines, for the "new session" picker (global)
  //   initialMachine  — open the first tab here on mount (per-machine / resume launch); null = empty
  //   initialSession  — reattach this resumable session on initialMachine (tmux), else a fresh shell
  //   embedded        — render inline inside a page (global console) instead of a fixed overlay
  //   shareGrant/shareSession/shareMachine — open a read-only session from a shared link (no step-up)
  let {
    machines = [],
    initialMachine = null,
    initialSession = null,
    startFiles = false,
    embedded = false,
    onclose,
    ontabs = null, // called with the open tabs [{machine_id, machine_name, session, label}] on change
    shareGrant = null,
    shareSession = null,
    shareMachine = null,
  } = $props()

  const darkTheme = {
    background: '#0f1419', foreground: '#d7dce2', cursor: '#58a6ff',
    selectionBackground: '#2d3340', black: '#1a1f29', brightBlack: '#5c6773',
  }
  const lightTheme = {
    background: '#ffffff', foreground: '#1f2328', cursor: '#0969da',
    selectionBackground: '#b6d7ff', black: '#1f2328', brightBlack: '#8c959f',
  }

  let tabs = $state([])
  let activeId = $state(null)
  let error = $state('')
  let busy = $state(false)
  let readonly = $state(!!shareGrant)
  let searchVisible = $state(false)
  let searchQuery = $state('')
  let splitView = $state(false) // false = one session shown (tabs); true = all sessions in a grid

  // --- File browser (slide-in panel over the active session) ---
  let filesVisible = $state(startFiles)
  let filesCwd = $state('/root')
  let filesList = $state([])
  let filesLoading = $state(false)
  // Inline editor (textarea); opened from the browser, saved back via putFile.
  let editPath = $state(null)
  let editContent = $state('')
  let editLoading = $state(false)
  const editPending = new Set() // paths fetched for EDITING (vs downloading) — routes file-chunk

  // One grant per machine, reused across that machine's tabs/reconnects until the server rejects it.
  const grants = new Map()
  if (shareGrant && shareMachine) grants.set(shareMachine.id, shareGrant)
  let fileInput
  let filesUploadInput

  // The machine whose name/badges the header shows and the + button opens onto.
  const activeTab = $derived(tabs.find((t) => t.id === activeId) || null)
  const activeMachine = $derived(activeTab?.machine || initialMachine || shareMachine || null)

  // --- chrome state (font / theme / rename / maximize / menus / live clock) ---
  let fontSize = $state(13)
  let termLight = $state(false)
  let maximizedId = $state(null) // in split, show only this pane
  let newMenuOpen = $state(false)
  let allMenuOpen = $state(false)
  let now = $state(Date.now()) // ticks every second for live durations
  onMount(() => {
    const iv = setInterval(() => (now = Date.now()), 1000)
    return () => clearInterval(iv)
  })

  function applyTermOpts() {
    const theme = termLight ? lightTheme : darkTheme
    for (const t of tabs) {
      if (!t.term) continue
      t.term.options.fontSize = fontSize
      t.term.options.theme = theme
    }
    fitAll()
  }
  function setFont(d) { fontSize = Math.min(24, Math.max(9, fontSize + d)); applyTermOpts() }
  function toggleTheme() { termLight = !termLight; applyTermOpts() }
  function tabTitle(tab) { return tab.name || ('Session ' + (tab.label ?? '•')) }
  function startRename(tab) {
    const name = window.prompt('Rename session', tabTitle(tab))
    if (name != null) { tab.name = name.trim() || null; tabs = [...tabs] }
  }
  function toggleMaximize(tab) { maximizedId = maximizedId === tab.id ? null : tab.id; fitAll() }
  function pasteInto(tab) {
    navigator.clipboard?.readText?.().then((t) => { if (t && tab?.socket) tab.socket.sendInput(t) }).catch(() => {})
  }

  // Tab close (X): confirm, then KILL the session (not just detach) — matches the session list.
  async function killTab(tab) {
    const ok = await confirm({
      title: 'Close session',
      message: `Close ${tabTitle(tab)} on ${tab.machine.name || tab.machine.id}? Anything running in it is terminated.`,
      variant: 'destructive', confirmText: 'Close',
    })
    if (!ok) return
    try {
      await apiPost('/api/fleet/console/kill', { machine_id: tab.machine.id, session: tab.id })
    } catch (e) {
      toast(e.message || 'could not close session', 'error')
    }
    closeTab(tab) // detach locally; the server tears down the tmux session
  }

  // --- bottom status-bar formatting ---
  function fmtDuration(ms) {
    const s = Math.max(0, Math.floor(ms / 1000))
    if (s < 60) return s + 's'
    const m = Math.floor(s / 60)
    if (m < 60) return m + 'm ' + (s % 60) + 's'
    return Math.floor(m / 60) + 'h ' + (m % 60) + 'm'
  }
  const fmtClock = (ms) => new Date(ms).toLocaleTimeString()
  const fmtStart = (ms) => new Date(ms).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })

  function randSession() {
    const b = new Uint8Array(16)
    crypto.getRandomValues(b) // CSPRNG, not Math.random — the id gates session access
    return 's' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
  }

  // ensureGrant mints (or reuses) a console grant for a specific machine. Normal grants need a
  // step-up; the first call per machine prompts, later ones reuse the multi-use grant until rejected.
  async function ensureGrant(machine) {
    const have = grants.get(machine.id)
    if (have) return have
    const r = await stepUpConfirm({
      title: 'Open console',
      description: `Re-authenticate to open an interactive console on "${machine.name || machine.id}".`,
    })
    if (!r?.confirmed) throw new Error('cancelled')
    const res = await apiPost('/api/fleet/console/grant', {
      machine_id: machine.id, currentPassword: r.password, totpCode: r.totp,
    })
    grants.set(machine.id, res.grant)
    return res.grant
  }

  // openTab opens a session on a given machine. sessionId reattaches an existing resumable session
  // (tmux new -A); null opens a fresh one. label is the "Session N" shown on the tab.
  async function openTab(machine, sessionId = null, label = null) {
    if (!machine) return
    error = ''
    const session = readonly && shareSession ? shareSession : (sessionId || randSession())
    const existing = tabs.find((t) => t.id === session && t.machine.id === machine.id)
    if (existing) { activate(session); return } // already open — just focus it
    busy = true
    try {
      const g = await ensureGrant(machine)
      const tab = { id: session, machine, label, name: null, startedAt: Date.now(), latency: null, cwd: '', pinger: null, el: null, term: null, fit: null, search: null, socket: null, exited: false }
      tabs = [...tabs, tab]
      activeId = session
      await tick() // let the terminal container mount
      const mounted = tabs.find((t) => t.id === session)
      startTerminal(mounted, g, session)
    } catch (e) {
      if (e?.message !== 'cancelled') error = e.message || 'could not open console'
    } finally {
      busy = false
    }
  }

  // Driven by the parent (the global console page).
  export function openNew(machine) { openTab(machine) }
  export function openSession(s) { openTab({ id: s.machine_id, name: s.machine_name }, s.id, s.label) }
  export function hasTabs() { return tabs.length > 0 }
  // Pre-seed per-machine grants (from one bulk step-up) so auto-opening every session doesn't prompt.
  export function seedGrants(obj) { for (const [mid, g] of Object.entries(obj || {})) if (g) grants.set(mid, g) }
  // Focus an already-open session's tab (the one the user clicked "resume" on).
  export function focus(machineId, session) {
    const t = tabs.find((x) => x.id === session && x.machine.id === machineId)
    if (t) activate(t.id)
  }

  function startTerminal(tab, g, session) {
    // Look the container up directly from the DOM (don't rely on Svelte's proxy write-back of
    // bind:this, which can leave the local `el` null) — this is the mount node xterm needs.
    const el = tab?.el || document.getElementById('wt-' + session)
    if (!el) {
      error = 'terminal container failed to mount'
      return
    }
    if (tab) tab.el = el
    const term = new Terminal({
      cursorBlink: true, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize, theme: termLight ? lightTheme : darkTheme, scrollback: 5000, allowProposedApi: true,
    })
    const fit = new FitAddon()
    const search = new SearchAddon()
    term.loadAddon(fit)
    term.loadAddon(search)
    term.loadAddon(new WebLinksAddon())
    term.open(el)
    fit.fit()
    tab.term = term
    tab.fit = fit
    tab.search = search

    const socket = new ConsoleSocket({
      machine: tab.machine.id, grant: g, session: tab.id, cols: term.cols, rows: term.rows,
      onOpen: () => {
        if (!readonly) term.focus()
        if (filesVisible && tab.id === activeId) listFiles(filesCwd)
        socket.ping() // first latency/cwd probe, then keep it fresh
        clearInterval(tab.pinger)
        tab.pinger = setInterval(() => socket.ping(), 5000)
      },
      onData: (bytes) => term.write(bytes),
      onExit: () => { tab.exited = true; clearInterval(tab.pinger); term.write('\r\n\x1b[90m[session ended]\x1b[0m\r\n'); tabs = [...tabs] },
      onError: (m) => { error = m; if (/grant/i.test(m)) grants.delete(tab.machine.id) },
      onClose: () => { if (!tab.exited) term.write('\r\n\x1b[90m[disconnected]\x1b[0m\r\n') },
      onPong: (latency, cwd) => { tab.latency = latency; tab.cwd = cwd; tabs = [...tabs] },
      onFileChunk: (path, parts) => handleFileChunk(path, parts),
      onFileList: (path, items) => handleFileList(tab.id, path, items),
    })
    socket.connect()
    tab.socket = socket
    if (!readonly) term.onData((d) => socket.sendInput(d))
    term.onResize(({ cols, rows }) => socket.resize(cols, rows))
  }

  function activate(id) {
    activeId = id
    const tab = tabs.find((t) => t.id === id)
    tick().then(() => { tab?.fit?.fit(); tab?.term?.focus() })
  }

  function closeTab(tab) {
    clearInterval(tab.pinger)
    tab.socket?.close()
    tab.term?.dispose()
    tabs = tabs.filter((t) => t.id !== tab.id)
    if (maximizedId === tab.id) maximizedId = null
    if (activeId === tab.id) activeId = tabs[tabs.length - 1]?.id || null
    if (tabs.length === 0) onclose?.()
  }

  function closeAll() {
    for (const t of tabs) { clearInterval(t.pinger); t.socket?.close(); t.term?.dispose() }
    tabs = []
    onclose?.()
  }

  // Re-fit terminals to their containers. Split view resizes every pane; tab view only the visible one.
  function fitAll() {
    tick().then(() => { for (const t of tabs) t.fit?.fit() })
  }
  function onResize() {
    if (splitView) fitAll()
    else tabs.find((t) => t.id === activeId)?.fit?.fit()
  }
  // Square-ish grid for the panes (2 → 1×2, 3-4 → 2×2, …).
  const splitCols = $derived(Math.ceil(Math.sqrt(Math.max(1, tabs.length))))
  const inSplit = $derived(splitView && !maximizedId) // maximizing a pane collapses the grid
  // Re-fit whenever the layout, pane count, or the files panel (which narrows the terminal) changes.
  $effect(() => { splitView; tabs.length; filesVisible; fitAll() })

  // --- toolbar actions ---
  function runSearch(dir) {
    const tab = tabs.find((t) => t.id === activeId)
    if (!tab?.search || !searchQuery) return
    dir === 'prev' ? tab.search.findPrevious(searchQuery) : tab.search.findNext(searchQuery)
  }

  function upload() {
    fileInput?.click()
  }
  async function onFilePicked(e) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    const tab = tabs.find((t) => t.id === activeId)
    if (!tab) return
    const path = window.prompt('Upload to path on the machine:', '/root/' + file.name)
    if (!path) return
    await tab.socket.putFile(path, file)
    toast('Uploading ' + file.name + '…', 'info')
  }
  function download() {
    const tab = tabs.find((t) => t.id === activeId)
    if (!tab) return
    const path = window.prompt('Download file from the machine (absolute path):', '/root/')
    if (path) tab.socket.getFile(path)
  }
  function deliverDownload(path, parts) {
    const blob = new Blob(parts)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = path.split('/').pop() || 'download'
    a.click()
    URL.revokeObjectURL(url)
  }

  // --- file browser ---
  function activeSocket() {
    return tabs.find((t) => t.id === activeId)?.socket
  }
  function joinPath(base, name) {
    return base.endsWith('/') ? base + name : base + '/' + name
  }
  function parentPath(p) {
    if (!p || p === '/') return '/'
    const parts = p.replace(/\/+$/, '').split('/')
    parts.pop()
    return parts.join('/') || '/'
  }
  function listFiles(path) {
    const s = activeSocket()
    if (!s) return toast('Open a session first', 'error')
    filesLoading = true
    s.listDir(path)
  }
  function openFiles() {
    filesVisible = true
    listFiles(filesCwd)
  }
  // Agent reply for a listing (only the active session's).
  function handleFileList(session, path, items) {
    if (session !== activeId) return
    filesCwd = path
    filesList = items
    filesLoading = false
  }
  // Route a delivered file: into the editor if we requested it for editing, else download it.
  function handleFileChunk(path, parts) {
    if (editPending.has(path)) {
      editPending.delete(path)
      new Blob(parts).text().then((t) => { editContent = t; editLoading = false })
      return
    }
    deliverDownload(path, parts)
  }
  function downloadFromBrowser(name) {
    activeSocket()?.getFile(joinPath(filesCwd, name))
  }
  function editFromBrowser(name) {
    const p = joinPath(filesCwd, name)
    editPending.add(p)
    editPath = p
    editContent = ''
    editLoading = true
    activeSocket()?.getFile(p)
  }
  async function saveEdit() {
    const s = activeSocket()
    if (!s || editPath == null) return
    await s.putFile(editPath, new Blob([editContent]))
    toast('Saving ' + editPath + '…', 'info')
    editPath = null
  }
  async function uploadHere(e) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    const s = activeSocket()
    if (!s) return
    await s.putFile(joinPath(filesCwd, file.name), file)
    toast('Uploading ' + file.name + '…', 'info')
  }
  const enterDir = (name) => listFiles(joinPath(filesCwd, name))
  const upDir = () => listFiles(parentPath(filesCwd))
  function fmtSize(n) {
    if (!n) return ''
    const u = ['B', 'K', 'M', 'G']
    let v = n, i = 0
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
    return (i === 0 ? v : v.toFixed(1)) + u[i]
  }

  async function share() {
    const tab = tabs.find((t) => t.id === activeId)
    if (!tab) return toast('Open a session first', 'error')
    try {
      const r = await stepUpConfirm({ title: 'Share read-only console', description: 'Re-authenticate to create a view-only link.' })
      if (!r?.confirmed) return
      const res = await apiPost('/api/fleet/console/grant?readonly=true', {
        machine_id: tab.machine.id, session: tab.id, currentPassword: r.password, totpCode: r.totp,
      })
      // res.session is the owner's namespaced session the grant is bound to — the viewer must open that.
      const link = `${location.origin}/#fconsole=${encodeURIComponent(tab.machine.id)}|${encodeURIComponent(res.session)}|${encodeURIComponent(res.grant)}`
      await navigator.clipboard.writeText(link)
      toast('Read-only link copied (valid ~30 min)', 'success')
    } catch (e) {
      toast(e.message || 'could not create share link', 'error')
    }
  }

  $effect(() => {
    // Auto-open the first tab on mount for a direct launch (per-machine or a share link). In the
    // global console no initial machine is passed — the parent drives openNew/openSession instead.
    if (tabs.length > 0 || busy) return
    if (shareGrant && shareMachine) openTab(shareMachine, shareSession)
    else if (initialMachine) openTab(initialMachine, initialSession)
  })

  // Report the open tabs to the parent (to mirror into the URL hash for refresh/deep-link).
  $effect(() => { ontabs?.(tabs.map((t) => ({ machine_id: t.machine.id, machine_name: t.machine.name, session: t.id, label: t.label }))) })

  onDestroy(() => { for (const t of tabs) { clearInterval(t.pinger); t.socket?.close(); t.term?.dispose() } })
</script>

<svelte:window on:resize={onResize} />

<!-- Per-session bottom status bar (reused in single + split): live status, start, duration, clock. -->
{#snippet statusBar(tab)}
  <div class="flex items-center gap-3 px-3 py-1 text-[10px] border-t border-white/10 bg-[#12161d] text-white/50 overflow-x-auto shrink-0">
    <span class="flex items-center gap-1 shrink-0">
      <span class="w-1.5 h-1.5 rounded-full {tab.exited ? 'bg-white/30' : 'bg-green-400'}"></span>{tab.exited ? 'Ended' : 'Active'}
    </span>
    <span class="shrink-0">start {fmtStart(tab.startedAt)}</span>
    <span class="shrink-0">duration {fmtDuration(now - tab.startedAt)}</span>
    <span class="flex items-center gap-1 shrink-0"><Icon name="clock" size={10} />{fmtClock(now)}</span>
    {#if tab.cwd}<span class="flex items-center gap-1 shrink-0" title={tab.cwd}><Icon name="folder" size={10} />{tab.cwd}</span>{/if}
    {#if tab.latency != null}<span class="flex items-center gap-1 shrink-0"><Icon name="activity" size={10} />{tab.latency} ms</span>{/if}
    <span class="shrink-0 text-white/30 ml-auto">{tab.machine.name || tab.machine.id}</span>
  </div>
{/snippet}

<!-- Overlay mode: inset past the app sidebar on desktop so it stays visible (a page, not a modal).
     Embedded mode (global console): fill the page column the parent lays out beside its rail. -->
<div class={embedded
    ? 'relative flex-1 min-w-0 flex flex-col bg-[#0f1419] text-[#d7dce2]'
    : 'fixed inset-0 lg:left-60 z-50 flex flex-col bg-[#0f1419] text-[#d7dce2]'}>
  <!-- TOP BAR: tabs on the left (can span machines); session controls on the right. -->
  <div class="flex items-center gap-2 px-2 py-1.5 border-b border-white/10 bg-[#12161d]">
    <div class="flex items-center gap-1 overflow-x-auto flex-1 min-w-0">
      {#each tabs as tab (tab.id)}
        <button onclick={() => activate(tab.id)}
          class="group flex items-center gap-1.5 pl-2 pr-1.5 py-1 rounded border-l-2 whitespace-nowrap shrink-0 {activeId === tab.id ? 'bg-white/10 border-[#58a6ff]' : 'border-transparent hover:bg-white/5'}">
          <span class="w-1.5 h-1.5 rounded-full {tab.exited ? 'bg-white/30' : 'bg-green-400'}"></span>
          <span class="flex flex-col items-start leading-tight text-left">
            <span class="text-xs {activeId === tab.id ? 'text-white' : 'text-white/70'}">{tabTitle(tab)}{tab.exited ? ' (ended)' : ''}</span>
            <span class="text-[9px] text-white/40 truncate max-w-[110px]">{tab.machine.name || tab.machine.id}</span>
          </span>
          {#if !readonly}
            <span role="button" tabindex="-1" onkeydown={() => {}} onclick={(e) => { e.stopPropagation(); killTab(tab) }}
              class="opacity-0 group-hover:opacity-100 hover:text-red-300 ml-1"><Icon name="x" size={11} /></span>
          {/if}
        </button>
      {/each}
      {#if tabs.length === 0}<span class="text-xs text-white/40 px-2">No sessions open</span>{/if}
    </div>

    <div class="flex items-center gap-1 shrink-0 relative">
      {#if !readonly}
        <!-- Jump to any live session across machines -->
        <button onclick={() => { allMenuOpen = !allMenuOpen; newMenuOpen = false }} title="All sessions" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="layout-list" size={15} /></button>
        {#if allMenuOpen}
          <div class="absolute right-0 top-9 z-50 w-64 max-h-80 overflow-y-auto bg-[#1a1f29] border border-white/10 rounded-lg shadow-xl py-1">
            <div class="px-3 py-1 text-[10px] uppercase tracking-wide text-white/40">Active sessions</div>
            {#if $consoleSessions.length}
              {#each $consoleSessions as s (s.machine_id + '|' + s.id)}
                <button onclick={() => { allMenuOpen = false; openSession(s) }} class="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-white/70 hover:bg-white/5 text-left">
                  <span class="w-1.5 h-1.5 rounded-full shrink-0 {s.attached ? 'bg-green-400' : 'bg-white/30'}"></span>
                  <span class="flex-1 truncate">Session {s.label} · {s.machine_name}</span>
                </button>
              {/each}
            {:else}<div class="px-3 py-2 text-xs text-white/40">No active sessions.</div>{/if}
          </div>
        {/if}
        <!-- New session (machine picker when more than one is available) -->
        <button onclick={() => { if (machines.length > 1) { newMenuOpen = !newMenuOpen; allMenuOpen = false } else if (activeMachine) openTab(activeMachine) }}
          disabled={busy} title="New session" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="plus" size={16} /></button>
        {#if newMenuOpen}
          <div class="absolute right-0 top-9 z-50 w-56 max-h-80 overflow-y-auto bg-[#1a1f29] border border-white/10 rounded-lg shadow-xl py-1">
            <div class="px-3 py-1 text-[10px] uppercase tracking-wide text-white/40">New session on…</div>
            {#each machines as m (m.id)}
              <button onclick={() => { newMenuOpen = false; openTab({ id: m.id, name: m.name, console_record: m.console_record }) }}
                class="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-white/70 hover:bg-white/5 text-left"><Icon name="server" size={13} class="text-[#58a6ff] shrink-0" /><span class="truncate">{m.name || m.id}</span></button>
            {/each}
          </div>
        {/if}
      {/if}
      {#if tabs.length > 1}
        <button onclick={() => (splitView = !splitView)} title={splitView ? 'Single view' : 'Split view'}
          class="p-1.5 rounded hover:bg-white/5 {splitView ? 'text-[#58a6ff]' : 'text-white/60'}"><Icon name={splitView ? 'layout-columns' : 'layout-grid'} size={15} /></button>
      {/if}
      <button onclick={() => closeAll()} title="Close console (back)" class="p-1.5 rounded text-white/60 hover:bg-red-500/20 hover:text-red-300"><Icon name="x" size={16} /></button>
    </div>
  </div>

  <!-- Backdrop that dismisses the dropdowns -->
  {#if newMenuOpen || allMenuOpen}
    <button aria-label="Close menu" class="fixed inset-0 z-40 cursor-default" onclick={() => { newMenuOpen = false; allMenuOpen = false }}></button>
  {/if}

  <!-- SESSION TOOLBAR (acts on the active session) -->
  {#if activeTab && !readonly}
    <div class="flex items-center gap-1 px-3 py-1.5 border-b border-white/10 bg-[#0f1419] overflow-x-auto">
      <span class="flex items-center gap-1.5 px-2 py-0.5 rounded bg-white/5 shrink-0">
        <span class="w-1.5 h-1.5 rounded-full {activeTab.exited ? 'bg-white/30' : 'bg-green-400'}"></span>
        <span class="text-white/80 font-mono text-[11px]">root@{activeMachine?.name || activeMachine?.id}</span>
      </span>
      <button onclick={() => startRename(activeTab)} title="Rename session" class="text-sm text-white/80 px-1 shrink-0 hover:text-white truncate max-w-[160px]">{tabTitle(activeTab)}</button>
      <div class="ml-auto flex items-center gap-0.5 shrink-0">
        <button onclick={() => (searchVisible = !searchVisible)} title="Search scrollback" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="search" size={14} /></button>
        <button onclick={openFiles} title="File browser" class="p-1.5 rounded hover:bg-white/5 {filesVisible ? 'text-[#58a6ff]' : 'text-white/60'}"><Icon name="folder" size={14} /></button>
        <button onclick={upload} title="Quick upload" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="upload" size={14} /></button>
        <button onclick={download} title="Quick download" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="download" size={14} /></button>
        <button onclick={() => pasteInto(activeTab)} title="Paste clipboard" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="clipboard" size={14} /></button>
        <button onclick={toggleTheme} title="Terminal theme" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name={termLight ? 'moon' : 'sun'} size={14} /></button>
        <span class="w-px h-4 bg-white/10 mx-0.5"></span>
        <button onclick={() => setFont(-1)} title="Smaller text" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="minus" size={14} /></button>
        <span class="text-[10px] text-white/40 tabular-nums w-4 text-center">{fontSize}</span>
        <button onclick={() => setFont(1)} title="Larger text" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="plus" size={14} /></button>
        <span class="w-px h-4 bg-white/10 mx-0.5"></span>
        <button onclick={() => startRename(activeTab)} title="Rename" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="pencil" size={14} /></button>
        <button onclick={share} title="Share read-only link" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="share" size={14} /></button>
        <button onclick={() => toggleMaximize(activeTab)} title="Maximize" class="p-1.5 rounded hover:bg-white/5 {maximizedId ? 'text-[#58a6ff]' : 'text-white/60'}"><Icon name="arrows-maximize" size={14} /></button>
        {#if activeMachine?.console_record}<span class="flex items-center gap-1 text-[10px] text-red-300 px-1.5"><span class="w-1.5 h-1.5 rounded-full bg-red-400"></span>rec</span>{/if}
      </div>
    </div>
  {/if}

  {#if searchVisible}
    <div class="flex items-center gap-2 px-3 py-1.5 bg-[#12161d] border-b border-white/10">
      <input bind:value={searchQuery} onkeydown={(e) => e.key === 'Enter' && runSearch('next')} placeholder="Search scrollback…"
        class="flex-1 bg-black/30 border border-white/10 rounded px-2 py-1 text-xs text-white outline-none focus:border-[#58a6ff]" />
      <button onclick={() => runSearch('prev')} class="p-1 text-white/60 hover:text-white"><Icon name="chevron-up" size={14} /></button>
      <button onclick={() => runSearch('next')} class="p-1 text-white/60 hover:text-white"><Icon name="chevron-down" size={14} /></button>
    </div>
  {/if}

  {#if error}
    <div class="px-3 py-1.5 text-xs bg-red-500/15 text-red-300 border-b border-red-500/20">{error}</div>
  {/if}

  <!-- Body: terminal area + optional file-browser panel, side by side -->
  <div class="flex-1 min-h-0 flex">
  <!-- Terminal panes. Single view shows the active pane full; split lays them in a grid, each with
       its own header + bottom status bar. Mount nodes (wt-<id>) stay stable so xterm isn't recreated. -->
  <div class="flex-1 min-h-0 relative overflow-hidden {inSplit ? 'grid gap-1 p-1' : ''}"
    style={inSplit ? `grid-template-columns: repeat(${splitCols}, minmax(0,1fr)); grid-auto-rows: minmax(0,1fr)` : ''}>
    {#each tabs as tab (tab.id)}
      {@const shown = maximizedId ? maximizedId === tab.id : splitView || activeId === tab.id}
      <div onclick={() => activate(tab.id)}
        class="flex flex-col min-h-0 {inSplit ? 'rounded border overflow-hidden ' + (activeId === tab.id ? 'border-[#58a6ff]' : 'border-white/10') : 'absolute inset-0'}"
        style:display={shown ? 'flex' : 'none'}>
        {#if inSplit || maximizedId === tab.id}
          <div class="flex items-center gap-2 px-2 py-1 text-[11px] border-b border-white/10 bg-[#12161d] shrink-0">
            <Icon name="grip-vertical" size={12} class="text-white/30" />
            <span class="text-white/70 truncate">{tabTitle(tab)}</span>
            <span class="text-white/40 truncate">· {tab.machine.name || tab.machine.id}</span>
            <div class="ml-auto flex items-center gap-1.5">
              <button onclick={(e) => { e.stopPropagation(); toggleMaximize(tab) }} title={maximizedId ? 'Restore' : 'Maximize'} class="text-white/50 hover:text-white"><Icon name={maximizedId ? 'arrows-minimize' : 'arrows-maximize'} size={12} /></button>
              {#if !readonly}<button onclick={(e) => { e.stopPropagation(); killTab(tab) }} title="Close session" class="text-white/50 hover:text-red-300"><Icon name="x" size={12} /></button>{/if}
            </div>
          </div>
        {/if}
        <div id={'wt-' + tab.id} bind:this={tab.el} class="flex-1 min-h-0 p-1.5"></div>
        {@render statusBar(tab)}
      </div>
    {/each}
    {#if tabs.length === 0}
      <div class="absolute inset-0 flex items-center justify-center text-white/40 text-sm">
        {busy ? 'Opening console…' : 'No session open — start one from the top bar.'}
      </div>
    {/if}
  </div>

  <!-- File browser panel -->
  {#if filesVisible}
    <aside class="w-80 shrink-0 border-l border-white/10 bg-[#12161d] flex flex-col">
      <div class="flex items-center gap-2 px-3 py-2 border-b border-white/10">
        <Icon name="folder" size={14} class="text-[#58a6ff]" />
        <span class="font-medium text-sm">Files</span>
        <button onclick={() => listFiles(filesCwd)} title="Refresh" class="ml-auto p-1 text-white/60 hover:text-white"><Icon name="refresh" size={13} /></button>
        <button onclick={() => (filesVisible = false)} title="Close" class="p-1 text-white/60 hover:text-white"><Icon name="x" size={14} /></button>
      </div>
      <div class="flex items-center gap-1 px-2 py-1.5 border-b border-white/10">
        <button onclick={upDir} title="Up a directory" class="p-1 text-white/60 hover:text-white"><Icon name="arrow-up" size={13} /></button>
        <span class="font-mono text-[11px] text-white/70 truncate flex-1" title={filesCwd}>{filesCwd}</span>
        <button onclick={() => filesUploadInput?.click()} title="Upload to this directory" class="p-1 text-white/60 hover:text-white"><Icon name="upload" size={13} /></button>
      </div>
      <div class="flex-1 overflow-y-auto">
        {#if filesLoading}
          <div class="p-3 text-xs text-white/40">Loading…</div>
        {:else if filesList.length}
          {#each filesList as it}
            <div class="group flex items-center gap-2 px-3 py-1.5 hover:bg-white/5 text-xs">
              <Icon name={it.dir ? 'folder' : 'file'} size={14} class={it.dir ? 'text-[#58a6ff] shrink-0' : 'text-white/50 shrink-0'} />
              {#if it.dir}
                <button onclick={() => enterDir(it.name)} class="flex-1 text-left truncate hover:text-white">{it.name}/</button>
              {:else}
                <span class="flex-1 truncate" title={it.name}>{it.name}</span>
                <span class="text-white/30 tabular-nums shrink-0">{fmtSize(it.size)}</span>
                <button onclick={() => editFromBrowser(it.name)} title="Edit" class="opacity-0 group-hover:opacity-100 p-0.5 text-white/60 hover:text-white shrink-0"><Icon name="pencil" size={12} /></button>
                <button onclick={() => downloadFromBrowser(it.name)} title="Download" class="opacity-0 group-hover:opacity-100 p-0.5 text-white/60 hover:text-white shrink-0"><Icon name="download" size={12} /></button>
              {/if}
            </div>
          {/each}
        {:else}
          <div class="p-3 text-xs text-white/40">Empty directory.</div>
        {/if}
      </div>
    </aside>
  {/if}
  </div>

  <!-- Inline file editor -->
  {#if editPath != null}
    <div class="absolute inset-0 z-20 bg-black/50 flex items-center justify-center p-4">
      <div class="w-full max-w-4xl h-[80%] bg-[#12161d] border border-white/10 rounded-lg flex flex-col overflow-hidden">
        <div class="flex items-center gap-2 px-3 py-2 border-b border-white/10">
          <Icon name="pencil" size={14} class="text-[#58a6ff]" />
          <span class="font-mono text-xs truncate flex-1" title={editPath}>{editPath}</span>
          <Button size="xs" variant="primary" icon="device-floppy" onclick={saveEdit}>Save</Button>
          <button onclick={() => (editPath = null)} class="p-1 text-white/60 hover:text-white"><Icon name="x" size={16} /></button>
        </div>
        {#if editLoading}
          <div class="flex-1 grid place-items-center text-white/40 text-sm">Loading…</div>
        {:else}
          <textarea bind:value={editContent} spellcheck="false"
            class="flex-1 w-full resize-none bg-[#0f1419] text-[#d7dce2] font-mono text-xs p-3 outline-none"></textarea>
        {/if}
      </div>
    </div>
  {/if}

  <input type="file" bind:this={fileInput} onchange={onFilePicked} class="hidden" />
  <input type="file" bind:this={filesUploadInput} onchange={uploadHere} class="hidden" />
</div>
