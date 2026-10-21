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
  const readonly = $derived(!!shareGrant) // a share-link console is view-only for its whole life
  let searchVisible = $state(false)
  let searchQuery = $state('')
  let splitView = $state(false) // false = one session shown (tabs); true = all sessions in a grid

  // --- File browser (slide-in panel over the active session) ---
  let filesVisible = $state(startFiles)
  let filesCwd = $state('/root')
  let filesList = $state([])
  let filesLoading = $state(false)
  let fileSel = $state(new Set()) // selected file names in the current directory (multi-select)
  let fileFilter = $state('')
  let showHidden = $state(false)
  const filesShown = $derived(filesList.filter((it) =>
    (showHidden || !it.name.startsWith('.')) &&
    (!fileFilter || it.name.toLowerCase().includes(fileFilter.toLowerCase()))))
  // Inline editor (textarea); opened from the browser, saved back via putFile.
  let editPath = $state(null)
  let editContent = $state('')
  let editLoading = $state(false)
  const editPending = new Set() // paths fetched for EDITING (vs downloading) — routes file-chunk

  // One grant per machine, reused across that machine's tabs/reconnects until the server rejects it.
  const grants = new Map()
  if (shareGrant && shareMachine) grants.set(shareMachine.id, shareGrant)
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
  // Per-session accent colour (stable hash of the id), mirrored on the tab + split pane like WebTerm,
  // so each session is recognisable at a glance across tabs and the grid.
  function sessionColor(id) {
    let h = 0
    for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0
    return `hsl(${h % 360} 68% 60%)`
  }

  // A small in-console text-input modal (replaces window.prompt), reusable for rename / new file etc.
  let promptState = $state(null) // { title, value, placeholder, onok }
  function openPrompt(opts) { promptState = { value: '', placeholder: '', ...opts } }
  function submitPrompt() {
    const cb = promptState?.onok
    const v = promptState?.value ?? ''
    promptState = null
    cb?.(v)
  }
  const autofocus = (node) => { node.focus(); node.select?.() }

  function startRename(tab) {
    openPrompt({
      title: 'Rename session',
      value: tabTitle(tab),
      placeholder: 'Session name',
      onok: (name) => { tab.name = (name || '').trim() || null; tabs = [...tabs] },
    })
  }
  function toggleMaximize(tab) { maximizedId = maximizedId === tab.id ? null : tab.id; activate(tab.id); fitAll() }

  // --- session toolbar model: defined once, rendered full (wide single view) or compact (split panes,
  // narrow/mobile screens) where the `more` items fold into a "…" menu, like WebTerm. ---
  let innerWidth = $state(typeof window !== 'undefined' ? window.innerWidth : 1280)
  const compactBar = $derived(innerWidth < 1024)
  let overflowFor = $state(null) // tab id whose "…" menu is open
  let rootEl
  // Run a toolbar action against a specific tab: focus it first, so actions that read the active
  // session (files, tools, paste…) target the pane whose toolbar was clicked.
  function act(tab, fn) {
    if (activeId !== tab.id) activate(tab.id)
    overflowFor = null
    fn()
  }
  // --- mobile key bar (touch devices): keys phone keyboards lack. Ctrl/Alt are sticky modifiers
  // applied to the NEXT keystroke, whether it comes from the bar or the on-screen keyboard. ---
  const isTouch = typeof window !== 'undefined' && !!window.matchMedia?.('(pointer: coarse)').matches
  let ctrlArmed = $state(false)
  let altArmed = $state(false)
  function applyMods(d) {
    if (!ctrlArmed && !altArmed) return d
    let out = d
    if (ctrlArmed && d.length === 1) {
      const c = d.toUpperCase().charCodeAt(0)
      if (c >= 64 && c <= 95) out = String.fromCharCode(c - 64) // Ctrl+A..Z, @ [ \ ] ^ _
      else if (d === ' ') out = '\x00'
    }
    if (altArmed) out = '\x1b' + out
    ctrlArmed = altArmed = false
    return out
  }
  function sendKey(seq) {
    activeSocket()?.sendInput(applyMods(seq))
    activeTab?.term?.focus()
  }
  const keyRows = [
    [{ l: 'Ctrl', mod: 'ctrl' }, { l: 'Alt', mod: 'alt' }, { l: 'Esc', s: '\x1b' }, { l: 'Tab', s: '\t' },
      { l: '↑', s: '\x1b[A' }, { l: '↓', s: '\x1b[B' }, { l: '←', s: '\x1b[D' }, { l: '→', s: '\x1b[C' }],
    [{ l: '⌨', kbd: true }, { l: '^C', s: '\x03' }, { l: '^D', s: '\x04' }, { l: 'PgUp', s: '\x1b[5~' },
      { l: 'PgDn', s: '\x1b[6~' }, { l: '|', s: '|' }, { l: '/', s: '/' }, { l: '-', s: '-' }],
  ]
  function pressKey(k) {
    if (k.mod === 'ctrl') ctrlArmed = !ctrlArmed
    else if (k.mod === 'alt') altArmed = !altArmed
    else if (k.kbd) { const t = activeTab?.term; if (document.activeElement?.closest?.('.xterm')) t?.blur(); else t?.focus() }
    else sendKey(k.s)
  }

  function copySelection(tab) {
    const sel = tab.term?.getSelection() || ''
    if (!sel) return toast('Select text in the terminal first', 'info')
    navigator.clipboard?.writeText(sel).then(() => toast('Copied', 'success')).catch(() => {})
  }
  function toggleFullscreen() {
    if (document.fullscreenElement) document.exitFullscreen?.()
    else rootEl?.requestFullscreen?.().catch(() => {})
    fitAll()
  }
  function toolItems(tab) {
    const mine = activeId === tab.id
    return [
      { icon: 'search', title: 'Search scrollback', on: searchVisible && mine, fn: () => (searchVisible = !searchVisible) },
      { icon: 'file', title: 'Files', on: filesVisible && mine, fn: toggleFiles },
      { icon: 'git-branch', title: 'Git status', on: tool === 'git' && mine, fn: () => openTool('git') },
      { icon: 'arrows-exchange', title: 'Port forwards', on: tool === 'forwards' && mine, fn: () => openTool('forwards') },
      { icon: 'brand-docker', title: 'Docker', on: tool === 'docker' && mine, fn: () => openTool('docker') },
      { icon: 'terminal-2', title: 'Snippets', on: tool === 'snippets' && mine, fn: () => openTool('snippets') },
      { icon: 'clipboard', title: 'Paste clipboard', fn: () => pasteInto(tab) },
      { icon: 'stethoscope', title: 'Diagnostics', on: tool === 'diag' && mine, more: true, fn: () => openTool('diag') },
      { icon: termLight ? 'moon' : 'sun', title: 'Terminal theme', more: true, fn: toggleTheme },
      { icon: 'copy', title: 'Copy selection', more: true, fn: () => copySelection(tab) },
      { icon: 'pencil', title: 'Rename session', more: true, fn: () => startRename(tab) },
      { text: 'A−', title: 'Smaller text', more: true, fn: () => setFont(-1) },
      { text: 'A+', title: 'Larger text', more: true, fn: () => setFont(1) },
      { icon: 'share', title: 'Share read-only link', more: true, fn: share },
      { icon: 'arrows-maximize', title: 'Fullscreen', more: true, fn: toggleFullscreen },
    ]
  }
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
      const tab = { id: session, machine, label, name: null, startedAt: Date.now(), latency: null, cwd: '', commands: [], pinger: null, el: null, term: null, fit: null, search: null, socket: null, exited: false }
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
  // Return openTab's promise so the parent can wait for the tab to exist (e.g. before openPanel).
  export function openNew(machine) { return openTab(machine) }
  export function openSession(s) { return openTab({ id: s.machine_id, name: s.machine_name }, s.id, s.label) }
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
    // A pane added in split view mounts into a grid cell that isn't sized yet, so the first fit
    // measures wrong (blank/garbled until a refresh). Refit on the next frame once layout settles.
    requestAnimationFrame(() => { try { fit.fit() } catch { /* detached */ } })

    const socket = new ConsoleSocket({
      machine: tab.machine.id, grant: g, session: tab.id, cols: term.cols, rows: term.rows,
      onOpen: () => {
        if (!readonly) term.focus()
        if (tab.id === activeId) { if (filesVisible) listFiles(filesCwd); else if (tool) loadTool(tool) }
        socket.ping() // first latency/cwd probe, then keep it fresh
        clearInterval(tab.pinger)
        tab.pinger = setInterval(() => socket.ping(), 5000)
      },
      onData: (bytes) => term.write(bytes),
      onExit: () => { tab.exited = true; clearInterval(tab.pinger); term.write('\r\n\x1b[90m[session ended]\x1b[0m\r\n'); tabs = [...tabs] },
      onError: (m) => { error = m; if (/grant/i.test(m)) grants.delete(tab.machine.id) },
      onClose: () => { if (!tab.exited) term.write('\r\n\x1b[90m[disconnected]\x1b[0m\r\n') },
      onPong: (latency, cwd) => { tab.latency = latency; tab.cwd = cwd; tabs = [...tabs] },
      onGit: (text) => { if (tab.id === activeId) { gitText = text; gitLoading = false } },
      onDocker: (action, data) => { if (tab.id === activeId) handleDocker(action, data) },
      onDiag: (_action, text) => { if (tab.id === activeId) { diagOut = text || '(no output)'; diagBusy = false } },
      onCommand: (c) => { tab.commands = [c, ...tab.commands].slice(0, 100); tabs = [...tabs] },
      onFileChunk: (path, parts, msg) => handleFileChunk(path, parts, msg),
      onFileList: (path, items) => handleFileList(tab.id, path, items),
    })
    socket.connect()
    tab.socket = socket
    if (!readonly) term.onData((d) => socket.sendInput(applyMods(d)))
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
  $effect(() => { splitView; tabs.length; filesVisible; tool; maximizedId; fitAll() })

  // --- toolbar actions ---
  function runSearch(dir) {
    const tab = tabs.find((t) => t.id === activeId)
    if (!tab?.search || !searchQuery) return
    dir === 'prev' ? tab.search.findPrevious(searchQuery) : tab.search.findNext(searchQuery)
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
    tool = null // one panel at a time
    filesVisible = true
    listFiles(filesCwd)
  }
  function toggleFiles() { if (filesVisible) filesVisible = false; else openFiles() }
  // Agent reply for a listing (only the active session's).
  function handleFileList(session, path, items) {
    if (session !== activeId) return
    if (path !== filesCwd) fileSel = new Set() // leaving a directory drops its selection
    filesCwd = path
    filesList = items
    filesLoading = false
  }

  // --- file multi-select (download / delete / new folder) ---
  function toggleSel(name) { const s = new Set(fileSel); s.has(name) ? s.delete(name) : s.add(name); fileSel = s }
  function clearSel() { fileSel = new Set() }
  function toggleSelAll() {
    const names = filesShown.filter((it) => !it.dir).map((it) => it.name)
    fileSel = (names.length && names.every((n) => fileSel.has(n))) ? new Set() : new Set(names)
  }
  function downloadSelected() {
    const s = activeSocket()
    if (!s) return
    for (const n of fileSel) s.getFile(joinPath(filesCwd, n))
    clearSel()
  }
  async function deleteSelected() {
    const names = [...fileSel]
    if (!names.length) return
    const ok = await confirm({ title: 'Delete files', message: `Delete ${names.length} item(s) from ${filesCwd}? This cannot be undone.`, variant: 'destructive', confirmText: 'Delete' })
    if (!ok) return
    const s = activeSocket()
    if (!s) return
    for (const n of names) s.deleteFile(joinPath(filesCwd, n)) // agent replies with a fresh listing
    clearSel()
  }
  function newFolder() {
    openPrompt({ title: 'New folder name', placeholder: 'folder', onok: (name) => {
      const n = (name || '').trim()
      if (n) activeSocket()?.mkdir(joinPath(filesCwd, n))
    } })
  }
  // Route a finished file transfer. The agent ends an UPLOAD (or an editor save) with the same EOF
  // frame type as a download, tagged "upload complete" — that must update the upload queue, never
  // trigger a browser download. Otherwise: into the editor if requested for editing, else download.
  function handleFileChunk(path, parts, msg) {
    if (msg === 'upload complete') { onUploadDone(path); return }
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
    await s.putFile(editPath, new Blob([editContent])) // "Saved …" toast arrives on the agent's confirm
    editPath = null
  }
  // --- upload queue (file picker or drag-and-drop; sequential, per-file status) ---
  const MAX_UPLOAD = 64 * 1024 * 1024 // mirrors the agent's per-file cap, so we refuse up front
  let uploads = $state([]) // [{ path, name, status: 'sending' | 'done' | 'error', note }]
  let dropActive = $state(false)
  // Upload under the basename only — a crafted name with path parts must not escape the cwd.
  const safeName = (n) => (n.split(/[\\/]/).pop() || 'upload').replace(/\.{2,}/g, '.')
  async function uploadFiles(list) {
    const s = activeSocket()
    if (!s || !list?.length) return
    for (const file of list) {
      const name = safeName(file.name)
      const item = { path: joinPath(filesCwd, name), name, status: 'sending', note: '' }
      if (file.size > MAX_UPLOAD) { item.status = 'error'; item.note = 'over 64 MB' }
      uploads = [...uploads, item]
      if (item.status === 'error') continue
      try { await s.putFile(item.path, file) } catch { item.status = 'error'; item.note = 'failed'; uploads = [...uploads] }
    }
  }
  function onUploadDone(path) {
    const item = uploads.find((u) => u.path === path && u.status === 'sending')
    if (item) {
      item.status = 'done'
      uploads = [...uploads]
      setTimeout(() => { uploads = uploads.filter((u) => u !== item) }, 3000) // fade finished rows
      listFiles(filesCwd) // show the new file
    } else {
      toast('Saved ' + path.split('/').pop(), 'success') // an editor save
    }
  }
  function uploadHere(e) {
    const files = [...(e.target.files || [])]
    e.target.value = ''
    uploadFiles(files)
  }
  function onDrop(e) {
    e.preventDefault()
    dropActive = false
    uploadFiles([...(e.dataTransfer?.files || [])])
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

  // --- tool panels (snippets / git / docker), one open at a time, acting on the active session ---
  let tool = $state(null) // 'snippets' | 'git' | 'docker' | null
  let gitText = $state('')
  let gitLoading = $state(false)
  let dockerList = $state([])
  let dockerLoading = $state(false)
  let dockerLog = $state(null) // { name, text } when viewing one container's logs

  function loadSnippets() {
    try {
      const s = JSON.parse(localStorage.getItem('console_snippets') || 'null')
      if (Array.isArray(s)) return s
    } catch { /* noop */ }
    return [
      { name: 'List files', command: 'ls -la' },
      { name: 'Disk usage', command: 'df -h' },
      { name: 'Top processes', command: 'top -b -n1 | head -20' },
    ]
  }
  let snippets = $state(loadSnippets())
  function saveSnippets() { try { localStorage.setItem('console_snippets', JSON.stringify(snippets)) } catch { /* noop */ } }
  function runSnippet(sn) { activeSocket()?.sendInput(sn.command + '\n') }
  function addSnippet() {
    openPrompt({ title: 'New snippet — command to run', placeholder: 'e.g. docker ps', onok: (command) => {
      if (!command.trim()) return
      openPrompt({ title: 'Name this snippet', value: command.slice(0, 28), onok: (name) => {
        snippets = [...snippets, { name: name.trim() || command, command }]
        saveSnippets()
      } })
    } })
  }
  function delSnippet(i) { snippets = snippets.filter((_, x) => x !== i); saveSnippets() }

  let forwards = $state([]) // [{id, url, host, port}] — reach a web service on the machine via the agent
  async function addForward() {
    openPrompt({ title: 'Forward to host:port (as the machine sees it)', placeholder: 'localhost:8080', onok: async (v) => {
      const t = (v || '').trim()
      if (!t) return
      const i = t.lastIndexOf(':')
      const host = i > 0 ? t.slice(0, i) : 'localhost'
      const port = parseInt(i > 0 ? t.slice(i + 1) : t, 10)
      if (!port || port < 1 || port > 65535) { toast('Enter a valid port', 'error'); return }
      try {
        const res = await apiPost('/api/fleet/console/forward', { machine_id: activeTab.machine.id, host, port })
        forwards = [...forwards, { id: res.id, url: res.url, host, port }]
      } catch (e) {
        toast(e.message || 'could not open forward', 'error')
      }
    } })
  }

  // Panel header icon + title per tool (same icons as the toolbar).
  const toolMeta = {
    snippets: { icon: 'terminal-2', title: 'Snippets' },
    git: { icon: 'git-branch', title: 'Git status' },
    docker: { icon: 'brand-docker', title: 'Docker' },
    forwards: { icon: 'arrows-exchange', title: 'Port forwards' },
    commands: { icon: 'list-details', title: 'Commands' },
    diag: { icon: 'stethoscope', title: 'Diagnostics' },
  }

  // Diagnostics: one reachability check at a time from the host (ping / traceroute / dns).
  let diagTarget = $state('')
  let diagOut = $state('')
  let diagBusy = $state(false)
  function runDiag(action) {
    const t = diagTarget.trim()
    if (!t) return toast('Enter a hostname or IP', 'error')
    const s = activeSocket()
    if (!s) return
    diagBusy = true
    diagOut = `Running ${action} ${t}…`
    s.diag(action, t)
  }

  // loadTool fetches a panel's data; shared by a toolbar click, a machine-page deep link, and the
  // socket's onOpen (a panel requested before the session connected loads once it does).
  function loadTool(t) {
    if (t === 'git') refreshGit()
    if (t === 'docker') { dockerLog = null; dockerPs() }
  }
  function openTool(t) {
    tool = tool === t ? null : t
    if (tool) filesVisible = false
    loadTool(tool)
    fitAll()
  }
  // Driven by the parent: open a panel on arrival (machine page → "Open Docker" etc.). Safe to call
  // before the session connects — the state is set now and the data loads in onOpen.
  export function openPanel(name) {
    if (name === 'files') { tool = null; filesVisible = true; if (activeSocket()?.isOpen) listFiles(filesCwd) }
    else { filesVisible = false; tool = name; if (activeSocket()?.isOpen) loadTool(name) }
  }
  function refreshGit() { const s = activeSocket(); if (!s) return; gitLoading = true; s.gitStatus() }
  function dockerPs() { const s = activeSocket(); if (!s) return; dockerLoading = true; s.docker('ps') }
  function dockerDo(c, action) { activeSocket()?.docker(action, c.id) }
  function dockerLogs(c) { dockerLog = { name: c.name, text: 'Loading…' }; activeSocket()?.docker('logs', c.id) }
  function parsePs(data) {
    return data.split('\n').filter(Boolean).map((l) => {
      const [id, name, image, state, status] = l.split('|')
      return { id, name, image, state, status }
    })
  }
  function handleDocker(action, data) {
    if (action === 'ps') { dockerList = parsePs(data); dockerLoading = false }
    else if (action === 'logs') { dockerLog = { ...(dockerLog || {}), text: data || '(no output)' } }
    else { dockerPs() } // start/stop/restart → refresh the list
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

<svelte:window on:resize={onResize} bind:innerWidth />

<!-- Live indicator (WebTerm's ring, first toolbar icon): colour = latency health, spins while connecting. -->
{#snippet activity(tab)}
  {@const c = tab.exited ? 'rgba(255,255,255,0.25)' : tab.latency == null ? '#8b949e' : tab.latency < 100 ? '#3fb950' : tab.latency < 300 ? '#d29922' : '#f85149'}
  <span class="p-1.5 shrink-0" title={tab.exited ? 'Session ended' : tab.latency == null ? 'Connecting…' : `Live · ${tab.latency} ms`}>
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none" class={!tab.exited && tab.latency == null ? 'animate-spin' : ''}>
      <circle cx="8" cy="8" r="6" stroke={c} stroke-opacity="0.3" stroke-width="2" />
      <path d="M8 2a6 6 0 0 1 6 6" stroke={c} stroke-width="2" stroke-linecap="round" />
    </svg>
  </span>
{/snippet}

<!-- Session toolbar (one definition). Full in wide single view; compact in split panes and on narrow
     screens, where the `more` items fold into a "…" menu. Every action targets THIS tab (see act). -->
{#snippet toolbar(tab, compact)}
  {@const items = toolItems(tab)}
  <div class="relative flex items-center gap-1 px-2 py-1 border-b border-white/10 bg-[#0f1419] shrink-0 min-w-0">
    <span class="flex items-center gap-1.5 px-2 py-0.5 rounded bg-white/5 min-w-0">
      <span class="w-1.5 h-1.5 rounded-full shrink-0" style:background-color={sessionColor(tab.id)}></span>
      <span class="text-white/80 font-mono text-[11px] truncate">root@{tab.machine.name || tab.machine.id}</span>
    </span>
    {#if !compact}
      <button onclick={() => act(tab, () => startRename(tab))} title="Rename session" class="text-sm text-white/80 px-1 shrink-0 hover:text-white truncate max-w-[160px]">{tabTitle(tab)}</button>
    {/if}
    <div class="ml-auto flex items-center gap-0.5 shrink-0">
      {@render activity(tab)}
      <button onclick={() => act(tab, () => openTool('commands'))} title="Command history"
        class="px-1.5 py-1 rounded text-[11px] font-mono hover:bg-white/5 {tool === 'commands' && activeId === tab.id ? 'bg-[#58a6ff]/15 text-[#58a6ff]' : 'text-white/60'}">&gt;{tab.commands.length || ''}</button>
      {#each items.filter((it) => !compact || !it.more) as it (it.title)}
        <button onclick={() => act(tab, it.fn)} title={it.title} class="p-1.5 rounded hover:bg-white/5 {it.on ? 'text-[#58a6ff]' : 'text-white/60'}">
          {#if it.text}<span class="text-[11px] font-medium px-0.5">{it.text}</span>{:else}<Icon name={it.icon} size={14} />{/if}
        </button>
      {/each}
      {#if compact}
        <button onclick={() => (overflowFor = overflowFor === tab.id ? null : tab.id)} title="More" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="dots" size={14} /></button>
        {#if overflowFor === tab.id}
          <div class="absolute right-2 top-full mt-1 z-50 w-48 bg-[#1a1f29] border border-white/10 rounded-lg shadow-xl py-1">
            {#each items.filter((it) => it.more) as it (it.title)}
              <button onclick={() => act(tab, it.fn)} class="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-white/70 hover:bg-white/5 text-left">
                {#if it.text}<span class="w-[14px] text-center text-[11px]">{it.text}</span>{:else}<Icon name={it.icon} size={14} />{/if}{it.title}
              </button>
            {/each}
          </div>
        {/if}
      {/if}
      {#if tab.machine.console_record}<span class="flex items-center gap-1 text-[10px] text-red-300 px-1.5" title="This session is being recorded"><span class="w-1.5 h-1.5 rounded-full bg-red-400"></span>rec</span>{/if}
    </div>
  </div>
{/snippet}

<!-- Per-session bottom status bar (reused in single + split): live status, start, duration, clock. -->
{#snippet statusBar(tab)}
  <div class="flex flex-wrap items-center gap-x-3 gap-y-0.5 px-3 py-1 text-[10px] border-t border-white/10 bg-[#12161d] text-white/50 shrink-0">
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
<div bind:this={rootEl} class={embedded
    ? 'relative flex-1 min-w-0 flex flex-col bg-[#0f1419] text-[#d7dce2]'
    : 'fixed inset-0 lg:left-60 z-50 flex flex-col bg-[#0f1419] text-[#d7dce2]'}>
  <!-- TOP BAR: tabs on the left (can span machines); session controls on the right. -->
  <div class="flex items-center gap-2 px-2 py-1.5 border-b border-white/10 bg-[#12161d]">
    <div class="flex items-center gap-1 overflow-x-auto flex-1 min-w-0">
      {#each tabs as tab (tab.id)}
        <button onclick={() => activate(tab.id)} style:border-left-color={sessionColor(tab.id)}
          class="group flex items-center gap-1.5 pl-2 pr-1.5 py-1 rounded border-l-2 whitespace-nowrap shrink-0 {activeId === tab.id ? 'bg-white/10' : 'hover:bg-white/5'}">
          <span class="w-1.5 h-1.5 rounded-full {tab.exited ? 'opacity-40' : ''}" style:background-color={sessionColor(tab.id)}></span>
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
  {#if newMenuOpen || allMenuOpen || overflowFor}
    <button aria-label="Close menu" class="fixed inset-0 z-40 cursor-default" onclick={() => { newMenuOpen = false; allMenuOpen = false; overflowFor = null }}></button>
  {/if}

  <!-- SESSION TOOLBAR — single view only; in split view every pane renders its own (below). -->
  {#if activeTab && !readonly && !splitView}
    {@render toolbar(activeTab, compactBar)}
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

  <!-- Body: terminal area + optional file/tool panel. On desktop the panel docks on the right (lg:static);
       on mobile it becomes a full overlay INSIDE this container (absolute) so it never squishes the terminal. -->
  <div class="flex-1 min-h-0 flex relative">
  <!-- Terminal panes. Single view shows the active pane full; split lays them in a grid, each with
       its own header + bottom status bar. Mount nodes (wt-<id>) stay stable so xterm isn't recreated. -->
  <div class="flex-1 min-h-0 relative overflow-hidden {inSplit ? 'grid gap-1 p-1' : ''}"
    style={inSplit ? `grid-template-columns: repeat(${splitCols}, minmax(0,1fr)); grid-auto-rows: minmax(0,1fr)` : ''}>
    {#each tabs as tab (tab.id)}
      {@const shown = maximizedId ? maximizedId === tab.id : splitView || activeId === tab.id}
      <div onclick={() => activate(tab.id)}
        style:border-color={inSplit ? (activeId === tab.id ? sessionColor(tab.id) : 'rgba(255,255,255,0.1)') : undefined}
        class="flex flex-col min-h-0 {inSplit ? 'rounded border-2' : 'absolute inset-0'}"
        style:display={shown ? 'flex' : 'none'}>
        {#if inSplit || maximizedId === tab.id}
          <div class="flex items-center gap-2 px-2 py-1 text-[11px] border-b border-white/10 bg-[#12161d] shrink-0" style:border-left={'3px solid ' + sessionColor(tab.id)}>
            <Icon name="grip-vertical" size={12} style="color:{sessionColor(tab.id)}" />
            <span class="text-white/70 truncate">{tabTitle(tab)}</span>
            <span class="text-white/40 truncate">· {tab.machine.name || tab.machine.id}</span>
            <div class="ml-auto flex items-center gap-1.5">
              <button onclick={(e) => { e.stopPropagation(); toggleMaximize(tab) }} title={maximizedId ? 'Restore' : 'Maximize'} class="text-white/50 hover:text-white"><Icon name={maximizedId ? 'arrows-minimize' : 'arrows-maximize'} size={12} /></button>
              {#if !readonly}<button onclick={(e) => { e.stopPropagation(); killTab(tab) }} title="Close session" class="text-white/50 hover:text-red-300"><Icon name="x" size={12} /></button>{/if}
            </div>
          </div>
          <!-- Each split pane carries its own full toolbar (compact, tail in "…"), like WebTerm. -->
          {#if !readonly}{@render toolbar(tab, true)}{/if}
        {/if}
        <!-- overflow-hidden lives here (not on the pane) so the toolbar's "…" menu isn't clipped. -->
        <div id={'wt-' + tab.id} bind:this={tab.el} class="flex-1 min-h-0 p-1.5 overflow-hidden"></div>
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
    <aside class="absolute inset-y-0 right-0 z-30 w-full sm:w-96 lg:relative lg:w-80 shrink-0 border-l border-white/10 bg-[#12161d] flex flex-col"
      ondragover={(e) => { e.preventDefault(); dropActive = true }} ondragleave={(e) => { if (!e.currentTarget.contains(e.relatedTarget)) dropActive = false }} ondrop={onDrop}>
      {#if dropActive}
        <div class="absolute inset-0 z-10 m-2 rounded-lg border-2 border-dashed border-[#58a6ff] bg-[#58a6ff]/10 grid place-items-center pointer-events-none">
          <span class="text-sm text-[#58a6ff]">Drop to upload to {filesCwd}</span>
        </div>
      {/if}
      <div class="flex items-center gap-2 px-3 py-2 border-b border-white/10">
        <Icon name="folder" size={14} class="text-[#58a6ff]" />
        <span class="font-medium text-sm">Files</span>
        <button onclick={() => listFiles(filesCwd)} title="Refresh" class="ml-auto p-1 text-white/60 hover:text-white"><Icon name="refresh" size={13} /></button>
        <button onclick={() => (filesVisible = false)} title="Close" class="p-1 text-white/60 hover:text-white"><Icon name="x" size={14} /></button>
      </div>
      <div class="flex items-center gap-1 px-2 py-1.5 border-b border-white/10">
        <button onclick={upDir} title="Up a directory" class="p-1 text-white/60 hover:text-white"><Icon name="arrow-up" size={13} /></button>
        <span class="font-mono text-[11px] text-white/70 truncate flex-1" title={filesCwd}>{filesCwd}</span>
        <button onclick={newFolder} title="New folder" class="p-1 text-white/60 hover:text-white"><Icon name="folder-plus" size={14} /></button>
        <button onclick={() => filesUploadInput?.click()} title="Upload files here (or drag & drop onto this panel)" class="p-1 text-white/60 hover:text-white"><Icon name="upload" size={13} /></button>
        <button onclick={() => (showHidden = !showHidden)} title="Show hidden files" class="px-1 text-[11px] font-mono {showHidden ? 'text-[#58a6ff]' : 'text-white/50 hover:text-white'}">.*</button>
      </div>
      <div class="px-2 py-1.5 border-b border-white/10">
        <input bind:value={fileFilter} placeholder="filter…"
          class="w-full bg-black/30 border border-white/10 rounded px-2 py-1 text-[11px] text-white outline-none focus:border-[#58a6ff]" />
      </div>
      <div class="flex-1 overflow-y-auto">
        {#if filesLoading}
          <div class="p-3 text-xs text-white/40">Loading…</div>
        {:else if filesShown.length}
          <!-- select-all (files only) -->
          <label class="flex items-center gap-2 px-3 py-1 text-[10px] uppercase tracking-wide text-white/40 border-b border-white/5 cursor-pointer">
            <input type="checkbox" class="accent-[#58a6ff]"
              checked={filesShown.some((it) => !it.dir) && filesShown.filter((it) => !it.dir).every((it) => fileSel.has(it.name))}
              onchange={toggleSelAll} />
            name
          </label>
          {#each filesShown as it (it.name)}
            <div class="group flex items-center gap-2 px-3 py-1.5 hover:bg-white/5 text-xs {fileSel.has(it.name) ? 'bg-[#58a6ff]/10' : ''}">
              {#if it.dir}
                <span class="w-[13px] shrink-0"></span>
                <Icon name="folder" size={14} class="text-[#58a6ff] shrink-0" />
                <button onclick={() => enterDir(it.name)} class="flex-1 text-left truncate hover:text-white">{it.name}/</button>
              {:else}
                <input type="checkbox" class="accent-[#58a6ff] shrink-0" checked={fileSel.has(it.name)} onchange={() => toggleSel(it.name)} />
                <Icon name="file" size={14} class="text-white/50 shrink-0" />
                <button onclick={() => toggleSel(it.name)} class="flex-1 truncate text-left" title={it.name}>{it.name}</button>
                <span class="text-white/30 tabular-nums shrink-0">{fmtSize(it.size)}</span>
                <button onclick={() => editFromBrowser(it.name)} title="Edit" class="opacity-0 group-hover:opacity-100 p-0.5 text-white/60 hover:text-white shrink-0"><Icon name="pencil" size={12} /></button>
                <button onclick={() => downloadFromBrowser(it.name)} title="Download" class="opacity-0 group-hover:opacity-100 p-0.5 text-white/60 hover:text-white shrink-0"><Icon name="download" size={12} /></button>
              {/if}
            </div>
          {/each}
        {:else}
          <div class="p-3 text-xs text-white/40">{fileFilter ? 'No match.' : 'Empty directory.'}</div>
        {/if}
      </div>
      {#if uploads.length}
        <div class="border-t border-white/10 max-h-32 overflow-y-auto">
          {#each uploads as u (u.path + u.status)}
            <div class="flex items-center gap-2 px-3 py-1 text-[11px]">
              <Icon name={u.status === 'done' ? 'check' : u.status === 'error' ? 'alert-circle' : 'upload'} size={12}
                class="shrink-0 {u.status === 'done' ? 'text-green-400' : u.status === 'error' ? 'text-red-300' : 'text-[#58a6ff] animate-pulse'}" />
              <span class="truncate flex-1 text-white/70" title={u.path}>{u.name}</span>
              <span class="shrink-0 {u.status === 'error' ? 'text-red-300' : 'text-white/40'}">{u.status === 'sending' ? 'uploading…' : u.status === 'done' ? 'done' : u.note}</span>
            </div>
          {/each}
        </div>
      {/if}
      {#if fileSel.size}
        <div class="flex items-center gap-3 px-3 py-2 border-t border-white/10 bg-[#0f1419] text-xs">
          <span class="text-white/50">{fileSel.size} selected</span>
          <button onclick={downloadSelected} class="flex items-center gap-1 text-white/70 hover:text-white"><Icon name="download" size={13} />Download</button>
          <button onclick={deleteSelected} class="flex items-center gap-1 text-red-300 hover:text-red-200"><Icon name="trash" size={13} />Delete</button>
          <button onclick={clearSel} class="ml-auto text-white/50 hover:text-white">Clear</button>
        </div>
      {/if}
    </aside>
  {/if}

  <!-- Tool panel: snippets / git / docker (one at a time). Same responsive dock/overlay as Files. -->
  {#if tool}
    <aside class="absolute inset-y-0 right-0 z-30 w-full sm:w-96 lg:relative lg:w-80 shrink-0 border-l border-white/10 bg-[#12161d] flex flex-col">
      <div class="flex items-center gap-2 px-3 py-2 border-b border-white/10">
        <Icon name={toolMeta[tool]?.icon} size={14} class="text-[#58a6ff]" />
        <span class="font-medium text-sm">{toolMeta[tool]?.title}</span>
        {#if tool === 'git'}<button onclick={refreshGit} title="Refresh" class="ml-auto p-1 text-white/60 hover:text-white"><Icon name="refresh" size={13} /></button>{/if}
        {#if tool === 'docker'}<button onclick={() => { dockerLog = null; dockerPs() }} title="Refresh" class="ml-auto p-1 text-white/60 hover:text-white"><Icon name="refresh" size={13} /></button>{/if}
        {#if tool === 'snippets'}<button onclick={addSnippet} title="Add snippet" class="ml-auto p-1 text-white/60 hover:text-white"><Icon name="plus" size={14} /></button>{/if}
        {#if tool === 'forwards'}<button onclick={addForward} title="New forward" class="ml-auto p-1 text-white/60 hover:text-white"><Icon name="plus" size={14} /></button>{/if}
        <button onclick={() => (tool = null)} title="Close" class="p-1 text-white/60 hover:text-white"><Icon name="x" size={14} /></button>
      </div>
      <div class="flex-1 overflow-y-auto">
        {#if tool === 'snippets'}
          {#each snippets as sn, i (i)}
            <div class="group flex items-center gap-2 px-3 py-1.5 hover:bg-white/5 text-xs">
              <button onclick={() => runSnippet(sn)} class="min-w-0 flex-1 text-left">
                <div class="text-white/80 truncate">{sn.name}</div>
                <div class="text-white/40 font-mono text-[10px] truncate">{sn.command}</div>
              </button>
              <button onclick={() => runSnippet(sn)} title="Run" class="opacity-0 group-hover:opacity-100 p-0.5 text-[#58a6ff]"><Icon name="player-play" size={13} /></button>
              <button onclick={() => delSnippet(i)} title="Delete" class="opacity-0 group-hover:opacity-100 p-0.5 text-white/50 hover:text-red-300"><Icon name="trash" size={12} /></button>
            </div>
          {/each}
          {#if !snippets.length}<div class="p-3 text-xs text-white/40">No snippets. Add one with +.</div>{/if}
        {:else if tool === 'git'}
          {#if gitLoading}<div class="p-3 text-xs text-white/40">Loading…</div>
          {:else}<pre class="p-3 text-[11px] text-[#d7dce2] font-mono whitespace-pre-wrap break-all">{gitText}</pre>{/if}
        {:else if tool === 'docker'}
          {#if dockerLog}
            <div class="flex items-center gap-2 px-3 py-1.5 border-b border-white/10 text-xs">
              <button onclick={() => (dockerLog = null)} class="text-white/60 hover:text-white"><Icon name="chevron-up" size={13} /></button>
              <span class="truncate font-mono text-white/70">{dockerLog.name}</span>
            </div>
            <pre class="p-3 text-[10px] text-[#d7dce2] font-mono whitespace-pre-wrap break-all">{dockerLog.text}</pre>
          {:else if dockerLoading}
            <div class="p-3 text-xs text-white/40">Loading…</div>
          {:else if dockerList.length}
            {#each dockerList as c (c.id)}
              <div class="px-3 py-2 border-b border-white/5 text-xs">
                <div class="flex items-center gap-2">
                  <span class="w-1.5 h-1.5 rounded-full shrink-0 {c.state === 'running' ? 'bg-green-400' : 'bg-white/30'}"></span>
                  <span class="truncate font-medium text-white/80 flex-1" title={c.image}>{c.name}</span>
                </div>
                <div class="text-white/40 text-[10px] truncate mt-0.5">{c.status}</div>
                <div class="flex items-center gap-1 mt-1.5">
                  <button onclick={() => dockerLogs(c)} class="px-1.5 py-0.5 rounded bg-white/5 text-white/70 hover:bg-white/10">logs</button>
                  {#if c.state === 'running'}
                    <button onclick={() => dockerDo(c, 'restart')} class="px-1.5 py-0.5 rounded bg-white/5 text-white/70 hover:bg-white/10">restart</button>
                    <button onclick={() => dockerDo(c, 'stop')} class="px-1.5 py-0.5 rounded bg-white/5 text-amber-300 hover:bg-white/10">stop</button>
                  {:else}
                    <button onclick={() => dockerDo(c, 'start')} class="px-1.5 py-0.5 rounded bg-white/5 text-green-300 hover:bg-white/10">start</button>
                  {/if}
                </div>
              </div>
            {/each}
          {:else}
            <div class="p-3 text-xs text-white/40">No containers.</div>
          {/if}
        {:else if tool === 'forwards'}
          {#if forwards.length}
            {#each forwards as f (f.id)}
              <div class="flex items-center gap-2 px-3 py-2 border-b border-white/5 text-xs">
                <Icon name="arrows-exchange" size={13} class="text-[#58a6ff] shrink-0" />
                <span class="font-mono text-white/80 truncate flex-1">{f.host}:{f.port}</span>
                <a href={f.url} target="_blank" rel="noopener noreferrer" class="text-[#58a6ff] hover:underline shrink-0">open ↗</a>
              </div>
            {/each}
          {:else}
            <div class="p-3 text-xs text-white/40 leading-relaxed">No forwards. Add one with + to reach a web service the machine can see (e.g. <span class="font-mono">localhost:8080</span>) in your browser.</div>
          {/if}
        {:else if tool === 'diag'}
          <div class="p-3 space-y-2">
            <input bind:value={diagTarget} placeholder="hostname or IP (e.g. 1.1.1.1)"
              onkeydown={(e) => e.key === 'Enter' && runDiag('ping')}
              class="w-full bg-black/30 border border-white/10 rounded px-2 py-1.5 text-xs text-white font-mono outline-none focus:border-[#58a6ff]" />
            <div class="flex gap-1.5">
              {#each [['ping', 'Ping'], ['traceroute', 'Traceroute'], ['dns', 'DNS']] as [a, l] (a)}
                <button onclick={() => runDiag(a)} disabled={diagBusy}
                  class="flex-1 px-2 py-1 rounded text-xs bg-white/5 text-white/80 hover:bg-white/10 disabled:opacity-40">{l}</button>
              {/each}
            </div>
            <p class="text-[10px] text-white/40 leading-relaxed">Runs from this host, so it shows what <em>it</em> can reach and resolve.</p>
          </div>
          {#if diagOut}<pre class="px-3 pb-3 text-[11px] text-[#d7dce2] font-mono whitespace-pre-wrap break-all">{diagOut}</pre>{/if}
        {:else if tool === 'commands'}
          {#if activeTab?.commands?.length}
            {#each activeTab.commands as c, i (i)}
              <div class="px-3 py-1.5 border-b border-white/5 text-xs">
                <div class="flex items-center gap-2">
                  <span class="w-1.5 h-1.5 rounded-full shrink-0 {c.exit === 0 ? 'bg-green-400' : 'bg-red-400'}"></span>
                  <span class="font-mono text-white/80 truncate flex-1" title={c.cmd}>{c.cmd}</span>
                  <span class="text-white/40 shrink-0 tabular-nums">{c.ms} ms</span>
                </div>
                {#if c.exit !== 0}<div class="text-red-300/70 text-[10px] pl-3.5">exit {c.exit}</div>{/if}
              </div>
            {/each}
          {:else}
            <div class="p-3 text-xs text-white/40 leading-relaxed">No commands yet. Run something — your history appears here with exit status and timing (bash sessions).</div>
          {/if}
        {/if}
      </div>
    </aside>
  {/if}
  </div>

  <!-- Mobile key bar (touch only). pointerdown is cancelled so a tap never blurs the terminal and
       dismisses the on-screen keyboard. Ctrl/Alt light up while armed for the next key. -->
  {#if isTouch && activeTab && !readonly}
    <div class="shrink-0 border-t border-white/10 bg-[#12161d] p-1.5 grid gap-1 select-none">
      {#each keyRows as row, ri (ri)}
        <div class="grid grid-cols-8 gap-1">
          {#each row as k (k.l)}
            <button onpointerdown={(e) => e.preventDefault()} onclick={() => pressKey(k)}
              class="h-9 rounded text-xs font-medium {(k.mod === 'ctrl' && ctrlArmed) || (k.mod === 'alt' && altArmed) ? 'bg-[#58a6ff] text-white' : 'bg-white/5 text-white/80 active:bg-white/15'}">{k.l}</button>
          {/each}
        </div>
      {/each}
    </div>
  {/if}

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

  <input type="file" multiple bind:this={filesUploadInput} onchange={uploadHere} class="hidden" />

  <!-- In-console text prompt (rename, new file/folder…) — a modal, not window.prompt -->
  {#if promptState}
    <button aria-label="Cancel" class="absolute inset-0 z-[60] bg-black/50 cursor-default" onclick={() => (promptState = null)}></button>
    <div class="absolute inset-0 z-[61] flex items-center justify-center p-4 pointer-events-none">
      <div class="w-full max-w-sm bg-[#1a1f29] border border-white/10 rounded-lg p-4 pointer-events-auto shadow-xl">
        <div class="text-sm font-medium text-white mb-2">{promptState.title}</div>
        <input use:autofocus bind:value={promptState.value} placeholder={promptState.placeholder}
          onkeydown={(e) => { if (e.key === 'Enter') submitPrompt(); if (e.key === 'Escape') promptState = null }}
          class="w-full bg-black/30 border border-white/10 rounded px-2 py-1.5 text-sm text-white outline-none focus:border-[#58a6ff]" />
        <div class="flex justify-end gap-2 mt-3">
          <button onclick={() => (promptState = null)} class="px-3 py-1.5 text-xs rounded text-white/60 hover:text-white">Cancel</button>
          <button onclick={submitPrompt} class="px-3 py-1.5 text-xs rounded bg-[#58a6ff] text-white hover:bg-[#4d96ef]">Save</button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  /* Native <button>s don't carry a pointer cursor; every control in the console chrome is clickable. */
  button:not(:disabled) { cursor: pointer; }
</style>
