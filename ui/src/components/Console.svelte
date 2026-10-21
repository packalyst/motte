<script>
  // Full-screen interactive console for a fleet machine. Opens one step-up-granted WebSocket per
  // tab (session), rendered with xterm.js. Supports multiple tabs, reattach to a resumable session
  // (tmux survives a disconnect), resize, copy/paste (xterm), scrollback search, file
  // upload/download, a read-only share link, and shows a recording badge.
  import { onDestroy, tick } from 'svelte'
  import { Terminal } from '@xterm/xterm'
  import { FitAddon } from '@xterm/addon-fit'
  import { SearchAddon } from '@xterm/addon-search'
  import { WebLinksAddon } from '@xterm/addon-web-links'
  import '@xterm/xterm/css/xterm.css'
  import { apiPost, stepUpConfirm, toast } from '../stores/app.js'
  import { ConsoleSocket } from '../lib/console.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'

  // shareGrant/shareSession open a read-only session from a shared link (no step-up).
  // initialSession reattaches a specific resumable session (tmux) instead of opening a fresh one.
  // startFiles opens with the file-browser panel showing.
  let { machine, onclose, shareGrant = null, shareSession = null, initialSession = null, startFiles = false } = $props()

  const termTheme = {
    background: '#0f1419', foreground: '#d7dce2', cursor: '#58a6ff',
    selectionBackground: '#2d3340', black: '#1a1f29', brightBlack: '#5c6773',
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

  let grant = shareGrant // reused across tabs/reconnects until it stops working
  let fileInput
  let filesUploadInput

  function randSession() {
    const b = new Uint8Array(16)
    crypto.getRandomValues(b) // CSPRNG, not Math.random — the id gates session access
    return 's' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
  }

  // ensureGrant mints (or reuses) a console grant. Normal grants need a step-up; the first call
  // prompts, later ones reuse the multi-use grant until the server rejects it.
  async function ensureGrant() {
    if (grant) return grant
    const r = await stepUpConfirm({
      title: 'Open console',
      description: `Re-authenticate to open an interactive console on "${machine.name || machine.id}".`,
    })
    if (!r?.confirmed) throw new Error('cancelled')
    const res = await apiPost('/api/fleet/console/grant', {
      machine_id: machine.id, currentPassword: r.password, totpCode: r.totp,
    })
    grant = res.grant
    return grant
  }

  // sessionId reattaches an existing resumable session (tmux new -A); null opens a fresh one.
  async function openTab(sessionId = null) {
    error = ''
    busy = true
    try {
      const g = await ensureGrant()
      const session = readonly && shareSession ? shareSession : (sessionId || randSession())
      const tab = { id: session, el: null, term: null, fit: null, search: null, socket: null, title: 'shell', exited: false }
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
      fontSize: 13, theme: termTheme, scrollback: 5000, allowProposedApi: true,
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
      machine: machine.id, grant: g, session: tab.id, cols: term.cols, rows: term.rows,
      onOpen: () => { if (!readonly) term.focus(); if (filesVisible && tab.id === activeId) listFiles(filesCwd) },
      onData: (bytes) => term.write(bytes),
      onExit: () => { tab.exited = true; term.write('\r\n\x1b[90m[session ended]\x1b[0m\r\n'); tabs = [...tabs] },
      onError: (m) => { error = m; if (/grant/i.test(m)) grant = null },
      onClose: () => { if (!tab.exited) term.write('\r\n\x1b[90m[disconnected]\x1b[0m\r\n') },
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
    tab.socket?.close()
    tab.term?.dispose()
    tabs = tabs.filter((t) => t.id !== tab.id)
    if (activeId === tab.id) activeId = tabs[tabs.length - 1]?.id || null
    if (tabs.length === 0) onclose?.()
  }

  function closeAll() {
    for (const t of tabs) { t.socket?.close(); t.term?.dispose() }
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
        machine_id: machine.id, session: tab.id, currentPassword: r.password, totpCode: r.totp,
      })
      // res.session is the owner's namespaced session the grant is bound to — the viewer must open that.
      const link = `${location.origin}/#fconsole=${encodeURIComponent(machine.id)}|${encodeURIComponent(res.session)}|${encodeURIComponent(res.grant)}`
      await navigator.clipboard.writeText(link)
      toast('Read-only link copied (valid ~30 min)', 'success')
    } catch (e) {
      toast(e.message || 'could not create share link', 'error')
    }
  }

  $effect(() => {
    // Auto-open the first tab on mount — reattaching initialSession when one was passed.
    if (tabs.length === 0 && !busy) openTab(initialSession)
  })

  onDestroy(() => { for (const t of tabs) { t.socket?.close(); t.term?.dispose() } })
</script>

<svelte:window on:resize={onResize} />

<!-- Inset past the app sidebar on desktop so it stays visible/usable (a page, not a modal); the
     sidebar is off-canvas on mobile, so go full-width there. -->
<div class="fixed inset-0 lg:left-60 z-50 flex flex-col bg-[#0f1419] text-[#d7dce2]">
  <!-- Header / toolbar -->
  <div class="flex items-center gap-2 px-3 py-2 border-b border-white/10 bg-[#12161d]">
    <Icon name="terminal-2" size={16} class="text-[#58a6ff]" />
    <span class="text-sm font-medium truncate">{machine.name || machine.id}</span>
    {#if readonly}<span class="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300">read-only</span>{/if}
    {#if machine.console_record && !readonly}<span class="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-red-400"></span>recording</span>{/if}

    <!-- Tabs -->
    <div class="flex items-center gap-1 ml-2 overflow-x-auto">
      {#each tabs as tab (tab.id)}
        <button onclick={() => activate(tab.id)}
          class="group flex items-center gap-1.5 px-2.5 py-1 rounded text-xs whitespace-nowrap {activeId === tab.id ? 'bg-white/10 text-white' : 'text-white/60 hover:bg-white/5'}">
          <Icon name="terminal" size={12} />
          {tab.title}{tab.exited ? ' (ended)' : ''}
          <span onclick={(e) => { e.stopPropagation(); closeTab(tab) }} class="opacity-0 group-hover:opacity-100 hover:text-red-300"><Icon name="x" size={11} /></span>
        </button>
      {/each}
      {#if !readonly}
        <button onclick={() => openTab()} disabled={busy} title="New session" class="px-2 py-1 rounded text-white/60 hover:bg-white/5"><Icon name="plus" size={13} /></button>
      {/if}
    </div>

    <div class="ml-auto flex items-center gap-1">
      {#if tabs.length > 1}
        <button onclick={() => (splitView = !splitView)} title={splitView ? 'Single view' : 'Split view'}
          class="p-1.5 rounded hover:bg-white/5 {splitView ? 'text-[#58a6ff]' : 'text-white/60'}"><Icon name={splitView ? 'layout-columns' : 'layout-grid'} size={14} /></button>
      {/if}
      <button onclick={() => (searchVisible = !searchVisible)} title="Search" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="search" size={14} /></button>
      {#if !readonly}
        <button onclick={openFiles} title="File browser" class="p-1.5 rounded hover:bg-white/5 {filesVisible ? 'text-[#58a6ff]' : 'text-white/60'}"><Icon name="folder" size={14} /></button>
        <button onclick={upload} title="Quick upload" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="upload" size={14} /></button>
        <button onclick={download} title="Quick download" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="download" size={14} /></button>
        <button onclick={share} title="Share read-only" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="share" size={14} /></button>
      {/if}
      <button onclick={closeAll} title="Close console" class="p-1.5 rounded text-white/60 hover:bg-red-500/20 hover:text-red-300"><Icon name="x" size={16} /></button>
    </div>
  </div>

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
  <!-- Terminal area: one container per session. Tab view stacks them (only the active one shown);
       split view lays them in a grid. The mount nodes stay stable across the switch so xterm is not
       re-created. -->
  <div class="flex-1 min-h-0 relative overflow-hidden {splitView ? 'grid gap-1 p-1' : ''}"
    style={splitView ? `grid-template-columns: repeat(${splitCols}, minmax(0,1fr)); grid-auto-rows: minmax(0,1fr)` : ''}>
    {#each tabs as tab (tab.id)}
      <div id={'wt-' + tab.id} bind:this={tab.el}
        onclick={() => { if (splitView) activate(tab.id) }}
        class={splitView
          ? 'relative overflow-hidden rounded border p-1 min-h-0 ' + (activeId === tab.id ? 'border-[#58a6ff]' : 'border-white/10')
          : 'absolute inset-0 p-1.5'}
        style:display={splitView || activeId === tab.id ? 'block' : 'none'}></div>
    {/each}
    {#if tabs.length === 0}
      <div class="absolute inset-0 flex items-center justify-center text-white/40 text-sm">
        {busy ? 'Opening console…' : 'No session'}
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
