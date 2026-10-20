<script>
  // Full-screen interactive console for a fleet machine. Opens one step-up-granted WebSocket per
  // tab (session), rendered with xterm.js. Supports multiple tabs, resize, copy/paste (xterm),
  // scrollback search, file upload/download, a read-only share link, and shows a recording badge.
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
  let { machine, onclose, shareGrant = null, shareSession = null } = $props()

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

  let grant = shareGrant // reused across tabs/reconnects until it stops working
  let fileInput

  function randSession() {
    return 's' + Math.random().toString(36).slice(2, 8)
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

  async function openTab() {
    error = ''
    busy = true
    try {
      const g = await ensureGrant()
      const session = readonly && shareSession ? shareSession : randSession()
      const tab = { id: session, el: null, term: null, fit: null, search: null, socket: null, title: 'shell', exited: false }
      tabs = [...tabs, tab]
      activeId = session
      await tick() // let the terminal container mount
      // Re-fetch from the reactive array: bind:this set `el` on Svelte's proxied copy, not on the
      // local `tab` reference, so open the terminal into the proxied object.
      const mounted = tabs.find((t) => t.id === session)
      startTerminal(mounted, g)
    } catch (e) {
      if (e?.message !== 'cancelled') error = e.message || 'could not open console'
    } finally {
      busy = false
    }
  }

  function startTerminal(tab, g) {
    if (!tab?.el) {
      error = 'terminal container failed to mount'
      return
    }
    const term = new Terminal({
      cursorBlink: true, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize: 13, theme: termTheme, scrollback: 5000, allowProposedApi: true,
    })
    const fit = new FitAddon()
    const search = new SearchAddon()
    term.loadAddon(fit)
    term.loadAddon(search)
    term.loadAddon(new WebLinksAddon())
    term.open(tab.el)
    fit.fit()
    tab.term = term
    tab.fit = fit
    tab.search = search

    const socket = new ConsoleSocket({
      machine: machine.id, grant: g, session: tab.id, cols: term.cols, rows: term.rows,
      onOpen: () => { if (!readonly) term.focus() },
      onData: (bytes) => term.write(bytes),
      onExit: () => { tab.exited = true; term.write('\r\n\x1b[90m[session ended]\x1b[0m\r\n'); tabs = [...tabs] },
      onError: (m) => { error = m; if (/grant/i.test(m)) grant = null },
      onClose: () => { if (!tab.exited) term.write('\r\n\x1b[90m[disconnected]\x1b[0m\r\n') },
      onFileChunk: (path, parts) => deliverDownload(path, parts),
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

  function onResize() {
    const tab = tabs.find((t) => t.id === activeId)
    tab?.fit?.fit()
  }

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

  async function share() {
    const tab = tabs.find((t) => t.id === activeId)
    if (!tab) return toast('Open a session first', 'error')
    try {
      const r = await stepUpConfirm({ title: 'Share read-only console', description: 'Re-authenticate to create a view-only link.' })
      if (!r?.confirmed) return
      const res = await apiPost('/api/fleet/console/grant?readonly=true', {
        machine_id: machine.id, session: tab.id, currentPassword: r.password, totpCode: r.totp,
      })
      const link = `${location.origin}/#fconsole=${encodeURIComponent(machine.id)}|${encodeURIComponent(tab.id)}|${encodeURIComponent(res.grant)}`
      await navigator.clipboard.writeText(link)
      toast('Read-only link copied (valid ~30 min)', 'success')
    } catch (e) {
      toast(e.message || 'could not create share link', 'error')
    }
  }

  $effect(() => {
    // Auto-open the first tab on mount.
    if (tabs.length === 0 && !busy) openTab()
  })

  onDestroy(() => { for (const t of tabs) { t.socket?.close(); t.term?.dispose() } })
</script>

<svelte:window on:resize={onResize} />

<div class="fixed inset-0 z-50 flex flex-col bg-[#0f1419] text-[#d7dce2]">
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
        <button onclick={openTab} disabled={busy} title="New session" class="px-2 py-1 rounded text-white/60 hover:bg-white/5"><Icon name="plus" size={13} /></button>
      {/if}
    </div>

    <div class="ml-auto flex items-center gap-1">
      <button onclick={() => (searchVisible = !searchVisible)} title="Search" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="search" size={14} /></button>
      {#if !readonly}
        <button onclick={upload} title="Upload file" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="upload" size={14} /></button>
        <button onclick={download} title="Download file" class="p-1.5 rounded text-white/60 hover:bg-white/5"><Icon name="download" size={14} /></button>
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

  <!-- Terminal area: one container per tab, only the active one shown -->
  <div class="flex-1 relative overflow-hidden">
    {#each tabs as tab (tab.id)}
      <div bind:this={tab.el} class="absolute inset-0 p-1.5" style:display={activeId === tab.id ? 'block' : 'none'}></div>
    {/each}
    {#if tabs.length === 0}
      <div class="absolute inset-0 flex items-center justify-center text-white/40 text-sm">
        {busy ? 'Opening console…' : 'No session'}
      </div>
    {/if}
  </div>

  <input type="file" bind:this={fileInput} onchange={onFilePicked} class="hidden" />
</div>
