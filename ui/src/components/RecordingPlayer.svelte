<script>
  // In-app playback of a console session recording (asciicast v2), WebTerm-style: a Playback tab
  // (play/pause, seek, speed, long idle gaps compressed to 2s) with a command list that jumps to each
  // command, a searchable Text tab, and .cast / .txt downloads. Recorded output is only ever written
  // into xterm or shown as escaped text — never as markup. Fetching it is audited server-side.
  import { onMount, onDestroy, tick } from 'svelte'
  import { Terminal } from '@xterm/xterm'
  import '@xterm/xterm/css/xterm.css'
  import { apiGetText } from '../stores/app.js'
  import Icon from './Icon.svelte'

  let { machineId, rec, onclose } = $props()

  const IDLE_CAP = 2 // seconds: longer pauses in the recording play back as this
  let loading = $state(true)
  let failed = $state('')
  let tabName = $state('play')
  let raw = $state('') // the .cast text, kept for download (reactive: it enables the download buttons)
  let header = $state({ width: 80, height: 24, title: '' })
  let out = [] // [{ t, d }] output events, t = idle-compressed seconds
  let markers = $state([]) // [{ t, label }] commands
  let duration = $state(0)
  let pos = $state(0)
  let playing = $state(false)
  let speed = $state(1)
  let idx = 0 // next output event to write
  let termEl = $state(null)
  let term
  let raf = 0
  let last = 0

  // Plain text: strip escape sequences, keep each line's final state after carriage returns (so a
  // progress bar reads as its last frame), drop other control characters.
  // eslint-disable-next-line no-control-regex
  const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]/g
  function toText(s) {
    return s.replace(ANSI, '').split('\n').map((l) => {
      const parts = l.split('\r')
      // eslint-disable-next-line no-control-regex
      return (parts.findLast((p) => p.length) ?? '').replace(/[\x00-\x08\x0b-\x1f\x7f]/g, '')
    }).join('\n')
  }
  let fullText = $state('')
  let query = $state('')
  const textLines = $derived(fullText ? fullText.split('\n') : [])
  const matches = $derived(query.trim()
    ? textLines.filter((l) => l.toLowerCase().includes(query.trim().toLowerCase()))
    : [])
  const shownLines = $derived(query.trim() ? matches.slice(0, 1000) : textLines.slice(-3000))

  function parse(text) {
    const lines = text.split('\n').filter(Boolean)
    header = JSON.parse(lines[0])
    let shift = 0
    let prev = 0
    const o = []
    const m = []
    for (let i = 1; i < lines.length; i++) {
      let ev
      try { ev = JSON.parse(lines[i]) } catch { continue }
      const [t, kind, data] = ev
      const gap = t - prev
      if (gap > IDLE_CAP) shift += gap - IDLE_CAP
      prev = t
      const at = Math.max(0, t - shift)
      if (kind === 'o') o.push({ t: at, d: data })
      else if (kind === 'm') m.push({ t: at, label: data })
    }
    out = o
    markers = m
    duration = Math.max(o.length ? o[o.length - 1].t : 0, m.length ? m[m.length - 1].t : 0)
    fullText = toText(o.map((e) => e.d).join(''))
  }

  // Render everything up to time t from scratch (seek), then keep playing from there.
  function seek(t) {
    pos = Math.min(Math.max(0, t), duration)
    term.reset()
    let buf = ''
    idx = 0
    while (idx < out.length && out[idx].t <= pos) buf += out[idx++].d
    if (buf) term.write(buf)
  }
  function frame(now) {
    if (!playing) return
    pos = Math.min(duration, pos + ((now - last) / 1000) * speed)
    last = now
    let buf = ''
    while (idx < out.length && out[idx].t <= pos) buf += out[idx++].d
    if (buf) term.write(buf)
    if (pos >= duration) { playing = false; return }
    raf = requestAnimationFrame(frame)
  }
  function play() {
    if (pos >= duration) seek(0)
    playing = true
    last = performance.now()
    raf = requestAnimationFrame(frame)
  }
  function pause() { playing = false; cancelAnimationFrame(raf) }
  function toggle() { playing ? pause() : play() }
  function jump(t) { const was = playing; pause(); seek(t); if (was) play() }

  function fmt(s) {
    s = Math.floor(s)
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60
    return (h ? h + ':' + String(m).padStart(2, '0') : m) + ':' + String(x).padStart(2, '0')
  }
  function save(text, name, type) {
    const url = URL.createObjectURL(new Blob([text], { type }))
    const a = document.createElement('a')
    a.href = url
    a.download = name
    a.click()
    URL.revokeObjectURL(url)
  }

  onMount(async () => {
    try {
      raw = await apiGetText(`/api/fleet/console/recording?machine_id=${encodeURIComponent(machineId)}&name=${encodeURIComponent(rec.name)}`)
      parse(raw)
      term = new Terminal({
        cols: header.width || 80, rows: header.height || 24, disableStdin: true, cursorBlink: false, scrollback: 5000,
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: 13,
        theme: { background: '#0f1419', foreground: '#d7dce2', cursor: '#0f1419' },
      })
      loading = false
      await tick() // the terminal's mount node renders only once loading is off
      term.open(termEl)
      play()
    } catch (e) {
      failed = e.message || 'Couldn’t load the recording — try again.'
      loading = false
    }
  })
  onDestroy(() => { cancelAnimationFrame(raf); term?.dispose() })

  function onKey(e) {
    if (e.key === 'Escape') onclose?.()
    else if (e.key === ' ' && tabName === 'play' && e.target === document.body) { e.preventDefault(); toggle() }
  }
</script>

<svelte:window onkeydown={onKey} />

<div class="fixed inset-0 z-[70] bg-black/60 flex items-center justify-center p-2 sm:p-6 [&_button]:cursor-pointer [&_button:disabled]:cursor-not-allowed" role="dialog" aria-modal="true" aria-label={'Playing recording: ' + (rec.title || 'session')}>
  <div class="w-full max-w-6xl h-full max-h-[90vh] bg-[#12161d] text-[#d7dce2] border border-white/10 rounded-xl flex flex-col overflow-hidden shadow-2xl">
    <div class="flex items-center gap-2 px-3 py-2 border-b border-white/10">
      <Icon name="player-play" size={14} class="text-[#58a6ff]" />
      <span class="text-sm font-medium truncate">{rec.title || 'Session'}</span>
      <span class="text-[11px] text-white/40 truncate">· {rec.user} · {new Date(rec.started * 1000).toLocaleString()}</span>
      <span class="text-[10px] uppercase tracking-wide text-white/40 border border-white/10 rounded px-1.5 py-0.5 shrink-0">recording playback</span>
      <div class="ml-auto flex items-center gap-1 shrink-0">
        <button onclick={() => (tabName = 'play')} class="px-2 py-1 rounded text-xs {tabName === 'play' ? 'bg-white/10 text-white' : 'text-white/60 hover:text-white'}">Playback</button>
        <button onclick={() => (tabName = 'text')} class="px-2 py-1 rounded text-xs {tabName === 'text' ? 'bg-white/10 text-white' : 'text-white/60 hover:text-white'}">Text</button>
        <button onclick={() => save(raw, rec.name, 'application/x-asciicast')} disabled={!raw} title="Download .cast" class="p-1.5 rounded text-white/60 hover:bg-white/5 disabled:opacity-30"><Icon name="download" size={14} /></button>
        <button onclick={() => save(fullText, rec.name.replace(/\.cast$/, '.txt'), 'text/plain')} disabled={!raw} title="Download .txt" class="px-1.5 py-1 rounded text-[11px] text-white/60 hover:bg-white/5 disabled:opacity-30">.txt</button>
        <button onclick={onclose} title="Close (Esc)" aria-label="Close"
          class="ml-1 grid h-7 w-7 place-items-center rounded-lg border border-white/10 text-white/60 transition hover:border-white/20 hover:bg-white/10 hover:text-white"><Icon name="x" size={15} /></button>
      </div>
    </div>

    {#if loading}
      <div class="flex-1 grid place-items-center text-sm text-white/40">Loading recording…</div>
    {:else if failed}
      <div class="flex-1 grid place-items-center text-sm text-red-300">{failed}</div>
    {:else}
      <div class="flex-1 min-h-0 flex">
        <!-- Playback -->
        <div class="flex-1 min-w-0 flex flex-col {tabName === 'play' ? '' : 'hidden'}">
          <div class="flex-1 min-h-0 overflow-auto p-2 bg-[#0f1419]"><div bind:this={termEl}></div></div>
          <div class="flex items-center gap-2 px-3 py-2 border-t border-white/10">
            <button onclick={toggle} title={playing ? 'Pause' : 'Play'} class="p-1.5 rounded text-white hover:bg-white/10">
              <Icon name={playing ? 'player-pause' : 'player-play'} size={16} />
            </button>
            <span class="text-[11px] tabular-nums text-white/60 w-24 shrink-0">{fmt(pos)} / {fmt(duration)}</span>
            <input type="range" min="0" max={duration || 0} step="0.1" value={pos} aria-label="Position in the recording"
              oninput={(e) => jump(+e.currentTarget.value)} class="flex-1 accent-[#58a6ff]" />
            <select bind:value={speed} title="Speed" class="bg-black/30 border border-white/10 rounded text-[11px] px-1 py-0.5">
              {#each [1, 2, 4, 8] as s (s)}<option value={s}>{s}×</option>{/each}
            </select>
          </div>
        </div>
        {#if tabName === 'play' && markers.length}
          <aside class="hidden md:flex w-64 shrink-0 border-l border-white/10 flex-col">
            <div class="px-3 py-2 text-[10px] uppercase tracking-wide text-white/40 border-b border-white/10">Commands · {markers.length}</div>
            <div class="flex-1 overflow-y-auto">
              {#each markers as mk, i (i)}
                <button onclick={() => jump(mk.t)} title={'Jump to ' + fmt(mk.t)}
                  class="w-full flex items-start gap-2 px-3 py-1.5 text-left text-xs hover:bg-white/5 {mk.t <= pos ? 'text-white/80' : 'text-white/45'}">
                  <span class="tabular-nums text-white/35 shrink-0">{fmt(mk.t)}</span>
                  <span class="font-mono truncate {mk.label.includes('(exit ') ? 'text-red-300' : ''}" title={mk.label}>{mk.label}</span>
                </button>
              {/each}
            </div>
          </aside>
        {/if}

        <!-- Text -->
        {#if tabName === 'text'}
          <div class="flex-1 min-w-0 flex flex-col">
            <div class="flex items-center gap-2 px-3 py-2 border-b border-white/10">
              <input bind:value={query} placeholder="Search the history (command, output, error)…"
                class="flex-1 bg-black/30 border border-white/10 rounded px-2 py-1 text-xs text-white outline-none focus:border-[#58a6ff]" />
              <span class="text-[11px] text-white/40 shrink-0">{query.trim() ? `${matches.length} matches` : `${textLines.length} lines`}</span>
            </div>
            {#if query.trim() && matches.length > 1000}
              <div class="px-3 py-1 text-[11px] text-amber-300">Too many matches — showing the first 1000. Refine the search or download the .txt.</div>
            {:else if !query.trim() && textLines.length > 3000}
              <div class="px-3 py-1 text-[11px] text-white/40">Showing the last 3000 lines — download the .txt for all of it.</div>
            {/if}
            <pre class="flex-1 overflow-auto p-3 text-[11px] leading-relaxed font-mono whitespace-pre-wrap break-all bg-[#0f1419]">{shownLines.join('\n')}</pre>
          </div>
        {/if}
      </div>
    {/if}
  </div>
</div>
