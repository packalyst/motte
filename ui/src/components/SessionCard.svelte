<script>
  // A live session shown as a card with a terminal snapshot preview (like the reference UI's
  // "active sessions"). Clicking it resumes the session; the X kills it. Reused on the machine
  // Sessions tab and the dashboard resume strip. Fetches its own one-shot snapshot.
  import { onMount, onDestroy } from 'svelte'
  import { requestSnapshot, openConsoleEvents } from '../lib/consoleEvents.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'

  let { session, machine, onresume, onkill } = $props()

  let releaseEvents
  onMount(() => { releaseEvents = openConsoleEvents() })
  onDestroy(() => releaseEvents?.())

  let preview = $state('')
  let loading = $state(true)

  function decodeB64(b64) {
    try {
      const bin = atob(b64)
      const bytes = new Uint8Array(bin.length)
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
      return new TextDecoder().decode(bytes)
    } catch {
      return ''
    }
  }
  // The snapshot keeps colour escapes; strip them for a plain-text thumbnail, and show the last
  // lines (what a terminal preview naturally shows).
  function clean(s) {
    // eslint-disable-next-line no-control-regex
    const noAnsi = s.replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    const lines = noAnsi.replace(/\s+$/g, '').split('\n')
    return lines.slice(-12).join('\n')
  }

  async function loadPreview() {
    loading = true
    try {
      const data = await requestSnapshot(machine.id, session.id)
      preview = data ? clean(decodeB64(data)) : ''
    } catch {
      preview = ''
    } finally {
      loading = false
    }
  }
  $effect(() => {
    session.id
    machine.id
    loadPreview()
  })
</script>

<div class="group bg-card border border-border rounded-xl overflow-hidden hover:border-primary/40 transition">
  <!-- terminal snapshot -->
  <button type="button" onclick={() => onresume?.(session)} title="Resume this session"
    class="block w-full text-left bg-[#0f1419] h-28 overflow-hidden cursor-pointer">
    {#if loading}
      <div class="h-full grid place-items-center text-white/30 text-xs">loading preview…</div>
    {:else if preview}
      <pre class="text-[9px] leading-[1.25] text-[#d7dce2] font-mono p-2 whitespace-pre overflow-hidden">{preview}</pre>
    {:else}
      <div class="h-full grid place-items-center text-white/25 text-xs">no preview</div>
    {/if}
  </button>
  <!-- footer -->
  <div class="flex items-center gap-2 px-3 py-2">
    <!-- A listed session is always alive (tmux). Green = live; dimmed when no one is attached. -->
    <span class="w-2 h-2 rounded-full shrink-0 bg-success {session.attached ? '' : 'opacity-40'}"
      title={session.attached ? `live · ${session.viewers} watching` : 'live · detached'}></span>
    <button type="button" onclick={() => onresume?.(session)} class="min-w-0 flex-1 text-left cursor-pointer">
      <div class="text-sm font-medium text-foreground truncate">Session {session.label || '?'}</div>
      <div class="text-[11px] text-muted-foreground truncate">{machine.name || machine.id}</div>
    </button>
    {#if session.viewers > 0}
      <span class="flex items-center gap-1 text-[11px] text-muted-foreground shrink-0" title="viewers">
        <Icon name="eye" size={12} />{session.viewers}
      </span>
    {/if}
    <Button variant="ghost-danger" size="xs" iconOnly icon="x" onclick={() => onkill?.(session)} title="Close session" />
  </div>
</div>
