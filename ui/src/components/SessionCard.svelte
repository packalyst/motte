<script>
  // A live session shown as a card with a terminal snapshot preview (like the reference UI's
  // "active sessions"). Clicking it resumes the session; the X kills it. Reused on the machine
  // Sessions tab and the dashboard resume strip. Fetches its own one-shot snapshot.
  import { onMount, onDestroy } from 'svelte'
  import { requestSnapshot, openConsoleEvents, sessionColor } from '../lib/consoleEvents.js'
  import Icon from './Icon.svelte'
  import GroupButton from './GroupButton.svelte'

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

<!-- The left edge carries the session's colour, the same one its console tab shows. -->
<div class="group overflow-hidden rounded-xl border border-l-[3px] border-border bg-card transition hover:shadow-md"
  style:border-left-color={sessionColor(session.id)}>
  <!-- terminal snapshot -->
  <button type="button" onclick={() => onresume?.(session)} aria-label="Resume Session {session.label || ''} on {machine.name || machine.id}"
    class="block h-28 w-full cursor-pointer overflow-hidden bg-[#0f1419] text-left">
    {#if loading}
      <div class="grid h-full place-items-center text-xs text-white/30">loading preview…</div>
    {:else if preview}
      <pre class="overflow-hidden whitespace-pre p-2 font-mono text-[9px] leading-[1.25] text-[#d7dce2]">{preview}</pre>
    {:else}
      <div class="grid h-full place-items-center text-xs text-white/25">no preview</div>
    {/if}
  </button>
  <div class="flex items-center gap-2.5 px-3 py-2">
    <span class="h-2 w-2 shrink-0 rounded-full" style:background-color={sessionColor(session.id)}></span>
    <div class="min-w-0 flex-1">
      <div class="truncate text-sm font-medium text-foreground">Session {session.label || '?'}</div>
      <!-- A listed session is always alive (tmux); "watching" means a browser is attached right now. -->
      <div class="flex items-center gap-1.5 truncate text-[11px] text-muted-foreground">
        {machine.name || machine.id}
        <span class="h-1 w-1 rounded-full bg-muted-foreground/50"></span>
        {#if session.attached}<span class="inline-flex items-center gap-1 text-success"><Icon name="eye" size={11} />{session.viewers} watching</span>{:else}detached{/if}
      </div>
    </div>
    <div class="btn-group shrink-0">
      <GroupButton icon="terminal-2" tone="primary" tooltip="Resume session" onclick={() => onresume?.(session)} />
      <GroupButton icon="x" tone="destructive" tooltip="Close session" onclick={() => onkill?.(session)} />
    </div>
  </div>
</div>
