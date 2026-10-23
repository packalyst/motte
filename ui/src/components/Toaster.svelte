<script>
  /**
   * Toaster — the app's toasts (from toast() in stores/app.js), stacked in the bottom-right corner:
   * the newest in front, older ones peeking out behind it, smaller and higher. Hovering spreads the
   * stack into a list and pauses every timer; leaving collapses it and the timers carry on. Full
   * width at the bottom on phones. Messages render as text, so a toast can never inject markup.
   */
  import { fly } from 'svelte/transition'
  import { toasts, dismissToast } from '../stores/app.js'
  import Icon from './Icon.svelte'

  const ICON = {
    success: ['circle-check', 'text-success'],
    error: ['alert-circle', 'text-destructive'],
    warning: ['alert-triangle', 'text-warning'],
    info: ['info-circle', 'text-info'],
  }
  const PEEK = 10 // px each older toast shows above the one in front
  const GAP = 8 // px between toasts when spread out
  const SHOWN_BEHIND = 3 // older toasts visible behind the front one; the rest fade out

  let expanded = $state(false)
  let heights = $state({}) // id → rendered height (px)
  const timers = new Map() // id → { handle, remaining, started }

  const ordered = $derived([...$toasts].reverse()) // newest first
  const frontHeight = $derived(heights[ordered[0]?.id] || 0)

  function start(id, ms) {
    timers.set(id, { handle: setTimeout(() => dismissToast(id), ms), remaining: ms, started: Date.now() })
  }
  // New toasts get a timer (held while the stack is spread out); dismissed ones lose theirs.
  $effect(() => {
    const ids = new Set($toasts.map((t) => t.id))
    for (const t of $toasts) {
      if (timers.has(t.id)) continue
      if (expanded) timers.set(t.id, { handle: null, remaining: t.duration, started: 0 })
      else start(t.id, t.duration)
    }
    for (const [id, tm] of timers) {
      if (!ids.has(id)) { clearTimeout(tm.handle); timers.delete(id) }
    }
  })
  function pause() {
    expanded = true
    for (const tm of timers.values()) {
      if (!tm.handle) continue
      clearTimeout(tm.handle)
      tm.handle = null
      tm.remaining -= Date.now() - tm.started
    }
  }
  function resume() {
    expanded = false
    for (const [id, tm] of timers) {
      if (!tm.handle) start(id, Math.max(1000, tm.remaining)) // at least a second to notice it
    }
  }

  // How far up toast i (0 = newest) sits: a small peek when stacked, the heights below it when spread.
  function offset(i) {
    if (!expanded) return i * PEEK
    let y = 0
    for (let k = 0; k < i; k++) y += (heights[ordered[k].id] || 0) + GAP
    return y
  }
  const stackHeight = $derived(expanded
    ? ordered.reduce((sum, t) => sum + (heights[t.id] || 0) + GAP, 0)
    : frontHeight + Math.min(ordered.length - 1, SHOWN_BEHIND) * PEEK)
</script>

{#if ordered.length}
  <section aria-label="Notifications" aria-live="polite"
    class="fixed inset-x-3 bottom-3 z-[100] sm:inset-x-auto sm:bottom-6 sm:right-6 sm:w-[356px]"
    style="height: {stackHeight}px" onmouseenter={pause} onmouseleave={resume}>
    {#each ordered as t, i (t.id)}
      {@const [icon, tone] = ICON[t.type] || ICON.info}
      {@const behind = !expanded && i > 0}
      <div role={t.type === 'error' ? 'alert' : 'status'} bind:clientHeight={heights[t.id]}
        in:fly={{ y: 24, duration: 260 }} out:fly={{ y: 12, duration: 180 }}
        class="toast absolute inset-x-0 bottom-0 flex origin-bottom items-start gap-2.5 rounded-[9px] px-4 py-3 text-xs
          transition-[transform,opacity] duration-300 ease-out"
        style="transform: translateY(-{offset(i)}px) scale({expanded ? 1 : 1 - i * 0.05});
          z-index: {50 - i}; opacity: {behind && i > SHOWN_BEHIND ? 0 : 1};
          {behind ? `height: ${frontHeight}px; overflow: hidden;` : ''}">
        <Icon name={icon} size={15} class="mt-px shrink-0 {tone} {behind ? 'opacity-0' : ''}" />
        <span class="min-w-0 flex-1 break-words leading-relaxed {behind ? 'opacity-0' : ''}">{t.message}</span>
        <button type="button" onclick={() => dismissToast(t.id)} aria-label="Dismiss" tabindex={behind ? -1 : 0}
          class="-mr-1 grid h-5 w-5 shrink-0 cursor-pointer place-items-center rounded opacity-60 transition hover:bg-white/10 hover:opacity-100 {behind ? 'invisible' : ''}">
          <Icon name="x" size={12} />
        </button>
      </div>
    {/each}
  </section>
{/if}

<style>
  /* Dark navy note on the light theme; a raised dark surface on the dark theme. */
  .toast {
    background: #152238;
    color: #fff;
    box-shadow: 0 8px 35px rgb(21 34 56 / 0.21);
  }
  :global(.dark) .toast {
    background: #1f2a3d;
    border: 1px solid rgb(255 255 255 / 0.08);
  }
</style>
