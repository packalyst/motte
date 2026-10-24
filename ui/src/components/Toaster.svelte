<script>
  /**
   * Toaster — the app's toasts (from toast() in stores/app.js). Messages render as text, so a
   * toast can never inject markup.
   *
   * Desktop: stacked in the bottom-right corner, the newest in front and older ones peeking out
   * behind it, smaller and higher. Hovering spreads the stack into a list and pauses every timer;
   * leaving collapses it and the timers carry on.
   *
   * Phones: app-style notifications from the top (below the notch). A new one drops in with a
   * blur and a soft overshoot; older ones sit behind it, lower, smaller and dimmer. A tap spreads
   * the stack (and pauses the timers), another tap folds it; a sideways swipe throws a toast off
   * the screen.
   */
  import { onMount } from 'svelte'
  import { fly } from 'svelte/transition'
  import { backOut } from 'svelte/easing'
  import { toasts, dismissToast } from '../stores/app.js'
  import Icon from './Icon.svelte'

  const ICON = {
    success: ['circle-check', 'text-success', 'Done'],
    error: ['alert-circle', 'text-destructive', 'Failed'],
    warning: ['alert-triangle', 'text-warning', 'Heads up'],
    info: ['info-circle', 'text-info', 'Info'],
  }
  const GAP = 8 // px between toasts when spread out
  const SHOWN_BEHIND = 3 // older toasts visible behind the front one; the rest fade out
  const SWIPE = 85 // px sideways that dismisses a toast (phones)

  let phone = $state(false)
  onMount(() => {
    const mq = window.matchMedia('(max-width: 639px)')
    const set = () => (phone = mq.matches)
    set()
    mq.addEventListener('change', set)
    return () => mq.removeEventListener('change', set)
  })
  const dir = $derived(phone ? 1 : -1) // which way the stack grows on screen (+1 down, -1 up)
  const peek = $derived(phone ? 13 : 10) // px each older toast shows past the one in front

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
    if (!$toasts.length) expanded = false
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

  // How far toast i (0 = newest) sits from the edge: a small peek when stacked, the heights of
  // the ones before it when spread.
  function offset(i) {
    if (!expanded) return i * peek
    let y = 0
    for (let k = 0; k < i; k++) y += (heights[ordered[k].id] || 0) + GAP
    return y
  }
  const stackHeight = $derived(expanded
    ? ordered.reduce((sum, t) => sum + (heights[t.id] || 0) + GAP, 0)
    : frontHeight + Math.min(ordered.length - 1, SHOWN_BEHIND) * peek)

  // Phone gestures: a sideways drag follows the finger and, past SWIPE, throws the toast out that
  // way; a tap (no drag) spreads or folds the stack.
  let drag = $state({}) // id → px dragged sideways
  let gesture = null // { id, x, y, moved }
  const thrown = new Map() // id → { dir, dx } for the exit animation
  function down(e, id) {
    if (!phone) return
    gesture = { id, x: e.clientX, y: e.clientY, moved: false }
    e.currentTarget.setPointerCapture(e.pointerId)
  }
  function move(e) {
    if (!gesture) return
    const dx = e.clientX - gesture.x
    if (!gesture.moved && Math.abs(dx) > 8 && Math.abs(dx) > Math.abs(e.clientY - gesture.y)) gesture.moved = true
    if (gesture.moved) drag = { ...drag, [gesture.id]: dx }
  }
  function up(e) {
    if (!gesture) return
    const { id, moved, y } = gesture
    const dx = drag[id] || 0
    gesture = null
    const { [id]: _, ...rest } = drag
    drag = rest
    if (Math.abs(dx) > SWIPE) {
      thrown.set(id, { dir: Math.sign(dx), dx })
      dismissToast(id)
    } else if (!moved && Math.abs(e.clientY - y) < 20) {
      expanded ? resume() : pause()
    }
  }
  function cancel() {
    gesture = null
    drag = {}
  }

  // Phones: drop in from above, blurred, with a soft overshoot. Desktop: rise a little.
  function arrive(node) {
    if (!phone) return fly(node, { y: 24, duration: 260 })
    return {
      duration: 650,
      css: (t) => {
        const b = backOut(t)
        return `transform: translateY(${-110 * (1 - b)}px) scale(${0.85 + 0.15 * b});
          filter: blur(${13 * Math.max(0, 1 - t * 1.9)}px); opacity: ${Math.min(1, t * 1.9)}`
      },
    }
  }
  // Phones: thrown sideways after a swipe, otherwise lifted away and faded. Desktop: sink a
  // little. Each starts from where the toast is now (its place in the stack, its drag), so one
  // leaving from behind the front one moves on from there instead of jumping.
  function leave(node, { id }) {
    if (!phone) return fly(node, { y: 12, duration: 180 })
    const now = getComputedStyle(node)
    const from = now.transform === 'none' ? '' : now.transform
    const op = +now.opacity || 1
    const th = thrown.get(id)
    thrown.delete(id)
    if (th) {
      return {
        duration: 340,
        css: (t, u) => `transform: translateX(${th.dir * 115 * u}%) translateY(${-22 * u}px) ${from}
          rotate(${th.dir * 8 * u}deg) scale(${1 - 0.15 * u}); filter: blur(${7 * u}px); opacity: ${op * t}`,
      }
    }
    return {
      duration: 300,
      easing: (x) => x * x * (3 - 2 * x), // smoothstep: eases in and out
      css: (t, u) => `transform: translateY(${-40 * u}px) ${from} scale(${1 - 0.06 * u}); filter: blur(${5 * u}px); opacity: ${op * t}`,
    }
  }
</script>

<!-- Always present (empty when there are no toasts), so the first toast's entrance and the last
     one's exit animate like the rest; it lets taps through while empty. -->
<section aria-label="Notifications" aria-live="polite"
  class="fixed inset-x-3 top-[max(0.5rem,env(safe-area-inset-top))] z-[100] sm:inset-x-auto sm:top-auto sm:bottom-6 sm:right-6 sm:w-[356px]"
  style="height: {stackHeight}px; {ordered.length ? '' : 'pointer-events: none;'}" onmouseenter={() => !phone && pause()} onmouseleave={() => !phone && resume()}>
  {#each ordered as t, i (t.id)}
    {@const [icon, tone, label] = ICON[t.type] || ICON.info}
    {@const behind = !expanded && i > 0}
    {@const dx = drag[t.id] || 0}
    <div role={t.type === 'error' ? 'alert' : 'status'} bind:clientHeight={heights[t.id]}
      onpointerdown={(e) => down(e, t.id)} onpointermove={move} onpointerup={up} onpointercancel={cancel}
      in:arrive out:leave={{ id: t.id }}
      class="toast {t.type} absolute inset-x-0 top-0 flex origin-top items-start gap-3 sm:gap-2.5 px-4 py-3 text-xs
        sm:top-auto sm:bottom-0 sm:origin-bottom"
      class:dragging={dx !== 0}
      style="transform: translateX({dx}px) translateY({dir * offset(i)}px) rotate({dx / 22}deg) scale({expanded ? 1 : 1 - i * (phone ? 0.055 : 0.05)});
        z-index: {50 - i}; opacity: {behind && i > SHOWN_BEHIND ? 0 : phone && dx ? Math.max(0.25, 1 - Math.abs(dx) / 360) : 1};
        {phone && behind ? `filter: brightness(${1 - i * 0.12});` : ''}
        {behind ? `height: ${frontHeight}px; overflow: hidden;` : ''}">
      <span class="toast-icon {behind ? 'opacity-0' : ''}"><Icon name={icon} size={phone ? 19 : 15} class={phone ? '' : tone} /></span>
      <div class="min-w-0 flex-1 {behind ? 'opacity-0' : ''}">
        {#if phone}
          <div class="mb-0.5 flex items-baseline justify-between gap-2">
            <strong class="text-[13px] font-semibold">{label}</strong>
            <span class="text-[10px] text-white/60">now</span>
          </div>
        {/if}
        <span class="block break-words leading-relaxed">{t.message}</span>
      </div>
      {#if !phone}
        <button type="button" onclick={() => dismissToast(t.id)} aria-label="Dismiss" tabindex={behind ? -1 : 0}
          class="-mr-1 grid h-5 w-5 shrink-0 cursor-pointer place-items-center rounded opacity-60 transition hover:bg-white/10 hover:opacity-100 {behind ? 'invisible' : ''}">
          <Icon name="x" size={12} />
        </button>
      {/if}
    </div>
  {/each}
</section>

<style>
  /* Dark navy note on the light theme; a raised dark surface on the dark theme. */
  .toast {
    background: #152238;
    color: #fff;
    border-radius: 9px;
    box-shadow: 0 8px 35px rgb(21 34 56 / 0.21);
    transition: transform 0.3s ease-out, opacity 0.3s ease-out;
  }
  :global(.dark) .toast {
    background: #1f2a3d;
    border: 1px solid rgb(255 255 255 / 0.08);
  }
  .toast-icon {
    display: contents;
  }
  .toast-icon :global(span) {
    margin-top: 1px;
  }

  /* Phones: a glassy notification card with an app-style icon tile, moving on a springy curve */
  @media (max-width: 639px) {
    .toast {
      border-radius: 22px;
      padding: 14px 16px;
      font-size: 12.5px;
      color: #e6e8f2;
      background: linear-gradient(115deg, rgb(47 50 70 / 0.96), rgb(27 30 44 / 0.97));
      border: 1px solid rgb(255 255 255 / 0.15);
      box-shadow: 0 22px 45px rgb(0 0 0 / 0.5), 0 2px 4px rgb(0 0 0 / 0.25), inset 0 1px rgb(255 255 255 / 0.15);
      backdrop-filter: blur(30px);
      -webkit-backdrop-filter: blur(30px);
      touch-action: pan-y;
      user-select: none;
      -webkit-user-select: none;
      cursor: pointer;
      transition: transform 0.5s cubic-bezier(0.2, 1.3, 0.22, 1), opacity 0.36s ease, filter 0.5s ease;
    }
    :global(.dark) .toast {
      background: linear-gradient(115deg, rgb(47 50 70 / 0.96), rgb(27 30 44 / 0.97));
      border: 1px solid rgb(255 255 255 / 0.15);
    }
    .toast.dragging {
      transition: none;
    }
    .toast-icon {
      display: grid;
      place-items: center;
      width: 38px;
      height: 38px;
      flex: none;
      border-radius: 12px;
      color: #fff;
      box-shadow: inset 0 1px 1px rgb(255 255 255 / 0.35), 0 6px 14px rgb(0 0 0 / 0.3);
    }
    .toast-icon :global(span) {
      margin-top: 0;
    }
    .success .toast-icon { background: linear-gradient(145deg, #4fd88a, #16955a); }
    .error .toast-icon { background: linear-gradient(145deg, #ff7a7a, #d63b3b); }
    .warning .toast-icon { background: linear-gradient(145deg, #ffc56b, #df8420); }
    .info .toast-icon { background: linear-gradient(145deg, #77b8ff, #3b76e0); }
  }

  @media (prefers-reduced-motion: reduce) {
    .toast { transition-duration: 0.01ms; }
  }
</style>
