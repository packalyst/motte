<script>
  /**
   * Pull-to-refresh for the mobile PWA. Listens on the document (fixed modals sit outside any
   * wrapper) but judges "at the top" by `scroller`, the element that actually scrolls the
   * page: the window never scrolls in this layout, so checking it made every downward swipe,
   * fast scroll-ups included, a pull.
   */
  let { children, onRefresh = () => {}, scroller = null } = $props()

  let startX = 0
  let startY = 0
  let pullDistance = $state(0)
  let isPulling = $state(false)
  let isRefreshing = $state(false)

  const threshold = 80 // Distance to trigger refresh
  const maxPull = 120 // Max pull distance
  // Movement before a pull counts: filters finger settle and the tail of a scroll.
  const deadZone = 24
  // The page must have rested at the top this long before a touch can start a pull, so a
  // flick that carries the content up to the top and keeps going never refreshes.
  const settleMs = 400

  let lastScrollAt = 0
  const atTop = () => (scroller ? scroller.scrollTop : window.scrollY) <= 0

  // A touch inside a dialog, or inside a box that scrolls on its own and isn't at its top, is
  // for that element, not the page.
  function ownsGesture(target) {
    if (!(target instanceof Element) || target.closest('.kt-modal, [role="dialog"], [data-no-pull]')) return true
    for (let el = target; el && el !== scroller && el !== document.body; el = el.parentElement) {
      if (el.scrollTop > 0 && el.scrollHeight > el.clientHeight) return true
    }
    return false
  }

  function handleTouchStart(e) {
    if (isRefreshing || e.touches.length !== 1 || !atTop() || Date.now() - lastScrollAt < settleMs || ownsGesture(e.target)) return
    startX = e.touches[0].clientX
    startY = e.touches[0].clientY
    isPulling = true
  }

  function handleTouchMove(e) {
    if (!isPulling || isRefreshing) return
    const dy = e.touches[0].clientY - startY
    const dx = Math.abs(e.touches[0].clientX - startX)
    // Upward, sideways (a swipe, not a pull) or the content started scrolling: not a pull.
    if (dy < 0 || dx > dy || !atTop()) {
      isPulling = false
      pullDistance = 0
      return
    }
    if (dy < deadZone) return
    // Apply resistance; subtract the dead-zone so effective travel starts at 0.
    pullDistance = Math.min((dy - deadZone) * 0.5, maxPull)
  }

  async function handleTouchEnd() {
    if (!isPulling) return

    if (pullDistance >= threshold && !isRefreshing) {
      isRefreshing = true
      pullDistance = 60 // Keep indicator visible

      try {
        await onRefresh()
      } finally {
        isRefreshing = false
      }
    }

    // Reset
    isPulling = false
    pullDistance = 0
  }

  // A cancelled touch (a system gesture took over) never refreshes.
  function handleTouchCancel() {
    isPulling = false
    pullDistance = 0
  }

  $effect(() => {
    const onScroll = () => { lastScrollAt = Date.now() }
    const target = scroller || window
    target.addEventListener('scroll', onScroll, { passive: true })
    document.addEventListener('touchstart', handleTouchStart, { passive: true })
    document.addEventListener('touchmove', handleTouchMove, { passive: true })
    document.addEventListener('touchend', handleTouchEnd, { passive: true })
    document.addEventListener('touchcancel', handleTouchCancel, { passive: true })
    return () => {
      target.removeEventListener('scroll', onScroll)
      document.removeEventListener('touchstart', handleTouchStart)
      document.removeEventListener('touchmove', handleTouchMove)
      document.removeEventListener('touchend', handleTouchEnd)
      document.removeEventListener('touchcancel', handleTouchCancel)
    }
  })
</script>

<!-- Pull indicator (fixed position, outside content flow) -->
{#if pullDistance > 10 || isRefreshing}
  <div
    class="pull-indicator"
    style:transform="translateY({Math.min(pullDistance, maxPull) - 40}px)"
    style:opacity={Math.min(pullDistance / 40, 1)}
  >
    <div class="pull-spinner" class:spinning={isRefreshing || pullDistance >= threshold}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21 12a9 9 0 11-6.219-8.56" />
      </svg>
    </div>
    <span class="pull-text">
      {#if isRefreshing}
        Refreshing...
      {:else if pullDistance >= threshold}
        Release to refresh
      {:else}
        Pull to refresh
      {/if}
    </span>
  </div>
{/if}

<!-- Content rendered directly without wrapper -->
{@render children()}

<style>
  .pull-indicator {
    position: fixed;
    top: calc(60px + env(safe-area-inset-top)); /* below the header */
    left: 0;
    right: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.75rem;
    pointer-events: none;
    z-index: 40;
  }

  .pull-spinner {
    width: 20px;
    height: 20px;
    color: var(--color-muted-foreground);
  }

  .pull-spinner.spinning {
    animation: spin 1s linear infinite;
  }

  .pull-spinner svg {
    width: 100%;
    height: 100%;
  }

  .pull-text {
    font-size: 0.75rem;
    color: var(--color-muted-foreground);
  }

  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
</style>
