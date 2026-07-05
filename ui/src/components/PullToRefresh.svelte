<script>
  /**
   * Pull-to-refresh component for mobile PWA
   * Uses document-level touch detection to avoid wrapper issues with fixed modals
   */
  import { onMount } from 'svelte'

  let { children, onRefresh = () => {} } = $props()

  let startY = $state(0)
  let pullDistance = $state(0)
  let isPulling = $state(false)
  let isRefreshing = $state(false)

  const threshold = 80 // Distance to trigger refresh
  const maxPull = 120 // Max pull distance

  // Dead-zone in pixels before we start accumulating pullDistance. This filters
  // out finger-settle jitter and momentum-scroll artifacts that were falsely
  // arming the refresh when the user flick-scrolled up quickly and their touch
  // landed at scrollY=0.
  const deadZone = 20

  function handleTouchStart(e) {
    // Only start pull if at top of scroll, not refreshing, and single-touch
    // (multi-touch = pinch/zoom, not a pull gesture).
    if (
      window.scrollY === 0 &&
      document.documentElement.scrollTop === 0 &&
      !isRefreshing &&
      e.touches.length === 1
    ) {
      startY = e.touches[0].clientY
      isPulling = true
    }
  }

  function handleTouchMove(e) {
    if (!isPulling || isRefreshing) return

    const currentY = e.touches[0].clientY
    const diff = currentY - startY

    // Cancel on upward movement.
    if (diff < 0) {
      isPulling = false
      pullDistance = 0
      return
    }

    // Ignore movement within the dead-zone — real pull gestures cross it
    // decisively, momentum/jitter usually don't.
    if (diff < deadZone) return

    if (window.scrollY === 0 && document.documentElement.scrollTop === 0) {
      // Apply resistance; subtract dead-zone so effective travel starts at 0.
      pullDistance = Math.min((diff - deadZone) * 0.5, maxPull)
    }
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

  onMount(() => {
    // Use passive: false for touchmove to allow preventDefault if needed
    document.addEventListener('touchstart', handleTouchStart, { passive: true })
    document.addEventListener('touchmove', handleTouchMove, { passive: true })
    document.addEventListener('touchend', handleTouchEnd, { passive: true })

    return () => {
      document.removeEventListener('touchstart', handleTouchStart)
      document.removeEventListener('touchmove', handleTouchMove)
      document.removeEventListener('touchend', handleTouchEnd)
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
    top: 60px; /* Below header */
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
