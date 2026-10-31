<script module>
  // Stacked modals (a confirm or step-up opened from inside another modal) that are open right now.
  // KTUI allows one modal at a time: showing one hides every other, and Escape hides the first one
  // open in the page. While a stacked modal is open, the modals under it refuse those hides, so
  // they are still there, unchanged, when it closes.
  const openStacked = new Set()
</script>

<script>
  import { onMount, onDestroy } from 'svelte'
  import Icon from './Icon.svelte'

  const KTModal = window.KTModal

  let {
    open = $bindable(false),
    onclose,
    title = '',
    size = 'md',
    headerClass = '',
    bodyClass = '',
    dismissible = true, // when false, neither a backdrop click nor Escape closes the modal
    showClose = true,   // when false, the header X is hidden (e.g. gate close until an action)
    stacked = false,    // opens on top of an open modal, which stays open under it (confirm dialogs)
    children,
    header,
    footer
  } = $props()

  const sizes = {
    sm: 'max-w-md',   // 448px
    md: 'max-w-xl',   // 576px
    lg: 'max-w-2xl',  // 672px
    wide: 'max-w-3xl', // 768px
    xl: 'max-w-4xl'   // 896px
  }

  let modalElement = $state(null)
  let ktModal = $state(null)

  onMount(() => {
    if (modalElement && KTModal) {
      // A stacked modal sits above the modals under it, its backdrop included (KTUI's default is 90).
      ktModal = KTModal.getOrCreateInstance(modalElement, stacked ? { zindex: '100' } : undefined)

      // KTUI closes the modal itself on Escape and dispatches a plain 'hidden' event; sync `open`
      // from it so the modal can be opened again.
      modalElement.addEventListener('hidden', handleHideEvent)
      // KTUI's Escape handler closes any open modal; a non-dismissible one cancels that here.
      modalElement.addEventListener('hide', blockUnwantedHide)
    }
  })

  // Only while still meant to be open: closing through `open` (our own hide()) is never blocked.
  // KTUI's own hides are refused for a non-dismissible modal, and for any modal under an open
  // stacked one (see openStacked).
  function blockUnwantedHide(e) {
    if (e.target !== modalElement || !open) return
    if (!dismissible || (!stacked && openStacked.size > 0)) e.detail.payload.cancel = true
  }

  // KTUI loses track of a backdrop when a modal reopens while its close is still fading out (it
  // removes the new backdrop and leaves the old one, invisible, over the whole page, so nothing
  // can be clicked any more). Once no modal is open, any backdrop left is an orphan: remove it.
  function sweepBackdrops() {
    if (document.querySelector('.kt-modal.open')) return
    const stale = document.querySelectorAll('.kt-modal-backdrop')
    if (!stale.length) return // nothing left behind: the scroll lock isn't ours to touch
    stale.forEach((el) => el.remove())
    document.body.style.overflow = '' // KTModal's lock, left with its backdrop
  }

  function handleHideEvent(e) {
    // KTUI events bubble: a tooltip inside the modal fires 'hidden' too — only the modal's own counts
    if (e.target !== modalElement) return
    if (stacked) {
      openStacked.delete(modalElement)
      // KTUI unlocked page scroll on hide; a modal still open under this one needs it locked.
      if (document.querySelector('.kt-modal.open')) document.body.style.overflow = 'hidden'
    }
    sweepBackdrops()
    if (open) {
      if (onclose) {
        onclose()
      } else {
        open = false
      }
    }
  }

  onDestroy(() => {
    openStacked.delete(modalElement)
    if (modalElement) {
      modalElement.removeEventListener('hidden', handleHideEvent)
      modalElement.removeEventListener('hide', blockUnwantedHide)
    }
    if (ktModal) {
      ktModal.hide()
      // Dispose of the instance to prevent conflicts
      if (ktModal.dispose) {
        ktModal.dispose()
      }
      setTimeout(sweepBackdrops, 500) // the element is gone, so no 'hidden' arrives: sweep after the fade
    }
  })

  // React to open prop changes
  $effect(() => {
    if (ktModal) {
      if (open) {
        // Small delay to ensure previous modal is fully closed
        setTimeout(() => {
          if (open && ktModal) {
            if (stacked) openStacked.add(modalElement) // before show(): its hide of the others must be refused
            ktModal.show()
          }
        }, 10)
      } else {
        ktModal.hide()
      }
    }
  })

  function handleClose() {
    if (onclose) {
      onclose()
    } else {
      open = false
    }
  }
</script>

<div
  bind:this={modalElement}
  class="kt-modal"
  data-kt-modal="true"
  data-kt-modal-backdrop="true"
  data-kt-modal-backdrop-static="true"
  role="presentation"
  onclick={(e) => { if (dismissible && e.target === modalElement) handleClose() }}
>
  <!-- centred on every screen size (the overlay is fixed full-screen with p-4) -->
  <div class="kt-modal-content my-auto w-full {sizes[size]}">
    <div class="kt-modal-header {headerClass}">
      {#if header}
        {@render header()}
      {:else}
        <h3 class="kt-modal-title">{title}</h3>
      {/if}
      {#if showClose}
        <button
          type="button"
          onclick={handleClose}
          class="kt-modal-close"
          aria-label="Close modal"
        >
          <Icon name="x" size={20} />
        </button>
      {/if}
    </div>
    <div class="kt-modal-body {bodyClass}">
      {@render children()}
    </div>
    {#if footer}
      <div class="kt-modal-footer">
        {@render footer()}
      </div>
    {/if}
  </div>
</div>
