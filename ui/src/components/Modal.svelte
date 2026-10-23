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
      ktModal = KTModal.getOrCreateInstance(modalElement)

      // KTUI closes the modal itself on Escape and dispatches a plain 'hidden' event; sync `open`
      // from it so the modal can be opened again.
      modalElement.addEventListener('hidden', handleHideEvent)
      // KTUI's Escape handler closes any open modal; a non-dismissible one cancels that here.
      modalElement.addEventListener('hide', blockUnwantedHide)
    }
  })

  // Only while still meant to be open: closing through `open` (our own hide()) is never blocked.
  function blockUnwantedHide(e) {
    if (e.target === modalElement && open && !dismissible) e.detail.payload.cancel = true
  }

  function handleHideEvent(e) {
    // KTUI events bubble: a tooltip inside the modal fires 'hidden' too — only the modal's own counts
    if (e.target !== modalElement) return
    if (open) {
      if (onclose) {
        onclose()
      } else {
        open = false
      }
    }
  }

  onDestroy(() => {
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
    }
  })

  // React to open prop changes
  $effect(() => {
    if (ktModal) {
      if (open) {
        // Small delay to ensure previous modal is fully closed
        setTimeout(() => {
          if (open && ktModal) {
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
  <div class="kt-modal-content w-full {sizes[size]} top-[5%]">
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
