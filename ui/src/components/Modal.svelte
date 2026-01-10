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
    children,
    header,
    footer
  } = $props()

  const sizes = {
    sm: 'max-w-md',   // 448px
    md: 'max-w-xl',   // 576px
    lg: 'max-w-2xl'   // 672px
  }

  let modalElement = $state(null)
  let ktModal = $state(null)

  onMount(() => {
    if (modalElement && KTModal) {
      ktModal = KTModal.getOrCreateInstance(modalElement)

      // Listen for KTUI hide events (both hide and hidden)
      modalElement.addEventListener('hide.kt.modal', handleHideEvent)
      modalElement.addEventListener('hidden.kt.modal', handleHideEvent)
    }
  })

  function handleHideEvent() {
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
      modalElement.removeEventListener('hide.kt.modal', handleHideEvent)
      modalElement.removeEventListener('hidden.kt.modal', handleHideEvent)
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
  onclick={(e) => { if (e.target === modalElement) handleClose() }}
>
  <div class="kt-modal-content w-full {sizes[size]} top-[5%]">
    <div class="kt-modal-header {headerClass}">
      {#if header}
        {@render header()}
      {:else}
        <h3 class="kt-modal-title">{title}</h3>
      {/if}
      <button
        type="button"
        onclick={handleClose}
        class="kt-modal-close"
        aria-label="Close modal"
      >
        <Icon name="x" size={20} />
      </button>
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
