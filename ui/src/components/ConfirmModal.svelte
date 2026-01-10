<script>
  import { confirmModalStore, closeConfirmModal } from '../stores/app.js'
  import Modal from './Modal.svelte'
  import Button from './Button.svelte'
  import Icon from './Icon.svelte'

  const iconMap = {
    destructive: 'alert-triangle',
    warning: 'alert-circle',
    primary: 'help-circle',
    success: 'lock-open'
  }

  const colorMap = {
    destructive: 'text-destructive',
    warning: 'text-warning',
    primary: 'text-primary',
    success: 'text-success'
  }

  const bgMap = {
    destructive: 'bg-destructive/10 border-destructive/20',
    warning: 'bg-warning/10 border-warning/20',
    primary: 'bg-primary/10 border-primary/20',
    success: 'bg-success/10 border-success/20'
  }

  // Map variant to kt-alert class
  const alertMap = {
    destructive: 'kt-alert-destructive',
    warning: 'kt-alert-warning',
    primary: 'kt-alert-primary',
    success: 'kt-alert-success'
  }

  // Map modal variant to button variant (success -> primary since Button doesn't have success)
  const buttonVariantMap = {
    destructive: 'destructive',
    warning: 'primary',
    primary: 'primary',
    success: 'primary'
  }

  function handleConfirm() {
    closeConfirmModal(true)
  }

  function handleCancel() {
    closeConfirmModal(false)
  }
</script>

{#if $confirmModalStore.open}
  <Modal open={$confirmModalStore.open} title={$confirmModalStore.title} size="sm" onclose={handleCancel}>
    <div class="space-y-4">
      {#if $confirmModalStore.alert}
        <!-- Alert style layout -->
        <div class="kt-alert {alertMap[$confirmModalStore.variant]}">
          <Icon name={iconMap[$confirmModalStore.variant]} size={18} />
          <div>
            <p class="font-medium">{$confirmModalStore.message}</p>
            {#if $confirmModalStore.description}
              <p class="text-sm opacity-80 mt-0.5">{$confirmModalStore.description}</p>
            {/if}
          </div>
        </div>
      {:else}
        <!-- Default circular badge layout -->
        <div class="flex gap-3">
          <div class="flex-shrink-0 w-10 h-10 rounded-full {bgMap[$confirmModalStore.variant]} border flex items-center justify-center">
            <Icon name={iconMap[$confirmModalStore.variant]} size={20} class={colorMap[$confirmModalStore.variant]} />
          </div>
          <div class="flex-1">
            <p class="text-foreground">{$confirmModalStore.message}</p>
            {#if $confirmModalStore.description}
              <p class="text-muted-foreground text-sm mt-1">{$confirmModalStore.description}</p>
            {/if}
          </div>
        </div>
      {/if}

      {#if $confirmModalStore.details}
        <div class="text-xs text-muted-foreground">
          {@html $confirmModalStore.details}
        </div>
      {/if}

      {#if $confirmModalStore.warning}
        <div class="p-3 {bgMap[$confirmModalStore.variant]} border rounded-md">
          <p class="{colorMap[$confirmModalStore.variant]} text-sm font-medium">{$confirmModalStore.warning}</p>
        </div>
      {/if}
    </div>

    {#snippet footer()}
      <Button onclick={handleCancel} variant="secondary" disabled={$confirmModalStore.loading}>
        {$confirmModalStore.cancelText}
      </Button>
      <Button onclick={handleConfirm} variant={buttonVariantMap[$confirmModalStore.variant]} disabled={$confirmModalStore.loading}>
        {#if $confirmModalStore.loading}
          <Icon name="refresh" size={14} class="animate-spin mr-1" />
        {/if}
        {$confirmModalStore.confirmText}
      </Button>
    {/snippet}
  </Modal>
{/if}
