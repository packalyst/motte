<script>
  import { toast, apiGet, apiPost, apiDelete, confirm, setConfirmLoading } from '../stores/app.js'
  import { copyWithToast } from '../stores/helpers.js'
  import { parseDate, formatDateShort, formatExpiryDate, isExpired, getDaysUntilExpiry } from '$lib/utils/format.js'
  import { useDataLoader } from '$lib/composables/index.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Select from '../components/Select.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import InfoCard from '../components/InfoCard.svelte'

  let { loading = $bindable(true) } = $props()

  // Data loading with useDataLoader
  const loader = useDataLoader(
    () => apiGet('/api/hs/apikeys'),
    { extract: 'apiKeys', isArray: true, errorMsg: 'Failed to load API keys' }
  )

  // Transform keys to add _expired flag
  const apiKeys = $derived(
    (loader.data || []).map(k => ({ ...k, _expired: isExpired(k.expiration) }))
  )

  // Sync loading state to parent
  $effect(() => { loading = loader.loading })

  let showCreateModal = $state(false)
  let newExpiration = $state('90')
  let newKey = $state(null)
  let creating = $state(false)

  // Sorted keys - active first, expired last
  const sortedKeys = $derived(
    [...apiKeys].sort((a, b) => {
      // Expired always last
      if (a._expired !== b._expired) return a._expired ? 1 : -1
      // Then by expiration date
      const dateA = parseDate(a.expiration)
      const dateB = parseDate(b.expiration)
      if (!dateA || !dateB) return 0
      return a._expired ? dateB - dateA : dateA - dateB
    })
  )

  async function createKey() {
    creating = true
    try {
      const expiration = new Date()
      expiration.setDate(expiration.getDate() + parseInt(newExpiration))

      const res = await apiPost('/api/hs/apikeys', { expiration: expiration.toISOString() })
      newKey = res.apiKey
      toast('API key created', 'success')
      loader.reload()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      creating = false
    }
  }

  async function confirmExpireKey(key) {
    const confirmed = await confirm({
      title: 'Expire API Key',
      message: `Expire key ${key.prefix}...?`,
      description: 'This key will no longer work for API access. This action cannot be undone.',
      confirmText: 'Expire Key',
      alert: true
    })
    if (!confirmed) return

    setConfirmLoading(true)
    try {
      await apiDelete(`/api/hs/apikeys/${key.prefix}`)
      toast('Key expired', 'success')
      loader.reload()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }

  const copyToClipboard = (text) => copyWithToast(text, toast)
</script>

<div class="space-y-4">
  <InfoCard
    icon="key"
    title="API Keys"
    description="Generate API keys for programmatic access to Headscale. Use these keys for automation, scripts, or third-party integrations."
  >
    <Button onclick={() => { showCreateModal = true; newKey = null }} size="sm" class="hidden sm:flex shrink-0">
      <Icon name="plus" size={16} />
      Create Key
    </Button>
  </InfoCard>

  {#if loading}
    <LoadingSpinner centered size="lg" />
  {:else if sortedKeys.length > 0}
    <div class="grid-cards">
      <!-- Add key card - always first -->
      <div
        onclick={() => { showCreateModal = true; newKey = null }}
        onkeydown={(e) => e.key === 'Enter' && (showCreateModal = true, newKey = null)}
        role="button"
        tabindex="0"
        class="add-item-card"
      >
        <div class="flex h-8 w-8 items-center justify-center rounded-full bg-secondary text-foreground">
          <Icon name="plus" size={16} />
        </div>
        <div class="font-medium text-foreground">Create API key</div>
        <p class="max-w-[200px] text-muted-foreground">
          Generate keys for programmatic access
        </p>
      </div>

      {#each sortedKeys as key (key.id + '-' + (key.expiration?.seconds || key.expiration))}
        {@const daysLeft = getDaysUntilExpiry(key.expiration)}
        {@const isExpiringSoon = daysLeft !== null && daysLeft > 0 && daysLeft <= 7}
        {@const statusClass = key._expired ? 'error' : isExpiringSoon ? 'warning' : 'success'}

        <div class="bg-card border border-border rounded-lg overflow-hidden hover:border-primary/50 transition-colors shadow-sm card-border-{statusClass} {key._expired ? 'opacity-60' : ''}">
          <!-- Header -->
          <div class="flex items-center gap-3 p-3">
            <div class="status-icon status-icon-{statusClass}">
              <Icon name="key" size={18} />
            </div>
            <div class="flex-1 min-w-0">
              <code class="text-sm font-mono text-foreground truncate block">{key.prefix}...</code>
              <div class="text-[11px] text-muted-foreground flex items-center gap-1 mt-0.5">
                <Icon name="clock" size={11} />
                {formatExpiryDate(key.expiration)}
              </div>
            </div>
          </div>

          <!-- Info -->
          <div class="grid grid-cols-2 gap-x-3 border-t border-border px-3 py-2.5 text-[11px]">
            <div class="flex items-center gap-1.5">
              <Icon name="plus" size={12} class="text-dim" />
              <span class="text-muted-foreground">{formatDateShort(key.createdAt)}</span>
            </div>
            <div class="flex items-center gap-1.5">
              <Icon name="clock" size={12} class="text-dim" />
              <span class="text-muted-foreground">{formatDateShort(key.expiration)}</span>
            </div>
          </div>

          <!-- Actions -->
          <div class="flex items-center justify-between px-2 py-1.5 border-t border-border bg-muted/30">
            <div class="flex items-center gap-1.5 text-[10px]">
              {#if key._expired}
                <span class="kt-badge kt-badge-xs kt-badge-outline kt-badge-destructive">Expired</span>
              {:else if isExpiringSoon}
                <span class="kt-badge kt-badge-xs kt-badge-success">Active</span>
                <span class="kt-badge kt-badge-xs kt-badge-outline kt-badge-warning">Expiring soon</span>
              {:else}
                <span class="kt-badge kt-badge-xs kt-badge-success">Active</span>
              {/if}
            </div>
            <div class="flex items-center gap-0.5">
              {#if !key._expired}
                <button
                  onclick={() => confirmExpireKey(key)}
                  class="icon-btn-destructive"
                  data-kt-tooltip
                >
                  <Icon name="ban" size={14} />
                  <span data-kt-tooltip-content class="kt-tooltip hidden">Expire key</span>
                </button>
              {:else}
                <span class="icon-btn cursor-not-allowed" data-kt-tooltip>
                  <Icon name="ban" size={14} />
                  <span data-kt-tooltip-content class="kt-tooltip hidden">Key expired</span>
                </span>
              {/if}
            </div>
          </div>
        </div>
      {/each}
    </div>
  {:else}
    <EmptyState
      icon="key"
      title="No API keys"
      description="Create an API key for programmatic access"
    >
      <Button onclick={() => { showCreateModal = true; newKey = null }} size="sm">
        <Icon name="plus" size={14} />
        Create Key
      </Button>
    </EmptyState>
  {/if}
</div>

<!-- Create Modal -->
<Modal bind:open={showCreateModal} title={newKey ? "Key Created" : "Create API Key"} size="sm">
  {#if newKey}
    <div class="space-y-4">
      <div class="flex items-center gap-3 pb-3 border-b border-border">
        <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-success/15 text-success">
          <Icon name="check" size={20} />
        </div>
        <div>
          <p class="font-medium text-foreground">API Key Created</p>
          <p class="text-xs text-muted-foreground">Save this key now - you won't see it again</p>
        </div>
      </div>

      <div>
        <label class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5 block">API Key</label>
        <code class="block text-xs font-mono break-all p-3 bg-muted rounded-lg border border-border">{newKey}</code>
      </div>
    </div>
  {:else}
    <Select
      label="Expiration"
      bind:value={newExpiration}
      options={[
        { value: '7', label: '7 days' },
        { value: '30', label: '30 days' },
        { value: '90', label: '90 days' },
        { value: '365', label: '1 year' }
      ]}
      helperText="Key will expire on {new Date(Date.now() + parseInt(newExpiration) * 24 * 60 * 60 * 1000).toLocaleDateString()}"
    />
  {/if}

  {#snippet footer()}
    {#if newKey}
      <Button onclick={() => copyToClipboard(newKey)} icon="copy">Copy to Clipboard</Button>
      <Button onclick={() => showCreateModal = false} variant="secondary">Done</Button>
    {:else}
      <Button onclick={() => showCreateModal = false} variant="secondary">Cancel</Button>
      <Button onclick={createKey} disabled={creating}>
        {creating ? 'Creating...' : 'Create'}
      </Button>
    {/if}
  {/snippet}
</Modal>

