<script>
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPost, confirm, setConfirmLoading } from '../stores/app.js'
  import { parseDate, formatExpiryDate, isExpired, getDaysUntilExpiry } from '$lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import CreateAuthKeyModal from '../components/CreateAuthKeyModal.svelte'

  let { loading = $bindable(true) } = $props()

  let users = $state([])
  let authKeys = $state([])
  let showCreateModal = $state(false)

  async function loadData() {
    try {
      users = (await apiGet('/api/hs/users')).users || []

      // Load keys for all users
      const allKeys = []
      for (const user of users) {
        try {
          const res = await apiGet(`/api/hs/preauthkeys?user=${user.name}`)
          const keys = res.preAuthKeys || []
          keys.forEach(k => {
            k.userName = user.name
            k._expired = isExpired(k.expiration)
            allKeys.push(k)
          })
        } catch (e) {
          // Skip users with no keys or errors
        }
      }
      authKeys = allKeys
    } catch (e) {
      toast('Failed to load auth keys: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  // Sorted keys - active first, used in middle, expired last
  const sortedKeys = $derived(
    [...authKeys].sort((a, b) => {
      // Expired always last
      if (a._expired !== b._expired) return a._expired ? 1 : -1
      // Then active (not used) before used
      const aActive = !a._expired && !a.used
      const bActive = !b._expired && !b.used
      if (aActive !== bActive) return aActive ? -1 : 1
      // Then by expiration date
      const dateA = parseDate(a.expiration)
      const dateB = parseDate(b.expiration)
      if (!dateA || !dateB) return 0
      return aActive ? dateA - dateB : dateB - dateA
    })
  )

  async function confirmExpireKey(key) {
    const confirmed = await confirm({
      title: 'Expire Auth Key',
      message: 'Expire this key?',
      description: 'This key will no longer work to register new devices. This action cannot be undone.',
      // Structured rows are auto-escaped by the modal — no manual escaping / {@html} needed.
      details: [
        { label: 'Key:', value: (key.keyPrefix || '') + '…' },
        { label: 'User:', value: key.userName || key.user || '' },
      ],
      confirmText: 'Expire Key',
      alert: true
    })
    if (!confirmed) return

    setConfirmLoading(true)
    try {
      await apiPost('/api/hs/preauthkeys/expire', { user: key.userName || key.user, id: key.id })
      toast('Key expired', 'success')
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }

  onMount(() => {
    loadData()
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="key"
    title="Pre-Authentication Keys"
    description="Generate keys to automatically register devices without manual approval. Perfect for CI/CD pipelines, containerized workloads, or bulk device onboarding."
  >
    <Button onclick={() => (showCreateModal = true)} size="sm" class="hidden sm:flex shrink-0">
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
        onclick={() => (showCreateModal = true)}
        onkeydown={(e) => e.key === 'Enter' && (showCreateModal = true)}
        role="button"
        tabindex="0"
        class="add-item-card"
      >
        <div class="flex h-8 w-8 items-center justify-center rounded-full bg-secondary text-foreground">
          <Icon name="plus" size={16} />
        </div>
        <div class="font-medium text-foreground">Create auth key</div>
        <p class="max-w-[200px] text-muted-foreground">
          Allow devices to join automatically
        </p>
      </div>

      {#each sortedKeys as key (key.userName + ':' + key.id)}
        {@const daysLeft = getDaysUntilExpiry(key.expiration)}
        {@const isExpiringSoon = daysLeft !== null && daysLeft > 0 && daysLeft <= 7}
        {@const isUsed = key.used}
        {@const isActive = !key._expired && !isUsed}
        {@const statusClass = key._expired ? 'error' : isUsed ? 'muted' : isExpiringSoon ? 'warning' : 'success'}

        <div class="bg-card border border-border rounded-lg overflow-hidden hover:border-primary/50 transition-colors shadow-sm card-border-{statusClass} {key._expired ? 'opacity-60' : ''}">
          <!-- Header -->
          <div class="flex items-center gap-3 p-3">
            <div class="status-icon status-icon-{statusClass}">
              <Icon name="key" size={18} />
            </div>
            <div class="flex-1 min-w-0">
              <code class="text-xs font-mono text-foreground truncate block">{key.keyPrefix}…</code>
              <div class="text-[11px] text-muted-foreground flex items-center gap-1 mt-0.5">
                <Icon name="user" size={11} />
                {key.userName || key.user}
              </div>
            </div>
          </div>

          <!-- Info -->
          <div class="border-t border-border px-3 py-2.5 text-[11px] space-y-1.5">
            <div class="flex items-center gap-1.5">
              <Icon name="clock" size={12} class="text-dim" />
              <span class="text-muted-foreground truncate">{formatExpiryDate(key.expiration)}</span>
            </div>
            <div class="flex items-center gap-2 flex-wrap">
              {#if key.reusable}
                <span class="flex items-center gap-1 text-info">
                  <Icon name="refresh" size={12} />
                  Reusable
                </span>
              {:else}
                <span class="flex items-center gap-1 text-muted-foreground">
                  <Icon name="hand-stop" size={12} />
                  Single-use
                </span>
              {/if}
              {#if key.ephemeral}
                <span class="flex items-center gap-1 text-warning">
                  <Icon name="clock" size={12} />
                  Ephemeral
                </span>
              {/if}
            </div>
          </div>

          <!-- Actions -->
          <div class="flex items-center justify-between px-2 py-1.5 border-t border-border bg-muted/30">
            <div class="flex items-center gap-1.5 text-[10px]">
              {#if key._expired}
                <span class="kt-badge kt-badge-xs kt-badge-outline kt-badge-destructive">Expired</span>
              {:else if isUsed && !key.reusable}
                <span class="kt-badge kt-badge-xs kt-badge-outline kt-badge-secondary">Used</span>
              {:else if isExpiringSoon}
                <span class="kt-badge kt-badge-xs kt-badge-success">Active</span>
                <span class="kt-badge kt-badge-xs kt-badge-outline kt-badge-warning">Expiring soon</span>
              {:else}
                <span class="kt-badge kt-badge-xs kt-badge-success">Active</span>
              {/if}
            </div>
            <div class="flex items-center gap-0.5">
              {#if isActive}
                <Button variant="ghost-danger" size="xs" iconOnly icon="ban" tooltip="Expire key" onclick={() => confirmExpireKey(key)} />
              {/if}
            </div>
          </div>
        </div>
      {/each}
    </div>
  {:else}
    <EmptyState
      icon="key"
      title="No auth keys"
      description="Create keys to allow devices to join automatically"
    >
      <Button onclick={() => (showCreateModal = true)} size="sm">
        <Icon name="plus" size={14} />
        Create Key
      </Button>
    </EmptyState>
  {/if}
</div>

<CreateAuthKeyModal bind:open={showCreateModal} oncreated={loadData} />
