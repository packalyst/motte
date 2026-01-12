<script>
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPost, confirm, setConfirmLoading } from '../stores/app.js'
  import { copyWithToast } from '../stores/helpers.js'
  import { parseDate, formatDateShort, formatExpiryDate, isExpired, getDaysUntilExpiry } from '$lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Select from '../components/Select.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Checkbox from '../components/Checkbox.svelte'

  let { loading = $bindable(true) } = $props()

  let users = $state([])
  let authKeys = $state([])
  let showCreateModal = $state(false)
  let createForm = $state({ user: '', reusable: false, ephemeral: false, expiration: '90' })
  let creating = $state(false)
  let createdKey = $state(null)

  // Get server URL for command display (from settings)
  let serverUrl = $state('')

  async function loadData() {
    try {
      const [usersRes, settings] = await Promise.all([
        apiGet('/api/hs/users'),
        apiPost('/api/settings', { keys: ['headscale_url'] })
      ])
      users = usersRes.users || []
      serverUrl = settings.headscale_url || ''

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

  async function createKey() {
    if (!createForm.user) {
      toast('Please select a user', 'error')
      return
    }
    creating = true
    try {
      const expiration = new Date()
      const days = parseInt(createForm.expiration)
      expiration.setDate(expiration.getDate() + days)

      const res = await apiPost('/api/hs/preauthkeys', {
        user: createForm.user,
        reusable: createForm.reusable,
        ephemeral: createForm.ephemeral,
        expiration: expiration.toISOString()
      })
      createdKey = res.preAuthKey
      toast('Auth key created', 'success')
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      creating = false
    }
  }

  async function confirmExpireKey(key) {
    const confirmed = await confirm({
      title: 'Expire Auth Key',
      message: 'Expire this key?',
      description: 'This key will no longer work to register new devices. This action cannot be undone.',
      details: `<p><strong>Key:</strong> <code class="font-mono">${key.key?.substring(0, 16)}...</code></p><p><strong>User:</strong> ${key.userName || key.user}</p>`,
      confirmText: 'Expire Key',
      alert: true
    })
    if (!confirmed) return

    setConfirmLoading(true)
    try {
      await apiPost('/api/hs/preauthkeys/expire', { user: key.userName || key.user, key: key.key })
      toast('Key expired', 'success')
      loadData()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }

  const copyToClipboard = (text) => copyWithToast(text, toast)

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
    <Button onclick={() => { showCreateModal = true; createdKey = null }} size="sm" class="hidden sm:flex shrink-0">
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
        onclick={() => { showCreateModal = true; createdKey = null }}
        onkeydown={(e) => e.key === 'Enter' && (showCreateModal = true, createdKey = null)}
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

      {#each sortedKeys as key (key.key)}
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
              <code class="text-xs font-mono text-foreground truncate block">{key.key?.substring(0, 12)}...</code>
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
              {#if !key._expired && (!isUsed || key.reusable)}
                <button
                  onclick={() => copyToClipboard(`tailscale up --login-server=${serverUrl} --authkey=${key.key}`)}
                  class="icon-btn"
                  data-kt-tooltip
                >
                  <Icon name="copy" size={14} />
                  <span data-kt-tooltip-content class="kt-tooltip hidden">Copy command</span>
                </button>
              {:else}
                <span class="icon-btn cursor-not-allowed" data-kt-tooltip>
                  <Icon name="copy-off" size={14} />
                  <span data-kt-tooltip-content class="kt-tooltip hidden">{key._expired ? 'Key expired' : 'Key already used'}</span>
                </span>
              {/if}
              {#if isActive}
                <button
                  onclick={() => confirmExpireKey(key)}
                  class="icon-btn-destructive"
                  data-kt-tooltip
                >
                  <Icon name="ban" size={14} />
                  <span data-kt-tooltip-content class="kt-tooltip hidden">Expire key</span>
                </button>
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
      <Button onclick={() => { showCreateModal = true; createdKey = null }} size="sm">
        <Icon name="plus" size={14} />
        Create Key
      </Button>
    </EmptyState>
  {/if}
</div>

<!-- Create Modal -->
<Modal bind:open={showCreateModal} title={createdKey ? "Key Created" : "Create Auth Key"} size="sm">
  {#if createdKey}
    <div class="space-y-4">
      <div class="flex items-center gap-3 pb-3 border-b border-border">
        <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-success/15 text-success">
          <Icon name="check" size={20} />
        </div>
        <div>
          <p class="font-medium text-foreground">Auth Key Created</p>
          <p class="text-xs text-muted-foreground">Copy the command below to connect a device</p>
        </div>
      </div>

      <div>
        <label class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5 block">Command</label>
        <code class="block text-xs font-mono break-all p-3 bg-muted rounded-lg border border-border">tailscale up --login-server={serverUrl} --authkey={createdKey.key}</code>
      </div>

      <div class="grid grid-cols-2 gap-3 text-xs">
        <div class="p-2 bg-muted/50 rounded">
          <span class="text-muted-foreground">User:</span>
          <span class="text-foreground ml-1">{createdKey.user}</span>
        </div>
        <div class="p-2 bg-muted/50 rounded">
          <span class="text-muted-foreground">Expires:</span>
          <span class="text-foreground ml-1">{formatExpiryDate(createdKey.expiration)}</span>
        </div>
      </div>
    </div>
  {:else}
    <div class="space-y-4">
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Select label="User" bind:value={createForm.user}>
          <option value="">Select user...</option>
          {#each users as user}
            <option value={user.name}>{user.name}</option>
          {/each}
        </Select>
        <Select
          label="Expiration"
          bind:value={createForm.expiration}
          options={[
            { value: '1', label: '1 day' },
            { value: '7', label: '7 days' },
            { value: '30', label: '30 days' },
            { value: '90', label: '90 days' },
            { value: '365', label: '1 year' }
          ]}
        />
      </div>
      <div class="flex gap-4">
        <Checkbox variant="chip" bind:checked={createForm.reusable} icon="refresh" label="Reusable" />
        <Checkbox variant="chip" bind:checked={createForm.ephemeral} icon="clock" label="Ephemeral" color="warning" />
      </div>
      <div class="text-xs text-muted-foreground bg-muted/50 p-2 rounded space-y-1">
        <p><strong>Reusable:</strong> Key can register multiple devices (e.g., CI runners)</p>
        <p><strong>Ephemeral:</strong> Nodes auto-removed when offline (e.g., containers)</p>
        <p class="text-[10px] opacity-75">Both can be enabled for short-lived workloads like CI/CD pipelines</p>
      </div>
    </div>
  {/if}

  {#snippet footer()}
    {#if createdKey}
      <Button onclick={() => copyToClipboard(`tailscale up --login-server=${serverUrl} --authkey=${createdKey.key}`)} icon="copy">Copy Command</Button>
      <Button onclick={() => { showCreateModal = false; createdKey = null; createForm = { user: '', reusable: false, ephemeral: false, expiration: '90' } }} variant="secondary">Done</Button>
    {:else}
      <Button onclick={() => showCreateModal = false} variant="secondary">Cancel</Button>
      <Button onclick={createKey} disabled={creating || !createForm.user}>
        {creating ? 'Creating...' : 'Create'}
      </Button>
    {/if}
  {/snippet}
</Modal>

