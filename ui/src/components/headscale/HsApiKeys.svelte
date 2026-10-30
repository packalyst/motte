<script>
  /**
   * HsApiKeys — the API keys section of the Headscale page (admins only, like the server; the page
   * doesn't mount it for others). keys come from the page; after a change onchange() reloads them.
   * search filters by key prefix; stats reports { total, shown, active } to the page.
   */
  import { toast, apiPost, apiDelete, confirm, setConfirmLoading, withStepUp, STEPUP_CANCELLED } from '../../stores/app.js'
  import { formatDateShort, timeAgo, withTz } from '$lib/utils/format.js'
  import { sortKeys, keyWorks } from '$lib/hskeys.js'
  import Icon from '../Icon.svelte'
  import Button from '../Button.svelte'
  import Modal from '../Modal.svelte'
  import Select from '../Select.svelte'
  import EmptyState from '../EmptyState.svelte'
  import GroupHeading from '../GroupHeading.svelte'
  import HsKeyRow from './HsKeyRow.svelte'

  let { keys = [], search = '', stats = $bindable(null), onchange } = $props()

  let showCreateModal = $state(false)
  let newExpiration = $state('90')
  let newKey = $state(null)
  let creating = $state(false)

  const sorted = $derived(sortKeys(keys))
  const q = $derived(search.trim().toLowerCase())
  const shownKeys = $derived(q ? sorted.filter((k) => (k.prefix || '').toLowerCase().includes(q)) : sorted)
  const activeCount = $derived(keys.filter(keyWorks).length)
  $effect(() => { stats = { total: keys.length, shown: shownKeys.length, active: activeCount } })
  const openCreate = () => { showCreateModal = true; newKey = null }

  async function createKey() {
    creating = true
    try {
      const expiration = new Date()
      expiration.setDate(expiration.getDate() + parseInt(newExpiration))

      const res = await withStepUp((extra) => apiPost('/api/hs/apikeys', { expiration: expiration.toISOString(), ...extra }),
        { title: 'Create API key', message: 'An API key gives full control of Headscale.', confirmText: 'Create' })
      if (res === STEPUP_CANCELLED) return
      newKey = res.apiKey
      toast('API key created', 'success')
      onchange?.()
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
      onchange?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }
</script>

<section class="space-y-2" aria-label="API keys">
  <GroupHeading title="API keys" color="var(--color-warning)" note="{activeCount} active"
    action={{ label: 'Create API key', onclick: openCreate }} />

  {#if keys.length > 0}
    <ul class="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {#each shownKeys as key (key.id)}
        <HsKeyRow {key} prefix={key.prefix} label="API key {key.prefix}" onexpire={() => confirmExpireKey(key)}>
          {#snippet facts()}
            {#if key.createdAt}<span>·</span><span>created {formatDateShort(key.createdAt)}</span>{/if}
            {#if key.lastSeen}<span>·</span><span>last used {timeAgo(key.lastSeen)}</span>{/if}
          {/snippet}
        </HsKeyRow>
      {/each}
    </ul>
  {:else}
    <EmptyState
      icon="key"
      title="No API keys"
      description="Create an API key for programmatic access"
    >
      <Button onclick={openCreate} size="sm">
        <Icon name="plus" size={14} />
        Create Key
      </Button>
    </EmptyState>
  {/if}
</section>

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
        <span class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5 block">API Key</span>
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
      helperText="Key will expire on {new Date(Date.now() + parseInt(newExpiration) * 24 * 60 * 60 * 1000).toLocaleDateString(undefined, withTz())}"
    />
  {/if}

  {#snippet footer()}
    {#if newKey}
      <Button copyText={newKey} icon="copy">Copy to Clipboard</Button>
      <Button onclick={() => showCreateModal = false} variant="secondary">Done</Button>
    {:else}
      <Button onclick={() => showCreateModal = false} variant="secondary">Cancel</Button>
      <Button onclick={createKey} disabled={creating}>
        {creating ? 'Creating...' : 'Create'}
      </Button>
    {/if}
  {/snippet}
</Modal>

