<script>
  /**
   * HsAuthKeys — the Auth keys section of the Headscale page (admins only: the keys are read with
   * the admin-only /api/hs/keys, and the page doesn't mount it for others). keys come from the page;
   * after a change onchange() reloads them. search filters by key prefix or owner; stats reports
   * { total, shown, active } to the page.
   */
  import { toast, apiPost, confirm, setConfirmLoading } from '../../stores/app.js'
  import { sortKeys, keyWorks, keyOwner } from '$lib/hskeys.js'
  import Icon from '../Icon.svelte'
  import Button from '../Button.svelte'
  import EmptyState from '../EmptyState.svelte'
  import GroupHeading from '../GroupHeading.svelte'
  import HsKeyRow from './HsKeyRow.svelte'
  import CreateAuthKeyModal from '../CreateAuthKeyModal.svelte'

  let { keys = [], search = '', stats = $bindable(null), onchange } = $props()

  let showCreateModal = $state(false)

  const sorted = $derived(sortKeys(keys))
  const q = $derived(search.trim().toLowerCase())
  const shownKeys = $derived(q ? sorted.filter((k) => `${k.keyPrefix || ''} ${keyOwner(k)}`.toLowerCase().includes(q)) : sorted)
  const activeCount = $derived(keys.filter(keyWorks).length)
  $effect(() => { stats = { total: keys.length, shown: shownKeys.length, active: activeCount } })

  async function confirmExpireKey(key) {
    const confirmed = await confirm({
      title: 'Expire Auth Key',
      message: 'Expire this key?',
      description: 'This key will no longer work to register new devices. This action cannot be undone.',
      // Structured rows are auto-escaped by the modal — no manual escaping / {@html} needed.
      details: [
        { label: 'Key:', value: (key.keyPrefix || '') + '…' },
        { label: 'User:', value: keyOwner(key) },
      ],
      confirmText: 'Expire Key',
      alert: true
    })
    if (!confirmed) return

    setConfirmLoading(true)
    try {
      await apiPost('/api/hs/preauthkeys/expire', { user: keyOwner(key), id: key.id })
      toast('Key expired', 'success')
      onchange?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }
</script>

<section class="space-y-2" aria-label="Auth keys">
  <GroupHeading title="Auth keys" color="var(--color-success)" note="{activeCount} active"
    action={{ label: 'Create key', onclick: () => (showCreateModal = true) }} />

  {#if keys.length > 0}
    <ul class="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {#each shownKeys as key (keyOwner(key) + ':' + key.id)}
        <HsKeyRow {key} prefix={key.keyPrefix} label="key {key.keyPrefix} of {keyOwner(key)}" onexpire={() => confirmExpireKey(key)}>
          {#snippet meta()}
            <span class="inline-flex min-w-0 items-center gap-1 text-[11px] text-muted-foreground"><Icon name="user" size={11} /><span class="truncate">{keyOwner(key)}</span></span>
          {/snippet}
          {#snippet facts()}
            <span>·</span><span>{key.reusable ? 'Reusable' : 'Single-use'}</span>
            {#if key.ephemeral}<span>·</span><span class="text-info" title="Devices that join with it are removed when they go offline">Ephemeral</span>{/if}
          {/snippet}
        </HsKeyRow>
      {/each}
    </ul>
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
</section>

<CreateAuthKeyModal bind:open={showCreateModal} oncreated={onchange} />
