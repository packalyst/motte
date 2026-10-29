<script>
  /**
   * CreateAuthKeyModal — creates a Headscale pre-auth key and shows the `tailscale up` command to
   * join a device with it. Self-contained (loads the users and the public Headscale URL when
   * opened) so the Auth Keys page and All clients → Add client both use it. oncreated() lets the
   * parent refresh its list.
   */
  import { toast, apiGet, apiPost, withStepUp, STEPUP_CANCELLED } from '../stores/app.js'
  import { formatExpiryDate } from '$lib/utils/format.js'
  import { tailscaleUpCommand } from '$lib/nodes.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Modal from './Modal.svelte'
  import Select from './Select.svelte'
  import Checkbox from './Checkbox.svelte'

  let { open = $bindable(false), oncreated = undefined } = $props()

  const blankForm = () => ({ user: '', reusable: false, ephemeral: false, expiration: '90' })
  let users = $state([])
  let serverUrl = $state('')
  let createForm = $state(blankForm())
  let creating = $state(false)
  let createdKey = $state(null)

  // Each opening starts a fresh form and reloads the users and the server URL.
  $effect(() => {
    if (!open) return
    createForm = blankForm()
    createdKey = null
    Promise.all([apiGet('/api/hs/users'), apiPost('/api/settings', { keys: ['headscale_url'] })])
      .then(([u, s]) => { users = u.users || []; serverUrl = s.headscale_url || '' })
      .catch((e) => toast('Failed to load users: ' + e.message, 'error'))
  })

  async function createKey() {
    if (!createForm.user) {
      toast('Please select a user', 'error')
      return
    }
    creating = true
    try {
      const expiration = new Date()
      expiration.setDate(expiration.getDate() + parseInt(createForm.expiration))
      const res = await withStepUp((extra) => apiPost('/api/hs/preauthkeys', {
        user: createForm.user,
        reusable: createForm.reusable,
        ephemeral: createForm.ephemeral,
        expiration: expiration.toISOString(),
        ...extra
      }), { title: 'Create auth key', message: 'Anyone with this key can add a device to the VPN.', confirmText: 'Create' })
      if (res === STEPUP_CANCELLED) return
      createdKey = res.preAuthKey
      toast('Auth key created', 'success')
      oncreated?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      creating = false
    }
  }
</script>

<Modal bind:open title={createdKey ? 'Key Created' : 'Create Auth Key'} size="sm">
  {#if createdKey}
    <div class="space-y-4">
      <div class="flex items-center gap-3 pb-3 border-b border-border">
        <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-success/15 text-success">
          <Icon name="check" size={20} />
        </div>
        <div>
          <p class="font-medium text-foreground">Auth Key Created</p>
          <p class="text-xs text-muted-foreground">Copy the command below to connect a device. It's shown only now: the key list keeps just its start.</p>
        </div>
      </div>

      <div>
        <span class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1.5 block">Command</span>
        <code class="block text-xs font-mono break-all p-3 bg-muted rounded-lg border border-border">{tailscaleUpCommand(serverUrl, createdKey.key)}</code>
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
          {#each users as user (user.name)}
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
      <Button copyText={tailscaleUpCommand(serverUrl, createdKey.key)} icon="copy">Copy Command</Button>
      <Button onclick={() => (open = false)} variant="secondary">Done</Button>
    {:else}
      <Button onclick={() => (open = false)} variant="secondary">Cancel</Button>
      <Button onclick={createKey} disabled={creating || !createForm.user}>
        {creating ? 'Creating...' : 'Create'}
      </Button>
    {/if}
  {/snippet}
</Modal>
