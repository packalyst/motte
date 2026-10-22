<script>
  /**
   * AddPeerModal — creates a WireGuard peer, then shows its name/IP with config download and copy
   * (the private key is only available now). oncreated() lets the parent reload its list.
   */
  import { toast, apiPost } from '../stores/app.js'
  import { downloadPeerConfig, copyPeerConfig } from '$lib/nodes.js'
  import Icon from './Icon.svelte'
  import Modal from './Modal.svelte'
  import Input from './Input.svelte'
  import Button from './Button.svelte'
  import ContentBlock from './ContentBlock.svelte'

  let { open = $bindable(false), oncreated = undefined } = $props()

  let newPeerName = $state('')
  let createdPeer = $state(null)

  // Each opening starts a fresh form.
  $effect(() => {
    if (open) { newPeerName = ''; createdPeer = null }
  })

  async function createWgPeer() {
    if (!newPeerName.trim()) return
    try {
      createdPeer = await apiPost('/api/wg/peers', { name: newPeerName })
      toast('Peer created', 'success')
      oncreated?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }
</script>

<Modal bind:open title="Add WireGuard Node" size="md">
  {#if createdPeer}
    <div class="space-y-4">
      <div class="p-4 bg-success/10 border border-success/20 rounded-lg flex items-center gap-3">
        <div class="w-10 h-10 rounded-full bg-success/20 flex items-center justify-center shrink-0">
          <Icon name="check" size={20} class="text-success" />
        </div>
        <div>
          <p class="font-medium text-foreground">Peer created successfully!</p>
          <p class="text-xs text-muted-foreground mt-0.5">Save this configuration - the private key won't be shown again.</p>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-4">
        <ContentBlock variant="data" label="Name">
          <Icon name="device-desktop" size={14} class="text-muted-foreground mr-2" />
          <span class="text-sm font-medium text-foreground">{createdPeer.name}</span>
        </ContentBlock>
        <ContentBlock variant="data" label="IP Address">
          <Icon name="network" size={14} class="text-muted-foreground mr-2" />
          <code class="text-sm font-mono text-foreground">{createdPeer.ipAddress}</code>
        </ContentBlock>
      </div>
    </div>
  {:else}
    <Input
      label="Device Name"
      helperText="A friendly name to identify this device"
      bind:value={newPeerName}
      placeholder="e.g., iPhone, Laptop, Home Router"
    />
  {/if}

  {#snippet footer()}
    {#if createdPeer}
      <Button onclick={() => downloadPeerConfig(createdPeer.id, createdPeer.name)} icon="download">Download</Button>
      <Button onclick={() => copyPeerConfig(createdPeer.id)} variant="secondary" icon="copy">Copy Config</Button>
      <Button onclick={() => (open = false)} variant="secondary">Done</Button>
    {:else}
      <Button onclick={() => (open = false)} variant="secondary">Cancel</Button>
      <Button onclick={createWgPeer}>Create WireGuard Device</Button>
    {/if}
  {/snippet}
</Modal>
