<script>
  /**
   * AllowedPorts — the firewall's allowed incoming ports (Settings → Firewall), by port number; amber
   * = open to the internet, green = VPN & LAN only. Each port shows its service, whether
   * it's a system port, one you added or Docker's, and one control: Public / Private plus remove
   * (ports you added) or a lock saying why it stays. The panel API port and Docker's ports can't
   * change exposure. Every change is confirmed; the server enforces who may do it.
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, apiDelete, toast, confirm } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Input from './Input.svelte'
  import Segmented from './Segmented.svelte'
  import SegmentedAction from './SegmentedAction.svelte'
  import TileRow from './TileRow.svelte'

  let ports = $state([])
  let newPort = $state('')

  // kind: docker (published by a container), pinned (always private), required (system), removable
  const KIND = {
    docker: { icon: 'brand-docker', text: 'Docker', lock: 'Published by a Docker container: change it in its compose file.' },
    pinned: { icon: 'server', text: 'System', lock: "Always private: the panel API is never reachable from the internet. Open the panel through your domain or the server's IP." },
    required: { icon: 'server', text: 'System', lock: "System port: it can't be removed, only made public or private." },
    removable: { icon: 'user', text: 'Your port' },
  }
  const kindOf = (p) => (!p.lockable ? 'docker' : p.pinned ? 'pinned' : p.essential ? 'required' : 'removable')
  const isPublic = (p) => p.scope !== 'private' && !p.pinned
  const proto = (p) => (p.protocol || 'tcp').toLowerCase()
  const label = (p) => (p.service ? `${p.port} (${p.service})` : `port ${p.port}`)

  const sorted = $derived([...ports].sort((a, b) => a.port - b.port))

  async function load() {
    try {
      const res = await apiGet('/api/fw/ports')
      ports = res.ports || res || []
    } catch (e) {
      toast('Failed to load ports: ' + e.message, 'error')
    }
  }
  onMount(load)

  async function addPort() {
    const port = parseInt(newPort)
    if (!port || port < 1 || port > 65535) {
      toast('Invalid port number', 'error')
      return
    }
    try {
      await apiPost('/api/fw/ports', { port, protocol: 'tcp' })
      toast(`Port ${port} added`, 'success')
      newPort = ''
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function removePort(p) {
    const ok = await confirm({
      title: 'Remove Port',
      message: `Remove port ${p.port}/${proto(p).toUpperCase()}?`,
      description: 'This port will no longer allow incoming connections.',
      confirmText: 'Remove',
    })
    if (!ok) return
    try {
      await apiDelete(`/api/fw/ports/${p.port}?protocol=${proto(p)}`)
      toast(`Port ${p.port} removed`, 'success')
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // setScope moves a port between public (reachable from the internet) and private (VPN/LAN only),
  // confirmed both ways: private can cut off outside access, public exposes it.
  async function setScope(p, target) {
    const makingPrivate = target === 'private'
    const ok = await confirm({
      title: makingPrivate ? `Make ${label(p)} private?` : `Make ${label(p)} public?`,
      message: makingPrivate ? `${label(p)} will stop answering on the internet.` : `${label(p)} will be reachable from the internet again.`,
      description: makingPrivate
        ? 'It stays reachable over WireGuard and the local network — use this for admin pages and DNS you don’t want exposed.'
        : 'Anyone on the internet can reach this port (still subject to your other firewall rules).',
      confirmText: makingPrivate ? 'Make private' : 'Make public',
    })
    if (!ok) return
    try {
      await apiPost('/api/fw/ports/scope', { port: p.port, protocol: p.protocol, scope: target })
      toast(`Port ${p.port} is now ${target}`, 'success')
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }
</script>

{#snippet row(p)}
  {@const k = kindOf(p)}
  {@const pub = isPublic(p)}
  <TileRow value={p.port} unit={proto(p)} tone={pub ? 'warning' : 'success'} title={p.service || 'Custom port'} subIcon={KIND[k].icon} sub={KIND[k].text}>
    {#snippet action()}
      {#if k === 'removable'}
        <SegmentedAction icon="trash" tooltip="Remove port" label="Remove port {p.port}" danger onclick={() => removePort(p)} />
      {:else}
        <SegmentedAction icon="lock" tooltip={KIND[k].lock} />
      {/if}
    {/snippet}
    <Segmented size="sm" class="shrink-0" label="Exposure of port {p.port}" disabled={k === 'docker' || k === 'pinned'}
      value={pub ? 'public' : 'private'} onchange={(v) => setScope(p, v)} trailing={action}
      options={[{ value: 'public', label: 'Public', tone: 'warning' }, { value: 'private', label: 'Private', tone: 'success' }]} />
  </TileRow>
{/snippet}

<div class="panel">
  <div class="panel-head">
    <span class="panel-icon text-primary"><Icon name="lock" size={17} /></span>
    <div class="min-w-0 flex-1">
      <div class="panel-title">Allowed Ports</div>
      <div class="panel-sub">incoming connections the firewall lets through</div>
    </div>
    <Input type="number" bind:value={newPort} placeholder="Port" prefixIcon="plug" class="w-32" min="1" max="65535"
      suffixAddonBtn={{ icon: 'plus', onclick: addPort }} onkeydown={(e) => e.key === 'Enter' && addPort()} />
  </div>
  {#if sorted.length}
    <ul class="grid grid-cols-1 gap-2 lg:grid-cols-2">{#each sorted as p (p.port + '/' + proto(p))}{@render row(p)}{/each}</ul>
  {:else}
    <p class="text-xs text-muted-foreground italic">No ports configured</p>
  {/if}
</div>
