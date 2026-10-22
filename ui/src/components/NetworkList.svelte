<script>
  /**
   * NetworkList — the managed private networks (the panel is gateway + DHCP for each): list, add,
   * edit, delete (Settings → Networks). Their devices are on the Clients page.
   */
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete, confirm } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Modal from './Modal.svelte'
  import Input from './Input.svelte'
  import Select from './Select.svelte'
  import Checkbox from './Checkbox.svelte'
  import EmptyState from './EmptyState.svelte'
  import Badge from './Badge.svelte'
  import GroupButton from './GroupButton.svelte'

  let networks = $state([])
  let interfaces = $state([])
  let suggestions = $state([]) // safe CIDR candidates from the backend
  let wan = $state('')

  // Add/edit network modal.
  let formOpen = $state(false)
  let editing = $state(null)
  let saving = $state(false)
  let form = $state(blankForm())
  let cidrChoice = $state('') // selected suggestion CIDR or '__custom__'
  let customCidr = $state(false)

  function blankForm() {
    return { iface: '', cidr: '', gateway_ip: '', pool_start: '', pool_end: '',
             lease_secs: 43200, domain: 'lan', mode: 'approve', nat_enabled: false, enabled: true }
  }

  async function load() {
    try {
      const [n, ifc] = await Promise.all([apiGet('/api/dhcp/networks'), apiGet('/api/dhcp/interfaces')])
      networks = n.networks || []
      interfaces = ifc.interfaces || []
      suggestions = ifc.suggestions || []
      wan = ifc.wan || ''
    } catch (e) {
      toast('Failed to load networks: ' + e.message, 'error')
    }
  }
  onMount(load)

  // Derive the network base (e.g. 10.20.20.0/24) from an address like 10.20.20.1/24.
  function networkBase(cidr) {
    const [ip, prefixStr] = cidr.split('/')
    const prefix = parseInt(prefixStr, 10)
    const o = ip.split('.').map(Number)
    if (o.length !== 4 || isNaN(prefix)) return null
    const ipInt = ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
    const net = (ipInt & mask) >>> 0
    const base = [(net >>> 24) & 255, (net >>> 16) & 255, (net >>> 8) & 255, net & 255]
    return { base, prefix }
  }

  // When an interface with an existing address is picked, prefill sensible defaults so the
  // common "I set ens19=10.20.20.1/24 by hand" case is one click.
  function onPickIface() {
    const i = interfaces.find(x => x.name === form.iface)
    if (!i || !i.addrs || !i.addrs.length) return
    const nb = networkBase(i.addrs[0])
    if (!nb) return
    const [a, b, c] = nb.base
    form.cidr = `${nb.base.join('.')}/${nb.prefix}`
    form.gateway_ip = i.addrs[0].split('/')[0]
    form.pool_start = `${a}.${b}.${c}.50`
    form.pool_end = `${a}.${b}.${c}.200`
    // The interface already carries an address — switch to custom so the prefilled CIDR shows.
    customCidr = true
    cidrChoice = '__custom__'
  }

  // Lease presets (seconds) for the dropdown; the backend accepts 2min–30d.
  const LEASE_PRESETS = [
    { value: 3600, label: '1 hour' },
    { value: 21600, label: '6 hours' },
    { value: 43200, label: '12 hours' },
    { value: 86400, label: '1 day' },
    { value: 604800, label: '7 days' },
    { value: 2592000, label: '30 days' },
  ]
  // Include the current lease as a "custom" option if it isn't one of the presets (e.g. editing).
  let leaseOptions = $derived.by(() => {
    const opts = LEASE_PRESETS.slice()
    const cur = Number(form.lease_secs)
    if (!opts.some((o) => o.value === cur)) {
      opts.push({ value: cur, label: `Custom (${Math.round((cur / 3600) * 10) / 10}h)` })
    }
    return opts
  })
  let cidrOptions = $derived([
    ...suggestions.map((s) => ({ value: s.cidr, label: s.cidr })),
    { value: '__custom__', label: 'Custom subnet…' },
  ])
  let selectedIface = $derived(interfaces.find((i) => i.name === form.iface))

  // Apply a picked suggestion (gateway/pool follow the subnet), or reveal the custom input.
  function applySuggestion() {
    if (cidrChoice === '__custom__') { customCidr = true; return }
    const s = suggestions.find((x) => x.cidr === cidrChoice)
    if (!s) return
    customCidr = false
    form.cidr = s.cidr
    form.gateway_ip = s.gateway_ip
    form.pool_start = s.pool_start
    form.pool_end = s.pool_end
  }
  // Custom subnet typed → derive gateway (.1) and pool (.50–.200) defaults from it.
  function onCustomCidr() {
    const nb = networkBase(form.cidr)
    if (!nb) return
    const [a, b, c] = nb.base
    form.gateway_ip = `${a}.${b}.${c}.1`
    form.pool_start = `${a}.${b}.${c}.50`
    form.pool_end = `${a}.${b}.${c}.200`
  }

  function openAdd() {
    editing = null
    form = blankForm()
    customCidr = suggestions.length === 0
    cidrChoice = suggestions.length ? suggestions[0].cidr : '__custom__'
    applySuggestion()
    formOpen = true
  }
  function openEdit(net) {
    editing = net
    form = { ...net }
    customCidr = true
    cidrChoice = '__custom__'
    formOpen = true
  }


  async function saveForm() {
    saving = true
    const body = { ...form, lease_secs: Number(form.lease_secs) }
    try {
      if (editing) await apiPut(`/api/dhcp/networks/${editing.id}`, body)
      else await apiPost('/api/dhcp/networks', body)
      toast('Network saved', 'success')
      formOpen = false
      await load()
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      saving = false
    }
  }

  async function removeNetwork(net) {
    const ok = await confirm({
      title: 'Delete network',
      message: `Delete ${net.iface} (${net.cidr})?`,
      description: 'DHCP stops for this segment and the gateway address is removed from the interface.',
      confirmText: 'Delete',
    })
    if (!ok) return
    try {
      await apiDelete(`/api/dhcp/networks/${net.id}`)
      toast('Network deleted', 'success')
      await load()
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  function leaseHours(secs) { return Math.round((secs / 3600) * 10) / 10 }
</script>

<div class="kt-panel">
  <div class="kt-panel-header">
    <h3 class="kt-panel-title"><Icon name="router" size={16} /> Networks <span class="font-normal text-muted-foreground">{networks.length}</span></h3>
    <Button icon="plus" size="sm" onclick={openAdd}>Add network</Button>
  </div>
  <div class="kt-panel-body !p-0">
    {#if !networks.length}
      <div class="p-6">
        <EmptyState icon="router" title="No managed networks yet"
          description="Add one to hand out DHCP addresses on an internal interface." />
      </div>
    {:else}
      <div class="divide-y divide-border">
        {#each networks as net (net.id)}
          <div class="flex items-center gap-3 px-4 py-3">
            <span class="grid h-9 w-9 shrink-0 place-items-center rounded-lg {net.enabled ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'}">
              <Icon name="router" size={17} />
            </span>
            <div class="min-w-0 flex-1">
              <div class="flex flex-wrap items-center gap-2">
                <span class="font-medium text-foreground">{net.iface}</span>
                <span class="font-mono text-sm text-muted-foreground">{net.cidr}</span>
                {#if !net.enabled}<Badge variant="secondary" size="sm">disabled</Badge>{/if}
                <Badge variant={net.mode === 'approve' ? 'warning' : 'secondary'} size="sm">{net.mode === 'approve' ? 'approval needed' : 'auto'}</Badge>
                {#if net.nat_enabled}<Badge variant="info" size="sm">internet for new devices</Badge>{/if}
              </div>
              <div class="mt-0.5 flex flex-wrap gap-x-3 font-mono text-[11px] text-muted-foreground">
                <span>gateway {net.gateway_ip}</span><span>pool {net.pool_start}–{net.pool_end}</span><span>lease {leaseHours(net.lease_secs)}h</span>
              </div>
            </div>
            <div class="btn-group shrink-0">
              <GroupButton icon="pencil" tooltip="Edit network" onclick={() => openEdit(net)} />
              <GroupButton icon="trash" tone="destructive" tooltip="Delete network" onclick={() => removeNetwork(net)} />
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>

<!-- Add / edit modal -->
<Modal bind:open={formOpen} title={editing ? 'Edit network' : 'Add network'} size="lg">
  <div class="flex flex-col gap-4">
    <!-- Interface -->
    {#if editing}
      <Input label="Interface" value={form.iface} disabled prefixIcon="plug-connected" class="font-mono"
             helperText="The interface can't be changed after creation." />
    {:else}
      <Select label="Interface" bind:value={form.iface} onchange={onPickIface}
              helperText={`Your WAN (${wan || 'unknown'}), docker and VPN interfaces are hidden — they can't be used.`}>
        <option value="" disabled>Select an internal interface…</option>
        {#each interfaces as i (i.name)}
          <option value={i.name} disabled={i.managed}>
            {i.name}{i.addrs?.length ? ` (${i.addrs[0]})` : ''}{i.up ? '' : ' — down'}{i.managed ? ' — already managed' : ''}
          </option>
        {/each}
      </Select>
    {/if}

    <!-- Pre-save warning: this NIC is already defined in a hand-written netplan file -->
    {#if selectedIface?.conflict}
      <div class="flex items-start gap-2 rounded-lg border border-warning/40 bg-warning/10 p-3 text-sm">
        <Icon name="alert-triangle" class="text-warning mt-0.5 shrink-0" />
        <div>
          <span class="font-medium">{form.iface} is already configured in <span class="font-mono">{selectedIface.conflict}</span>.</span>
          Remove that stanza first — the panel will own this interface's address. Leaving both can cause a duplicate address or a failed apply.
        </div>
      </div>
    {/if}

    <!-- Subnet: pick a safe suggestion or enter a custom one -->
    <div class="grid grid-cols-2 gap-3">
      <Select label="Subnet (CIDR)" bind:value={cidrChoice} onchange={applySuggestion}
              options={cidrOptions} helperText="Suggestions avoid your VPN and existing networks." />
      {#if customCidr}
        <Input label="Custom subnet" bind:value={form.cidr} oninput={onCustomCidr}
               prefixIcon="network" placeholder="10.20.20.0/24" class="font-mono" />
      {:else}
        <Input label="Subnet" value={form.cidr} disabled prefixIcon="network" class="font-mono" />
      {/if}
    </div>

    <div class="grid grid-cols-2 gap-3">
      <Input label="Gateway IP" bind:value={form.gateway_ip} prefixIcon="router"
             placeholder="10.20.20.1" class="font-mono" />
      <Input label="Domain" bind:value={form.domain} prefixIcon="world-www" placeholder="lan"
             helperText="DNS suffix for clients — a device 'laptop' resolves as laptop.<domain>." />
      <Input label="Pool start" bind:value={form.pool_start} prefixIcon="list"
             placeholder="10.20.20.50" class="font-mono" />
      <Input label="Pool end" bind:value={form.pool_end} prefixIcon="list"
             placeholder="10.20.20.200" class="font-mono" />
      <Select label="Lease time" bind:value={form.lease_secs} options={leaseOptions} />
      <Select label="Registration" bind:value={form.mode}
              options={[
                { value: 'approve', label: 'Approve — device waits for your OK' },
                { value: 'auto', label: 'Auto — any device gets an address' },
              ]} />
    </div>

    <div class="flex flex-col gap-2 pt-1">
      <Checkbox variant="switch" bind:checked={form.nat_enabled}
                label="Internet access for new devices"
                helperText="The starting value of each new device's internet switch — change it per device on the Clients page. Off = new devices are fully isolated." />
      <Checkbox variant="switch" bind:checked={form.enabled} label="Enabled" />
    </div>
  </div>

  {#snippet footer()}
    <Button variant="secondary" onclick={() => formOpen = false}>Cancel</Button>
    <Button variant="primary" loading={saving} onclick={saveForm}>{editing ? 'Save' : 'Create'}</Button>
  {/snippet}
</Modal>
