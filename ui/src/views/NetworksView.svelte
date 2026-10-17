<script>
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete, confirm } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Input from '../components/Input.svelte'
  import Select from '../components/Select.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import EmptyState from '../components/EmptyState.svelte'

  let { loading = $bindable(true) } = $props()

  let networks = $state([])
  let interfaces = $state([])
  let suggestions = $state([]) // safe CIDR candidates from the backend
  let wan = $state('')
  let vpnClients = $state([])
  let searchQuery = $state('')
  let filteredNetworks = $derived(
    !searchQuery.trim()
      ? networks
      : networks.filter((n) => `${n.iface} ${n.cidr}`.toLowerCase().includes(searchQuery.trim().toLowerCase()))
  )

  // Inline per-network detail (clients + reachability), fetched on expand.
  let expandedId = $state(null)
  let detail = $state(null)

  // Add/edit network modal.
  let formOpen = $state(false)
  let editing = $state(null)
  let saving = $state(false)
  let form = $state(blankForm())
  let cidrChoice = $state('') // selected suggestion CIDR or '__custom__'
  let customCidr = $state(false)

  // Per-client reservation inline edit.
  let editClientId = $state(null)
  let resIP = $state('')
  let resName = $state('')

  function blankForm() {
    return { iface: '', cidr: '', gateway_ip: '', pool_start: '', pool_end: '',
             lease_secs: 43200, domain: 'lan', mode: 'approve', nat_enabled: false, enabled: true }
  }

  async function load() {
    try {
      const [n, ifc, vc] = await Promise.all([
        apiGet('/api/dhcp/networks'),
        apiGet('/api/dhcp/interfaces'),
        apiGet('/api/vpn/clients'),
      ])
      networks = n.networks || []
      interfaces = ifc.interfaces || []
      suggestions = ifc.suggestions || []
      wan = ifc.wan || ''
      vpnClients = Array.isArray(vc) ? vc : (vc.clients || [])
    } catch (e) {
      toast('Failed to load networks: ' + e.message, 'error')
    } finally {
      loading = false
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
      if (expandedId) await refreshDetail()
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
      if (expandedId === net.id) { expandedId = null; detail = null }
      await load()
    } catch (e) {
      toast(e.message, 'error')
    }
  }

  async function toggleExpand(id) {
    if (expandedId === id) { expandedId = null; detail = null; return }
    expandedId = id
    await refreshDetail()
  }
  async function refreshDetail() {
    try { detail = await apiGet(`/api/dhcp/networks/${expandedId}`) }
    catch (e) { toast(e.message, 'error') }
  }

  async function approveClient(c) {
    try { await apiPost(`/api/dhcp/clients/${c.id}/approve`); toast('Approved', 'success'); await refreshDetail() }
    catch (e) { toast(e.message, 'error') }
  }
  async function deleteClient(c) {
    const ok = await confirm({ title: 'Remove device', message: `Remove ${c.name || c.mac}?`, confirmText: 'Remove' })
    if (!ok) return
    try { await apiDelete(`/api/dhcp/clients/${c.id}`); toast('Removed', 'success'); await refreshDetail() }
    catch (e) { toast(e.message, 'error') }
  }
  function startEditClient(c) { editClientId = c.id; resIP = c.ip || ''; resName = c.name || '' }
  async function saveReservation(c) {
    try {
      await apiPut(`/api/dhcp/clients/${c.id}`, { ip: resIP.trim(), name: resName.trim() })
      toast('Reservation saved', 'success'); editClientId = null; await refreshDetail()
    } catch (e) { toast(e.message, 'error') }
  }

  function aclHas(clientId) { return detail?.acl?.includes(clientId) }
  async function toggleReach(client) {
    try {
      if (aclHas(client.id)) await apiDelete(`/api/dhcp/networks/${expandedId}/acl/${client.id}`)
      else await apiPost(`/api/dhcp/networks/${expandedId}/acl`, { client_id: client.id })
      await refreshDetail()
    } catch (e) { toast(e.message, 'error') }
  }

  function leaseHours(secs) { return Math.round((secs / 3600) * 10) / 10 }
</script>

<div class="space-y-4">
  <InfoCard
    icon="router"
    title="Private Networks"
    description="The panel acts as gateway + DHCP for an isolated LAN segment. Devices are reachable over the VPN only after you opt a client in — default-deny."
  />

  <Toolbar bind:search={searchQuery} placeholder="Search networks...">
    <Button size="xs" icon="plus" onclick={openAdd}>Add network</Button>
  </Toolbar>

  {#if !networks.length}
    <EmptyState
      icon="router"
      title="No managed networks yet"
      description="Add one to hand out DHCP addresses on an internal interface."
    />
  {/if}

  <div class="flex flex-col gap-3">
    {#each filteredNetworks as net (net.id)}
      <div class="border border-base-300 rounded-xl overflow-hidden">
        <!-- Network summary row -->
        <button class="w-full flex items-center gap-3 p-4 text-left hover:bg-base-200/40 transition-colors"
                onclick={() => toggleExpand(net.id)}>
          <Icon name={expandedId === net.id ? 'chevron-down' : 'chevron-right'} size={16} class="text-base-content/50" />
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="font-medium">{net.iface}</span>
              <span class="text-sm text-base-content/60 font-mono">{net.cidr}</span>
              {#if !net.enabled}<span class="kt-badge kt-badge-sm kt-badge-outline">disabled</span>{/if}
              <span class="kt-badge kt-badge-sm {net.mode === 'approve' ? 'kt-badge-warning' : 'kt-badge-secondary'} kt-badge-outline">{net.mode}</span>
              {#if net.nat_enabled}<span class="kt-badge kt-badge-sm kt-badge-info kt-badge-outline">internet-out</span>{/if}
            </div>
            <div class="text-xs text-base-content/50 mt-0.5 font-mono">
              gw {net.gateway_ip} · pool {net.pool_start}–{net.pool_end} · lease {leaseHours(net.lease_secs)}h
            </div>
          </div>
          <span class="flex items-center gap-1" role="group">
            <Button variant="ghost" size="sm" icon="pencil" iconOnly onclick={(e) => { e.stopPropagation(); openEdit(net) }} tooltip="Edit" />
            <Button variant="ghost" size="sm" icon="trash" iconOnly onclick={(e) => { e.stopPropagation(); removeNetwork(net) }} tooltip="Delete" />
          </span>
        </button>

        <!-- Expanded detail -->
        {#if expandedId === net.id && detail}
          <div class="border-t border-base-300 p-4 bg-base-200/20 flex flex-col gap-6">
            <!-- Devices / leases -->
            <div>
              <h3 class="text-sm font-semibold mb-2 flex items-center gap-2">
                <Icon name="device-desktop" size={16} /> Devices
                <span class="text-xs font-normal text-base-content/50">({detail.clients?.length || 0})</span>
              </h3>
              {#if !detail.clients?.length}
                <p class="text-sm text-base-content/50">No devices have asked for an address yet.</p>
              {:else}
                <div class="overflow-x-auto">
                  <table class="w-full text-sm">
                    <thead class="text-xs text-base-content/50 text-left">
                      <tr><th class="py-1 pr-3"></th><th class="py-1 pr-3">Name</th><th class="py-1 pr-3">MAC</th><th class="py-1 pr-3">IP</th><th class="py-1 pr-3"></th></tr>
                    </thead>
                    <tbody>
                      {#each detail.clients as c (c.id)}
                        <tr class="border-t border-base-300/60">
                          <td class="py-1.5 pr-3">
                            <span class="inline-block w-2 h-2 rounded-full {c.online ? 'bg-success' : 'bg-base-content/20'}" title={c.online ? 'online' : 'offline'}></span>
                          </td>
                          {#if editClientId === c.id}
                            <td class="py-1.5 pr-3"><input class="kt-input kt-input-sm w-28" bind:value={resName} placeholder="name" /></td>
                            <td class="py-1.5 pr-3 font-mono text-xs">{c.mac}</td>
                            <td class="py-1.5 pr-3"><input class="kt-input kt-input-sm w-28 font-mono" bind:value={resIP} placeholder="reserved IP" /></td>
                            <td class="py-1.5 pr-3 text-right whitespace-nowrap">
                              <Button variant="primary" size="sm" icon="check" iconOnly onclick={() => saveReservation(c)} tooltip="Save" />
                              <Button variant="ghost" size="sm" icon="x" iconOnly onclick={() => editClientId = null} tooltip="Cancel" />
                            </td>
                          {:else}
                            <td class="py-1.5 pr-3">{c.name || '—'}</td>
                            <td class="py-1.5 pr-3 font-mono text-xs">{c.mac}</td>
                            <td class="py-1.5 pr-3 font-mono text-xs">{c.ip || '—'}</td>
                            <td class="py-1.5 pr-3 text-right whitespace-nowrap">
                              {#if net.mode === 'approve' && !c.approved}
                                <Button variant="primary" size="sm" icon="check" onclick={() => approveClient(c)}>Approve</Button>
                              {/if}
                              <Button variant="ghost" size="sm" icon="pencil" iconOnly onclick={() => startEditClient(c)} tooltip="Reservation" />
                              <Button variant="ghost" size="sm" icon="trash" iconOnly onclick={() => deleteClient(c)} tooltip="Remove" />
                            </td>
                          {/if}
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}
            </div>

            <!-- Reachability -->
            <div>
              <h3 class="text-sm font-semibold mb-1 flex items-center gap-2">
                <Icon name="shield-check" size={16} /> Who can reach this network
              </h3>
              <p class="text-xs text-base-content/50 mb-2">Default-deny. Tick a VPN client to let it reach the whole {net.cidr} over WireGuard.</p>
              {#if !vpnClients.length}
                <p class="text-sm text-base-content/50">No VPN clients yet.</p>
              {:else}
                <div class="flex flex-wrap gap-2">
                  {#each vpnClients as vc (vc.id)}
                    <button class="kt-badge kt-badge-sm cursor-pointer {aclHas(vc.id) ? 'kt-badge-success' : 'kt-badge-outline kt-badge-secondary'}"
                            onclick={() => toggleReach(vc)} title={vc.ip}>
                      {#if aclHas(vc.id)}<Icon name="check" size={12} />{/if}
                      {vc.name} <span class="opacity-60 font-mono">{vc.ip}</span>
                    </button>
                  {/each}
                </div>
              {/if}
            </div>
          </div>
        {/if}
      </div>
    {/each}
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
                label="Allow internet access (NAT out the WAN)"
                helperText="Off = fully isolated sandbox." />
      <Checkbox variant="switch" bind:checked={form.enabled} label="Enabled" />
    </div>
  </div>

  {#snippet footer()}
    <Button variant="secondary" onclick={() => formOpen = false}>Cancel</Button>
    <Button variant="primary" loading={saving} onclick={saveForm}>{editing ? 'Save' : 'Create'}</Button>
  {/snippet}
</Modal>
