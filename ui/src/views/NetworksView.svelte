<script>
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete, confirm } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'

  let { loading = $bindable(true) } = $props()

  let networks = $state([])
  let interfaces = $state([])
  let wan = $state('')
  let vpnClients = $state([])

  // Inline per-network detail (clients + reachability), fetched on expand.
  let expandedId = $state(null)
  let detail = $state(null)

  // Add/edit network modal.
  let formOpen = $state(false)
  let editing = $state(null)
  let saving = $state(false)
  let form = $state(blankForm())

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
  }

  function openAdd() { editing = null; form = blankForm(); formOpen = true }
  function openEdit(net) { editing = net; form = { ...net }; formOpen = true }

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

<div class="p-4 sm:p-6 max-w-5xl mx-auto">
  <div class="flex items-center justify-between gap-3 mb-5">
    <div>
      <h1 class="text-xl font-semibold flex items-center gap-2">
        <Icon name="router" size={22} class="text-primary" /> Private Networks
      </h1>
      <p class="text-sm text-base-content/60 mt-1">
        The panel acts as gateway + DHCP for an isolated LAN segment. Devices are reachable over
        the VPN only after you opt a client in — default-deny.
      </p>
    </div>
    <Button variant="primary" icon="plus" onclick={openAdd}>Add network</Button>
  </div>

  {#if !networks.length}
    <div class="text-center py-16 border border-dashed border-base-300 rounded-xl">
      <Icon name="router" size={40} class="text-base-content/30 mx-auto" />
      <p class="mt-3 text-base-content/70">No managed networks yet.</p>
      <p class="text-sm text-base-content/50">Add one to hand out DHCP addresses on an internal interface.</p>
    </div>
  {/if}

  <div class="flex flex-col gap-3">
    {#each networks as net (net.id)}
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
<Modal bind:open={formOpen} title={editing ? 'Edit network' : 'Add network'} size="md">
  <div class="flex flex-col gap-4">
    <div>
      <label class="text-sm font-medium" for="dhcp-iface">Interface</label>
      {#if editing}
        <input id="dhcp-iface" class="kt-input w-full mt-1 font-mono" value={form.iface} disabled />
        <p class="text-xs text-base-content/50 mt-1">The interface can't be changed after creation.</p>
      {:else}
        <select id="dhcp-iface" class="kt-select w-full mt-1" bind:value={form.iface} onchange={onPickIface}>
          <option value="" disabled>Select an internal interface…</option>
          {#each interfaces as i (i.name)}
            <option value={i.name} disabled={i.managed}>
              {i.name}{i.addrs?.length ? ` (${i.addrs[0]})` : ''}{i.up ? '' : ' — down'}{i.managed ? ' — already managed' : ''}
            </option>
          {/each}
        </select>
        <p class="text-xs text-base-content/50 mt-1">Your WAN ({wan || 'unknown'}), docker and VPN interfaces are hidden — they can't be used.</p>
      {/if}
    </div>

    <div class="grid grid-cols-2 gap-3">
      <div>
        <label class="text-sm font-medium" for="dhcp-cidr">Subnet (CIDR)</label>
        <input id="dhcp-cidr" class="kt-input w-full mt-1 font-mono" bind:value={form.cidr} placeholder="10.20.20.0/24" />
      </div>
      <div>
        <label class="text-sm font-medium" for="dhcp-gw">Gateway IP</label>
        <input id="dhcp-gw" class="kt-input w-full mt-1 font-mono" bind:value={form.gateway_ip} placeholder="10.20.20.1" />
      </div>
      <div>
        <label class="text-sm font-medium" for="dhcp-ps">Pool start</label>
        <input id="dhcp-ps" class="kt-input w-full mt-1 font-mono" bind:value={form.pool_start} placeholder="10.20.20.50" />
      </div>
      <div>
        <label class="text-sm font-medium" for="dhcp-pe">Pool end</label>
        <input id="dhcp-pe" class="kt-input w-full mt-1 font-mono" bind:value={form.pool_end} placeholder="10.20.20.200" />
      </div>
      <div>
        <label class="text-sm font-medium" for="dhcp-lease">Lease (hours)</label>
        <input id="dhcp-lease" type="number" min="1" class="kt-input w-full mt-1"
               value={leaseHours(form.lease_secs)} oninput={(e) => form.lease_secs = Math.round(Number(e.target.value) * 3600)} />
      </div>
      <div>
        <label class="text-sm font-medium" for="dhcp-domain">Domain</label>
        <input id="dhcp-domain" class="kt-input w-full mt-1" bind:value={form.domain} placeholder="lan" />
      </div>
    </div>

    <div>
      <label class="text-sm font-medium" for="dhcp-mode">Registration</label>
      <select id="dhcp-mode" class="kt-select w-full mt-1" bind:value={form.mode}>
        <option value="approve">Approve — a new device gets no address until you approve it</option>
        <option value="auto">Auto — any device on the segment gets an address</option>
      </select>
    </div>

    <label class="flex items-center gap-2 text-sm">
      <input type="checkbox" class="kt-checkbox" bind:checked={form.nat_enabled} />
      Allow internet access (NAT out the WAN) — <span class="text-base-content/50">off = fully isolated sandbox</span>
    </label>
    <label class="flex items-center gap-2 text-sm">
      <input type="checkbox" class="kt-checkbox" bind:checked={form.enabled} />
      Enabled
    </label>
  </div>

  {#snippet footer()}
    <Button variant="ghost" onclick={() => formOpen = false}>Cancel</Button>
    <Button variant="primary" loading={saving} onclick={saveForm}>{editing ? 'Save' : 'Create'}</Button>
  {/snippet}
</Modal>
