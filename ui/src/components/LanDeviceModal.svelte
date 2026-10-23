<script>
  /**
   * LanDeviceModal — one LAN device: Overview (name and reserved IP), Access (which VPN clients may
   * reach it, its internet switch), Ad blocking (admins) and Actions (approve, block/unblock, forget). Open it by setting
   * `deviceId`; closing sets it back to null. Every change is admin-only and audited on the server;
   * onchanged() lets the parent refresh. Access starts empty: nobody reaches a device until granted.
   */
  import { apiGet, apiPost, apiPut, apiDelete, currentUser, hasRole, toast, confirm } from '../stores/app.js'
  import { timeAgo } from '$lib/utils/format.js'
  import { approveDevice, blockDevice, unblockDevice, setDeviceInternet } from '$lib/lan.js'
  import { fmtUptime } from '$lib/fleet.js'
  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import Button from './Button.svelte'
  import Modal from './Modal.svelte'
  import Input from './Input.svelte'
  import Checkbox from './Checkbox.svelte'
  import Tabs from './Tabs.svelte'
  import ContentBlock from './ContentBlock.svelte'
  import OptionCard from './OptionCard.svelte'
  import AdBlockPanel from './AdBlockPanel.svelte'

  let { deviceId = $bindable(null), network = '', onchanged = undefined } = $props()

  const isAdmin = $derived(hasRole($currentUser, 'admin'))
  // Ad blocking is admin-only (it shows browsing history).
  const TABS = $derived([
    { id: 'overview', label: 'Overview' },
    { id: 'access', label: 'Access' },
    ...(isAdmin ? [{ id: 'adblock', label: 'Ad blocking' }] : []),
    { id: 'actions', label: 'Actions' },
  ])

  let open = $state(false)
  let tab = $state('overview')
  let device = $state(null)
  let allowed = $state([]) // VPN client ids granted access
  let vpnClients = $state([])
  let busy = $state(false)
  let resName = $state('')
  let resIP = $state('')

  async function load() {
    try {
      const [d, v] = await Promise.all([apiGet(`/api/dhcp/clients/${deviceId}`), apiGet('/api/vpn/clients')])
      device = d.client
      allowed = d.allowed || []
      vpnClients = Array.isArray(v) ? v : v.clients || []
      resName = device.name || ''
      resIP = device.ip || ''
    } catch (e) {
      toast('Could not load the device: ' + e.message, 'error')
      deviceId = null
    }
  }

  // Opening: a new id resets the tab and loads the device; closing clears the id.
  let loadedId = null
  $effect(() => {
    if (deviceId && deviceId !== loadedId) {
      loadedId = deviceId
      tab = 'overview'
      device = null
      open = true
      load()
    }
  })
  $effect(() => {
    if (!open) { deviceId = null; loadedId = null }
  })

  // Run a change, then reload the device and tell the parent.
  async function act(fn, done) {
    busy = true
    try {
      await fn()
      if (done) toast(done, 'success')
      await load()
      onchanged?.()
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      busy = false
    }
  }

  const base = () => `/api/dhcp/clients/${device.id}`
  const approve = () => act(() => approveDevice(device.id), 'Approved')
  const block = () => act(() => blockDevice(device.id), 'Blocked')
  const unblock = () => act(() => unblockDevice(device.id), 'Unblocked')
  const setInternet = (on) => act(() => setDeviceInternet(device.id, on), on ? 'Internet on' : 'Internet off')
  const saveReservation = () => act(() => apiPut(base(), { ip: resIP.trim(), name: resName.trim() }), 'Saved')
  function toggleAccess(vpn) {
    const has = allowed.includes(vpn.id)
    act(() => (has ? apiDelete(`${base()}/acl/${vpn.id}`) : apiPost(base() + '/acl', { client_id: vpn.id })))
  }
  async function forget() {
    const ok = await confirm({
      title: 'Forget device',
      message: `Forget ${device.name || device.mac}?`,
      description: 'Its record, reservation and access are removed. If it connects again it shows up as a new device.',
      confirmText: 'Forget',
      variant: 'destructive',
    })
    if (!ok) return
    busy = true
    try {
      await apiDelete(base())
      toast('Device forgotten', 'success')
      onchanged?.()
      open = false
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      busy = false
    }
  }

  const leaseLeft = $derived(device?.lease_expires ? Math.max(0, device.lease_expires - Date.now() / 1000) : 0)
  const status = $derived(!device ? null : device.blocked ? ['Blocked', 'destructive'] : !device.approved ? ['Waiting for approval', 'warning'] : device.online ? ['Online', 'success'] : ['Offline', 'muted'])
</script>

<Modal bind:open size="lg" bodyClass="p-0">
  {#snippet header()}
    <div class="flex items-center gap-2.5 min-w-0">
      <span class="grid h-7 w-7 shrink-0 place-items-center rounded-lg" style="background: color-mix(in oklch, var(--client-lan) 14%, transparent); color: var(--client-lan)"><Icon name="router" size={14} /></span>
      <span class="truncate font-semibold text-foreground">{device?.name || device?.mac || 'LAN device'}</span>
      {#if status}<Badge variant={status[1]} size="sm">{status[0]}</Badge>{/if}
    </div>
  {/snippet}

  {#if device}
    <Tabs tabs={TABS} bind:activeTab={tab} size="xs" background class="px-4" />
    <div class="p-4 max-h-[60vh] overflow-y-auto space-y-4">
      {#if tab === 'overview'}
        <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
          <ContentBlock variant="data" size="sm" solid light label="IP address" value={device.ip || '—'} copyable={!!device.ip} mono />
          <ContentBlock variant="data" size="sm" solid light label="MAC address" value={device.mac} copyable mono />
          <ContentBlock variant="data" size="sm" solid light label="Network" value={network || '—'} />
          <ContentBlock variant="data" size="sm" solid light label="Lease" value={leaseLeft ? fmtUptime(leaseLeft) + ' left' : device.online ? 'Static' : 'None'} rightIcon="clock" />
          <ContentBlock variant="data" size="sm" solid light label="Last seen" value={device.last_seen ? timeAgo(device.last_seen) : '—'} rightIcon="clock" />
          <ContentBlock variant="data" size="sm" solid light label="Internet" value={device.internet ? 'Allowed' : 'Blocked'} rightIcon={device.internet ? 'world' : 'world-off'} />
        </div>
        {#if isAdmin}
          <div class="pt-3 border-t border-border">
            <h4 class="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-2">Name and reserved address</h4>
            <div class="grid grid-cols-1 sm:grid-cols-[1fr_1fr_auto] gap-2 items-end">
              <Input label="Name" bind:value={resName} placeholder="e.g. front-camera" prefixIcon="tag" />
              <Input label="Reserved IP" bind:value={resIP} placeholder="always give it this IP" prefixIcon="network" class="font-mono" />
              <Button icon="device-floppy" loading={busy} onclick={saveReservation}>Save</Button>
            </div>
            <p class="mt-1.5 text-[11px] text-muted-foreground">A reserved IP keeps the device on the same address, so its access rules keep matching it.</p>
          </div>
        {/if}

      {:else if tab === 'access'}
        <div class="flex items-start justify-between gap-3 rounded-lg border border-border p-3">
          <div class="min-w-0">
            <div class="text-sm font-medium text-foreground flex items-center gap-1.5"><Icon name={device.internet ? 'world' : 'world-off'} size={15} />Internet access</div>
            <p class="text-[11px] text-muted-foreground mt-0.5">Lets the device reach the public internet. Private and VPN networks stay off-limits either way.</p>
          </div>
          <Checkbox variant="switch" checked={device.internet} disabled={!isAdmin || busy || device.blocked} onchange={() => setInternet(!device.internet)} />
        </div>

        <div>
          <div class="flex items-center justify-between mb-2">
            <div class="text-[10px] uppercase tracking-wide text-muted-foreground">VPN clients that can reach this device</div>
            <span class="text-[10px] text-muted-foreground">{allowed.length} allowed</span>
          </div>
          {#if !device.approved || device.blocked}
            <p class="text-xs text-muted-foreground">{device.blocked ? 'Blocked devices' : 'Devices waiting for approval'} can't be reached by anyone.</p>
          {/if}
          {#if !vpnClients.length}
            <p class="text-sm text-muted-foreground">No VPN clients yet.</p>
          {:else}
            <div class="border border-border rounded-lg max-h-60 overflow-y-auto divide-y divide-border">
              {#each vpnClients as vc (vc.id)}
                <label class="flex items-center gap-2.5 p-2.5 text-sm {isAdmin && !busy ? 'cursor-pointer hover:bg-muted/40' : ''}">
                  <Checkbox checked={allowed.includes(vc.id)} disabled={!isAdmin || busy} onchange={() => toggleAccess(vc)} />
                  <span class="min-w-0 flex-1 truncate text-foreground">{vc.name}</span>
                  <span class="font-mono text-[11px] text-muted-foreground">{vc.ip}</span>
                  <span class="text-[10px] text-muted-foreground">{vc.type === 'wireguard' ? 'WG' : 'TS'}</span>
                </label>
              {/each}
            </div>
          {/if}
          <p class="text-[11px] text-muted-foreground mt-2">Nobody can reach a device until you allow them. An allowed client and the device can reach each other.</p>
        </div>

      {:else if tab === 'adblock'}
        {#if device.blocked || !device.approved}
          <p class="text-sm text-muted-foreground">{device.blocked ? 'Blocked devices get no address, so there is nothing to filter.' : 'Approve the device first.'}</p>
        {:else if !device.ip}
          <p class="text-sm text-muted-foreground">The device has no address yet.</p>
        {:else}
          <AdBlockPanel clientKey={'lan:' + device.id} />
        {/if}

      {:else}
        {#if !isAdmin}
          <p class="text-sm text-muted-foreground">Only admins can approve, block or forget devices.</p>
        {:else}
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {#if device.blocked}
              <OptionCard icon="lock-open" title="Unblock" description="Let it get an address again" color="success" size="lg" iconBox disabled={busy} onclick={unblock} />
            {:else}
              {#if !device.approved}
                <OptionCard icon="check" title="Approve" description="Open its firewall gate" color="success" size="lg" iconBox disabled={busy} onclick={approve} />
              {/if}
              <OptionCard icon="ban" title="Block" description="No address, all traffic dropped" color="destructive" size="lg" iconBox disabled={busy} onclick={block} />
            {/if}
            <OptionCard icon="trash" title="Forget" description={device.online ? 'Only while offline — block it instead' : 'Remove its record'} color="destructive" size="lg" iconBox disabled={busy || device.online} onclick={forget} />
          </div>
        {/if}
      {/if}
    </div>
  {:else}
    <div class="p-8 text-center text-sm text-muted-foreground">Loading…</div>
  {/if}
</Modal>
