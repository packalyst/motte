<script>
  /**
   * ClientModal — the detail modal for one VPN client (WireGuard peer or Tailscale node):
   * Overview (with its top destinations), Config (QR + virtual IPs), Access, Ad blocking and Actions. Open it by setting `node`
   * (a toNode() object); closing sets it back to null. onchanged() asks the parent to reload its
   * data after a change; vpnClients/routes are the parent's current lists.
   */
  import { onMount, onDestroy, untrack } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete, apiGetBlob, stepUpConfirm, currentUser, hasRole } from '../stores/app.js'
  import AdBlockPanel from './AdBlockPanel.svelte'
  import { copyWithToast } from '../stores/helpers.js'
  import { formatDate, timeAgo, formatBytes } from '$lib/utils/format.js'
  import { deviceIcon, downloadPeerConfig, copyPeerConfig } from '$lib/nodes.js'
  import Icon from './Icon.svelte'
  import AccessRow from './AccessRow.svelte'
  import Segmented from './Segmented.svelte'
  import Badge from './Badge.svelte'
  import Modal from './Modal.svelte'
  import Input from './Input.svelte'
  import Button from './Button.svelte'
  import ContentBlock from './ContentBlock.svelte'
  import EmptyState from './EmptyState.svelte'
  import Checkbox from './Checkbox.svelte'
  import LoadingSpinner from './LoadingSpinner.svelte'
  import Tabs from './Tabs.svelte'
  import OptionCard from './OptionCard.svelte'
  import BarList from './BarList.svelte'
  import Skeleton from './Skeleton.svelte'
  import TagEditor from './TagEditor.svelte'

  let { node: selectedNode = $bindable(null), vpnClients = [], routes = [], onchanged = undefined } = $props()

  // Opening: a new node resets the per-node state (tab, rename, QR, ACL) and loads its VPN record.
  let openedId = null
  $effect(() => {
    const id = selectedNode?.id
    if (!id || id === openedId) { if (!id) openedId = null; return }
    openedId = id
    untrack(() => {
      activeTab = 'overview'
      editingName = false
      tunnelMode = 'full'
      qrLoadedFor = null
      newName = selectedNode._displayName
      selectedVpnClient = null
      aclPolicy = 'selected'
      aclView = []
      hasDNS = false
      confirmAction = null
      showNodeModal = true
      loadVpnClientByIp(selectedNode._ip)
    })
  })

  onMount(checkRouterStatus)
  onDestroy(() => {
    mounted = false
    if (qrUrl) URL.revokeObjectURL(qrUrl)
  })

  // VPN Router state (minimal - for Access tab visibility)
  let routerRunning = $state(false)

  // ACL state
  let selectedVpnClient = $state(null)
  let aclPolicy = $state('selected')
  let aclView = $state([]) // All clients with isEnabled/isBi state from API
  let aclLoading = $state(false)
  let aclSyncing = $state(false)
  let hasDNS = $state(false)

  async function checkRouterStatus() {
    try {
      const status = await apiGet('/api/vpn/router/status')
      routerRunning = status?.status === 'running'
    } catch (e) {
      routerRunning = false
    }
  }

  // ACL functions - the parent reload (onchanged) re-syncs /api/vpn/clients
  async function syncVpnClients() {
    aclSyncing = true
    try {
      await onchanged?.()
      toast('VPN clients synced', 'success')
    } catch (e) {
      toast('Failed to sync clients: ' + e.message, 'error')
    } finally {
      aclSyncing = false
    }
  }

  async function loadVpnClientByIp(ip) {
    if (!ip) return null
    // Find VPN client that matches this IP
    const client = vpnClients.find(c => c.ip === ip)
    if (!client) return null

    try {
      const data = await apiGet(`/api/vpn/clients/${client.id}`)
      selectedVpnClient = data.client
      aclPolicy = data.client.aclPolicy || 'selected'
      aclView = data.aclView || []
      hasDNS = data.hasDNS || false
      return data.client
    } catch (e) {
      return null
    }
  }

  async function saveAcl() {
    if (!selectedVpnClient) return
    // Capture values before async operations to avoid stale references
    const clientId = selectedVpnClient.id
    const nodeIp = selectedNode?._ip
    aclLoading = true
    try {
      // Build rules array from aclView state
      const rules = aclView
        .filter(c => c.isEnabled)
        .map(c => ({ targetId: c.id, bidirectional: c.isBi || false }))

      await apiPut(`/api/vpn/clients/${clientId}/acl`, {
        policy: aclPolicy,
        rules: rules
      })
      // Auto-apply rules after saving
      await apiPost('/api/vpn/apply')
      toast('Access rules saved and applied', 'success')
      // Reload data to refresh client list and ACL states
      await onchanged?.()
      // Reload current client's ACL data using captured IP
      if (nodeIp) {
        await loadVpnClientByIp(nodeIp)
      }
    } catch (e) {
      toast('Failed to save access rules: ' + e.message, 'error')
    } finally {
      aclLoading = false
    }
  }

  async function toggleDNS() {
    if (!selectedVpnClient) return
    try {
      await apiPut(`/api/vpn/clients/${selectedVpnClient.id}/dns`, { enabled: !hasDNS })
      hasDNS = !hasDNS
      toast(hasDNS ? 'DNS enabled' : 'DNS disabled', 'success')
    } catch (e) {
      toast('Failed to toggle DNS: ' + e.message, 'error')
    }
  }

  function toggleClient(clientId) {
    aclView = aclView.map(c =>
      c.id === clientId ? { ...c, isEnabled: !c.isEnabled, isBi: !c.isEnabled ? c.isBi : false } : c
    )
  }

  function toggleBidirectional(clientId) {
    aclView = aclView.map(c =>
      c.id === clientId ? { ...c, isBi: !c.isBi } : c
    )
  }

  let activeTab = $state('overview')

  // Dynamic tabs based on node type. Ad blocking is admin-only (it shows browsing history).
  const isAdmin = $derived(hasRole($currentUser, 'admin'))
  const detailTabs = $derived([
    { id: 'overview', label: 'Overview' },
    ...(selectedNode?._type === 'wireguard' ? [{ id: 'qr', label: 'Config' }] : []),
    { id: 'access', label: 'Access' },
    ...(isAdmin ? [{ id: 'adblock', label: 'Ad blocking' }] : []),
    { id: 'actions', label: 'Actions' },
  ])
  // The All clients key AdGuard settings are filed under ("wg:<id>" / "ts:<node id>").
  const clientKey = $derived(selectedNode ? (selectedNode._type === 'wireguard' ? 'wg:' + selectedNode._wgId : 'ts:' + selectedNode.id) : '')

  // Per-peer destination traffic breakdown (conntrack byte accounting)
  let peerUsage = $state(null)
  let peerUsageLoading = $state(false)
  let peerUsagePeriod = $state('day')
  let peerUsageSeq = 0 // only the latest request may land (period clicks can overlap)

  // The previous list stays (dimmed) while a new period loads; another client's never does.
  async function loadPeerUsage() {
    const ip = selectedNode?._ip
    if (peerUsage?.ip !== ip) peerUsage = null
    if (!ip) return
    const seq = ++peerUsageSeq
    peerUsageLoading = true
    let res
    try {
      res = await apiGet(`/api/logs/peer-usage?peer=${encodeURIComponent(ip)}&period=${peerUsagePeriod}`)
    } catch {
      res = { destinations: [] } // shown as "no data"
    }
    if (seq !== peerUsageSeq) return
    peerUsage = { ...res, ip }
    peerUsageLoading = false
  }

  // Reset both the accumulated WireGuard totals (dashboard up/down) and the
  // per-destination breakdown (conntrack) for this peer, in one action.
  async function resetPeerTotals() {
    const ip = selectedNode?._ip
    if (!ip) return
    try {
      await apiPost(`/api/vpn/traffic/reset?peer=${encodeURIComponent(ip)}`)
      await apiDelete(`/api/logs/peer-usage?peer=${encodeURIComponent(ip)}`)
      if (selectedNode) { selectedNode.totalTx = 0; selectedNode.totalRx = 0 }
      peerUsage = null
      toast('Traffic reset', 'success')
      onchanged?.()
      if (activeTab === 'overview') loadPeerUsage()
    } catch (e) {
      toast('Failed to reset: ' + e.message, 'error')
    }
  }

  // Load usage when the Overview is shown or the period changes.
  $effect(() => {
    if (activeTab === 'overview' && selectedNode) {
      selectedNode._ip; peerUsagePeriod // track these only: the loader reads its own state
      untrack(loadPeerUsage)
    }
  })

  let showNodeModal = $state(false)

  // Handle node modal close - reset editing states
  $effect(() => {
    if (!showNodeModal) {
      selectedNode = null
      editingName = false
    }
  })

  let tunnelMode = $state('full') // 'full' or 'split'

  // Inline editing states
  let editingName = $state(false)
  let newName = $state('')

  // QR code - fetch with auth
  let qrUrl = $state(null)
  let qrLoading = $state(false)
  let qrLoadedFor = $state(null) // Track which peer/mode combo was loaded: "peerId:mode"
  let mounted = true // Track component lifecycle for async cleanup

  // Delete/expire confirmation
  let confirmAction = $state(null) // 'delete' | 'expire' | 'block-internet' | 'unblock-internet' | null
  let actionLoading = $state(false)

  async function loadQrCode(peerId, mode) {
    const key = `${peerId}:${mode}`
    // Skip if already loading or already loaded for this peer/mode
    if (qrLoading || qrLoadedFor === key) return

    qrLoading = true
    // Revoke old URL to prevent memory leak
    if (qrUrl) {
      URL.revokeObjectURL(qrUrl)
      qrUrl = null
    }
    try {
      const blob = await apiGetBlob(`/api/wg/peers/${peerId}/qr?mode=${mode}`)
      // Skip if the component unmounted during the fetch
      if (!mounted) return
      // Use a data: URL (not blob:) so the <img> passes the CSP img-src 'self' data: https:
      qrUrl = await new Promise((resolve, reject) => {
        const r = new FileReader()
        r.onload = () => resolve(r.result)
        r.onerror = () => reject(r.error)
        r.readAsDataURL(blob)
      })
      if (!mounted) { qrUrl = null; return }
      qrLoadedFor = key
    } catch (e) {
      if (!mounted) return
      toast('Failed to load QR code', 'error')
      qrLoadedFor = null // Allow retry on error
    } finally {
      qrLoading = false
    }
  }

  // Load QR when tab changes to 'qr' for wireguard peer. untrack: the effect follows the peer, tab
  // and mode only — not loadQrCode's own loading state, or a failed load would retry endlessly.
  $effect(() => {
    if (selectedNode?._type === 'wireguard' && activeTab === 'qr') {
      const id = selectedNode._wgId, mode = tunnelMode
      untrack(() => loadQrCode(id, mode))
    }
  })

  // Get routes for selected node
  const nodeRoutes = $derived(selectedNode && selectedNode._type === 'tailscale'
    ? routes.filter(r => r.node?.id === selectedNode.id)
    : [])
  const isExitNode = $derived(nodeRoutes.some(r => r.prefix === '0.0.0.0/0'))

  // Load VPN client when switching to 'access' tab
  $effect(() => {
    if (activeTab === 'access' && selectedNode && !selectedVpnClient) {
      loadVpnClientByIp(selectedNode._ip)
    }
  })

  // --- Virtual IPs (extra VPN /32s hosted by this peer, forwarded to a LAN device) ---
  let vips = $state([])
  let vipsLoading = $state(false)
  let vipsError = $state('')
  let newVipLabel = $state('')
  let newVipTargetIp = $state('')
  let newVipTargetPort = $state('')
  // A typed port must be a real one: dropping a bad one would forward every port instead.
  const vipPortProblem = $derived.by(() => {
    const p = newVipTargetPort.trim()
    return !p || (/^\d{1,5}$/.test(p) && +p >= 1 && +p <= 65535) ? '' : 'Port must be a number from 1 to 65535 (leave it blank to open all ports)'
  })
  let expandedVipCmd = $state(null) // vip id whose forwarding commands are inline-expanded
  let vipCmdText = $state('')       // fetched setup commands
  let vipRemoveText = $state('')    // fetched teardown commands
  let vipCmdMode = $state('add')    // 'add' | 'remove'
  let vipCmdLoading = $state(false)
  let postDeleteTeardown = $state(null) // { ip, commands } shown after deleting a forwarding vip

  async function loadVips() {
    const key = selectedNode?._wgId
    if (selectedNode?._type !== 'wireguard' || !key) { vips = []; return }
    vipsLoading = true
    vipsError = ''
    try {
      const res = (await apiGet(`/api/wg/peers/${key}/vips`)) || []
      if (mounted) vips = res
    } catch (e) {
      if (mounted) { vips = []; vipsError = e?.message || 'Failed to load virtual IPs' }
    } finally {
      if (mounted) vipsLoading = false
    }
  }

  async function addVip() {
    const label = newVipLabel.trim()
    if (!label) { toast('Give the virtual IP a name — it names the forwarding rule', 'error'); return }
    if (vipPortProblem) return
    try {
      const body = { label, restricted: true }
      if (newVipTargetIp.trim()) {
        body.targetIp = newVipTargetIp.trim()
        // Optional: a port forwards only that TCP port; blank forwards all ports.
        if (newVipTargetPort.trim()) body.targetPort = +newVipTargetPort.trim()
      }
      await apiPost(`/api/wg/peers/${selectedNode._wgId}/vips`, body)
      newVipLabel = ''; newVipTargetIp = ''; newVipTargetPort = ''
      toast('Virtual IP added', 'success')
      await loadVips()
    } catch (e) { toast(e?.message || 'Failed to add virtual IP', 'error') }
  }

  // Inline (in-modal) confirm — a stacked confirm modal breaks the parent modal.
  let confirmRemoveVipId = $state(null)
  let removingVip = $state(false)
  // While one is being deleted, it's the only card shown: the question can't be mistaken for another's.
  const shownVips = $derived.by(() => {
    const one = confirmRemoveVipId && vips.find((v) => v.id === confirmRemoveVipId)
    return one ? [one] : vips
  })
  async function doRemoveVip(vip) {
    removingVip = true
    try {
      const res = await apiDelete(`/api/wg/vips/${vip.id}`)
      toast('Virtual IP removed', 'success')
      confirmRemoveVipId = null
      // If the vip had a forward, surface the peer-side teardown so a forgotten cleanup
      // can't leave an orphan DNAT chain a recycled vip IP would inherit.
      if (res?.removeCommands) {
        postDeleteTeardown = { ip: res.ip || vip.ip, commands: res.removeCommands }
      }
      await loadVips()
    } catch (e) {
      toast(e?.message || 'Failed to remove', 'error')
    } finally {
      removingVip = false
    }
  }

  async function saveVipAcl(vip) {
    try {
      await apiPut(`/api/wg/vips/${vip.id}/acl`, { restricted: vip.restricted, quarantine: vip.quarantine, allowedClientIds: vip.allowedClientIds || [] })
    } catch (e) { toast(e?.message || 'Failed to update', 'error'); await loadVips() }
  }

  function toggleVipRestrict(vip) { vip.restricted = !vip.restricted; saveVipAcl(vip) }
  function toggleVipQuarantine(vip) { vip.quarantine = !vip.quarantine; saveVipAcl(vip) }

  function toggleVipPeer(vip, clientId) {
    const set = new Set(vip.allowedClientIds || [])
    if (set.has(clientId)) set.delete(clientId); else set.add(clientId)
    vip.allowedClientIds = [...set]
    saveVipAcl(vip)
  }

  // Show a vip's setup/remove commands inline (no nested modal → no stacking bug).
  // The Set up / Remove buttons drive the mode; clicking the active one collapses.
  async function showVipCmd(vip, mode) {
    if (expandedVipCmd === vip.id && vipCmdMode === mode) { expandedVipCmd = null; return }
    const needFetch = expandedVipCmd !== vip.id
    expandedVipCmd = vip.id
    vipCmdMode = mode
    if (!needFetch) return
    // Capture the target id: if the user switches to another vip mid-flight, a stale
    // response must not overwrite the now-active vip's commands or clear its spinner.
    const reqId = vip.id
    vipCmdText = ''; vipRemoveText = ''
    vipCmdLoading = true
    try {
      const res = await apiGet(`/api/wg/vips/${vip.id}/commands`)
      if (expandedVipCmd !== reqId) return
      vipCmdText = res.commands
      vipRemoveText = res.removeCommands || ''
    } catch (e) {
      if (expandedVipCmd !== reqId) return
      vipCmdText = '# ' + (e?.message || 'Failed to load commands')
    } finally {
      if (expandedVipCmd === reqId) vipCmdLoading = false
    }
  }

  // Whether this vip's set-up ('add') or tear-down ('remove') commands are the ones showing.
  const showingVipCmd = (vip, mode) => expandedVipCmd === vip.id && vipCmdMode === mode

  // Other peers that can be granted access to a virtual IP (exclude the host peer itself).
  const vipPeerChoices = $derived(
    (vpnClients || []).filter(c => c.ip !== selectedNode?._ip).map(c => ({ id: c.id, name: c.name || c.ip, ip: c.ip }))
  )

  // Key that identifies which peer's vips to show — a plain string, so it stays
  // stable across the frequent websocket-driven re-renders of selectedNode.
  const vipsKey = $derived(
    activeTab === 'qr' && selectedNode?._type === 'wireguard' ? (selectedNode?._wgId || '') : ''
  )

  // Fetch only when the key actually changes (untrack keeps loadVips's internal
  // state reads from feeding back into this effect and re-triggering it).
  $effect(() => {
    vipsKey // sole dependency
    untrack(() => { if (vipsKey) loadVips() })
  })

  function closeModal() {
    showNodeModal = false
    confirmAction = null
  }

  async function saveName() {
    if (!selectedNode || !newName.trim()) return
    try {
      if (selectedNode._type === 'wireguard') {
        await apiPut(`/api/wg/peers/${selectedNode._wgId}`, { name: newName })
      } else {
        await apiPost(`/api/hs/nodes/${selectedNode.id}/rename/${encodeURIComponent(newName)}`)
      }
      toast('Node renamed', 'success')
      editingName = false
      onchanged?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }


  // Headscale ACL tags set by an admin (forcedTags). Tags the device advertised itself (validTags)
  // are shown but can't be removed here.
  async function saveNodeTags(next) {
    await apiPut(`/api/hs/nodes/${selectedNode.id}/tags`, { tags: next })
    selectedNode.forcedTags = next
    onchanged?.()
  }

  async function deleteNode() {
    if (!selectedNode) return
    // Destructive + irreversible → step-up re-auth (password, +2FA when enabled), verified server-side.
    const su = await stepUpConfirm({
      title: 'Delete node',
      message: `Delete ${selectedNode._displayName}? This cannot be undone.`,
      confirmText: 'Delete',
      variant: 'destructive',
    })
    if (!su?.confirmed || !su?.password) return
    const body = { currentPassword: su.password, totpCode: su.totp || '' }
    actionLoading = true
    try {
      if (selectedNode._type === 'wireguard') {
        await apiDelete(`/api/wg/peers/${selectedNode._wgId}`, body)
      } else {
        await apiDelete(`/api/hs/nodes/${selectedNode.id}`, body)
      }
      toast('Node deleted', 'success')
      closeModal()
      onchanged?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      actionLoading = false
      confirmAction = null
    }
  }

  async function expireNode() {
    if (!selectedNode) return
    actionLoading = true
    try {
      await apiPost(`/api/hs/nodes/${selectedNode.id}/expire`)
      toast('Node key expired', 'success')
      confirmAction = null
      onchanged?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      actionLoading = false
    }
  }

  async function toggleBlockInternet() {
    if (!selectedNode) return
    actionLoading = true
    try {
      const block = !selectedNode.blockInternet
      await apiPost(`/api/wg/peers/${selectedNode._wgId}/${block ? 'block-internet' : 'unblock-internet'}`)
      toast(block ? 'Internet blocked for peer' : 'Internet restored', 'success')
      selectedNode = { ...selectedNode, blockInternet: block }
      confirmAction = null
      onchanged?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      actionLoading = false
    }
  }

  async function toggleWgPeer() {
    if (!selectedNode) return
    try {
      const newState = !selectedNode.enabled
      await apiPost(`/api/wg/peers/${selectedNode._wgId}/${selectedNode.enabled ? 'disable' : 'enable'}`)
      toast(newState ? 'Peer enabled' : 'Peer disabled', 'success')
      // Update selectedNode immediately for UI feedback
      selectedNode = { ...selectedNode, enabled: newState }
      onchanged?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }
</script>

<!-- Node Detail Modal -->
<Modal bind:open={showNodeModal} size="wide" bodyClass="p-0">
  {#snippet header()}
    {#if selectedNode}
      <!-- min-h-control: the name and its rename input take the same room, so nothing jumps -->
      <div class="flex min-h-control items-center">
        <div class="flex-1 min-w-0">
          {#if editingName}
            <div class="flex items-center gap-2">
              <Input
                bind:value={newName}
                onkeydown={(e) => e.key === 'Enter' && saveName()} 
                suffixAddonBtn={{ icon: "check", onclick: saveName ,color:'warning'}}
              />
            </div>
          {:else}
            <div class="flex items-center gap-2">
              <!-- the client's name, with its type icon (green when online); click to rename -->
              <button onclick={() => editingName = true} title="Rename" class="kt-badge kt-badge-outline kt-badge-secondary min-w-0 cursor-pointer">
                <Icon name={deviceIcon(selectedNode)} size={14} class={selectedNode._online ? 'text-success' : 'text-muted-foreground'} />
                <span class="truncate font-medium text-foreground">{selectedNode._displayName}</span>
                <Icon name="edit" size={12} class="text-muted-foreground" />
              </button>
              <!-- the rest of the state badges: hidden on phones, where the name alone fits -->
              <span class="hidden items-center gap-2 sm:flex">
              <Badge variant={selectedNode._online ? 'success' : 'muted'} size="sm">{selectedNode._online ? 'Online' : 'Offline'}</Badge>
              <Badge variant={selectedNode._type === 'wireguard' ? 'info' : 'primary'} size="sm">{selectedNode._type === 'wireguard' ? 'WG' : 'TS'}</Badge>
              {#if selectedNode._type === 'wireguard' && !selectedNode.enabled}<Badge variant="warning" size="sm">Disabled</Badge>{/if}
              {#if selectedNode._type === 'wireguard' && selectedNode.blockInternet}<Badge variant="destructive" size="sm">No Internet</Badge>{/if}
              {#if isExitNode}<Badge variant="success" size="sm">Exit</Badge>{/if}
              <button onclick={toggleDNS} class="kt-badge kt-badge-sm {hasDNS ? 'kt-badge-info' : 'kt-badge-outline kt-badge-secondary'} cursor-pointer" title="Toggle the DNS name for this client">DNS name</button>
              </span>
            </div>
          {/if}
        </div>
      </div>
    {/if}
  {/snippet}
  {#if selectedNode}
      <!-- Tabs -->
      <Tabs tabs={detailTabs} bind:activeTab size="xs" background class="px-4" />

      <!-- Content -->
      <div class="p-4 max-h-[60vh] overflow-y-auto">
        {#if activeTab === 'overview'}
          {#if selectedNode._type === 'wireguard'}
            <!-- WireGuard Overview -->
            <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
              <ContentBlock variant="data" size="sm" solid light label="IP Address" value={selectedNode._ip || '—'} copyable={!!selectedNode._ip} mono />
              <ContentBlock variant="data" size="sm" solid light label="Created" value={formatDate(selectedNode.createdAt)} rightIcon="calendar" />
              <ContentBlock variant="data" size="sm" solid light label="Last Seen" value={timeAgo(selectedNode.lastHandshake || selectedNode.lastSeen)} rightIcon="clock" />
              <ContentBlock variant="data" size="sm" solid light label="Uploaded" value={formatBytes(selectedNode.totalTx)} rightIcon="upload" />
              <ContentBlock variant="data" size="sm" solid light label="Downloaded" value={formatBytes(selectedNode.totalRx)} rightIcon="download" />
              <ContentBlock variant="data" size="sm" solid light label="Public Key" value={selectedNode.publicKey} copyable mono />
            </div>
          {:else}
            <!-- Tailscale Overview - Combined -->
            <div class="space-y-4">
              <!-- Main info grid - 2 cols mobile, 3 cols desktop -->
              <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <ContentBlock variant="data" size="sm" solid light label="User" value={selectedNode.user?.name || '—'} rightLabel="Node" rightValue={selectedNode.id} rightMono />
                <ContentBlock variant="data" size="sm" solid light label="Created" value={formatDate(selectedNode.createdAt)} rightIcon="calendar" />
                <ContentBlock variant="data" size="sm" solid light label="Last Seen" value={timeAgo(selectedNode.lastSeen)} rightIcon="clock" />
                <ContentBlock variant="data" size="sm" solid light label="Key Expiry" value={selectedNode.expiry && !selectedNode.expiry.startsWith('0001') ? formatDate(selectedNode.expiry) : 'Never'} rightIcon="key" />
                <ContentBlock variant="data" size="sm" solid light label="IPv4" value={selectedNode._ip || '—'} mono rightLabel={selectedNode.ipAddresses?.[1] ? 'IPv6' : ''} rightValue={selectedNode.ipAddresses?.[1] || ''} rightMono class="col-span-2" />
              </div>

              <!-- Keys -->
              <div class="grid grid-cols-2 gap-3">
                {#if selectedNode.registerMethod}
                  <ContentBlock variant="data" size="sm" solid light label="Auth Method" value={selectedNode.registerMethod.replace('REGISTER_METHOD_', '')} />
                {/if}
                {#each [['Machine Key', selectedNode.machineKey], ['Node Key', selectedNode.nodeKey], ['Disco Key', selectedNode.discoKey]].filter(([,v]) => v) as [label, key]}
                  <ContentBlock variant="data" size="sm" solid light label={label} value={key} copyable mono />
                {/each}
              </div>

              <!-- Tags -->
              <div class="pt-3 border-t border-border">
                <h4 class="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-2">ACL tags</h4>
                <TagEditor tags={selectedNode.forcedTags || []} prefix="tag:" canEdit={isAdmin} onsave={saveNodeTags} />
                {#if selectedNode.validTags?.length}
                  <p class="mt-1.5 text-[11px] text-muted-foreground">Advertised by the device: {selectedNode.validTags.map((t) => t.replace('tag:', '')).join(', ')}</p>
                {/if}
              </div>

              <!-- Routes -->
              {#if nodeRoutes.length > 0}
                <div class="pt-3 border-t border-border">
                  <h4 class="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-2">Routes</h4>
                  <div class="flex flex-wrap gap-2">
                    {#each nodeRoutes as route}
                      <div class="inline-flex items-center gap-2 px-2 py-1 bg-muted/50 rounded text-xs">
                        <code class="font-mono">{route.prefix}</code>
                        <span class="w-1.5 h-1.5 rounded-full {route.enabled ? 'bg-success' : 'bg-muted-foreground'}"></span>
                      </div>
                    {/each}
                  </div>
                </div>
              {/if}
            </div>
          {/if}

          <!-- Top destinations: where this client's traffic went (the conntrack watcher's byte counts) -->
          <div class="mt-4 pt-3 border-t border-border space-y-3">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <h4 class="text-[10px] font-medium text-muted-foreground uppercase tracking-wide">Top destinations</h4>
              <div class="flex items-center gap-2">
                <Segmented size="sm" label="Period" bind:value={peerUsagePeriod}
                  options={[{ value: 'hour', label: 'Hour' }, { value: 'day', label: 'Day' }, { value: 'week', label: 'Week' }]} />
                {#if selectedNode._type === 'wireguard'}
                  <Button onclick={resetPeerTotals} size="sm" variant="secondary" icon="refresh" tooltip="Set this client's totals and destinations back to zero">Reset traffic</Button>
                {/if}
              </div>
            </div>
            {#if peerUsage?.destinations?.length}
              <div class="transition-opacity {peerUsageLoading ? 'opacity-50' : ''}" aria-busy={peerUsageLoading}>
                <BarList data={peerUsage.destinations.slice(0, 5).map(d => ({ ...d, label: d.domain || d.dest_ip }))} labelKey="label" valueKey="bytes_total" labelWidth="w-40" format={formatBytes} barClass="bg-info" />
              </div>
              <p class="text-[10px] text-muted-foreground">Counted since the conntrack watcher was turned on, so it can be less than the totals above.</p>
            {:else if peerUsageLoading}
              <div class="space-y-2.5" aria-busy="true" aria-label="Loading destinations">
                {#each [100, 70, 45] as w}
                  <div class="flex items-center gap-3"><Skeleton class="h-3 w-40" /><Skeleton class="h-3" style="width: {w * 0.4}%" /></div>
                {/each}
              </div>
            {:else}
              <div class="text-center py-4 space-y-1">
                <Icon name="chart-bar" size={24} class="mx-auto text-muted-foreground/50" />
                <div class="text-sm text-foreground">No destination data yet</div>
                <div class="text-[11px] text-muted-foreground">Turn on the <span class="font-mono">conntrack</span> watcher in Settings → General → Log Watchers, then generate some traffic.</div>
              </div>
            {/if}
          </div>

        {:else if activeTab === 'qr'}
          <!-- WireGuard Config tab: QR and config side by side -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <!-- Left: Tunnel selector + actions -->
            <div class="space-y-4">
              <div>
                <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Tunnel Mode</div>
                <div class="grid grid-cols-2 gap-2">
                  <OptionCard title="Full" description="All traffic" active={tunnelMode === 'full'} onclick={() => tunnelMode = 'full'} />
                  <OptionCard title="Split" description="VPN only" active={tunnelMode === 'split'} onclick={() => tunnelMode = 'split'} />
                </div>
              </div>

              <div class="grid grid-cols-2 gap-2">
                <Button onclick={() => downloadPeerConfig(selectedNode._wgId, selectedNode._displayName, tunnelMode)} size="sm" icon="download" class="justify-center">
                  Download
                </Button>
                <Button onclick={() => copyPeerConfig(selectedNode._wgId, tunnelMode)} variant="secondary" size="sm" icon="copy" class="justify-center">
                  Copy
                </Button>
              </div>

              <!-- Mobile: Quick Setup with QR inline -->
              <div class="p-3 bg-muted/30 rounded-lg text-xs text-muted-foreground md:hidden">
                <div class="flex gap-3">
                  <div class="flex-1">
                    <p class="font-medium text-foreground mb-1">Quick Setup</p>
                    <ol class="list-decimal list-inside space-y-0.5">
                      <li>Select tunnel mode</li>
                      <li>Scan QR or download config</li>
                      <li>Import to WireGuard app</li>
                    </ol>
                  </div>
                  <div class="w-24 h-24 bg-white rounded-lg flex items-center justify-center shrink-0">
                    {#if qrLoading}
                      <div class="w-5 h-5 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
                    {:else if qrUrl}
                      <img src={qrUrl} alt="QR Code" class="w-20 h-20" />
                    {:else}
                      <span class="text-muted-foreground text-[10px]">Error</span>
                    {/if}
                  </div>
                </div>
              </div>

              <!-- Desktop: Quick Setup only -->
              <div class="p-3 bg-muted/30 rounded-lg text-xs text-muted-foreground hidden md:block">
                <p class="font-medium text-foreground mb-1">Quick Setup</p>
                <ol class="list-decimal list-inside space-y-0.5">
                  <li>Select tunnel mode</li>
                  <li>Scan QR or download config</li>
                  <li>Import to WireGuard app</li>
                </ol>
              </div>
            </div>

            <!-- Right: QR Code (desktop only) -->
            <div class="hidden md:flex items-center justify-center p-4 bg-white rounded-xl border border-border min-h-[200px]">
              {#if qrLoading}
                <div class="w-8 h-8 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
              {:else if qrUrl}
                <img src={qrUrl} alt="QR Code" class="max-w-full max-h-[200px]" />
              {:else}
                <span class="text-muted-foreground text-sm">Failed to load</span>
              {/if}
            </div>
          </div>

          <!-- Virtual IPs: expose a LAN device (camera, NAS…) over the VPN via this peer -->
          <div class="mt-5 pt-4 border-t border-border">
            <div class="flex items-center justify-between mb-1">
              <h4 class="text-sm font-semibold">Virtual IPs</h4>
              <span class="text-xs text-muted-foreground">expose a LAN device through this peer</span>
            </div>
            <div class="flex flex-col sm:flex-row gap-2 mt-2">
              <Input bind:value={newVipLabel} placeholder="Name (required, e.g. Tapo camera)" prefixIcon="tag" class="flex-1" />
              <Input bind:value={newVipTargetIp} placeholder="LAN device IP, e.g. 192.168.1.40" prefixIcon="device-laptop" class="flex-1" />
              <!-- port and Add share a line on phones; from sm up they join the row -->
              <div class="flex gap-2 sm:contents">
                <Input bind:value={newVipTargetPort} placeholder="Port" prefixIcon="hash" inputmode="numeric" class="min-w-0 flex-1 sm:w-24 sm:flex-none" />
                <Button onclick={addVip} icon="plus" disabled={!!vipPortProblem} class="shrink-0">Add</Button>
              </div>
            </div>
            {#if vipPortProblem}
              <p class="mt-1 flex items-center gap-1.5 text-xs text-destructive"><Icon name="alert-triangle" size={14} />{vipPortProblem}</p>
            {/if}
            <div class="text-xs text-muted-foreground mt-1">Its VPN address is assigned for you. Leave the device IP blank for an extra address of this client itself, or fill it in to reach a device on its network (a camera, a NAS). Add a port to open only that port; leave it blank to open all.</div>

            {#if postDeleteTeardown}
              <!-- Post-delete: hand over the peer-side teardown so a forgotten cleanup can't leave an orphan chain -->
              <div class="mt-3 rounded-lg border border-warning/40 bg-warning/5 p-3 space-y-2">
                <div class="flex items-start gap-2">
                  <Icon name="alert-triangle" size={16} class="text-warning shrink-0 mt-0.5" />
                  <div class="min-w-0 flex-1">
                    <div class="text-sm font-medium">Removed {postDeleteTeardown.ip} — clear the forward on the peer</div>
                    <div class="text-xs text-muted-foreground">Run these on the peer to remove the leftover DNAT chain (skip if you already tore it down).</div>
                  </div>
                  <button class="text-muted-foreground hover:text-foreground shrink-0" title="Dismiss" onclick={() => postDeleteTeardown = null}><Icon name="x" size={16} /></button>
                </div>
                <div class="relative">
                  <pre class="text-[11px] bg-secondary/60 rounded-md p-2.5 overflow-x-auto font-mono whitespace-pre">{postDeleteTeardown.commands}</pre>
                  <Button size="xs" variant="outline" icon="copy" class="absolute top-2 right-2" onclick={() => copyWithToast(postDeleteTeardown.commands, toast)}>Copy</Button>
                </div>
              </div>
            {/if}

            {#if vipsLoading}
              <div class="flex justify-center py-6"><LoadingSpinner /></div>
            {:else if vipsError}
              <div class="flex items-center justify-center gap-1.5 text-destructive py-4 text-sm">
                <Icon name="alert-triangle" size={14} />{vipsError}
              </div>
            {:else if vips.length === 0}
              <div class="mt-3">
                <EmptyState icon="network" title="No virtual IPs yet" description="Expose a LAN device (camera, NAS…) to the VPN through this peer — add one above." compact />
              </div>
            {:else}
              <div class="space-y-2.5 mt-3">
                {#each shownVips as vip (vip.id)}
                  <div class="rounded-lg border border-border bg-card overflow-hidden">
                    {#if confirmRemoveVipId === vip.id}
                      <!-- Delete mode: replaces the whole card body (like the node actions delete) -->
                      <div class="p-3 space-y-3 bg-destructive/5">
                        <div class="flex items-start gap-2.5">
                          <Icon name="alert-triangle" size={18} class="text-destructive shrink-0 mt-0.5" />
                          <div class="min-w-0">
                            <div class="text-sm font-medium">Remove this virtual IP?</div>
                            <div class="text-xs text-muted-foreground truncate"><span class="font-mono">{vip.ip}</span>{#if vip.label} · {vip.label}{/if} — unrouted from this peer immediately.</div>
                            {#if vip.targetIp}
                              <div class="text-xs text-warning mt-1">Run the <span class="font-medium">Tear-down commands</span> on the peer first — deleting here won't remove the iptables rule on the NAS.</div>
                            {/if}
                          </div>
                        </div>
                        <div class="flex justify-between gap-2">
                          <Button size="sm" variant="secondary" disabled={removingVip} onclick={() => confirmRemoveVipId = null}>Cancel</Button>
                          <Button size="sm" variant="destructive" disabled={removingVip} icon={removingVip ? undefined : 'trash'} onclick={() => doRemoveVip(vip)}>{removingVip ? 'Removing…' : 'Remove'}</Button>
                        </div>
                      </div>
                    {:else}
                      <!-- Header: icon, name and addresses on the left; actions with the state badges under them on the right -->
                      <div class="flex items-start gap-3 p-3">
                        <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                          <Icon name="network" size={18} />
                        </span>
                        <div class="min-w-0 flex-1 space-y-1">
                          <div class="truncate text-sm font-medium text-foreground">{vip.label || 'Virtual IP'}</div>
                          <div class="truncate font-mono text-xs text-muted-foreground">
                            {vip.ip}{#if vip.targetIp}<span class="mx-1">→</span>{vip.targetIp}{#if vip.targetPort}:{vip.targetPort}{/if}{/if}
                          </div>
                        </div>
                        <div class="flex shrink-0 flex-col items-end gap-1.5">
                          <!-- Grouped actions: the commands toggles stay highlighted while their commands show -->
                          <div class="kt-btn-group shrink-0">
                            {#if vip.targetIp}
                              <Button variant="outline" size="xs" icon="code" class="text-primary hover:bg-primary/10 {showingVipCmd(vip, 'add') ? 'bg-primary/15' : ''}"
                                tooltip="Set-up commands" aria-label="Set-up commands" aria-pressed={showingVipCmd(vip, 'add')} onclick={() => showVipCmd(vip, 'add')} />
                              <Button variant="outline" size="xs" icon="plug" class="text-warning hover:bg-warning/10 {showingVipCmd(vip, 'remove') ? 'bg-warning/15' : ''}"
                                tooltip="Tear-down commands" aria-label="Tear-down commands" aria-pressed={showingVipCmd(vip, 'remove')} onclick={() => showVipCmd(vip, 'remove')} />
                            {/if}
                            <Button variant="outline" size="xs" icon="trash" class="text-destructive hover:bg-destructive/10"
                              tooltip="Delete virtual IP" aria-label="Delete virtual IP" onclick={() => confirmRemoveVipId = vip.id} />
                          </div>
                          <div class="flex flex-wrap justify-end gap-1.5">
                            <Badge variant={vip.restricted ? 'warning' : 'success'} size="sm">{vip.restricted ? 'Restricted' : 'Open'}</Badge>
                            {#if vip.quarantine}<Badge variant="destructive" size="sm">Quarantined</Badge>{/if}
                          </div>
                        </div>
                      </div>

                      <!-- Forwarding commands (driven by the Set up / Remove buttons) -->
                      {#if expandedVipCmd === vip.id}
                        {@const cmdText = vipCmdMode === 'remove' ? vipRemoveText : vipCmdText}
                        <div class="border-t border-border bg-secondary/40 px-3 py-2.5 space-y-2">
                          {#if vipCmdLoading}
                            <div class="flex justify-center py-3"><LoadingSpinner /></div>
                          {:else}
                            <div class="text-[11px] font-medium text-muted-foreground">{vipCmdMode === 'remove' ? 'Remove the forward — run on the peer' : 'Set up the forward — run on the peer'}</div>
                            <div class="relative">
                              <pre class="bg-secondary text-secondary-foreground p-3 pr-14 rounded-lg text-[11px] font-mono overflow-x-auto whitespace-pre-wrap">{cmdText}</pre>
                              <Button size="xs" variant="outline" icon="copy" class="absolute top-2 right-2" onclick={() => copyWithToast(cmdText, toast)}>Copy</Button>
                            </div>
                            <p class="text-[11px] text-muted-foreground">
                              Runtime-only — persist with <span class="font-mono">iptables-save</span> or a boot task. Reach it from any allowed peer at <span class="font-mono">{vip.ip}</span>.
                            </p>
                          {/if}
                        </div>
                      {/if}

                      <!-- Controls -->
                      <div class="border-t border-border bg-muted/20 px-3 py-2.5 space-y-2.5">
                        <!-- one switch per line: text on the left, switch on the right -->
                        <div class="space-y-2">
                          <Checkbox variant="switch" label="Restrict to selected peers" checked={vip.restricted} onchange={() => toggleVipRestrict(vip)} />
                          <Checkbox variant="switch" label="Quarantine" checked={vip.quarantine} onchange={() => toggleVipQuarantine(vip)} />
                        </div>

                        {#if vip.restricted}
                          <div class="border-t border-border/50 pt-2.5">
                            <div class="text-xs text-muted-foreground mb-2">
                              Allowed peers{#if !(vip.allowedClientIds?.length)}<span class="ml-1 text-destructive">— none yet (unreachable)</span>{/if}
                            </div>
                            {#if vipPeerChoices.length === 0}
                              <div class="text-xs text-muted-foreground">No other peers to allow.</div>
                            {:else}
                              <div class="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                                {#each vipPeerChoices as peer (peer.id)}
                                  <div class="flex items-center gap-2 text-sm p-1.5 rounded-lg border border-transparent hover:border-border hover:bg-muted/50 transition">
                                    <Checkbox checked={(vip.allowedClientIds || []).includes(peer.id)} onchange={() => toggleVipPeer(vip, peer.id)} />
                                    <span class="truncate">{peer.name}</span>
                                    <span class="text-xs text-muted-foreground font-mono ml-auto">{peer.ip}</span>
                                  </div>
                                {/each}
                              </div>
                            {/if}
                          </div>
                        {/if}
                      </div>
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}
          </div>

        {:else if activeTab === 'access'}
          <!-- Access Control Tab -->
          <div class="space-y-4">
            {#if !selectedVpnClient}
              <!-- Not synced yet -->
              <div class="text-center py-6">
                <div class="w-12 h-12 rounded-full bg-muted/50 flex items-center justify-center mx-auto mb-3">
                  <Icon name="shield-lock" size={24} class="text-muted-foreground" />
                </div>
                <p class="text-sm text-muted-foreground mb-3">
                  This node hasn't been synced to the VPN access control system yet.
                </p>
                <Button onclick={syncVpnClients} size="sm" icon="refresh" disabled={aclSyncing}>
                  {aclSyncing ? 'Syncing...' : 'Sync VPN Clients'}
                </Button>
              </div>
            {:else}
              <!-- Access Policy -->
              <div>
                <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Access Policy</div>
                <div class="grid grid-cols-3 gap-2">
                  <OptionCard icon="ban" title="Block All" description="Isolated" hideDescOnPhone size="sm" color="destructive" active={aclPolicy === 'block_all'} onclick={() => aclPolicy = 'block_all'} />
                  <OptionCard icon="list-check" title="Selected" description="Choose below" hideDescOnPhone size="sm" active={aclPolicy === 'selected'} onclick={() => aclPolicy = 'selected'} />
                  <OptionCard icon="checks" title="Allow All" description="Full access" hideDescOnPhone size="sm" color="success" active={aclPolicy === 'allow_all'} onclick={() => aclPolicy = 'allow_all'} />
                </div>
              </div>

              {#if aclPolicy === 'selected'}
                <!-- Router info when not running -->
                {#if !routerRunning}
                  <div class="p-3 bg-info/10 border border-info/20 rounded-lg flex items-start gap-2 text-xs">
                    <Icon name="info-circle" size={14} class="text-info shrink-0 mt-0.5" />
                    <div>
                      {#if selectedNode?._type === 'wireguard'}
                        <span class="text-foreground">Only WireGuard clients are shown.</span>
                        <span class="text-muted-foreground">Enable VPN Router to allow communication with Tailscale nodes.</span>
                      {:else}
                        <span class="text-foreground">Only Tailscale clients are shown.</span>
                        <span class="text-muted-foreground">Enable VPN Router to allow communication with WireGuard nodes.</span>
                      {/if}
                    </div>
                  </div>
                {/if}

                <!-- Client Selection -->
                <div>
                  <div class="flex items-center justify-between mb-2">
                    <div class="text-[10px] uppercase tracking-wide text-muted-foreground">This client can reach:</div>
                    <span class="text-[10px] text-muted-foreground">{aclView.filter(c => c.isEnabled).length} selected</span>
                  </div>
                  <div class="border border-border rounded-lg max-h-48 overflow-y-auto">
                    {#each aclView.filter(c => routerRunning || (selectedNode?._type === 'wireguard' ? c.type === 'wireguard' : c.type === 'headscale')) as client}
                      <AccessRow name={client.name} ip={client.ip} type={client.type}
                        checked={client.isEnabled} both={client.isBi}
                        disabled={client.aclPolicy === 'block_all' || client.aclPolicy === 'allow_all'}
                        bothTitle="Allow {client.name} to also reach this client"
                        ontoggle={() => toggleClient(client.id)}
                        onboth={client.aclPolicy === 'selected' ? () => toggleBidirectional(client.id) : undefined}>
                        {#snippet note()}
                          {#if client.aclPolicy === 'block_all'}
                            <span class="text-destructive ml-1">• Can't be reached</span>
                          {:else if client.aclPolicy === 'allow_all'}
                            <span class="text-success ml-1">• You can connect</span>
                          {/if}
                        {/snippet}
                      </AccessRow>
                    {:else}
                      <div class="p-4 text-center text-sm text-muted-foreground">
                        No clients found
                      </div>
                    {/each}
                  </div>
                  <p class="text-[10px] text-muted-foreground mt-2">
                    <Icon name="info-circle" size={10} class="inline" /> Use "Bi" to allow bidirectional communication. Clients with special policies (Block All/Allow All) cannot be selected.
                  </p>
                </div>
              {/if}

              <!-- Save Button -->
              <div class="pt-3 mt-3 border-t border-dashed border-border flex justify-end">
                <Button onclick={saveAcl} disabled={aclLoading} icon={aclLoading ? undefined : 'device-floppy'}>
                  {aclLoading ? 'Saving...' : 'Save & Apply'}
                </Button>
              </div>
            {/if}
          </div>

        {:else if activeTab === 'adblock' && isAdmin}
          <AdBlockPanel {clientKey} />
        {:else if activeTab === 'actions' || activeTab === 'security'}
          <!-- Actions Tab -->
          {#if confirmAction === 'expire'}
            <!-- Expire Confirmation -->
            <div class="space-y-4">
              <div class="p-4 bg-warning/10 border border-warning/20 rounded-lg">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-warning/15 text-warning shrink-0">
                    <Icon name="alert-triangle" size={20} />
                  </div>
                  <div>
                    <p class="font-medium text-foreground">Expire key for {selectedNode._displayName}?</p>
                    <p class="text-sm text-muted-foreground mt-0.5">The device will need to re-authenticate to reconnect.</p>
                  </div>
                </div>
              </div>
              <div class="flex justify-between">
                <Button onclick={() => confirmAction = null} variant="secondary" disabled={actionLoading}>
                  Cancel
                </Button>
                <Button onclick={expireNode} class="kt-btn-warning" disabled={actionLoading} icon={actionLoading ? undefined : "clock"}>
                  {#if actionLoading}
                    <span class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                  {:else}
                    Expire Key
                  {/if}
                </Button>
              </div>
            </div>
          {:else if confirmAction === 'block-internet'}
            <!-- Block Internet Confirmation -->
            <div class="space-y-4">
              <div class="p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-destructive/15 text-destructive shrink-0">
                    <Icon name="world-off" size={20} />
                  </div>
                  <div>
                    <p class="font-medium text-foreground">Block internet for {selectedNode._displayName}?</p>
                    <p class="text-sm text-muted-foreground mt-0.5">Peer can still reach other VPN nodes and the server, but cannot access external sites until you unblock.</p>
                  </div>
                </div>
              </div>
              <div class="flex justify-between">
                <Button onclick={() => confirmAction = null} variant="secondary" disabled={actionLoading}>
                  Cancel
                </Button>
                <Button onclick={toggleBlockInternet} variant="destructive" disabled={actionLoading} icon={actionLoading ? undefined : "world-off"}>
                  {#if actionLoading}
                    <span class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                  {:else}
                    Block Internet
                  {/if}
                </Button>
              </div>
            </div>
          {:else if confirmAction === 'unblock-internet'}
            <!-- Unblock Internet Confirmation -->
            <div class="space-y-4">
              <div class="p-4 bg-success/10 border border-success/20 rounded-lg">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-success/15 text-success shrink-0">
                    <Icon name="world" size={20} />
                  </div>
                  <div>
                    <p class="font-medium text-foreground">Restore internet for {selectedNode._displayName}?</p>
                    <p class="text-sm text-muted-foreground mt-0.5">Peer will regain full WAN access.</p>
                  </div>
                </div>
              </div>
              <div class="flex justify-between">
                <Button onclick={() => confirmAction = null} variant="secondary" disabled={actionLoading}>
                  Cancel
                </Button>
                <Button onclick={toggleBlockInternet} class="kt-btn-success" disabled={actionLoading} icon={actionLoading ? undefined : "world"}>
                  {#if actionLoading}
                    <span class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                  {:else}
                    Restore Internet
                  {/if}
                </Button>
              </div>
            </div>
          {:else}
            <!-- Normal Actions View -->
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {#if selectedNode._type === 'wireguard'}
                <OptionCard
                  icon={selectedNode.enabled ? 'hand-off' : 'hand-stop'}
                  title={selectedNode.enabled ? 'Disable' : 'Enable'}
                  description={selectedNode.enabled ? 'Block connections' : 'Allow connections'}
                  color={selectedNode.enabled ? 'warning' : 'success'}
                  size="lg"
                  iconBox
                  onclick={toggleWgPeer}
                />
                <OptionCard
                  icon={selectedNode.blockInternet ? 'world' : 'world-off'}
                  title={selectedNode.blockInternet ? 'Restore Internet' : 'Block Internet'}
                  description={selectedNode.blockInternet ? 'Allow WAN access' : 'Keep VPN, drop WAN'}
                  color={selectedNode.blockInternet ? 'success' : 'destructive'}
                  size="lg"
                  iconBox
                  onclick={() => confirmAction = selectedNode.blockInternet ? 'unblock-internet' : 'block-internet'}
                />
              {:else}
                <OptionCard icon="clock" title="Expire Key" description="Force re-authentication" color="warning" size="lg" iconBox onclick={() => confirmAction = 'expire'} />
              {/if}
              <OptionCard icon="trash" title="Delete" description="Remove permanently" color="destructive" size="lg" iconBox onclick={deleteNode} />
            </div>
          {/if}
        {/if}
      </div>
  {/if}
</Modal>
