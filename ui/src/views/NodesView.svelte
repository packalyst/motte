<script>
  import { onMount, onDestroy, untrack } from 'svelte'
  import { toast, apiGet, apiPost, apiPut, apiDelete, apiGetText, apiGetBlob } from '../stores/app.js'
  import { subscribe, unsubscribe, nodesUpdatedStore } from '../stores/websocket.js'
  import { loadState, saveState, copyWithToast } from '../stores/helpers.js'
  import { formatDate, timeAgo, formatBytes } from '$lib/utils/format.js'
  import { useDataLoader } from '$lib/composables/index.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import ContentBlock from '../components/ContentBlock.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import Tabs from '../components/Tabs.svelte'
  import OptionCard from '../components/OptionCard.svelte'
  import BarList from '../components/BarList.svelte'

  let { loading = $bindable(true) } = $props()

  // Multi-source data loading
  const loader = useDataLoader([
    { fn: () => apiGet('/api/vpn/clients'), key: 'clients', isArray: true },
    { fn: () => apiGet('/api/hs/routes'), key: 'routes', extract: 'routes', isArray: true }
  ])

  const vpnClients = $derived(loader.data.clients || [])
  const routes = $derived(loader.data.routes || [])

  // Sync loading state to parent
  $effect(() => { loading = loader.loading })

  // VPN Router state (minimal - for Access tab visibility)
  let routerRunning = $state(false)

  // ACL state
  let selectedVpnClient = $state(null)
  let aclPolicy = $state('selected')
  let aclView = $state([]) // All clients with isEnabled/isBi state from API
  let aclLoading = $state(false)
  let aclSyncing = $state(false)
  let hasDNS = $state(false)

  // React to WebSocket nodes_updated notifications
  // The store is a counter that increments on each notification
  let lastNodesUpdate = 0
  $effect(() => {
    const updateCount = $nodesUpdatedStore
    if (updateCount > lastNodesUpdate) {
      lastNodesUpdate = updateCount
      loader.reload()
    }
  })

  async function checkRouterStatus() {
    try {
      const status = await apiGet('/api/vpn/router/status')
      routerRunning = status?.status === 'running'
    } catch (e) {
      routerRunning = false
    }
  }

  // ACL functions - sync now happens automatically on loader.reload via /api/vpn/clients
  async function syncVpnClients() {
    aclSyncing = true
    try {
      await loader.reload()
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
      await loader.reload()
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

  onMount(() => {
    checkRouterStatus()
    subscribe('nodes_updated')
  })

  onDestroy(() => {
    mounted = false
    unsubscribe('nodes_updated')
    // Clean up QR code object URL
    if (qrUrl) URL.revokeObjectURL(qrUrl)
  })

  // Load saved filters from localStorage
  const savedFilters = loadState('nodes')

  let search = $state('')
  let statusFilter = $state(savedFilters.status || 'all') // 'all' | 'online' | 'offline'
  let typeFilter = $state(savedFilters.type || 'all') // 'all' | 'tailscale' | 'wireguard'
  let showFiltersDropdown = $state(false)
  let selectedNode = $state(null)

  // Save filters to localStorage when they change
  $effect(() => {
    saveState('nodes', { status: statusFilter, type: typeFilter })
  })
  let activeTab = $state('overview')

  // Dynamic tabs based on node type
  const detailTabs = $derived(
    selectedNode?._type === 'wireguard'
      ? [{id:'overview',label:'Overview'},{id:'traffic',label:'Traffic'},{id:'qr',label:'QR & Config'},{id:'access',label:'Access'},{id:'actions',label:'Actions'}]
      : [{id:'overview',label:'Overview'},{id:'traffic',label:'Traffic'},{id:'access',label:'Access'},{id:'actions',label:'Actions'}]
  )

  // Per-peer destination traffic breakdown (conntrack byte accounting)
  let peerUsage = $state(null)
  let peerUsageLoading = $state(false)
  let peerUsagePeriod = $state('day')
  let conntrackStatus = $state(null)   // { enabled, running, lastError, processed }

  async function loadPeerUsage() {
    const ip = selectedNode?._ip
    if (!ip) { peerUsage = null; return }
    peerUsageLoading = true
    // Watcher status explains an empty breakdown (disabled / erroring / no flows yet).
    try {
      const statuses = await apiGet('/api/logs/status')
      conntrackStatus = (Array.isArray(statuses) ? statuses : []).find(s => s.name === 'conntrack') || null
    } catch { conntrackStatus = null }
    try {
      peerUsage = await apiGet(`/api/logs/peer-usage?peer=${encodeURIComponent(ip)}&period=${peerUsagePeriod}`)
    } catch (e) {
      peerUsage = { destinations: [], error: e.message }
    } finally {
      peerUsageLoading = false
    }
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
      loader.reload()
      if (activeTab === 'traffic') loadPeerUsage()
    } catch (e) {
      toast('Failed to reset: ' + e.message, 'error')
    }
  }

  // Load usage when the Traffic tab is opened or the period changes.
  $effect(() => {
    if (activeTab === 'traffic' && selectedNode) {
      peerUsagePeriod // track
      loadPeerUsage()
    }
  })

  let showCreateModal = $state(false)
  let showNodeModal = $state(false)

  // Handle node modal close - reset editing states
  $effect(() => {
    if (!showNodeModal) {
      selectedNode = null
      editingName = false
    }
  })

  function openNodeModal(node) {
    selectedNode = node
    showNodeModal = true
  }

  let newPeerName = $state('')
  let createdPeer = $state(null)
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
      // Skip URL creation if component unmounted during fetch
      if (!mounted) return
      qrUrl = URL.createObjectURL(blob)
      qrLoadedFor = key
    } catch (e) {
      if (!mounted) return
      toast('Failed to load QR code', 'error')
      qrLoadedFor = null // Allow retry on error
    } finally {
      qrLoading = false
    }
  }

  // Load QR when tab changes to 'qr' for wireguard peer
  $effect(() => {
    if (selectedNode?._type === 'wireguard' && activeTab === 'qr') {
      loadQrCode(selectedNode._wgId, tunnelMode)
    }
  })

  // Build unified node list from vpnClients (which contains rawData with full info)
  const allNodes = $derived(vpnClients.map(client => {
    const raw = client.rawData || {}

    if (client.type === 'wireguard') {
      return {
        id: `wg-${client.externalId}`,
        _wgId: client.externalId,
        _type: 'wireguard',
        _displayName: client.name,
        _ip: client.ip,
        _online: raw.online || false,
        online: raw.online || false,
        lastHandshake: raw.lastHandshake,
        name: client.name,
        givenName: client.name,
        ipAddresses: [client.ip],
        createdAt: raw.createdAt || client.createdAt,
        lastSeen: raw.lastSeen,
        user: { name: 'WireGuard' },
        enabled: raw.enabled !== false,
        blockInternet: client.blockInternet === true,
        publicKey: raw.publicKey,
        privateKey: raw.privateKey,
        presharedKey: raw.presharedKey,
        totalTx: client.totalTx || 0,
        totalRx: client.totalRx || 0
      }
    } else {
      // Headscale node
      return {
        ...raw,
        id: client.externalId,
        _type: 'tailscale',
        _displayName: raw.givenName || raw.name || client.name,
        _ip: client.ip,
        _online: raw.online || false,
        ipAddresses: raw.ipAddresses || [client.ip],
        user: raw.user || { name: 'Unknown' }
      }
    }
  }))

  const filteredNodes = $derived(allNodes.filter(n => {
    // Status filter
    if (statusFilter === 'online' && !n._online) return false
    if (statusFilter === 'offline' && n._online) return false

    // Type filter
    if (typeFilter === 'tailscale' && n._type !== 'tailscale') return false
    if (typeFilter === 'wireguard' && n._type !== 'wireguard') return false

    // Search filter
    if (!search) return true
    const q = search.toLowerCase()
    return (
      n.name?.toLowerCase().includes(q) ||
      n.givenName?.toLowerCase().includes(q) ||
      n._displayName?.toLowerCase().includes(q) ||
      n._ip?.includes(q) ||
      n.user?.name?.toLowerCase().includes(q) ||
      n._type?.toLowerCase().includes(q)
    )
  }))

  // Get routes for selected node
  const nodeRoutes = $derived(selectedNode && selectedNode._type === 'tailscale'
    ? routes.filter(r => r.node?.id === selectedNode.id)
    : [])
  const isExitNode = $derived(nodeRoutes.some(r => r.prefix === '0.0.0.0/0'))

  function getDeviceIcon(node) {
    if (node._type === 'wireguard') return 'lock'
    const lower = node.name?.toLowerCase() || ''
    if (lower.includes('iphone') || lower.includes('android') || lower.includes('pixel')) return 'device-mobile'
    if (lower.includes('ipad') || lower.includes('tablet')) return 'device-tablet'
    if (lower.includes('macbook') || lower.includes('laptop')) return 'device-laptop'
    return 'device-desktop'
  }

  function selectNode(node) {
    selectedNode = node
    activeTab = 'overview'
    editingName = false
    tunnelMode = 'full'
    qrLoadedFor = null // Reset so QR loads fresh for new node
    newName = node._displayName
    // Reset ACL state
    selectedVpnClient = null
    aclPolicy = 'selected'
    aclView = []
    hasDNS = false
    showNodeModal = true
    // Load VPN client for DNS toggle
    loadVpnClientByIp(node._ip)
  }

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
  let expandedVipCmd = $state(null) // vip id whose forwarding commands are inline-expanded
  let vipCmdText = $state('')       // fetched setup commands
  let vipRemoveText = $state('')    // fetched teardown commands
  let vipCmdMode = $state('add')    // 'add' | 'remove'
  let vipCmdLoading = $state(false)

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
    try {
      const body = { label, restricted: true }
      if (newVipTargetIp.trim()) {
        body.targetIp = newVipTargetIp.trim()
        // Optional: a port forwards only that TCP port; blank forwards all ports.
        const p = parseInt(newVipTargetPort)
        if (p > 0) body.targetPort = p
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
  async function doRemoveVip(vip) {
    removingVip = true
    try {
      await apiDelete(`/api/wg/vips/${vip.id}`)
      toast('Virtual IP removed', 'success')
      confirmRemoveVipId = null
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
      loader.reload()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }


  async function deleteNode() {
    if (!selectedNode) return
    actionLoading = true
    try {
      if (selectedNode._type === 'wireguard') {
        await apiDelete(`/api/wg/peers/${selectedNode._wgId}`)
      } else {
        await apiDelete(`/api/hs/nodes/${selectedNode.id}`)
      }
      toast('Node deleted', 'success')
      closeModal()
      loader.reload()
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
      loader.reload()
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
      loader.reload()
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
      loader.reload()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function createWgPeer() {
    if (!newPeerName.trim()) return
    try {
      const data = await apiPost('/api/wg/peers', { name: newPeerName })
      createdPeer = data
      toast('Peer created', 'success')
      loader.reload()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function downloadConfig() {
    if (!selectedNode) return
    try {
      const config = await apiGetText(`/api/wg/peers/${selectedNode._wgId}/config?mode=${tunnelMode}`)
      const blob = new Blob([config], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${selectedNode._displayName}.conf`
      a.click()
      URL.revokeObjectURL(url)
      toast('Configuration downloaded', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function copyConfig() {
    if (!selectedNode) return
    try {
      const config = await apiGetText(`/api/wg/peers/${selectedNode._wgId}/config?mode=${tunnelMode}`)
      copyToClipboard(config)
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  const copyToClipboard = (text) => copyWithToast(text, toast)
</script>

<div class="space-y-4">
  <InfoCard
    icon="server"
    title="Network Nodes"
    description="Manage all connected devices in your mesh network. Includes both Tailscale/Headscale nodes and standalone WireGuard peers. Monitor status, configure routes, and control access."
  />

  <Toolbar bind:search placeholder="Search nodes by name, IP or user...">
    <!-- Mobile: Filter dropdown button -->
    <div class="relative sm:hidden">
      <button
        type="button"
        onclick={() => showFiltersDropdown = !showFiltersDropdown}
        class="kt-badge kt-badge-outline kt-badge-secondary cursor-pointer"
      >
        <Icon name="filter" size={14} />
        Filters
        {#if statusFilter !== 'all' || typeFilter !== 'all'}
          <span class="kt-badge kt-badge-xs kt-badge-primary">{(statusFilter !== 'all' ? 1 : 0) + (typeFilter !== 'all' ? 1 : 0)}</span>
        {/if}
      </button>

      {#if showFiltersDropdown}
        <div class="absolute right-0 top-full z-20 mt-2 w-48 rounded-lg border border-border bg-card p-2 shadow-lg">
          <div class="mb-2 text-[10px] font-medium uppercase text-muted-foreground">Status</div>
          <button type="button" onclick={() => { statusFilter = 'all'; typeFilter = 'all' }} class="kt-badge kt-badge-outline {statusFilter === 'all' && typeFilter === 'all' ? 'kt-badge-primary' : 'kt-badge-secondary'} w-full justify-center mb-1 cursor-pointer">All ({allNodes.length})</button>
          <button type="button" onclick={() => statusFilter = 'online'} class="kt-badge kt-badge-outline {statusFilter === 'online' ? 'kt-badge-success' : 'kt-badge-secondary'} w-full justify-center mb-1 cursor-pointer">Online</button>
          <button type="button" onclick={() => statusFilter = 'offline'} class="kt-badge kt-badge-outline {statusFilter === 'offline' ? 'kt-badge-warning' : 'kt-badge-secondary'} w-full justify-center mb-1 cursor-pointer">Offline</button>

          <div class="my-2 border-t border-border"></div>
          <div class="mb-2 text-[10px] font-medium uppercase text-muted-foreground">Type</div>
          <button type="button" onclick={() => typeFilter = 'tailscale'} class="kt-badge kt-badge-outline {typeFilter === 'tailscale' ? 'kt-badge-info' : 'kt-badge-secondary'} w-full justify-center mb-1 cursor-pointer"><Icon name="cloud" size={12} /> Tailscale ({vpnClients.filter(c => c.type === 'headscale').length})</button>
          <button type="button" onclick={() => typeFilter = 'wireguard'} class="kt-badge kt-badge-outline {typeFilter === 'wireguard' ? 'kt-badge-success' : 'kt-badge-secondary'} w-full justify-center cursor-pointer"><Icon name="shield" size={12} /> WireGuard ({vpnClients.filter(c => c.type === 'wireguard').length})</button>
        </div>
      {/if}
    </div>

    <!-- Desktop: Filter badges -->
    <div class="hidden flex-wrap items-center gap-2 sm:flex">
      <!-- All / Reset -->
      <button
        type="button"
        onclick={() => { statusFilter = 'all'; typeFilter = 'all' }}
        class="kt-badge kt-badge-outline {statusFilter === 'all' && typeFilter === 'all' ? 'kt-badge-primary' : 'kt-badge-secondary'} cursor-pointer"
      >
        All
        <span class="kt-badge kt-badge-xs kt-badge-primary">{allNodes.length}</span>
      </button>

      <!-- Status filters -->
      <button
        type="button"
        onclick={() => statusFilter = statusFilter === 'online' ? 'all' : 'online'}
        class="kt-badge kt-badge-outline {statusFilter === 'online' ? 'kt-badge-success' : 'kt-badge-secondary'} cursor-pointer"
      >
        Online
      </button>
      <button
        type="button"
        onclick={() => statusFilter = statusFilter === 'offline' ? 'all' : 'offline'}
        class="kt-badge kt-badge-outline {statusFilter === 'offline' ? 'kt-badge-warning' : 'kt-badge-secondary'} cursor-pointer"
      >
        Offline
      </button>

      <span class="mx-1 h-4 w-px bg-border"></span>

      <!-- Type filters -->
      <button
        type="button"
        onclick={() => typeFilter = typeFilter === 'tailscale' ? 'all' : 'tailscale'}
        class="kt-badge kt-badge-outline {typeFilter === 'tailscale' ? 'kt-badge-info' : 'kt-badge-secondary'} cursor-pointer"
      >
        <Icon name="cloud" size={14} />
        Tailscale
        <span class="kt-badge kt-badge-xs kt-badge-info">{vpnClients.filter(c => c.type === 'headscale').length}</span>
      </button>
      <button
        type="button"
        onclick={() => typeFilter = typeFilter === 'wireguard' ? 'all' : 'wireguard'}
        class="kt-badge kt-badge-outline {typeFilter === 'wireguard' ? 'kt-badge-success' : 'kt-badge-secondary'} cursor-pointer"
      >
        <Icon name="shield" size={14} />
        WireGuard
        <span class="kt-badge kt-badge-xs kt-badge-success">{vpnClients.filter(c => c.type === 'wireguard').length}</span>
      </button>
    </div>
  </Toolbar>

  <!-- Nodes grid -->
  {#if filteredNodes.length > 0}
  <div class="mt-4 grid-cards">
    <!-- Add node card - always first -->
    <div
      onclick={() => { showCreateModal = true; newPeerName = ''; createdPeer = null }}
      onkeydown={(e) => e.key === 'Enter' && (showCreateModal = true, newPeerName = '', createdPeer = null)}
      role="button"
      tabindex="0"
      class="add-item-card"
    >
      <div class="flex h-8 w-8 items-center justify-center rounded-full bg-secondary text-foreground">
        <Icon name="plus" size={16} />
      </div>
      <div class="font-medium text-foreground">Add WireGuard peer</div>
      <p class="max-w-[200px] text-muted-foreground">
        Create new WireGuard peers. For Tailscale, <a href="/authkeys" onclick={(e) => e.stopPropagation()} class="text-primary hover:underline">create auth keys</a>
      </p>
    </div>

    {#each filteredNodes as node (node.id)}
      {@const isKeyExpired = node._type === 'tailscale' && node.expiry && !node.expiry.startsWith('0001') && new Date(node.expiry) < new Date()}
      <div
        onclick={() => selectNode(node)}
        onkeydown={(e) => e.key === 'Enter' && selectNode(node)}
        role="button"
        tabindex="0"
        class="group flex cursor-pointer flex-col rounded-lg border shadow-sm transition hover:shadow-md bg-card
          {node._online
            ? 'border-success/30'
            : 'border-border'}"
      >
        <!-- Header: Icon + Name + Status -->
        <div class="flex items-center gap-2.5 p-3">
          <!-- Device icon -->
          <div class="flex h-9 w-9 items-center justify-center rounded-lg shrink-0
            {node._online
              ? 'bg-success/10 text-success'
              : 'bg-muted text-muted-foreground'}">
            <Icon name={getDeviceIcon(node)} size={18} />
          </div>

          <!-- Name -->
          <div class="flex-1 min-w-0">
            <h2 class="truncate text-sm font-semibold text-foreground">{node._displayName}</h2>
            <div class="flex items-center gap-1 mt-0.5 text-[11px] text-muted-foreground">
              <Icon name="user" size={11} class="shrink-0" />
              <span class="truncate">{node.user?.name || 'Unassigned'}</span>
            </div>
          </div>

          <!-- Status indicator -->
          <div class="flex flex-col items-end gap-1 shrink-0">
            <span class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium
              {node._online
                ? 'bg-success/10 text-success'
                : 'bg-muted text-muted-foreground'}">
              <span class="status-dot {node._online ? 'status-dot-success' : 'status-dot-muted'}"></span>
              {node._online ? 'Online' : 'Offline'}
            </span>
            {#if isKeyExpired}
              <span class="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium bg-destructive/10 text-destructive">
                Key Expired
              </span>
            {:else if node._type === 'wireguard' && !node.enabled}
              <span class="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium bg-warning/10 text-warning">
                Disabled
              </span>
            {/if}
            {#if node._type === 'wireguard' && node.blockInternet}
              <span class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium bg-destructive/10 text-destructive">
                <Icon name="world-off" size={10} />
                No Internet
              </span>
            {/if}
          </div>
        </div>

        <!-- Info grid: 2 columns -->
        <div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t border-border/50 px-3 py-2.5 text-[11px]">
          <!-- IP -->
          <div class="flex items-center gap-1.5">
            <Icon name="network" size={12} class="text-dim shrink-0" />
            <code class="text-foreground font-mono truncate">{node._ip || '—'}</code>
          </div>
          <!-- Type -->
          <div class="flex items-center gap-1.5">
            <Icon name={node._type === 'wireguard' ? 'shield' : 'cloud'} size={12} class="text-dim shrink-0" />
            <span class="text-muted-foreground">{node._type === 'wireguard' ? 'WireGuard' : 'Tailscale'}</span>
          </div>
          <!-- Last seen -->
          <div class="flex items-center gap-1.5">
            <Icon name="clock" size={12} class="text-dim shrink-0" />
            <span class="text-muted-foreground truncate">{timeAgo(node.lastHandshake || node.lastSeen)}</span>
          </div>
          <!-- Key expiry or enabled status -->
          {#if node._type === 'tailscale' && node.expiry && !node.expiry.startsWith('0001')}
            <div class="flex items-center gap-1.5">
              <Icon name="key" size={12} class="{isKeyExpired ? 'text-destructive' : 'text-dim'} shrink-0" />
              <span class="{isKeyExpired ? 'text-destructive' : 'text-muted-foreground'} truncate">
                {isKeyExpired ? 'Expired' : timeAgo(node.expiry)}
              </span>
            </div>
          {:else if node._type === 'wireguard'}
            <div class="flex items-center gap-1.5">
              <Icon name={node.enabled ? 'check' : 'ban'} size={12} class="{node.enabled ? 'text-success' : 'text-warning'} shrink-0" />
              <span class="{node.enabled ? 'text-success' : 'text-warning'}">
                {node.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
          {:else}
            <div></div>
          {/if}
        </div>

        <!-- Tags footer -->
        <div class="flex flex-wrap gap-1 border-t border-border/50 px-3 py-2 min-h-[32px]">
          {#if node._type === 'tailscale' && (node.forcedTags?.length || node.validTags?.length)}
            {#each [...(node.forcedTags || []), ...(node.validTags || [])].slice(0, 3) as tag}
              <span class="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                {tag.replace('tag:', '')}
              </span>
            {/each}
            {#if [...(node.forcedTags || []), ...(node.validTags || [])].length > 3}
              <span class="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                +{[...(node.forcedTags || []), ...(node.validTags || [])].length - 3}
              </span>
            {/if}
          {:else}
            <span class="text-[10px] text-muted-foreground">No tags</span>
          {/if}
        </div>
      </div>
    {/each}
  </div>
  {/if}

  {#if filteredNodes.length === 0}
    <EmptyState
      icon="server"
      title="No nodes found"
      description={search ? 'Try a different search term' : 'Add a device using the button below'}
      large
    >
      {#if !search}
        <Button onclick={() => { showCreateModal = true; newPeerName = ''; createdPeer = null }} size="sm" icon="plus">
          Add Node
        </Button>
      {/if}
    </EmptyState>
  {/if}
</div>

<!-- Node Detail Modal -->
<Modal bind:open={showNodeModal} size="lg" bodyClass="p-0">
  {#snippet header()}
    {#if selectedNode}
      <div class="flex items-center gap-3">
        <div class="w-6 h-6 rounded flex items-center justify-center {selectedNode._online ? 'bg-success/15 text-success' : 'bg-muted text-muted-foreground'}">
          <Icon name={getDeviceIcon(selectedNode)} size={12} />
        </div>
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
            <div class="flex items-center gap-2 mt-0.5">
              <button onclick={() => editingName = true} class="kt-badge kt-badge-sm kt-badge-outline kt-badge-secondary} cursor-pointer">{selectedNode._displayName} <Icon name="edit" size={12} /></button>
              <Badge variant={selectedNode._online ? 'success' : 'muted'} size="sm">{selectedNode._online ? 'Online' : 'Offline'}</Badge>
              <Badge variant={selectedNode._type === 'wireguard' ? 'info' : 'primary'} size="sm">{selectedNode._type === 'wireguard' ? 'WG' : 'TS'}</Badge>
              {#if selectedNode._type === 'wireguard' && !selectedNode.enabled}<Badge variant="warning" size="sm">Disabled</Badge>{/if}
              {#if selectedNode._type === 'wireguard' && selectedNode.blockInternet}<Badge variant="destructive" size="sm">No Internet</Badge>{/if}
              {#if isExitNode}<Badge variant="success" size="sm">Exit</Badge>{/if}
              <button onclick={toggleDNS} class="kt-badge kt-badge-sm {hasDNS ? 'kt-badge-info' : 'kt-badge-outline kt-badge-secondary'} cursor-pointer" title="Toggle DNS rewrite">DNS</button>
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
            <div class="mt-2 flex justify-end">
              <Button onclick={resetPeerTotals} size="sm" variant="secondary" icon="refresh">Reset traffic</Button>
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

        {:else if activeTab === 'traffic'}
          <!-- Traffic Tab - per-destination byte breakdown (conntrack) -->
          <div class="space-y-3">
            <div class="flex items-center justify-between gap-2">
              <div class="text-xs text-muted-foreground">Where this peer's traffic went, by bytes.</div>
              <div class="flex items-center gap-1">
                {#each ['hour','day','week'] as p}
                  <button
                    class="px-2 py-0.5 text-[11px] rounded capitalize {peerUsagePeriod === p ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}"
                    onclick={() => peerUsagePeriod = p}
                  >{p}</button>
                {/each}
              </div>
            </div>

            <!-- conntrack watcher status: explains why the list may be empty -->
            {#if conntrackStatus && !conntrackStatus.enabled}
              <div class="flex items-start gap-2 p-2 bg-warning/10 rounded text-[11px]">
                <Icon name="alert-triangle" size={13} class="text-warning mt-0.5 shrink-0" />
                <div>The <span class="font-mono">conntrack</span> watcher is <strong>disabled</strong>. Enable it in Settings → Logs Watchers to record per-destination traffic.</div>
              </div>
            {:else if conntrackStatus?.lastError}
              <div class="flex items-start gap-2 p-2 bg-destructive/10 rounded text-[11px]">
                <Icon name="alert-triangle" size={13} class="text-destructive mt-0.5 shrink-0" />
                <div class="break-all">conntrack error: {conntrackStatus.lastError}</div>
              </div>
            {:else if conntrackStatus}
              <div class="text-[10px] text-muted-foreground">
                conntrack watcher: {conntrackStatus.running ? 'running' : 'stopped'} · {conntrackStatus.processed ?? 0} flows recorded
              </div>
            {/if}

            {#if peerUsageLoading}
              <div class="text-xs text-muted-foreground py-6 text-center">Loading…</div>
            {:else if peerUsage?.destinations?.length}
              {@const rows = peerUsage.destinations.slice(0, 5).map(d => ({ ...d, label: d.domain || d.dest_ip }))}
              <div class="grid grid-cols-2 gap-3">
                <ContentBlock variant="data" size="sm" solid light label="Uploaded (measured)" value={formatBytes(peerUsage.total_up)} rightIcon="upload" />
                <ContentBlock variant="data" size="sm" solid light label="Downloaded (measured)" value={formatBytes(peerUsage.total_down)} rightIcon="download" />
              </div>
              <BarList data={rows} labelKey="label" valueKey="bytes_total" labelWidth="w-40" format={formatBytes} barClass="bg-info" />
              <p class="text-[10px] text-muted-foreground">
                Measured from when the conntrack watcher was enabled (updates every ~10s as connections transfer data, including still-open ones). Traffic from before it was enabled isn't included, so this won't match the peer's lifetime WireGuard total.
              </p>
            {:else}
              <div class="text-center py-6 space-y-1">
                <Icon name="chart-bar" size={24} class="mx-auto text-muted-foreground/50" />
                <div class="text-sm text-foreground">No destination data yet</div>
                <div class="text-[11px] text-muted-foreground">Enable the <span class="font-mono">conntrack</span> watcher in Settings → Logs, then generate some traffic.</div>
              </div>
            {/if}
          </div>

        {:else if activeTab === 'qr'}
          <!-- WireGuard QR & Config Tab - Side by side layout -->
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
                <Button onclick={downloadConfig} size="sm" icon="download" class="justify-center">
                  Download
                </Button>
                <Button onclick={copyConfig} variant="secondary" size="sm" icon="copy" class="justify-center">
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
              <Input bind:value={newVipTargetIp} placeholder="Device IP (optional)" prefixIcon="device-laptop" class="flex-1" />
              <Input bind:value={newVipTargetPort} placeholder="Port" class="w-full sm:w-20" />
              <Button onclick={addVip} icon="plus">Add</Button>
            </div>
            <div class="text-xs text-muted-foreground mt-1">The VPN IP is auto-assigned; the name labels the forwarding rule. Device IP forwards to a LAN device — with a Port it exposes only that TCP port, blank forwards all. No Device IP = a bare routed IP.</div>

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
                {#each vips as vip (vip.id)}
                  <div class="rounded-lg border border-border bg-card overflow-hidden">
                    <!-- Header: address + status + actions -->
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
                      <!-- Header: title, then badges + action group (own line on mobile) -->
                      <div class="flex flex-col sm:flex-row sm:items-center gap-2.5 p-3">
                        <div class="flex items-center gap-3 min-w-0 flex-1">
                          <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                            <Icon name="network" size={18} />
                          </span>
                          <div class="min-w-0">
                            <div class="font-mono text-sm font-medium truncate">
                              {vip.ip}{#if vip.targetIp}<span class="text-muted-foreground"> → {vip.targetIp}{#if vip.targetPort}:{vip.targetPort}{/if}</span>{/if}
                            </div>
                            {#if vip.label}<div class="text-xs text-muted-foreground truncate">{vip.label}</div>{/if}
                          </div>
                        </div>
                        <div class="flex items-center gap-2 shrink-0">
                          {#if vip.quarantine}<Badge variant="destructive">Quarantined</Badge>{/if}
                          <Badge variant={vip.restricted ? 'warning' : 'success'}>{vip.restricted ? 'Restricted' : 'Open'}</Badge>
                          <!-- Grouped actions (Docker-style: btn-group / custom_btns) -->
                          <div class="btn-group shrink-0">
                            {#if vip.targetIp}
                              <button class="custom_btns text-primary! hover:bg-primary/10! {expandedVipCmd === vip.id && vipCmdMode === 'add' ? 'bg-primary/15!' : ''}" data-kt-tooltip onclick={() => showVipCmd(vip, 'add')}>
                                <Icon name="code" size={14} />
                                <span data-kt-tooltip-content class="kt-tooltip hidden">Set-up commands</span>
                              </button>
                              <button class="custom_btns text-warning! hover:bg-warning/10! {expandedVipCmd === vip.id && vipCmdMode === 'remove' ? 'bg-warning/15!' : ''}" data-kt-tooltip onclick={() => showVipCmd(vip, 'remove')}>
                                <Icon name="plug" size={14} />
                                <span data-kt-tooltip-content class="kt-tooltip hidden">Tear-down commands</span>
                              </button>
                            {/if}
                            <button class="custom_btns text-destructive! hover:bg-destructive/10!" data-kt-tooltip onclick={() => confirmRemoveVipId = vip.id}>
                              <Icon name="trash" size={14} />
                              <span data-kt-tooltip-content class="kt-tooltip hidden">Delete virtual IP</span>
                            </button>
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
                        <div class="flex flex-wrap gap-x-6 gap-y-2">
                          <Checkbox variant="switch" label="Restrict to selected peers" checked={vip.restricted} onchange={() => toggleVipRestrict(vip)} />
                          <Checkbox variant="switch" label="Quarantine" checked={vip.quarantine} onchange={() => toggleVipQuarantine(vip)} />
                        </div>

                        {#if vip.restricted}
                          <div class="border-t border-border/50 pt-2.5">
                            <div class="text-xs text-muted-foreground mb-2">
                              Allowed peers{#if !(vip.allowedClientIds?.length)}<span class="text-destructive"> — none yet (unreachable)</span>{/if}
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
                  <OptionCard icon="ban" title="Block All" description="Isolated" size="sm" color="destructive" active={aclPolicy === 'block_all'} onclick={() => aclPolicy = 'block_all'} />
                  <OptionCard icon="list-check" title="Selected" description="Choose below" size="sm" active={aclPolicy === 'selected'} onclick={() => aclPolicy = 'selected'} />
                  <OptionCard icon="checks" title="Allow All" description="Full access" size="sm" color="success" active={aclPolicy === 'allow_all'} onclick={() => aclPolicy = 'allow_all'} />
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
                      {@const isBlockedPolicy = client.aclPolicy === 'block_all' || client.aclPolicy === 'allow_all'}
                      <div class="flex items-center gap-2 p-2.5 border-b border-border last:border-b-0 {isBlockedPolicy ? 'opacity-60' : 'hover:bg-accent/30'} transition-colors">
                        <!-- Allow checkbox -->
                        <button
                          onclick={() => !isBlockedPolicy && toggleClient(client.id)}
                          disabled={isBlockedPolicy}
                          class="w-5 h-5 rounded border flex items-center justify-center shrink-0
                            {isBlockedPolicy ? 'border-border bg-muted cursor-not-allowed' : client.isEnabled ? 'bg-primary border-primary text-white cursor-pointer' : 'border-border cursor-pointer'}"
                        >
                          {#if client.isEnabled && !isBlockedPolicy}
                            <Icon name="check" size={12} />
                          {/if}
                        </button>
                        <!-- Client info -->
                        <div class="flex-1 min-w-0" onclick={() => !isBlockedPolicy && toggleClient(client.id)} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && !isBlockedPolicy && toggleClient(client.id)} role="button" tabindex="0" class:cursor-pointer={!isBlockedPolicy}>
                          <div class="text-sm font-medium text-foreground truncate">{client.name}</div>
                          <div class="text-[10px] text-muted-foreground">
                            {client.ip} • {client.type === 'wireguard' ? 'WG' : 'TS'}
                            {#if client.aclPolicy === 'block_all'}
                              <span class="text-destructive ml-1">• Can't be reached</span>
                            {:else if client.aclPolicy === 'allow_all'}
                              <span class="text-success ml-1">• You can connect</span>
                            {/if}
                          </div>
                        </div>
                        <!-- Bidirectional toggle (only if enabled and target has 'selected' policy) -->
                        {#if client.isEnabled && client.aclPolicy === 'selected'}
                          <button
                            onclick={() => toggleBidirectional(client.id)}
                            class="flex items-center gap-1.5 px-2 py-1 rounded text-[10px] transition-colors shrink-0
                              {client.isBi ? 'bg-info/15 text-info border border-info/30' : 'bg-muted/50 text-muted-foreground border border-border hover:border-info/30'}"
                            title="Allow {client.name} to also reach this client"
                          >
                            <Icon name="arrows-right-left" size={12} />
                            Bi
                          </button>
                        {/if}
                      </div>
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

        {:else if activeTab === 'actions' || activeTab === 'security'}
          <!-- Actions Tab -->
          {#if confirmAction === 'delete'}
            <!-- Delete Confirmation -->
            <div class="space-y-4">
              <div class="p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
                <div class="flex items-center gap-3">
                  <div class="w-10 h-10 rounded-lg flex items-center justify-center bg-destructive/15 text-destructive shrink-0">
                    <Icon name="alert-triangle" size={20} />
                  </div>
                  <div>
                    <p class="font-medium text-foreground">Delete {selectedNode._displayName}?</p>
                    <p class="text-sm text-muted-foreground mt-0.5">This action cannot be undone. The node will be permanently removed.</p>
                  </div>
                </div>
              </div>
              <div class="flex justify-between">
                <Button onclick={() => confirmAction = null} variant="secondary" disabled={actionLoading}>
                  Cancel
                </Button>
                <Button onclick={deleteNode} variant="destructive" disabled={actionLoading} icon={actionLoading ? undefined : "trash"}>
                  {#if actionLoading}
                    <span class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                  {:else}
                    Delete
                  {/if}
                </Button>
              </div>
            </div>
          {:else if confirmAction === 'expire'}
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
              <OptionCard icon="trash" title="Delete" description="Remove permanently" color="destructive" size="lg" iconBox onclick={() => confirmAction = 'delete'} />
            </div>
          {/if}
        {/if}
      </div>
  {/if}
</Modal>

<!-- Virtual IP setup-commands Modal -->
<!-- Create WireGuard Peer Modal -->
<Modal bind:open={showCreateModal} title="Add WireGuard Node" size="md">
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
      <Button
        onclick={async () => {
          const config = await apiGetText(`/api/wg/peers/${createdPeer.id}/config`)
          const blob = new Blob([config], { type: 'text/plain' })
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = `${createdPeer.name}.conf`
          a.click()
          URL.revokeObjectURL(url)
          toast('Config downloaded', 'success')
        }}
        icon="download"
      >
        Download
      </Button>
      <Button
        onclick={async () => {
          const config = await apiGetText(`/api/wg/peers/${createdPeer.id}/config`)
          copyToClipboard(config)
        }}
        variant="secondary"
        icon="copy"
      >
        Copy Config
      </Button>
      <Button onclick={() => showCreateModal = false} variant="secondary">Done</Button>
    {:else}
      <Button onclick={() => showCreateModal = false} variant="secondary">Cancel</Button>
      <Button onclick={createWgPeer}>Create WireGuard Device</Button>
    {/if}
  {/snippet}
</Modal>
