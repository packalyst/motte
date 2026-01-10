<script>
  import { onMount, onDestroy } from 'svelte'
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
  import Tabs from '../components/Tabs.svelte'
  import OptionCard from '../components/OptionCard.svelte'

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
      ? [{id:'overview',label:'Overview'},{id:'qr',label:'QR & Config'},{id:'access',label:'Access'},{id:'actions',label:'Actions'}]
      : [{id:'overview',label:'Overview'},{id:'network',label:'Network'},{id:'access',label:'Access'},{id:'security',label:'Actions'}]
  )

  let showCreateModal = $state(false)
  let showNodeModal = $state(false)

  // Handle node modal close - reset editing states
  $effect(() => {
    if (!showNodeModal) {
      selectedNode = null
      editingName = false
      editingTags = false
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
  let editingTags = $state(false)
  let newName = $state('')
  let newTags = $state('')

  // QR code - fetch with auth
  let qrUrl = $state(null)
  let qrLoading = $state(false)
  let qrLoadedFor = $state(null) // Track which peer/mode combo was loaded: "peerId:mode"
  let mounted = true // Track component lifecycle for async cleanup

  // Delete/expire confirmation
  let confirmAction = $state(null) // 'delete' | 'expire' | null
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
    editingTags = false
    tunnelMode = 'full'
    qrLoadedFor = null // Reset so QR loads fresh for new node
    newName = node._displayName
    newTags = (node.forcedTags || []).map(t => t.replace('tag:', '')).join(', ')
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

  async function saveTags() {
    if (!selectedNode) return
    try {
      const tags = newTags.split(',').map(t => t.trim()).filter(Boolean).map(t => t.startsWith('tag:') ? t : `tag:${t}`)
      await apiPut(`/api/hs/nodes/${selectedNode.id}/tags`, { tags })
      toast('Tags updated', 'success')
      editingTags = false
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
  <div class="mt-4 grid-cards">
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

    <!-- Add node card -->
    {#if filteredNodes.length > 0}
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
    {/if}
  </div>

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
          <!-- Info Grid -->
          <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <ContentBlock variant="data" label="IP Address" value={selectedNode._ip || '—'} copyable={!!selectedNode._ip} mono />
            <ContentBlock variant="data" label="Created" value={formatDate(selectedNode.createdAt)} />
            <ContentBlock variant="data" label="Last Seen" value={timeAgo(selectedNode.lastHandshake || selectedNode.lastSeen)} />
            {#if selectedNode._type === 'wireguard'}
              <ContentBlock variant="data" label="Uploaded" value={formatBytes(selectedNode.totalTx)} />
              <ContentBlock variant="data" label="Downloaded" value={formatBytes(selectedNode.totalRx)} />
              <ContentBlock variant="data" label="Public Key" value={selectedNode.publicKey} copyable mono class="col-span-2 sm:col-span-3" />
            {:else}
              <ContentBlock variant="data" label="User" value={selectedNode.user?.name || '—'} />
              <ContentBlock variant="data" label="Key Expiry" value={selectedNode.expiry && !selectedNode.expiry.startsWith('0001') ? formatDate(selectedNode.expiry) : 'Never'} />
              {#if selectedNode.ipAddresses?.[1]}
                <ContentBlock variant="data" label="IPv6" value={selectedNode.ipAddresses[1]} copyable mono />
              {/if}
            {/if}
          </div>

          <!-- Tags (Tailscale only) -->
          {#if selectedNode._type === 'tailscale'}
            <div class="mt-4 pt-4 border-t border-border">
              <div class="flex items-center justify-between mb-2">
                <h4 class="text-xs font-medium text-foreground uppercase tracking-wide">ACL Tags</h4>
                {#if !editingTags}
                  <button onclick={() => editingTags = true} class="p-1 text-muted-foreground hover:text-foreground hover:bg-accent rounded"><Icon name="edit" size={12} /></button>
                {/if}
              </div>
              {#if editingTags}
                <div class="flex items-center gap-2">
                  <Input bind:value={newTags} placeholder="server, trusted" class="kt-input-sm flex-1" />
                  <button onclick={saveTags} class="p-1.5 text-success hover:bg-success/10 rounded"><Icon name="check" size={16} /></button>
                  <button onclick={() => editingTags = false} class="p-1.5 text-muted-foreground hover:bg-accent rounded"><Icon name="x" size={16} /></button>
                </div>
              {:else}
                <div class="flex flex-wrap gap-1.5">
                  {#if selectedNode.forcedTags?.length > 0}
                    {#each selectedNode.forcedTags as tag}<Badge variant="muted" size="sm">{tag}</Badge>{/each}
                  {:else}
                    <span class="text-xs text-muted-foreground">No tags</span>
                  {/if}
                </div>
              {/if}
            </div>

            <!-- Routes -->
            {#if nodeRoutes.length > 0}
              <div class="mt-4 pt-4 border-t border-border">
                <h4 class="text-xs font-medium text-foreground uppercase tracking-wide mb-2">Routes</h4>
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
          {/if}

        {:else if activeTab === 'network'}
          <!-- Tailscale Network Tab -->
          <div class="space-y-3">
            <ContentBlock variant="data" label="Node ID" value={selectedNode.id} mono />
            {#if selectedNode.registerMethod}
              <ContentBlock variant="data" label="Registration" value={selectedNode.registerMethod.replace('REGISTER_METHOD_', '')} />
            {/if}
            {#each [['Machine Key', selectedNode.machineKey], ['Node Key', selectedNode.nodeKey], ['Disco Key', selectedNode.discoKey]].filter(([,v]) => v) as [label, key]}
              <ContentBlock variant="data" label={label} value={key} copyable mono />
            {/each}
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

              <div class="p-3 bg-muted/30 rounded-lg text-xs text-muted-foreground">
                <p class="font-medium text-foreground mb-1">Quick Setup</p>
                <ol class="list-decimal list-inside space-y-0.5">
                  <li>Select tunnel mode</li>
                  <li>Scan QR or download config</li>
                  <li>Import to WireGuard app</li>
                </ol>
              </div>
            </div>

            <!-- Right: QR Code -->
            <div class="flex items-center justify-center p-4 bg-white rounded-xl min-h-[200px]">
              {#if qrLoading}
                <div class="w-8 h-8 border-2 border-muted border-t-primary rounded-full animate-spin"></div>
              {:else if qrUrl}
                <img src={qrUrl} alt="QR Code" class="max-w-full max-h-[200px]" />
              {:else}
                <span class="text-muted-foreground text-sm">Failed to load</span>
              {/if}
            </div>
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
