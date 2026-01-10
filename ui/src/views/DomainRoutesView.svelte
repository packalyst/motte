<script>
  import { toast, apiGet, apiPost, apiPut, apiDelete, confirm, setConfirmLoading } from '../stores/app.js'
  import { generalInfoStore } from '../stores/websocket.js'
  import { useDataLoader } from '$lib/composables/index.js'
  import { filterByFields } from '$lib/utils/data.js'
  import { toggleInArray } from '$lib/utils/array.js'
  import {
    defaultSentinelConfig, normalizeSentinelConfig, buildRoutePayload,
    defaultRouteForm, routeToFormData, TIMEZONES, WEEK_DAYS, ERROR_MODES
  } from '$lib/utils/domains.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import Input from '../components/Input.svelte'
  import Select from '../components/Select.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Checkbox from '../components/Checkbox.svelte'

  let { loading = $bindable(true) } = $props()

  // Multi-source data loading
  const loader = useDataLoader([
    { fn: () => apiGet('/api/domains'), key: 'routes', extract: 'routes', isArray: true },
    { fn: () => apiGet('/api/vpn/clients'), key: 'clients', isArray: true },
    { fn: () => apiGet('/api/traefik/overview'), key: 'traefik', default: {} },
    { fn: () => apiGet('/api/domains/certificates').catch(() => ({ certificates: [] })), key: 'certs', default: { certificates: [] } }
  ])

  const routes = $derived(loader.data.routes || [])
  const vpnClients = $derived(loader.data.clients || [])
  const certificates = $derived(loader.data.certs?.certificates || [])
  const availableMiddlewares = $derived.by(() => {
    const mws = loader.data.traefik?.middlewares || []
    return mws
      .filter(m => m.provider === 'file' && !m.name.includes('@internal') && !m.name.startsWith('sentinel_domain-'))
      .map(m => ({ name: m.name, type: m.type }))
  })

  // Sync loading state to parent
  $effect(() => { loading = loader.loading })

  let searchQuery = $state('')

  // Modal states
  let formModalMode = $state(null) // 'create' | 'edit' | null
  let showFormModal = $derived(formModalMode !== null)
  let showScanModal = $state(false)
  let editingRoute = $state(null)

  // Port scanning state
  let scanMode = $state('common') // common, range, full
  let scanning = $state(false)
  let scanProgress = $state({ total: 0, scanned: 0, found: 0, completed: false })
  let discoveredPorts = $state([])
  let selectedPorts = $state([]) // Array of {port, domain, description, middlewares, httpsBackend}
  let scanClientId = $state(null)
  let scanClientIp = $state('')
  let scanClientName = $state('')

  // Watch WebSocket for scan progress (always listen, not just when scanning)
  $effect(() => {
    const info = $generalInfoStore
    if (!info) return

    const event = info.event
    if ((event === 'scan:progress' || event === 'scan:complete') && String(info.clientId) === String(scanClientId)) {
      // If we receive scan:progress and we're not in scanning state, restore it
      if (event === 'scan:progress' && !info.completed && !scanning) {
        scanning = true
        scanClientIp = info.ip || scanClientIp
      }

      if (scanning) {
        scanProgress = {
          total: info.total || 0,
          scanned: info.scanned || 0,
          found: info.found || 0,
          completed: info.completed || false
        }

        // Update discovered ports live
        if (info.ports && info.ports.length > 0) {
          discoveredPorts = info.ports
        }

        if (event === 'scan:complete') {
          scanning = false
          if (info.error) {
            toast('Scan failed: ' + info.error, 'error')
          } else if (info.stopped) {
            toast(`Scan stopped. Found ${info.found || 0} ports`, 'info')
          } else if (info.found === 0) {
            toast('No open ports found', 'info')
          } else {
            toast(`Scan complete. Found ${info.found} open ports`, 'success')
          }
        }
      }
    }
  })

  // Form state
  let formData = $state(defaultRouteForm())

  // Helper functions for sentinel config
  function toggleSentinelConfig() {
    formData.sentinelConfig = formData.sentinelConfig ? null : defaultSentinelConfig()
  }

  // Generic array helpers for sentinel config
  function addToSentinel(path, item) {
    if (!formData.sentinelConfig) return
    const parts = path.split('.')
    let target = formData.sentinelConfig
    for (let i = 0; i < parts.length - 1; i++) target = target[parts[i]]
    target[parts[parts.length - 1]] = [...target[parts[parts.length - 1]], item]
  }

  function removeFromSentinel(path, index) {
    if (!formData.sentinelConfig) return
    const parts = path.split('.')
    let target = formData.sentinelConfig
    for (let i = 0; i < parts.length - 1; i++) target = target[parts[i]]
    target[parts[parts.length - 1]] = target[parts[parts.length - 1]].filter((_, i) => i !== index)
  }

  function toggleDay(day) {
    if (!formData.sentinelConfig) return
    formData.sentinelConfig.timeAccess.days = toggleInArray(formData.sentinelConfig.timeAccess.days, day)
  }

  // Certificate lookup by domain
  function getCertForDomain(domain) {
    return certificates.find(c => c.domain === domain)
  }

  // Filtered routes
  const filteredRoutes = $derived(
    filterByFields(routes, ['domain', 'targetIp', 'description', 'vpnClientName'], searchQuery)
  )

  // VPN client options for select
  const clientOptions = $derived([
    { value: '', label: 'Manual IP' },
    ...vpnClients.map(c => ({ value: c.id, label: `${c.name} (${c.ip})` }))
  ])

  function resetForm() {
    formData = defaultRouteForm()
  }

  function openCreateModal() {
    resetForm()
    editingRoute = null
    formModalMode = 'create'
  }

  function openEditModal(route) {
    editingRoute = route
    formData = routeToFormData(route)
    formModalMode = 'edit'
  }

  function closeFormModal() {
    formModalMode = null
    editingRoute = null
  }

  function toggleMiddleware(mwName) {
    formData.middlewares = toggleInArray(formData.middlewares, mwName)
  }

  async function confirmDelete(route) {
    const confirmed = await confirm({
      title: 'Delete Domain Route',
      message: `Delete route for ${route.domain}?`,
      description: 'This action cannot be undone.'
    })
    if (!confirmed) return

    setConfirmLoading(true)
    try {
      await apiDelete(`/api/domains/${route.id}`)
      toast('Domain route deleted', 'success')
      loader.reload()
    } catch (e) {
      toast('Failed to delete route: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }

  // When VPN client is selected, auto-fill the IP
  function onClientChange(e) {
    const clientId = e.target.value
    formData.vpnClientId = clientId || null
    if (clientId) {
      const client = vpnClients.find(c => c.id == clientId)
      if (client) {
        formData.targetIp = client.ip
      }
    }
  }

  async function submitForm() {
    if (!formData.domain || !formData.targetIp || !formData.targetPort) {
      toast('Domain, IP, and Port are required', 'error')
      return
    }
    const payload = buildRoutePayload(formData)
    const isCreate = formModalMode === 'create'
    try {
      if (isCreate) {
        await apiPost('/api/domains', payload)
      } else {
        await apiPut(`/api/domains/${editingRoute.id}`, payload)
      }
      toast(`Domain route ${isCreate ? 'created' : 'updated'}`, 'success')
      closeFormModal()
      loader.reload()
    } catch (e) {
      toast(`Failed to ${isCreate ? 'create' : 'update'} route: ${e.message}`, 'error')
    }
  }

  async function toggleRoute(route) {
    try {
      await apiPost(`/api/domains/${route.id}/toggle`)
      toast(`Route ${route.enabled ? 'disabled' : 'enabled'}`, 'success')
      loader.reload()
    } catch (e) {
      toast('Failed to toggle route: ' + e.message, 'error')
    }
  }

  // Port scanning functions
  function openScanModal() {
    // Check if there's an active scan in the WS store
    const info = $generalInfoStore
    const isActiveScan = info?.event === 'scan:progress' && !info?.completed

    if (isActiveScan && info.clientId) {
      // Restore active scan state
      scanClientId = info.clientId
      scanClientIp = info.ip || ''
      scanMode = info.mode || 'common'
      scanning = true
      scanProgress = {
        total: info.total || 0,
        scanned: info.scanned || 0,
        found: info.found || 0,
        completed: false
      }
      discoveredPorts = info.ports || []
      selectedPorts = []
      // Find client name
      const client = vpnClients.find(c => c.id == info.clientId)
      scanClientName = client?.name || ''
    } else {
      // Fresh state
      scanMode = 'common'
      scanning = false
      scanProgress = { total: 0, scanned: 0, found: 0, completed: false }
      discoveredPorts = []
      selectedPorts = []
      scanClientId = null
      scanClientIp = ''
      scanClientName = ''
    }
    showScanModal = true
  }

  function onScanClientChange(e) {
    const clientId = e.target.value
    scanClientId = clientId || null
    if (clientId) {
      const client = vpnClients.find(c => c.id == clientId)
      if (client) {
        scanClientIp = client.ip
        scanClientName = client.name
      }
    } else {
      scanClientIp = ''
      scanClientName = ''
    }
    // Reset ports when client changes
    discoveredPorts = []
    selectedPorts = []
  }

  async function startScan() {
    if (!scanClientId) {
      toast('Please select a VPN client to scan', 'error')
      return
    }

    // Clear old WS message to prevent re-processing stale scan:complete
    generalInfoStore.set(null)

    scanning = true
    scanProgress = { total: 0, scanned: 0, found: 0, completed: false }
    discoveredPorts = []
    selectedPorts = []

    try {
      // Start scan - returns immediately, progress comes via WebSocket
      await apiPost(`/api/vpn/clients/${scanClientId}/scan`, { mode: scanMode })
    } catch (e) {
      toast('Failed to start scan: ' + e.message, 'error')
      scanning = false
    }
  }

  async function stopScan() {
    if (!scanClientId) return
    try {
      await apiDelete(`/api/vpn/clients/${scanClientId}/scan`)
    } catch (e) {
      // Scan may have already finished
    }
  }

  function togglePortSelection(port) {
    const existing = selectedPorts.find(p => p.port === port)
    if (existing) {
      selectedPorts = selectedPorts.filter(p => p.port !== port)
    } else {
      // Create editable entry with defaults
      const portInfo = discoveredPorts.find(p => p.port === port)
      const serviceName = portInfo?.service || `port-${port}`
      const clientName = scanClientName?.toLowerCase().replace(/[^a-z0-9]/g, '-') || 'device'
      selectedPorts = [...selectedPorts, {
        port,
        service: serviceName,
        domain: `${clientName}-${serviceName.toLowerCase().replace(/[^a-z0-9]/g, '-')}.local`,
        description: `${serviceName} on ${scanClientName || 'device'}`,
        middlewares: [],
        httpsBackend: false
      }]
    }
  }

  function selectAllPorts() {
    const clientName = scanClientName?.toLowerCase().replace(/[^a-z0-9]/g, '-') || 'device'
    selectedPorts = discoveredPorts.map(p => {
      const serviceName = p.service || `port-${p.port}`
      return {
        port: p.port,
        service: serviceName,
        domain: `${clientName}-${serviceName.toLowerCase().replace(/[^a-z0-9]/g, '-')}.local`,
        description: `${serviceName} on ${scanClientName || 'device'}`,
        middlewares: [],
        httpsBackend: false
      }
    })
  }

  function deselectAllPorts() {
    selectedPorts = []
  }

  function updateSelectedPort(port, field, value) {
    selectedPorts = selectedPorts.map(p =>
      p.port === port ? { ...p, [field]: value } : p
    )
  }

  function toggleSelectedPortMiddleware(port, mwName) {
    selectedPorts = selectedPorts.map(p => {
      if (p.port !== port) return p
      const mws = p.middlewares || []
      if (mws.includes(mwName)) {
        return { ...p, middlewares: mws.filter(m => m !== mwName) }
      } else {
        return { ...p, middlewares: [...mws, mwName] }
      }
    })
  }

  async function createRoutesFromScan() {
    if (selectedPorts.length === 0) {
      toast('Please select at least one port', 'error')
      return
    }

    let created = 0
    let errors = []

    for (const entry of selectedPorts) {
      try {
        await apiPost('/api/domains', {
          domain: entry.domain,
          targetIp: scanClientIp,
          targetPort: entry.port,
          vpnClientId: parseInt(scanClientId),
          httpsBackend: entry.httpsBackend,
          middlewares: entry.middlewares || [],
          description: entry.description
        })
        created++
      } catch (e) {
        errors.push(`${entry.domain}: ${e.message}`)
      }
    }

    if (created > 0) {
      toast(`Created ${created} route(s)`, 'success')
      showScanModal = false
      loader.reload()
    }
    if (errors.length > 0) {
      toast(`${errors.length} failed: ${errors[0]}`, 'warning')
    }
  }

  // Port options for manual selection (from discovered ports + common)
  const portOptions = $derived([
    { value: '', label: 'Select port...' },
    ...discoveredPorts.map(p => ({ value: p.port, label: `${p.port} - ${p.service || 'Unknown'}` }))
  ])

  // Use discovered port when selected
  function onPortSelect(e) {
    const port = e.target.value
    if (port) {
      formData.targetPort = parseInt(port)
    }
  }
</script>

<div class="space-y-4">
  <InfoCard
    icon="world-www"
    title="Domain Routes"
    description="Map custom domains to services running on your VPN devices. Routes are handled by Traefik reverse proxy with automatic DNS configuration via AdGuard."
  />

  <!-- Toolbar -->
  <Toolbar bind:search={searchQuery} placeholder="Search domains...">
    <div class="kt-btn-group">
      <Button variant="outline" size="sm" icon="scan" onclick={openScanModal}>
        Scan
      </Button>
      <Button size="sm" icon="plus" onclick={openCreateModal}>
        Add Route
      </Button>
    </div>
  </Toolbar>

  <!-- Routes List -->
  {#if routes.length > 0}
    {#if filteredRoutes.length > 0}
      <div class="space-y-2">
        {#each filteredRoutes as route}
          <div class="bg-card border border-border rounded-lg px-4 py-3 hover:border-primary/30 transition-colors">
            <div class="flex flex-wrap sm:flex-nowrap items-center gap-3 sm:gap-4">
              <!-- Domain + Description -->
              <div class="flex items-center gap-3 min-w-0 flex-1 sm:flex-none sm:min-w-[240px]">
                <div class="w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0 {route.enabled ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                  <Icon name="world-www" size={16} />
                </div>
                <div class="min-w-0">
                  <a href="http://{route.domain}" target="_blank" rel="noopener" class="kt-link kt-link-underlined kt-link-dashed">{route.domain}</a>
                  {#if route.description}
                    <p class="text-[11px] text-muted-foreground truncate">{route.description}</p>
                  {/if}
                </div>
              </div>

              <!-- Mobile: Status + Actions aligned right -->
              <div class="flex flex-col items-end gap-1.5 sm:hidden">
                <div class="flex items-center gap-1">
                  <Badge variant={route.enabled ? 'success' : 'muted'} size="sm">
                    {route.enabled ? 'Enabled' : 'Disabled'}
                  </Badge>
                  {#if getCertForDomain(route.domain)}
                    {@const cert = getCertForDomain(route.domain)}
                    <Badge variant={cert.status === 'error' ? 'destructive' : cert.status === 'pending' ? 'warning' : cert.status === 'valid' ? 'success' : 'destructive'} size="sm">
                      {cert.status === 'error' ? 'SSL!' : cert.status === 'pending' ? 'SSL...' : 'SSL'}
                    </Badge>
                  {:else if route.frontendSsl}
                    <Badge variant="muted" size="sm">SSL?</Badge>
                  {/if}
                </div>
                <div class="btn-group">
                  <button onclick={() => toggleRoute(route)} class="custom_btns" data-kt-tooltip>
                    <Icon name={route.enabled ? 'player-pause' : 'player-play'} size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">{route.enabled ? 'Disable' : 'Enable'}</span>
                  </button>
                  <button onclick={() => openEditModal(route)} class="custom_btns" data-kt-tooltip>
                    <Icon name="pencil" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Edit</span>
                  </button>
                  <button onclick={() => confirmDelete(route)} class="custom_btns text-destructive" data-kt-tooltip>
                    <Icon name="trash" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Delete</span>
                  </button>
                </div>
              </div>

              <!-- Desktop: Inline layout -->
              <div class="hidden sm:contents">
                <!-- Status -->
                <Badge variant={route.enabled ? 'success' : 'muted'} size="sm">
                  {route.enabled ? 'Enabled' : 'Disabled'}
                </Badge>

                <!-- Target -->
                <code class="text-xs text-muted-foreground font-mono">
                  {route.targetIp}:{route.targetPort}
                </code>

                <!-- Device -->
                <span class="text-xs text-muted-foreground hidden md:inline">
                  {route.vpnClientName || '—'}
                </span>

                <!-- Options -->
                <div class="hidden md:flex items-center gap-1">
                  <!-- Access Mode Badge -->
                  <Badge variant={route.accessMode === 'public' ? 'warning' : 'info'} size="sm">
                    {route.accessMode === 'public' ? 'Public' : 'VPN'}
                  </Badge>
                  <!-- Frontend SSL Badge with certificate status -->
                  {#if getCertForDomain(route.domain)}
                    {@const cert = getCertForDomain(route.domain)}
                    {#if cert.status === 'error'}
                      <Badge variant="destructive" size="sm" title={cert.error || 'Certificate generation failed'}>
                        SSL Error
                      </Badge>
                    {:else if cert.status === 'pending'}
                      <Badge variant="warning" size="sm" title="Waiting for certificate">
                        SSL Pending
                      </Badge>
                    {:else}
                      <Badge
                        variant={cert.status === 'valid' ? 'success' : cert.status === 'warning' ? 'warning' : 'destructive'}
                        size="sm"
                        title={`Expires: ${new Date(cert.notAfter).toLocaleDateString()} (${cert.daysLeft} days)`}
                      >
                        SSL {cert.daysLeft}d
                      </Badge>
                    {/if}
                  {:else if route.frontendSsl}
                    <Badge variant="muted" size="sm" title="SSL enabled, not yet processed">
                      SSL?
                    </Badge>
                  {/if}
                  <!-- Backend HTTPS Badge -->
                  {#if route.httpsBackend}
                    <Badge variant="muted" size="sm">HTTPS↗</Badge>
                  {/if}
                  {#each (route.middlewares || []).filter(m => !m.includes('vpn-only')).slice(0, 2) as mw}
                    <Badge variant="muted" size="sm">{mw.replace('@file', '')}</Badge>
                  {/each}
                  {#if (route.middlewares || []).filter(m => !m.includes('vpn-only')).length > 2}
                    {@const extraMws = (route.middlewares || []).filter(m => !m.includes('vpn-only')).slice(2)}
                    <span class="text-[10px] text-muted-foreground cursor-help" data-kt-tooltip>
                      +{extraMws.length}
                      <span data-kt-tooltip-content class="kt-tooltip hidden">{extraMws.map(m => m.replace('@file', '')).join(', ')}</span>
                    </span>
                  {/if}
                </div>

                <!-- Spacer -->
                <div class="flex-1"></div>

                <!-- Actions -->
                <div class="btn-group">
                  <button onclick={() => toggleRoute(route)} class="custom_btns" data-kt-tooltip>
                    <Icon name={route.enabled ? 'player-pause' : 'player-play'} size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">{route.enabled ? 'Disable' : 'Enable'}</span>
                  </button>
                  <button onclick={() => openEditModal(route)} class="custom_btns" data-kt-tooltip>
                    <Icon name="pencil" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Edit</span>
                  </button>
                  <button onclick={() => confirmDelete(route)} class="custom_btns text-destructive" data-kt-tooltip>
                    <Icon name="trash" size={14} />
                    <span data-kt-tooltip-content class="kt-tooltip hidden">Delete</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        {/each}
      </div>
    {:else}
      <EmptyState
        icon="search"
        title="No matching routes"
        description="Try adjusting your search query"
      />
    {/if}
  {:else}
    <EmptyState
      icon="world-www"
      title="No domain routes"
      description="Create your first domain route to map a custom domain to a service on your VPN"
    />
  {/if}
</div>

<!-- Create/Edit Modal -->
<Modal open={showFormModal} onclose={closeFormModal} title={formModalMode === 'create' ? 'Add Domain Route' : 'Edit Domain Route'} size="md">
  <div class="space-y-4">
    <Input
      label="Domain"
      placeholder="wiki.local"
      bind:value={formData.domain}
      prefixIcon="world-www"
      suffixCheckbox={{ icon: "lock", label: "SSL", color: "warning" }}
      bind:suffixCheckboxChecked={formData.frontendSsl}
    />

    <Select
      label="VPN Device (optional)"
      value={formData.vpnClientId || ''}
      onchange={onClientChange}
    >
      {#each clientOptions as opt}
        <option value={opt.value}>{opt.label}</option>
      {/each}
    </Select>

    <div class="grid grid-cols-2 gap-4">
      <Input
        label="Target IP"
        placeholder="10.8.0.5"
        bind:value={formData.targetIp}
        prefixIcon="network"
        suffixCheckbox={{ icon: "lock", label: "HTTPS", color: "warning" }}
        bind:suffixCheckboxChecked={formData.httpsBackend}
      />
      <Input
        label="Target Port"
        type="number"
        placeholder="8000"
        bind:value={formData.targetPort}
        prefixIcon="plug"
      />
    </div>

    <Input
      label="Description (optional)"
      placeholder="Wiki.js on Raspberry Pi"
      bind:value={formData.description}
      prefixIcon="file-text"
    />

    <!-- Access Mode -->
    <div>
      <span class="text-sm font-medium text-foreground">Access Mode</span>
      <div class="mt-2 flex gap-2">
        <Checkbox
          variant="chip"
          checked={formData.accessMode === 'vpn'}
          onchange={() => formData.accessMode = 'vpn'}
          icon="lock"
          label="VPN Only"
        />
        <Checkbox
          variant="chip"
          color="warning"
          checked={formData.accessMode === 'public'}
          onchange={() => formData.accessMode = 'public'}
          icon="world"
          label="Public"
        />
      </div>
    </div>

    {#if availableMiddlewares.length > 0}
      <div>
        <span class="text-sm font-medium text-foreground">Middlewares</span>
        <div class="mt-2 flex flex-wrap gap-2">
          {#each availableMiddlewares as mw}
            <Checkbox
              variant="chip"
              checked={formData.middlewares.includes(mw.name)}
              onchange={() => toggleMiddleware(mw.name)}
              label={mw.name.replace('@file', '')}
            />
          {/each}
        </div>
      </div>
    {/if}

    <!-- Custom Sentinel Config -->
    <div class="border-t border-border pt-4 mt-4">
      <div class="flex items-center justify-between">
        <span class="text-sm font-medium text-foreground">Custom Access Rules</span>
        <Checkbox
          variant="chip"
          icon="shield"
          checked={!!formData.sentinelConfig}
          onchange={toggleSentinelConfig}
          label={formData.sentinelConfig ? 'Enabled' : 'Disabled'}
        />
      </div>
      <p class="text-xs text-muted-foreground mt-1">
        Configure custom IP filtering, time-based access, maintenance mode, and more
      </p>

      {#if formData.sentinelConfig}
        <div class="mt-4 space-y-4">
          <!-- Error Mode -->
          <Select
            label="Error Response Mode"
            bind:value={formData.sentinelConfig.errorMode}
          >
            {#each ERROR_MODES as mode}
              <option value={mode.value}>{mode.label}</option>
            {/each}
          </Select>

          <div class="border-t border-border my-4"></div>

          <!-- IP Filter Section -->
          <div >
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <Icon name="shield" size={16} class="text-muted-foreground" />
                <span class="text-sm font-medium text-foreground">IP Allowlist</span>
              </div>
              <Button variant="outline" size="xs" icon="plus" onclick={() => addToSentinel('ipFilter.sourceRange', '')}>Add</Button>
            </div>
            <p class="text-xs text-muted-foreground">Only these IP ranges will be allowed (CIDR notation)</p>
            <div class="space-y-2 mt-3">
            {#if formData.sentinelConfig.ipFilter.sourceRange.length > 0}
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {#each formData.sentinelConfig.ipFilter.sourceRange as ip, i}
                  <Input
                    placeholder="10.0.0.0/8 or 192.168.1.100"
                    value={ip}
                    oninput={(e) => formData.sentinelConfig.ipFilter.sourceRange[i] = e.target.value}
                    prefixIcon="network"
                    suffixAddonBtn={{ icon: 'trash', onclick: () => removeFromSentinel('ipFilter.sourceRange', i) }}
                  />
                {/each}
              </div>
            {/if}
            </div>
          </div>

          <div class="border-t border-border my-4"></div>

          <!-- Maintenance Mode -->
          <div class="space-y-2">
            <div class="flex items-center justify-between mb-4">
              <div class="flex items-center gap-2">
                <Icon name="tool" size={16} class="text-muted-foreground" />
                <span class="text-sm font-medium text-foreground">Maintenance Mode</span>
              </div>
              <Checkbox
                variant="chip"
                icon="tool"
                checked={formData.sentinelConfig.maintenance.enabled}
                onchange={(e) => formData.sentinelConfig.maintenance.enabled = e.target.checked}
                label={formData.sentinelConfig.maintenance.enabled ? 'On' : 'Off'}
              />
            </div>
            {#if formData.sentinelConfig.maintenance.enabled}
              <Input
                placeholder="Service is undergoing scheduled maintenance"
                bind:value={formData.sentinelConfig.maintenance.message}
                prefixIcon="message"
              />
            {/if}
          </div>

          <div class="border-t border-border my-4"></div>

          <!-- Time Access Section -->
          <div >
            <div class="flex items-center gap-2">
              <Icon name="calendar-time" size={16} class="text-muted-foreground" />
              <span class="text-sm font-medium text-foreground">Time-Based Access</span>
            </div>
            <p class="text-xs text-muted-foreground">Restrict access to specific days and times</p>
            <div class="space-y-2 mt-3">
            <div class="grid grid-cols-3 gap-3">
              <Select
                label="Timezone"
                bind:value={formData.sentinelConfig.timeAccess.timezone}
              >
                {#each TIMEZONES as tz}
                  <option value={tz}>{tz}</option>
                {/each}
              </Select>
              <Input
                label="Allow Range"
                placeholder="09:00-18:00"
                bind:value={formData.sentinelConfig.timeAccess.allowRange}
              />
              <Input
                label="Deny Range"
                placeholder="12:00-13:00"
                bind:value={formData.sentinelConfig.timeAccess.denyRange}
              />
            </div>
            <div>
              <span class="text-xs text-muted-foreground">Allowed Days (lowercase: mon, tue, wed, thu, fri, sat, sun)</span>
              <div class="mt-1 kt-btn-group">
                {#each WEEK_DAYS as day}
                  <Button
                    variant={formData.sentinelConfig.timeAccess.days.includes(day.substring(0, 3).toLowerCase()) ? 'success' : 'outline'}
                    size="xs"
                    icon="calendar"
                    onclick={() => toggleDay(day.substring(0, 3).toLowerCase())}
                  >
                    {day.substring(0, 3)}
                  </Button>
                {/each}
              </div>
            </div>
            </div>
          </div>

          <div class="border-t border-border my-4"></div>

          <!-- Header Validation Section -->
          <div>
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <Icon name="key" size={16} class="text-muted-foreground" />
                <span class="text-sm font-medium text-foreground">Required Headers</span>
              </div>
              <Button variant="outline" size="xs" icon="plus" onclick={() => addToSentinel('headers', { name: '', values: [], matchType: 'one', regex: '', required: true, contains: false })}>Add</Button>
            </div>
            <p class="text-xs text-muted-foreground">Require specific headers to be present</p>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-3">
            {#each formData.sentinelConfig.headers as header, i}
              <div class="border border-border rounded-lg p-3 space-y-2">
                <div class="grid grid-cols-2 gap-2">
                  <Input
                    placeholder="X-Api-Key"
                    value={header.name}
                    oninput={(e) => formData.sentinelConfig.headers[i].name = e.target.value}
                    prefixIcon="key"
                  />
                  <Select
                    value={header.matchType}
                    onchange={(e) => formData.sentinelConfig.headers[i].matchType = e.target.value}
                  >
                    <option value="one">Match any value</option>
                    <option value="all">Match all values</option>
                    <option value="none">Blacklist values</option>
                  </Select>
                </div>
                <Input
                  placeholder="Regex pattern (optional)"
                  value={header.regex}
                  oninput={(e) => formData.sentinelConfig.headers[i].regex = e.target.value}
                  suffixAddonBtn={{ icon: 'trash', onclick: () => removeFromSentinel('headers', i) }}
                />
              </div>
            {/each}
            </div>
          </div>

          <div class="border-t border-border my-4"></div>

          <!-- User Agent Blocking Section -->
          <div>
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <Icon name="robot" size={16} class="text-muted-foreground" />
                <span class="text-sm font-medium text-foreground">Blocked User Agents</span>
              </div>
              <Button variant="outline" size="xs" icon="plus" onclick={() => addToSentinel('userAgents.block', '')}>Add</Button>
            </div>
            <p class="text-xs text-muted-foreground">Block requests matching these patterns (regex)</p>
            <div class="space-y-2 mt-3">
            {#if formData.sentinelConfig.userAgents.block.length > 0}
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {#each formData.sentinelConfig.userAgents.block as ua, i}
                  <Input
                    placeholder="(?i)bot|crawler|spider"
                    value={ua}
                    oninput={(e) => formData.sentinelConfig.userAgents.block[i] = e.target.value}
                    prefixIcon="robot"
                    suffixAddonBtn={{ icon: 'trash', onclick: () => removeFromSentinel('userAgents.block', i) }}
                  />
                {/each}
              </div>
            {/if}
            </div>
          </div>
        </div>
      {/if}
    </div>
  </div>

  {#snippet footer()}
    <div class="flex justify-between w-full">
      <Button variant="outline" onclick={closeFormModal}>Cancel</Button>
      <Button variant="primary" onclick={submitForm}>
        {formModalMode === 'create' ? 'Create Route' : 'Save Changes'}
      </Button>
    </div>
  {/snippet}
</Modal>

<!-- Port Scan Modal -->
<Modal bind:open={showScanModal} title="Scan VPN Client Ports" size="lg">
  <div class="space-y-4">
    <!-- Client Selection -->
    <div class="grid grid-cols-2 gap-4">
      <Select
        label="VPN Device"
        value={scanClientId || ''}
        onchange={onScanClientChange}
      >
        <option value="">Select a device...</option>
        {#each vpnClients as client}
          <option value={client.id}>{client.name} ({client.ip})</option>
        {/each}
      </Select>

      <Select
        label="Scan Mode"
        bind:value={scanMode}
        disabled={scanning}
      >
        <option value="common">Common Ports (~140)</option>
        <option value="range">Port Range (from settings)</option>
        <option value="full">Full Scan (1-65535)</option>
      </Select>
    </div>

    {#if scanClientIp}
      <p class="text-xs text-muted-foreground">
        Target IP: <code class="font-mono">{scanClientIp}</code>
      </p>
    {/if}

    <!-- Scan Controls -->
    <div class="flex items-center gap-2">
      <Button
        variant="primary"
        size="sm"
        icon="scan"
        onclick={startScan}
        loading={scanning}
        disabled={!scanClientId}
      >
        {scanning ? 'Scanning...' : 'Start Scan'}
      </Button>
      {#if scanning}
        <Button variant="outline" size="sm" icon="hand-stop" onclick={stopScan}>
          Stop
        </Button>
      {/if}
    </div>

    <!-- Progress Bar -->
    {#if scanning}
      {@const percent = scanProgress.total > 0 ? Math.round((scanProgress.scanned / scanProgress.total) * 100) : 0}
      <div class="space-y-1">
        <div class="w-full h-1 bg-muted rounded-full overflow-hidden">
          <div
            class="h-full bg-gradient-to-r from-primary via-primary/80 to-success transition-all duration-150 relative overflow-hidden"
            style="width: {percent}%"
          >
            <div class="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer"></div>
          </div>
        </div>
        <p class="text-xs text-muted-foreground">
          {#if scanProgress.total > 0}
            Scanning: {scanProgress.scanned.toLocaleString()} / {scanProgress.total.toLocaleString()} ports ({percent}%) — Found: {scanProgress.found}
          {:else}
            Starting scan...
          {/if}
        </p>
      </div>
    {/if}

    <!-- Discovered Ports -->
    {#if discoveredPorts.length > 0}
      <div class="kt-panel">
        <div class="kt-panel-header !py-2">
          <span class="text-xs font-medium text-foreground">
            Found {discoveredPorts.length} open port(s) — {selectedPorts.length} selected
          </span>
          <div class="flex items-center gap-2">
            <button onclick={selectAllPorts} class="text-xs text-primary hover:underline">
              Select All
            </button>
            <span class="text-muted-foreground">|</span>
            <button onclick={deselectAllPorts} class="text-xs text-primary hover:underline">
              Deselect All
            </button>
          </div>
        </div>
        <div class="max-h-[400px] overflow-y-auto divide-y divide-border">
          {#each discoveredPorts as portInfo}
            {@const entry = selectedPorts.find(p => p.port === portInfo.port)}
            {@const isSelected = !!entry}
            <div class="hover:bg-accent/30">
              <!-- Port header row -->
              <Checkbox
                checked={isSelected}
                onchange={() => togglePortSelection(portInfo.port)}
                class="!flex !gap-3 px-3 py-2"
              >
                <div class="flex-1 flex items-center gap-2">
                  <span class="font-mono text-sm font-medium text-foreground">{portInfo.port}</span>
                  {#if portInfo.service}
                    <span class="text-sm text-muted-foreground">{portInfo.service}</span>
                  {/if}
                </div>
                {#if isSelected}
                  <Icon name="chevron-down" size={14} class="text-muted-foreground" />
                {/if}
              </Checkbox>

              <!-- Inline editor when selected -->
              {#if isSelected && entry}
                <div class="px-3 pb-3 pt-1 ml-6 border-l-2 border-primary/30 space-y-3">
                  <Input
                    label="Domain"
                    placeholder="wiki.local"
                    value={entry.domain}
                    oninput={(e) => updateSelectedPort(entry.port, 'domain', e.target.value)}
                    prefixIcon="world-www"
                    suffixCheckbox={{ icon: "lock", label: "HTTPS", color: "warning" }}
                    suffixCheckboxChecked={entry.httpsBackend}
                    onSuffixCheckboxChange={(e) => updateSelectedPort(entry.port, 'httpsBackend', e.target.checked)}
                  />

                  <Input
                    label="Description"
                    placeholder="Service description"
                    value={entry.description}
                    oninput={(e) => updateSelectedPort(entry.port, 'description', e.target.value)}
                    prefixIcon="file-text"
                  />

                  {#if availableMiddlewares.length > 0}
                    <div class="flex items-center gap-2 flex-wrap">
                      <span class="text-xs text-muted-foreground">Middlewares:</span>
                      {#each availableMiddlewares as mw}
                        <Checkbox
                          variant="chip"
                          checked={(entry.middlewares || []).includes(mw.name)}
                          onchange={() => toggleSelectedPortMiddleware(entry.port, mw.name)}
                          label={mw.name.replace('@file', '')}
                        />
                      {/each}
                    </div>
                  {/if}
                </div>
              {/if}
            </div>
          {/each}
        </div>
      </div>
    {:else if scanProgress.completed && discoveredPorts.length === 0}
      <div class="text-center py-6 text-muted-foreground">
        <Icon name="search" size={32} class="mx-auto mb-2 opacity-50" />
        <p class="text-sm">No open ports found on this device</p>
      </div>
    {/if}
  </div>

  {#snippet footer()}
    <div class="flex justify-between w-full">
      <Button variant="outline" onclick={() => showScanModal = false}>Cancel</Button>
      <Button
        variant="primary"
        onclick={createRoutesFromScan}
        disabled={selectedPorts.length === 0}
      >
        Create {selectedPorts.length} Route(s)
      </Button>
    </div>
  {/snippet}
</Modal>
