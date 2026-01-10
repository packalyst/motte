<script>
  import { onMount } from 'svelte'
  import { theme, toast, apiGet, apiPost, apiPut, apiDelete, generateAdguardCredentials, confirm } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'
  import Badge from '../components/Badge.svelte'
  import Select from '../components/Select.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import ContentBlock from '../components/ContentBlock.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import Modal from '../components/Modal.svelte'

  let { loading = $bindable(true) } = $props()
  let savingAdguard = $state(false)
  let savingSession = $state(false)
  let savingTraefik = $state(false)
  let regeneratingKey = $state(false)

  // VPN Router state
  let routerStatus = $state(null)
  let routerLoading = $state(false)

  // Headscale settings
  let headscaleApiUrl = $state('')  // Internal API URL (readonly)
  let headscaleUrl = $state('')     // Public URL (editable)
  let headscaleHasKey = $state(false)
  let headscaleUrlChanged = $state(false)
  let savingHeadscale = $state(false)
  let originalHeadscaleUrl = ''

  // AdGuard settings
  let adguardUsername = $state('')
  let adguardPassword = $state('')
  let adguardDashboardEnabled = $state(true)
  let adguardDashboardURL = $state('')
  let adguardQuerylogSize = $state(1)
  let adguardChanged = $state(false)

  // Traefik settings
  let traefikForm = $state({
    rateLimitAverage: 100,
    rateLimitBurst: 200,
    strictRateAverage: 10,
    strictRateBurst: 20,
    ipAllowlist: [],
    newIP: '',
    dashboardEnabled: true
  })
  let originalTraefik = $state(null)

  // VPN-only mode: "off", "403", or "silent"
  let vpnOnlyMode = $state('off')
  let vpnOnlyLoading = $state(false)

  // Session settings
  let sessionTimeout = $state('24')
  let sessionChanged = $state(false)

  // Scanner settings
  let scannerSettings = $state({
    portStart: 1,
    portEnd: 5000,
    concurrent: 100,
    pauseMs: 10,
    timeoutMs: 500
  })
  let originalScanner = $state(null)
  let savingScanner = $state(false)

  // UI settings (stored in localStorage)
  let itemsPerPage = $state('25')

  // Logs watcher settings
  let watcherStatuses = $state([])
  let togglingWatcher = $state(null) // name of watcher being toggled

  // Geolocation settings
  let geoSettings = $state({
    lookup_provider: 'none',
    blocking_enabled: false,
    auto_update: false,
    update_hour: 3,
    update_services: 'all',
    maxmind_license_key: '',
    ip2location_token: '',
    ip2location_variant: 'DB1'
  })
  let geoStatus = $state(null)
  let geoProviders = $state(null)  // Provider configs from API
  let savingGeo = $state(false)
  let originalGeoSettings = $state(null)
  let triggeringGeoUpdate = $state(false)

  // Jails settings
  let jails = $state([])
  let loadingJails = $state(false)
  let showJailModal = $state(false)
  let savingJail = $state(false)

  // Ports settings
  let ports = $state([])
  let loadingPorts = $state(false)
  let newPort = $state('')

  // SSH port settings
  let sshPort = $state(22)
  let showSSHModal = $state(false)
  let newSSHPort = $state('')
  let changingSSH = $state(false)
  let jailForm = $state({
    id: null,
    name: '',
    enabled: true,
    logFile: '/var/log/auth.log',
    filterRegex: '',
    maxRetry: 5,
    findTime: 3600,
    banTime: 2592000,
    port: '',
    action: 'drop',
    escalateEnabled: false,
    escalateThreshold: 3,
    escalateWindow: 3600
  })

  // Original values for change detection
  let originalAdguard = { username: '', password: '', dashboardEnabled: true, querylogSize: 1 }
  let originalSession = { timeout: '24' }

  async function loadSettings() {
    loading = true
    try {
      // Single API call returns all settings data
      const settings = await apiGet('/api/settings')

      // VPN-only mode (from aggregated response)
      vpnOnlyMode = settings.vpn_only_mode || 'off'

      // Headscale
      headscaleApiUrl = settings.headscale_api_url || ''
      headscaleUrl = settings.headscale_url || ''
      originalHeadscaleUrl = headscaleUrl
      headscaleHasKey = !!settings.headscale_api_key

      // AdGuard
      adguardUsername = settings.adguard_username || ''
      adguardPassword = settings.adguard_password ? '••••••••' : ''
      adguardDashboardEnabled = settings.adguard_dashboard_enabled !== false
      adguardDashboardURL = settings.adguard_dashboard_url || ''
      adguardQuerylogSize = settings.adguard_querylog_size || 1
      originalAdguard = { username: adguardUsername, password: adguardPassword, dashboardEnabled: adguardDashboardEnabled, querylogSize: adguardQuerylogSize }

      // Traefik (from aggregated response)
      const traefikConfig = settings.traefik
      if (traefikConfig) {
        traefikForm = {
          rateLimitAverage: traefikConfig.rateLimitAverage || 100,
          rateLimitBurst: traefikConfig.rateLimitBurst || 200,
          strictRateAverage: traefikConfig.strictRateAverage || 10,
          strictRateBurst: traefikConfig.strictRateBurst || 20,
          ipAllowlist: [...(traefikConfig.ipAllowlist || [])],
          newIP: '',
          dashboardEnabled: traefikConfig.dashboardEnabled !== false
        }
        originalTraefik = {
          rateLimitAverage: traefikForm.rateLimitAverage,
          rateLimitBurst: traefikForm.rateLimitBurst,
          strictRateAverage: traefikForm.strictRateAverage,
          strictRateBurst: traefikForm.strictRateBurst,
          ipAllowlist: [...traefikForm.ipAllowlist],
          dashboardEnabled: traefikForm.dashboardEnabled
        }
      }

      // Session
      sessionTimeout = settings.session_timeout || '24'
      originalSession = { timeout: sessionTimeout }

      // Scanner
      scannerSettings = {
        portStart: settings.scanner_port_start || 1,
        portEnd: settings.scanner_port_end || 5000,
        concurrent: settings.scanner_concurrent || 100,
        pauseMs: settings.scanner_pause_ms || 10,
        timeoutMs: settings.scanner_timeout_ms || 500
      }
      originalScanner = { ...scannerSettings }

      // Router (from aggregated response)
      routerStatus = settings.router || null

      // Geo (from aggregated response)
      if (settings.geo) {
        geoSettings = {
          lookup_provider: settings.geo.lookup_provider || 'none',
          blocking_enabled: settings.geo.blocking_enabled || false,
          auto_update: settings.geo.auto_update || false,
          update_hour: settings.geo.update_hour ?? 3,
          update_services: settings.geo.update_services || 'all',
          maxmind_license_key: settings.geo.maxmind_configured ? '••••••••' : '',
          ip2location_token: settings.geo.ip2location_configured ? '••••••••' : '',
          ip2location_variant: settings.geo.ip2location_variant || 'DB1'
        }
        originalGeoSettings = { ...geoSettings }
        geoProviders = settings.geo.providers || null
      }
      if (settings.geo_status) {
        geoStatus = settings.geo_status
      }

      // UI (from localStorage)
      itemsPerPage = localStorage.getItem('settings_items_per_page') || '25'

      // Load independent resources in parallel - each can fail without blocking others
      const [watcherRes, jailsRes, fwStatusRes, portsRes] = await Promise.allSettled([
        apiGet('/api/logs/status'),
        apiGet('/api/fw/jails'),
        apiGet('/api/fw/status'),
        apiGet('/api/fw/ports')
      ])

      if (watcherRes.status === 'fulfilled') watcherStatuses = watcherRes.value
      if (jailsRes.status === 'fulfilled') jails = jailsRes.value.jails || jailsRes.value || []
      if (fwStatusRes.status === 'fulfilled' && fwStatusRes.value?.sshPort) sshPort = fwStatusRes.value.sshPort
      if (portsRes.status === 'fulfilled') ports = portsRes.value.ports || portsRes.value || []
    } catch (e) {
      toast('Failed to load settings: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  $effect(() => {
    headscaleUrlChanged = headscaleUrl !== originalHeadscaleUrl
  })

  $effect(() => {
    const userChanged = adguardUsername !== originalAdguard.username
    const passChanged = adguardPassword !== originalAdguard.password && adguardPassword !== '••••••••'
    const dashboardChanged = adguardDashboardEnabled !== originalAdguard.dashboardEnabled
    const querylogChanged = adguardQuerylogSize !== originalAdguard.querylogSize
    adguardChanged = userChanged || passChanged || dashboardChanged || querylogChanged
  })

  $effect(() => {
    sessionChanged = sessionTimeout !== originalSession.timeout
  })

  // Derived state for scanner change detection
  const scannerHasChanges = $derived.by(() => {
    if (!originalScanner) return false
    return (
      scannerSettings.portStart !== originalScanner.portStart ||
      scannerSettings.portEnd !== originalScanner.portEnd ||
      scannerSettings.concurrent !== originalScanner.concurrent ||
      scannerSettings.pauseMs !== originalScanner.pauseMs ||
      scannerSettings.timeoutMs !== originalScanner.timeoutMs
    )
  })

  // Derived state for traefik change detection
  const traefikHasChanges = $derived.by(() => {
    if (!originalTraefik) return false
    return (
      traefikForm.rateLimitAverage !== originalTraefik.rateLimitAverage ||
      traefikForm.rateLimitBurst !== originalTraefik.rateLimitBurst ||
      traefikForm.strictRateAverage !== originalTraefik.strictRateAverage ||
      traefikForm.strictRateBurst !== originalTraefik.strictRateBurst ||
      traefikForm.dashboardEnabled !== originalTraefik.dashboardEnabled ||
      JSON.stringify(traefikForm.ipAllowlist) !== JSON.stringify(originalTraefik.ipAllowlist)
    )
  })

  // Save Headscale public URL
  async function saveHeadscale() {
    savingHeadscale = true
    try {
      await apiPut('/api/settings', {
        headscale_url: headscaleUrl
      })
      originalHeadscaleUrl = headscaleUrl
      headscaleUrlChanged = false
      toast('Headscale URL saved', 'success')
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingHeadscale = false
    }
  }

  // Regenerate Headscale API key (only if expires within 7 days)
  async function regenerateHeadscaleKey() {
    regeneratingKey = true
    try {
      await apiPost('/api/setup/generate-apikey', {})
      headscaleHasKey = true
      toast('API key regenerated successfully', 'success')
    } catch (e) {
      toast(e.message || 'Failed to regenerate API key', 'error')
    } finally {
      regeneratingKey = false
    }
  }

  // Save AdGuard settings
  async function saveAdguard() {
    savingAdguard = true
    try {
      const res = await apiPut('/api/settings', {
        adguard_username: adguardUsername,
        adguard_password: adguardPassword === '••••••••' ? null : adguardPassword,
        adguard_dashboard_enabled: adguardDashboardEnabled,
        adguard_querylog_size: adguardQuerylogSize
      })
      originalAdguard = { username: adguardUsername, password: adguardPassword, dashboardEnabled: adguardDashboardEnabled, querylogSize: adguardQuerylogSize }
      adguardChanged = false

      // If AdGuard config was updated, restart the container
      if (res.adguardRestartRequired) {
        toast('Settings saved. Restarting AdGuard...', 'info')
        try {
          await apiPost('/api/docker/containers/adguard/restart')
          toast('AdGuard restarted successfully', 'success')
        } catch (e) {
          toast('Settings saved but failed to restart AdGuard: ' + e.message, 'warning')
        }
      } else {
        toast('AdGuard settings saved', 'success')
      }
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingAdguard = false
    }
  }

  // Save Session settings
  async function saveSession() {
    savingSession = true
    try {
      await apiPut('/api/settings', {
        session_timeout: sessionTimeout
      })
      originalSession = { timeout: sessionTimeout }
      sessionChanged = false
      toast('Session settings saved', 'success')
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingSession = false
    }
  }

  // Save Scanner settings
  async function saveScanner() {
    savingScanner = true
    try {
      await apiPut('/api/settings', {
        scanner_port_start: parseInt(scannerSettings.portStart),
        scanner_port_end: parseInt(scannerSettings.portEnd),
        scanner_concurrent: parseInt(scannerSettings.concurrent),
        scanner_pause_ms: parseInt(scannerSettings.pauseMs),
        scanner_timeout_ms: parseInt(scannerSettings.timeoutMs)
      })
      originalScanner = { ...scannerSettings }
      toast('Scanner settings saved', 'success')
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingScanner = false
    }
  }

  // Save Traefik settings
  async function saveTraefik() {
    savingTraefik = true
    try {
      const res = await apiPut('/api/traefik/config', {
        rateLimitAverage: traefikForm.rateLimitAverage,
        rateLimitBurst: traefikForm.rateLimitBurst,
        strictRateAverage: traefikForm.strictRateAverage,
        strictRateBurst: traefikForm.strictRateBurst,
        ipAllowlist: traefikForm.ipAllowlist,
        dashboardEnabled: traefikForm.dashboardEnabled
      })
      originalTraefik = {
        rateLimitAverage: traefikForm.rateLimitAverage,
        rateLimitBurst: traefikForm.rateLimitBurst,
        strictRateAverage: traefikForm.strictRateAverage,
        strictRateBurst: traefikForm.strictRateBurst,
        ipAllowlist: [...traefikForm.ipAllowlist],
        dashboardEnabled: traefikForm.dashboardEnabled
      }
      if (res.restartRequired) {
        toast('Configuration saved. Restarting Traefik...', 'info')
        try {
          await apiPost('/api/docker/containers/traefik/restart')
          toast('Traefik restarted successfully', 'success')
        } catch (e) {
          toast('Config saved but failed to restart Traefik: ' + e.message, 'warning')
        }
      } else {
        toast('Traefik settings saved', 'success')
      }
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingTraefik = false
    }
  }

  function addTraefikIP() {
    const ip = traefikForm.newIP.trim()
    if (ip && !traefikForm.ipAllowlist.includes(ip)) {
      traefikForm.ipAllowlist = [...traefikForm.ipAllowlist, ip]
      traefikForm.newIP = ''
    }
  }

  function removeTraefikIP(ip) {
    traefikForm.ipAllowlist = traefikForm.ipAllowlist.filter(i => i !== ip)
  }

  // Save UI settings (localStorage only)
  function saveUISettings() {
    localStorage.setItem('settings_items_per_page', itemsPerPage)
    toast('UI settings saved', 'success')
  }

  function toggleTheme() {
    theme.update(t => t === 'dark' ? 'light' : 'dark')
  }

  async function saveGeoSettings() {
    savingGeo = true
    try {
      // Don't send placeholder values for tokens/keys
      const payload = {
        ...geoSettings,
        maxmind_license_key: geoSettings.maxmind_license_key === '••••••••' ? undefined : geoSettings.maxmind_license_key,
        ip2location_token: geoSettings.ip2location_token === '••••••••' ? undefined : geoSettings.ip2location_token
      }
      await apiPut('/api/geo/settings', payload)
      originalGeoSettings = { ...geoSettings }
      // Reload status to see updated provider info
      geoStatus = await apiGet('/api/geo/status')
      toast('Geolocation settings saved', 'success')
    } catch (e) {
      toast('Failed to save: ' + e.message, 'error')
    } finally {
      savingGeo = false
    }
  }

  async function triggerGeoUpdate() {
    triggeringGeoUpdate = true
    try {
      const res = await apiPost('/api/geo/update')
      if (res.errors > 0) {
        toast(`Update completed with ${res.errors} errors`, 'warning')
      } else {
        toast('Geolocation data updated successfully', 'success')
      }
      // Reload status
      geoStatus = await apiGet('/api/geo/status')
    } catch (e) {
      toast('Failed to update: ' + e.message, 'error')
    } finally {
      triggeringGeoUpdate = false
    }
  }

  // Check if geo settings have changed
  const geoHasChanges = $derived.by(() => {
    if (!originalGeoSettings) return false
    return JSON.stringify(geoSettings) !== JSON.stringify(originalGeoSettings)
  })

  // VPN Router functions
  async function loadRouterStatus() {
    try {
      routerStatus = await apiGet('/api/vpn/router/status')
    } catch (e) {
      routerStatus = { status: 'not_started', message: 'Failed to fetch status' }
    }
  }

  async function setupRouter() {
    routerLoading = true
    try {
      await apiPost('/api/vpn/router/setup')
      toast('VPN Router setup started', 'success')
      await loadRouterStatus()
    } catch (e) {
      toast('Failed to setup router: ' + e.message, 'error')
    } finally {
      routerLoading = false
    }
  }

  async function restartRouter() {
    routerLoading = true
    try {
      await apiPost('/api/vpn/router/restart')
      toast('VPN Router restarted', 'success')
      await loadRouterStatus()
    } catch (e) {
      toast('Failed to restart router: ' + e.message, 'error')
    } finally {
      routerLoading = false
    }
  }

  async function removeRouter() {
    routerLoading = true
    try {
      await apiDelete('/api/vpn/router')
      toast('VPN Router removed', 'success')
      await loadRouterStatus()
    } catch (e) {
      toast('Failed to remove router: ' + e.message, 'error')
    } finally {
      routerLoading = false
    }
  }

  // Set VPN-only mode
  async function setVPNOnlyMode(mode) {
    vpnOnlyLoading = true
    try {
      await apiPost('/api/traefik/vpn-only', { mode })
      vpnOnlyMode = mode
      const messages = {
        'off': 'VPN-only mode disabled',
        '403': 'VPN-only mode enabled (403 Forbidden)',
        'silent': 'VPN-only mode enabled (Silent Drop)'
      }
      toast(messages[mode], 'success')
    } catch (e) {
      toast('Failed to set VPN-only mode: ' + e.message, 'error')
    } finally {
      vpnOnlyLoading = false
    }
  }

  // Toggle logs watcher
  async function toggleWatcher(name, enable) {
    togglingWatcher = name
    try {
      await apiPost('/api/logs/watcher', { name, enable })
      // Update local state
      watcherStatuses = watcherStatuses.map(w =>
        w.name === name ? { ...w, enabled: enable, running: enable } : w
      )
      toast(`${name} watcher ${enable ? 'enabled' : 'disabled'}`, 'success')
    } catch (e) {
      toast(`Failed to toggle ${name}: ` + e.message, 'error')
    } finally {
      togglingWatcher = null
    }
  }

  // Jail management
  function openCreateJail() {
    jailForm = {
      id: null,
      name: '',
      enabled: true,
      logFile: '/var/log/auth.log',
      filterRegex: '',
      maxRetry: 5,
      findTime: 3600,
      banTime: 2592000,
      port: '',
      action: 'drop',
      escalateEnabled: false,
      escalateThreshold: 3,
      escalateWindow: 3600
    }
    showJailModal = true
  }

  function openEditJail(jail) {
    jailForm = {
      id: jail.id,
      name: jail.name,
      enabled: jail.enabled,
      logFile: jail.logFile,
      filterRegex: jail.filterRegex,
      maxRetry: jail.maxRetry,
      findTime: jail.findTime,
      banTime: jail.banTime,
      port: jail.port,
      action: jail.action,
      escalateEnabled: jail.escalateEnabled || false,
      escalateThreshold: jail.escalateThreshold || 3,
      escalateWindow: jail.escalateWindow || 3600
    }
    showJailModal = true
  }

  async function saveJail() {
    if (!jailForm.name.trim()) {
      toast('Jail name is required', 'error')
      return
    }
    if (!jailForm.filterRegex.trim()) {
      toast('Filter regex is required', 'error')
      return
    }

    savingJail = true
    try {
      const jailData = {
        enabled: jailForm.enabled,
        logFile: jailForm.logFile,
        filterRegex: jailForm.filterRegex,
        maxRetry: parseInt(jailForm.maxRetry) || 5,
        findTime: parseInt(jailForm.findTime) || 3600,
        banTime: parseInt(jailForm.banTime) || 2592000,
        port: jailForm.port,
        action: jailForm.action,
        escalateEnabled: jailForm.escalateEnabled,
        escalateThreshold: parseInt(jailForm.escalateThreshold) || 3,
        escalateWindow: parseInt(jailForm.escalateWindow) || 3600
      }

      if (jailForm.id) {
        await apiPut(`/api/fw/jails/${jailForm.name}`, jailData)
        toast(`Jail "${jailForm.name}" updated`, 'success')
      } else {
        await apiPost('/api/fw/jails', { name: jailForm.name, ...jailData })
        toast(`Jail "${jailForm.name}" created`, 'success')
      }
      showJailModal = false
      // Reload jails
      const jailsRes = await apiGet('/api/fw/jails')
      jails = jailsRes.jails || jailsRes || []
    } catch (e) {
      toast('Failed to save jail: ' + e.message, 'error')
    } finally {
      savingJail = false
    }
  }

  async function deleteJail(jail) {
    if (!confirm(`Delete jail "${jail.name}"?`)) return
    try {
      await apiDelete(`/api/fw/jails/${jail.name}`)
      toast(`Jail "${jail.name}" deleted`, 'success')
      jails = jails.filter(j => j.id !== jail.id)
    } catch (e) {
      toast('Failed to delete jail: ' + e.message, 'error')
    }
  }

  async function toggleJail(jail) {
    try {
      await apiPut(`/api/fw/jails/${jail.name}`, { ...jail, enabled: !jail.enabled })
      jails = jails.map(j => j.id === jail.id ? { ...j, enabled: !j.enabled } : j)
      toast(`Jail "${jail.name}" ${!jail.enabled ? 'enabled' : 'disabled'}`, 'success')
    } catch (e) {
      toast('Failed to toggle jail: ' + e.message, 'error')
    }
  }

  function formatBanTime(seconds) {
    if (seconds < 60) return `${seconds}s`
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
    return `${Math.floor(seconds / 86400)}d`
  }

  // SSH port management
  function openSSHModal() {
    newSSHPort = sshPort.toString()
    showSSHModal = true
  }

  async function changeSSHPort() {
    const port = parseInt(newSSHPort)
    if (!port || port < 1 || port > 65535) {
      toast('Invalid port number (1-65535)', 'error')
      return
    }
    if (port === sshPort) {
      toast('SSH is already on this port', 'info')
      return
    }

    changingSSH = true
    try {
      const res = await apiPost('/api/fw/ssh', { port })
      if (res.newPort) {
        toast(`SSH port changed from ${res.oldPort} to ${res.newPort}`, 'success')
        sshPort = res.newPort
        showSSHModal = false
        newSSHPort = ''
      }
    } catch (e) {
      toast('Failed to change SSH port: ' + e.message, 'error')
    } finally {
      changingSSH = false
    }
  }

  // Generate random secure credentials for AdGuard
  function regenerateAdguardCredentials() {
    const creds = generateAdguardCredentials()
    adguardUsername = creds.username
    adguardPassword = creds.password
    toast('Credentials generated', 'success')
  }

  // Port management
  const sortedPorts = $derived.by(() => {
    const arr = ports || []
    if (!arr.slice) return []
    return [...arr].sort((a, b) => a.port - b.port)
  })

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
      const portsRes = await apiGet('/api/fw/ports')
      ports = portsRes.ports || portsRes || []
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function removePort(port, protocol = 'tcp') {
    try {
      await apiDelete(`/api/fw/ports/${port}?protocol=${protocol}`)
      toast(`Port ${port} removed`, 'success')
      const portsRes = await apiGet('/api/fw/ports')
      ports = portsRes.ports || portsRes || []
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function confirmRemovePort(port, protocol = 'tcp') {
    const confirmed = await confirm({
      title: 'Remove Port',
      message: `Remove port ${port}/${protocol.toUpperCase()}?`,
      description: 'This port will no longer allow incoming connections.',
      confirmText: 'Remove'
    })
    if (confirmed) {
      await removePort(port, protocol)
    }
  }

  onMount(() => {
    loadSettings()
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="settings"
    title="Settings"
    description="Configure your VPN admin panel. Manage Headscale connection, AdGuard integration, session preferences, and interface customization."
  />

  {#if loading}
    <LoadingSpinner centered size="lg" />
  {:else}
    <!-- Two column grid -->
    <div class="grid gap-4 lg:grid-cols-2">
      <!-- Headscale Settings -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="server" size={16} />
            Headscale
          </h3>
        </div>
        <div class="kt-panel-body">
          <div class="grid grid-cols-2 gap-3">
            <Input
              id="headscaleApiUrl"
              label="Internal API URL"
              helperText="Auto-detected from Docker"
              type="url"
              value={headscaleApiUrl}
              prefixIcon="link"
              class="text-xs bg-muted/50"
              disabled
            />
            <Input
              id="headscaleUrl"
              label="Public URL"
              helperText="External URL for Tailscale clients"
              type="url"
              bind:value={headscaleUrl}
              placeholder="http://your-server-ip:8080"
              prefixIcon="link"
              class="text-xs"
            />
          </div>
          <div>
            <span class="block text-xs font-medium text-foreground mb-1">API Key</span>
            <div class="kt-input">
                {#if headscaleHasKey}
                  <Icon name="check" size={14} class="text-success" />
                  <span class="text-muted-foreground">Configured</span>
                {:else}
                  <Icon name="alert-circle" size={14} class="text-destructive" />
                  <span class="text-destructive">Not configured</span>
                {/if}
                <input
                  id=""
                  type=""
                  placeholder=""
                  class="kt-input w-full text-xs"
                  disabled
                />
                <Button
                  onclick={regenerateHeadscaleKey}
                  loading={regeneratingKey}
                  variant="ghost"
                  size="xs"
                  iconOnly
                  icon="refresh"
                  class="-me-1.5 size-6"
                  title="Regenerate API key"
                />
              </div>
          </div>
        </div>
        <div class="kt-panel-footer">
          <Button
            onclick={saveHeadscale}
            loading={savingHeadscale}
            disabled={!headscaleUrlChanged}
            size="sm"
            icon="device-floppy"
          >
            Save
          </Button>
        </div>
      </div>

      <!-- AdGuard Settings -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="shield" size={16} />
            AdGuard Home
          </h3>
          <Button
            onclick={regenerateAdguardCredentials}
            variant="outline"
            size="xs"
            icon="wand"
            title="Generate random secure credentials"
          >
            Generate
          </Button>
        </div>
        <div class="kt-panel-body">
          <div class="grid grid-cols-2 gap-3">
            <Input
              id="adguardUsername"
              label="Username"
              type="text"
              bind:value={adguardUsername}
              placeholder="admin"
              prefixIcon="user"
              class="text-xs"
            />
            <Input
              id="adguardPassword"
              label="Password"
              type="password"
              bind:value={adguardPassword}
              placeholder="Password"
              prefixIcon="lock"
              class="text-xs"
            />
          </div>
          <div class="grid grid-cols-2 gap-3 pt-3 border-t border-border">
            <Input
              label="Query Log Buffer"
              type="number"
              bind:value={adguardQuerylogSize}
              prefixIcon="database"
              class="text-xs"
              min="1"
            />
            <div class="flex items-center justify-between">
              <div>
                <span class="text-xs font-medium text-foreground">Dashboard Access</span>
                <p class="text-[10px] text-muted-foreground">External access to AdGuard UI</p>
              </div>
              <Checkbox variant="switch" bind:checked={adguardDashboardEnabled} />
            </div>
          </div>
        </div>
        <div class="kt-panel-footer">
          <Button
            onclick={saveAdguard}
            loading={savingAdguard}
            disabled={!adguardChanged}
            size="sm"
            icon="device-floppy"
          >
            Save
          </Button>
          {#if adguardDashboardURL}
            <a href={adguardDashboardURL} target="_blank" class="kt-btn kt-btn-secondary kt-btn-sm">
              <Icon name="link" size={14} />
              Open Dashboard
            </a>
          {/if}
        </div>
      </div>

      <!-- Session & Interface Settings -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="settings" size={16} />
            Preferences
          </h3>
        </div>
        <div class="kt-panel-body">
          <div class="grid grid-cols-2 gap-3">
            <Select
              label="Session Timeout"
              bind:value={sessionTimeout}
              options={[
                { value: '1', label: '1 hour' },
                { value: '8', label: '8 hours' },
                { value: '24', label: '24 hours' },
                { value: '168', label: '7 days' },
                { value: '720', label: '30 days' }
              ]}
            />
            <Select
              label="Items per page"
              bind:value={itemsPerPage}
              onchange={saveUISettings}
              options={[
                { value: '10', label: '10' },
                { value: '25', label: '25' },
                { value: '50', label: '50' },
                { value: '100', label: '100' }
              ]}
            />
          </div>
          <div class="flex items-center justify-between border-t border-border pt-3">
            <div>
              <div class="text-xs font-medium text-foreground">Theme</div>
              <div class="text-[10px] text-muted-foreground">Current: {$theme}</div>
            </div>
            <Button
              onclick={toggleTheme}
              variant="secondary"
              size="sm"
              icon={$theme === 'dark' ? 'sun' : 'moon'}
            >
              {$theme === 'dark' ? 'Light' : 'Dark'}
            </Button>
          </div>
        </div>
        <div class="kt-panel-footer">
          <Button
            onclick={saveSession}
            loading={savingSession}
            disabled={!sessionChanged}
            size="sm"
            icon="device-floppy"
          >
            Save Session
          </Button>
        </div>
      </div>

      <!-- Cross-Network Router -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="route" size={16} />
            Cross-Network Router
          </h3>
          {#if routerStatus?.status === 'running'}
            <Badge variant="success" size="sm">Running</Badge>
          {:else if routerStatus?.status === 'starting'}
            <Badge variant="warning" size="sm">Starting</Badge>
          {:else}
            <Badge variant="muted" size="sm">Disabled</Badge>
          {/if}
        </div>
        <div class="kt-panel-body">
          {#if routerStatus?.status === 'running'}
            <div class="grid grid-cols-2 gap-2">
              <ContentBlock variant="data" label="Router IP" value={routerStatus.ip || '—'} mono padding="sm" />
              <ContentBlock variant="data" label="Route" value={routerStatus.advertisedRoute || '—'} mono padding="sm" />
            </div>
            <p class="text-[10px] text-muted-foreground">
              Routing between WireGuard and Headscale networks.
            </p>
          {:else if routerStatus?.status === 'starting'}
            <div class="flex items-center gap-2 p-2 bg-warning/10 rounded">
              <div class="w-4 h-4 border-2 border-warning/30 border-t-warning rounded-full animate-spin"></div>
              <div class="text-xs text-foreground">Starting up...</div>
            </div>
          {:else}
            <p class="text-[10px] text-muted-foreground">
              Enable routing between WireGuard and Headscale networks via a Tailscale container.
            </p>
          {/if}
        </div>
        <div class="kt-panel-footer">
          {#if routerStatus?.status === 'running'}
            <Button onclick={restartRouter} size="sm" variant="secondary" icon="refresh" disabled={routerLoading}>
              {routerLoading ? '...' : 'Restart'}
            </Button>
            <Button onclick={removeRouter} size="sm" variant="destructive" icon="trash" disabled={routerLoading}>
              {routerLoading ? '...' : 'Remove'}
            </Button>
          {:else if routerStatus?.status === 'starting'}
            <Button onclick={loadRouterStatus} size="sm" variant="secondary" icon="refresh">
              Check Status
            </Button>
          {:else}
            <Button onclick={setupRouter} size="sm" icon="play" disabled={routerLoading}>
              {routerLoading ? 'Setting up...' : 'Enable'}
            </Button>
          {/if}
        </div>
      </div>

      <!-- Logs Watchers -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="file-text" size={16} />
            Log Watchers
          </h3>
        </div>
        <div class="kt-panel-body">
          <p class="text-[10px] text-muted-foreground mb-3">
            Enable or disable log collection from various sources.
          </p>
          {#if watcherStatuses.length > 0}
            <div class="space-y-2">
              {#each watcherStatuses as watcher}
                {@const isToggling = togglingWatcher === watcher.name}
                {@const hasError = watcher.enabled && watcher.lastError}
                <div class="flex flex-col gap-1 p-2 rounded border border-border {!watcher.enabled && 'opacity-50'}">
                  <div class="flex items-center justify-between">
                    <div class="flex items-center gap-2">
                      <!-- Status indicator (not clickable) -->
                      <div class="flex h-6 w-6 items-center justify-center rounded {watcher.enabled ? (hasError ? 'bg-destructive/10 text-destructive' : (watcher.running ? 'bg-success/10 text-success' : 'bg-warning/10 text-warning')) : 'bg-muted text-muted-foreground'}">
                        <Icon name={hasError ? 'alert-triangle' : (watcher.running ? 'activity' : 'circle')} size={14} />
                      </div>
                      <div>
                        <span class="text-xs font-medium text-foreground capitalize">{watcher.name}</span>
                        {#if watcher.processed > 0}
                          <span class="text-[10px] text-muted-foreground ml-1">· {watcher.processed} processed</span>
                        {/if}
                      </div>
                    </div>
                    <!-- Action buttons -->
                    <div class="flex items-center gap-2">
                      {#if watcher.enabled}
                        {#if hasError}
                          <Button
                            size="xs"
                            variant="outline"
                            icon={isToggling ? 'loader-2' : 'refresh'}
                            loading={isToggling}
                            onclick={() => { toggleWatcher(watcher.name, false).then(() => toggleWatcher(watcher.name, true)) }}
                          >
                            Restart
                          </Button>
                        {/if}
                        <Button
                          size="xs"
                          variant="destructive"
                          icon={isToggling ? 'loader-2' : 'player-stop'}
                          loading={isToggling}
                          onclick={() => toggleWatcher(watcher.name, false)}
                        >
                          Stop
                        </Button>
                      {:else}
                        <Button
                          size="xs"
                          variant="success"
                          icon={isToggling ? 'loader-2' : 'player-play'}
                          loading={isToggling}
                          onclick={() => toggleWatcher(watcher.name, true)}
                        >
                          Start
                        </Button>
                      {/if}
                    </div>
                  </div>
                  {#if hasError}
                    <div class="text-[10px] text-destructive bg-destructive/10 rounded px-2 py-1">
                      {watcher.lastError}
                    </div>
                  {/if}
                </div>
              {/each}
            </div>
          {:else}
            <p class="text-xs text-muted-foreground italic">No watchers configured</p>
          {/if}
        </div>
      </div>

      <!-- Jails (Intrusion Detection) -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="shield-lock" size={16} />
            Jails
          </h3>
          <div class="kt-btn-group">
            <Button onclick={openSSHModal} variant="outline" size="xs" icon="key">
              SSH: {sshPort}
            </Button>
            <Button onclick={openCreateJail} variant="outline" size="xs" icon="plus">
              Add Jail
            </Button>
          </div>
        </div>
        <div class="kt-panel-body">
          <p class="text-[10px] text-muted-foreground mb-3">
            Intrusion detection - automatically block IPs based on log patterns.
          </p>
          {#if jails.length > 0}
            <div class="space-y-2">
              {#each jails as jail}
                <div class="flex items-center justify-between p-2 rounded border border-border {!jail.enabled && 'opacity-50'}">
                  <div class="flex items-center gap-2">
                    <!-- Status indicator (not clickable) -->
                    <div class="flex h-6 w-6 items-center justify-center rounded {jail.enabled ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                      <Icon name={jail.enabled ? 'shield-check' : 'shield'} size={14} />
                    </div>
                    <div>
                      <span class="text-xs font-medium text-foreground capitalize">{jail.name}</span>
                      <div class="text-[10px] text-muted-foreground">
                        {jail.maxRetry} retries / {formatBanTime(jail.findTime)} → ban {formatBanTime(jail.banTime)}
                      </div>
                    </div>
                  </div>
                  <div class="flex items-center gap-2">
                    {#if jail.currentlyBanned > 0}
                      <Badge variant="destructive" size="sm">{jail.currentlyBanned} banned</Badge>
                    {/if}
                    <div class="kt-btn-group">
                      {#if jail.enabled}
                        <Button onclick={() => toggleJail(jail)} variant="destructive" size="xs" icon="player-stop" tooltip="Stop" />
                      {:else}
                        <Button onclick={() => toggleJail(jail)} variant="success" size="xs" icon="player-play" tooltip="Start" />
                      {/if}
                      <Button onclick={() => openEditJail(jail)} variant="outline" size="xs" icon="edit" tooltip="Edit" />
                      <Button onclick={() => deleteJail(jail)} variant="outline" size="xs" icon="trash" tooltip="Delete" />
                    </div>
                  </div>
                </div>
              {/each}
            </div>
          {:else}
            <p class="text-xs text-muted-foreground italic">No jails configured</p>
          {/if}
        </div>
      </div>

      <!-- Allowed Ports -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="lock" size={16} />
            Allowed Ports
          </h3>
          <Input
            type="number"
            bind:value={newPort}
            placeholder="Port"
            prefixIcon="plug"
            suffixAddonBtn={{ icon: "plus", onclick: addPort }}
            class="w-32"
            min="1"
            max="65535"
            onkeydown={(e) => e.key === 'Enter' && addPort()}
          />
        </div>
        <div class="kt-panel-body">
          <p class="text-[10px] text-muted-foreground mb-3">
            Firewall ports allowed for incoming connections.
          </p>
          {#if sortedPorts.length > 0}
            <!-- New input-based layout -->
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">
              {#each sortedPorts as p}
                {@const serviceName = p.service || (p.port === 22 ? 'SSH' : p.port === 80 ? 'HTTP' : p.port === 443 ? 'HTTPS' : p.port === 51820 ? 'WireGuard' : '')}
                {#if p.essential}
                  <Input
                    value={p.port}
                    disabled
                    prefixAddon={p.protocol?.toUpperCase() || 'TCP'}
                    suffixAddonIcon={{ icon: "lock", tooltip: `Essential: ${serviceName}` }}
                    class="kt-input-group-warning"
                  />
                {:else}
                  <Input
                    value={p.port}
                    disabled
                    prefixAddon={p.protocol?.toUpperCase() || 'TCP'}
                    suffixAddonBtn={{
                      icon: "trash",
                      onclick: () => confirmRemovePort(p.port, p.protocol),
                      tooltip: "Remove port"
                    }}
                  />
                {/if}
              {/each}
            </div>
          {:else}
            <p class="text-xs text-muted-foreground italic">No ports configured</p>
          {/if}
        </div>
      </div>

      <!-- Port Scanner Settings -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="scan" size={16} />
            Port Scanner
          </h3>
        </div>
        <div class="kt-panel-body">
          <p class="text-[10px] text-muted-foreground">
            Default settings for scanning VPN client ports in Domain Routes.
          </p>
          <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
            <Input
              label="Port Start"
              type="number"
              bind:value={scannerSettings.portStart}
              min="1"
              max="65535"
              prefixIcon="player-play"
              class="text-xs"
            />
            <Input
              label="Port End"
              type="number"
              bind:value={scannerSettings.portEnd}
              min="1"
              max="65535"
              prefixIcon="player-stop"
              class="text-xs"
            />
            <Input
              label="Concurrent"
              type="number"
              bind:value={scannerSettings.concurrent}
              min="10"
              max="500"
              prefixIcon="layers-subtract"
              class="text-xs"
            />
            <Input
              label="Pause (ms)"
              type="number"
              bind:value={scannerSettings.pauseMs}
              min="0"
              max="1000"
              prefixIcon="player-pause"
              class="text-xs"
            />
            <Input
              label="Timeout (ms)"
              type="number"
              bind:value={scannerSettings.timeoutMs}
              min="100"
              max="5000"
              prefixIcon="clock"
              class="text-xs"
            />
          </div>
        </div>
        <div class="kt-panel-footer">
          <Button
            onclick={saveScanner}
            loading={savingScanner}
            disabled={!scannerHasChanges}
            size="sm"
            icon="device-floppy"
          >
            Save
          </Button>
        </div>
      </div>
    </div>

    <!-- Traefik Settings - Full width -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">
          <Icon name="route" size={16} />
          Traefik
        </h3>
      </div>
      <div class="kt-panel-body">
        <!-- Two columns: Rate Limiting + Switches -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <!-- Rate Limiting (4 inputs in 2x2) -->
          <div>
            <ContentBlock variant="header" title="Rate Limiting" />
            <div class="grid grid-cols-2 gap-3">
              <Input
                label="Standard (req/s)"
                type="number"
                bind:value={traefikForm.rateLimitAverage}
                prefixIcon="gauge"
                class="text-xs"
                min="1"
              />
              <Input
                label="Standard Burst"
                type="number"
                bind:value={traefikForm.rateLimitBurst}
                prefixIcon="bolt"
                class="text-xs"
                min="1"
              />
              <Input
                label="Strict (req/s)"
                type="number"
                bind:value={traefikForm.strictRateAverage}
                prefixIcon="gauge"
                class="text-xs"
                min="1"
              />
              <Input
                label="Strict Burst"
                type="number"
                bind:value={traefikForm.strictRateBurst}
                prefixIcon="bolt"
                class="text-xs"
                min="1"
              />
            </div>
          </div>

          <!-- Switches -->
          <div class="space-y-3">
            <ContentBlock variant="header" title="Access Control" />
            <ContentBlock title="Dashboard" description="Port 8080 (restart required)">
              <Checkbox variant="switch" bind:checked={traefikForm.dashboardEnabled} />
            </ContentBlock>
            <ContentBlock title="VPN-Only Mode" description="Restrict access to VPN clients">
              <div class="flex items-center gap-2">
                {#if vpnOnlyLoading}
                  <span class="w-3 h-3 border-2 border-primary border-t-transparent rounded-full animate-spin"></span>
                {/if}
                <Select
                  value={vpnOnlyMode}
                  options={[
                    { value: 'off', label: 'Disabled' },
                    { value: '403', label: '403 Forbidden' },
                    { value: 'silent', label: 'Silent Drop' }
                  ]}
                  onchange={(e) => setVPNOnlyMode(e.target.value)}
                  disabled={vpnOnlyLoading}
                />
              </div>
            </ContentBlock>
          </div>
        </div>

        <!-- IP Allowlist - Full width -->
        <div class="border-t border-border pt-3">
          <h4 class="text-xs font-medium text-foreground mb-2">Sentinel VPN Middleware</h4>
          <Input
            type="text"
            bind:value={traefikForm.newIP}
            prefixIcon="network"
            placeholder="e.g., 192.168.1.0/24"
            class="text-xs"
            suffixAddonBtn={{ icon: "plus", label: "Add", onclick: addTraefikIP }}
            onkeydown={(e) => e.key === 'Enter' && addTraefikIP()}
          />
          {#if traefikForm.ipAllowlist.length > 0}
            <div class="flex flex-wrap gap-1.5 pt-2">
              {#each traefikForm.ipAllowlist as ip}
                <div class="flex items-center gap-1 px-2 py-0.5 bg-muted rounded text-xs">
                  <code>{ip}</code>
                  <button onclick={() => removeTraefikIP(ip)} class="p-0.5 hover:text-destructive">
                    <Icon name="x" size={10} class="cursor-pointer"/>
                  </button>
                </div>
              {/each}
            </div>
          {:else}
            <p class="text-[10px] text-muted-foreground italic pt-2">No IP ranges configured</p>
          {/if}
        </div>
      </div>
      <div class="kt-panel-footer justify-end">
        <Button
          onclick={saveTraefik}
          loading={savingTraefik}
          disabled={!traefikHasChanges}
          size="sm"
          icon="device-floppy"
        >
          Save
        </Button>
      </div>
    </div>

    <!-- Geolocation Settings - Full width -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">
          <Icon name="world" size={16} />
          Geolocation
        </h3>
      </div>
      <div class="kt-panel-body">
          <!-- Two columns: IP Lookup + Toggles -->
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <!-- IP Lookup Provider -->
            <div>
              <ContentBlock variant="header" title="IP Lookup Provider" />
              <Select
                label="Provider"
                bind:value={geoSettings.lookup_provider}
                options={[
                  { value: 'none', label: 'None (disabled)' },
                  { value: 'maxmind', label: 'MaxMind GeoLite2' },
                  { value: 'ip2location', label: 'IP2Location Lite' }
                ]}
              />
              {#if geoSettings.lookup_provider === 'maxmind'}
                <div class="mt-3">
                  <Input
                    label="License Key"
                    type="password"
                    bind:value={geoSettings.maxmind_license_key}
                    placeholder="Your MaxMind license key"
                    prefixIcon="key"
                    helperText="Free at maxmind.com/en/geolite2/signup"
                  />
                </div>
              {:else if geoSettings.lookup_provider === 'ip2location'}
                <div class="space-y-3 mt-3">
                  <Select
                    label="Database Variant"
                    bind:value={geoSettings.ip2location_variant}
                    options={geoProviders?.ip2location?.variants?.map(v => ({ value: v.id, label: `${v.name}` })) || [{ value: 'DB1', label: 'DB1 - Country' }]}
                  />
                  <Input
                    label="Download Token"
                    type="password"
                    bind:value={geoSettings.ip2location_token}
                    placeholder="Your IP2Location download token"
                    prefixIcon="key"
                    helperText="Required. Get at ip2location.com/register"
                  />
                </div>
              {/if}
              {#if geoStatus?.providers && geoSettings.lookup_provider !== 'none'}
                <div class="mt-3 p-2 bg-muted/50 rounded text-[10px]">
                  {#if geoStatus.providers[geoSettings.lookup_provider]?.available}
                    <div class="flex items-center gap-1 text-success">
                      <Icon name="check" size={12} />
                      <span>Database available ({(geoStatus.providers[geoSettings.lookup_provider].file_size / 1024 / 1024).toFixed(1)}MB)</span>
                    </div>
                    {#if geoStatus.providers[geoSettings.lookup_provider].last_update}
                      <div class="text-muted-foreground mt-1">Last updated: {geoStatus.providers[geoSettings.lookup_provider].last_update}</div>
                    {/if}
                  {:else}
                    <div class="flex items-center gap-1 text-warning">
                      <Icon name="alert-circle" size={12} />
                      <span>Database not downloaded yet. Save settings and click "Update Now".</span>
                    </div>
                  {/if}
                </div>
              {/if}
            </div>

            <!-- Toggles -->
            <div class="space-y-3">
              <ContentBlock variant="header" title="Options" />
              <ContentBlock title="Country Blocking" description="Block traffic using IPDeny zone files">
                <Checkbox variant="switch" bind:checked={geoSettings.blocking_enabled} />
              </ContentBlock>
              {#if !geoSettings.blocking_enabled}
                <div class="p-2 bg-info/10 border border-info/20 rounded text-[10px] text-muted-foreground">
                  <Icon name="info-circle" size={12} class="inline mr-1" />
                  Firewall country controls hidden when disabled.
                </div>
              {/if}
              <ContentBlock title="Auto-Update" description="Update databases daily">
                <Checkbox variant="switch" bind:checked={geoSettings.auto_update} />
              </ContentBlock>
              {#if geoSettings.auto_update}
                <div class="grid grid-cols-2 gap-3">
                  <Select
                    label="Update Time"
                    bind:value={geoSettings.update_hour}
                    options={Array.from({length: 24}, (_, i) => ({ value: i, label: `${i.toString().padStart(2, '0')}:00` }))}
                  />
                  <Select
                    label="Services"
                    bind:value={geoSettings.update_services}
                    options={[
                      { value: 'all', label: 'All services' },
                      { value: 'lookup', label: 'IP lookup only' },
                      { value: 'blocking', label: 'Country blocking only' }
                    ]}
                  />
                </div>
              {/if}
            </div>
          </div>

          {#if geoStatus?.last_update_lookup || geoStatus?.last_update_blocking}
            <div class="text-[10px] text-muted-foreground pt-3 border-t border-border">
              {#if geoStatus.last_update_lookup}
                <span>Lookup: {geoStatus.last_update_lookup}</span>
              {/if}
              {#if geoStatus.last_update_lookup && geoStatus.last_update_blocking}
                <span class="mx-2">·</span>
              {/if}
              {#if geoStatus.last_update_blocking}
                <span>Blocking: {geoStatus.last_update_blocking}</span>
              {/if}
            </div>
          {/if}
        </div>
      <div class="kt-panel-footer justify-between">
        <Button
          onclick={triggerGeoUpdate}
          loading={triggeringGeoUpdate}
          disabled={geoSettings.lookup_provider === 'none' && !geoSettings.blocking_enabled}
          variant="secondary"
          size="sm"
          icon="refresh"
          title={geoSettings.lookup_provider === 'none' && !geoSettings.blocking_enabled ? 'Select a provider or enable blocking first' : 'Update geolocation databases now'}
        >
          Update Now
        </Button>
        <Button
          onclick={saveGeoSettings}
          loading={savingGeo}
          disabled={!geoHasChanges}
          size="sm"
          icon="device-floppy"
        >
          Save
        </Button>
      </div>
    </div>

    <!-- About - Full width -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">
          <Icon name="info-circle" size={16} />
          About
        </h3>
      </div>
      <div class="kt-panel-body flex items-center justify-between !py-3">
        <div class="text-xs text-muted-foreground">
          <p class="font-medium text-foreground">Wire Panel</p>
          <p class="mt-0.5">Headscale + WireGuard management interface</p>
        </div>
        <div class="text-[10px] text-muted-foreground text-right">
          <p>Built with Svelte 5</p>
          <p>Tailwind CSS v4 + KTUI</p>
          <div class="flex items-center justify-end gap-3 mt-2">
            <a href="https://www.maxmind.com" target="_blank" rel="noopener noreferrer" class="text-muted-foreground hover:text-foreground transition-colors" data-kt-tooltip>
              <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
              <span data-kt-tooltip-content class="kt-tooltip hidden">MaxMind GeoLite2</span>
            </a>
            <a href="https://www.ip2location.com" target="_blank" rel="noopener noreferrer" class="text-muted-foreground hover:text-foreground transition-colors" data-kt-tooltip>
              <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/><circle cx="12" cy="10" r="3"/></svg>
              <span data-kt-tooltip-content class="kt-tooltip hidden">IP2Location Lite</span>
            </a>
            <a href="https://www.ipdeny.com" target="_blank" rel="noopener noreferrer" class="text-muted-foreground hover:text-foreground transition-colors" data-kt-tooltip>
              <svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="8" y1="8" x2="16" y2="16"/><line x1="16" y1="8" x2="8" y2="16"/></svg>
              <span data-kt-tooltip-content class="kt-tooltip hidden">IPDeny Zone Files</span>
            </a>
          </div>
        </div>
      </div>
    </div>
  {/if}
</div>

<!-- Create/Edit Jail Modal -->
<Modal bind:open={showJailModal} title={jailForm.id ? 'Edit Jail' : 'Create Jail'} size="md">
  <div class="space-y-4">
    <div class="grid grid-cols-2 gap-4">
      <Input
        label="Name"
        bind:value={jailForm.name}
        placeholder="e.g. sshd, portscan"
        disabled={!!jailForm.id}
      />
      <Select label="Status" bind:value={jailForm.enabled}>
        <option value={true}>Enabled</option>
        <option value={false}>Disabled</option>
      </Select>
    </div>

    <Input
      label="Log File"
      bind:value={jailForm.logFile}
      placeholder="/var/log/auth.log"
    />

    <Input
      label="Filter Regex"
      bind:value={jailForm.filterRegex}
      placeholder="e.g. Failed password.*from (\d+\.\d+\.\d+\.\d+)"
      class="font-mono"
      helperText="Must contain at least one capture group for the IP address"
    />

    <div class="grid grid-cols-3 gap-4">
      <Input
        label="Max Retry"
        type="number"
        bind:value={jailForm.maxRetry}
        min="1"
        max="100"
      />
      <Select label="Find Time" bind:value={jailForm.findTime}>
        <option value={300}>5 minutes</option>
        <option value={600}>10 minutes</option>
        <option value={1800}>30 minutes</option>
        <option value={3600}>1 hour</option>
        <option value={7200}>2 hours</option>
        <option value={86400}>24 hours</option>
      </Select>
      <Select label="Ban Time" bind:value={jailForm.banTime}>
        <option value={3600}>1 hour</option>
        <option value={86400}>1 day</option>
        <option value={604800}>7 days</option>
        <option value={2592000}>30 days</option>
        <option value={31536000}>1 year</option>
        <option value={-1}>Permanent</option>
      </Select>
    </div>

    <div class="grid grid-cols-2 gap-4">
      <Input
        label="Port"
        bind:value={jailForm.port}
        placeholder="all or specific port"
      />
      <Select label="Action" bind:value={jailForm.action}>
        <option value="drop">Drop</option>
        <option value="reject">Reject</option>
      </Select>
    </div>

    <!-- Auto-Escalation Settings -->
    <div class="border-t border-border pt-4 mt-4">
      <div class="flex items-center justify-between mb-3">
        <div>
          <span class="kt-label mb-0">Auto-Escalation</span>
          <p class="text-xs text-muted-foreground">Automatically block entire /24 range when threshold IPs are blocked</p>
        </div>
        <Checkbox variant="switch" bind:checked={jailForm.escalateEnabled} />
      </div>

      {#if jailForm.escalateEnabled}
        <div class="grid grid-cols-2 gap-4 p-3 bg-muted/50 rounded-lg">
          <Input
            label="IP Threshold"
            type="number"
            bind:value={jailForm.escalateThreshold}
            min="2"
            max="20"
            helperText="Block /24 when this many IPs blocked"
          />
          <Select label="Time Window" bind:value={jailForm.escalateWindow}>
            <option value={1800}>30 minutes</option>
            <option value={3600}>1 hour</option>
            <option value={7200}>2 hours</option>
            <option value={14400}>4 hours</option>
            <option value={86400}>24 hours</option>
          </Select>
        </div>
      {/if}
    </div>
  </div>

  {#snippet footer()}
    <Button onclick={() => showJailModal = false} variant="secondary" disabled={savingJail}>
      Cancel
    </Button>
    <Button onclick={saveJail} icon={jailForm.id ? 'check' : 'plus'} disabled={savingJail}>
      {savingJail ? 'Saving...' : (jailForm.id ? 'Save Changes' : 'Create Jail')}
    </Button>
  {/snippet}
</Modal>

<!-- Change SSH Port Modal -->
<Modal bind:open={showSSHModal} title="Change SSH Port" size="sm">
  <div class="space-y-4">
    <div class="kt-alert kt-alert-warning">
      <Icon name="alert-triangle" size={18} />
      <div>
        <strong>This will change your SSH port.</strong>
        Ensure you can access the server on the new port before closing your session.
      </div>
    </div>

    <div class="flex gap-3">
      <div class="flex-1">
        <Input
          label="Current Port"
          value={sshPort}
          prefixIcon="key"
          size="default"
          class="font-mono"
          readonly
          disabled
        />
      </div>
      <div class="flex-1">
        <Input
          label="New Port"
          type="number"
          bind:value={newSSHPort}
          prefixIcon="key"
          size="default"
          class="font-mono"
          placeholder="2222"
          min="1"
          max="65535"
        />
      </div>
    </div>

    <p class="text-xs text-muted-foreground">
      Common ports: 2222, 2022, 22022
    </p>
  </div>

  {#snippet footer()}
    <Button onclick={() => showSSHModal = false} variant="secondary" disabled={changingSSH}>
      Cancel
    </Button>
    <Button onclick={changeSSHPort} icon="key" disabled={changingSSH || !newSSHPort || parseInt(newSSHPort) === sshPort}>
      {changingSSH ? 'Changing...' : 'Change Port'}
    </Button>
  {/snippet}
</Modal>
