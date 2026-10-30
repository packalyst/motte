<script>
  import { onMount } from 'svelte'
  import { theme, toast, apiGet, apiPost, apiPut, apiDelete, apiPostBlob, generateAdguardCredentials, confirm, stepUpConfirm, withStepUp, STEPUP_CANCELLED, hashParam, setHashParam, currentUser, hasRole } from '../stores/app.js'
  import { withTz, setDisplayTimezone, formatBanTime, formatNumber } from '../lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'
  import Badge from '../components/Badge.svelte'
  import Segmented from '../components/Segmented.svelte'
  import SegmentedAction from '../components/SegmentedAction.svelte'
  import TileRow from '../components/TileRow.svelte'
  import Select from '../components/Select.svelte'
  import SearchableSelect from '../components/SearchableSelect.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import SectionNav from '../components/SectionNav.svelte'
  import AgentListener from '../components/AgentListener.svelte'
  import NetworkList from '../components/NetworkList.svelte'
  import TeamSettings from '../components/TeamSettings.svelte'
  import TraefikOverview from '../components/TraefikOverview.svelte'
  import DockerSettings from '../components/DockerSettings.svelte'

  // Left-menu sections; the open one is kept in the URL (#s=…) so a refresh or link lands on it.
  // Team is admin-only (the server enforces it too).
  const ALL_SECTIONS = [
    { id: 'general', label: 'General', icon: 'settings', description: 'Your preferences, the mail server, log collection and version information.' },
    { id: 'team', label: 'Team', icon: 'users', description: "Accounts that can sign in to this panel. Roles set what each may do; owner is the break-glass role and can't be the last one removed.", minRole: 'admin' },
    { id: 'headscale', label: 'Headscale', icon: 'server', description: 'The Headscale connection Tailscale clients use, and the VPN router.' },
    { id: 'agents', label: 'Agents', icon: 'device-desktop', description: 'The listener that machine agents connect to.' },
    { id: 'certificates', label: 'Certificates', icon: 'certificate', description: 'Every certificate the panel depends on: when each expires, and what needs attention.', minRole: 'admin' },
    { id: 'networks', label: 'Networks', icon: 'router', description: 'Private networks the panel serves as gateway and DHCP server.' },
    { id: 'firewall', label: 'Firewall', icon: 'wall', description: 'Open ports, the port scanner and intrusion-detection jails.' },
    { id: 'web', label: 'Web access', icon: 'world-www', description: 'Traefik settings and what it is routing right now, plus geolocation, country blocking and DNS.' },
    { id: 'docker', label: 'Docker', icon: 'box', description: 'The panel\'s containers: restart services, view logs and check their health.' },
    { id: 'backups', label: 'Backups', icon: 'database', description: 'Encrypted export and restore, and automatic off-host copies.' },
  ]
  // How many certificates need attention: shown on the Certificates menu item (admins only).
  let certAttention = $state(0)
  const SECTIONS = $derived(ALL_SECTIONS.filter((x) => !x.minRole || hasRole($currentUser, x.minRole))
    .map((x) => (x.id === 'certificates' && certAttention ? { ...x, badge: certAttention } : x)))
  // Sections that were merged into another one: old links land on the new home.
  const MERGED = { logs: 'general', geo: 'web', email: 'general', dns: 'web' }
  const initial = MERGED[hashParam('s')] || hashParam('s')
  let section = $state(ALL_SECTIONS.some((x) => x.id === initial) ? initial : 'general')
  const current = $derived(SECTIONS.find((x) => x.id === section) || SECTIONS[0])
  function go(id) {
    section = id
    setHashParam('s', id === 'general' ? null : id)
  }
  import ContentBlock from '../components/ContentBlock.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import Modal from '../components/Modal.svelte'
  import OffhostBackup from '../components/OffhostBackup.svelte'
  import Certificates from '../components/Certificates.svelte'
  import CertLifetime from '../components/CertLifetime.svelte'
  import AllowedPorts from '../components/AllowedPorts.svelte'
  import SmtpSettings from '../components/SmtpSettings.svelte'

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
  // The VPN ranges: always in the allow-list, shown locked (the server refuses to drop them anyway)
  let lockedRanges = $state([])

  // VPN-only mode: "off", "403", or "silent"
  let vpnOnlyMode = $state('off')
  let vpnOnlyLoading = $state(false)

  // L7 firewall-block enforcement (apply the firewall block list to proxied/Cloudflare traffic)
  let fwBlockEnabled = $state(true)
  let fwBlockLoading = $state(false)

  // Panel direct-IP access (L3 nftables). On = API port reachable by IP; off = closed to
  // the public internet (still open to localhost, the Docker bridge/Traefik and WireGuard).
  let webCloudflareOnly = $state(false)
  let webCloudflareOnlyAvailable = $state(false)
  let cfOnlyLoading = $state(false)

  // Session settings
  let sessionTimeout = $state('24')
  let sessionChoices = $state([]) // the sign-in lengths the server accepts, in hours
  let idleChoices = $state([]) // and the idle-lock minutes (0 = off)
  // a length's name: "8 hours" up to a day, then "7 days"
  const hoursLabel = (h) => (h < 48 ? `${h} hour${h === 1 ? '' : 's'}` : `${h / 24} days`)
  const idleLabel = (m) => (m === 0 ? 'Disabled' : `After ${m < 60 ? `${m} min` : hoursLabel(m / 60)}`)
  let idleLock = $state('0') // minutes of inactivity before the UI locks; '0' = disabled
  let metricsRetention = $state('90')
  let displayTimezone = $state('browser')
  let sessionChanged = $state(false)

  // Timezone options: "Browser" (automatic) + the full IANA list where supported.
  const TZ_OPTIONS = (() => {
    let zones
    try { zones = Intl.supportedValuesOf('timeZone') } catch { zones = ['UTC', 'Europe/London', 'Europe/Bucharest', 'America/New_York', 'America/Los_Angeles', 'Asia/Tokyo'] }
    return [{ value: 'browser', label: 'Browser (automatic)' }, ...zones.map((z) => ({ value: z, label: z }))]
  })()

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
    ip2location_variant: 'DB1',
    ip2proxy_variant: '12',
    asn_enabled: false,
    proxy_enabled: false
  })
  let geoStatus = $state(null)
  let geoProviders = $state(null)  // Provider configs from API
  let enrichment = $state(null)    // ASN + proxy DB status

  async function loadEnrichment() {
    try { enrichment = await apiGet('/api/geo/enrichment') } catch { enrichment = null }
  }
  let savingGeo = $state(false)
  let originalGeoSettings = $state(null)
  let triggeringGeoUpdate = $state(false)

  // Jails settings
  let jails = $state([])
  let showJailModal = $state(false)
  let savingJail = $state(false)

  // Ports settings

  // SSH port settings
  let sshPort = $state(22)
  let showSSHModal = $state(false)
  let newSSHPort = $state('')
  let changingSSH = $state(false)
  let logFileOptions = $state([]) // candidate log files for the jail picker (from /api/fw/log-files)
  let logFileCustom = $state(false) // jail form: user is typing a custom log path
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
    escalateWindow: 3600,
    escalateAsn: false,
    escalateAsnThreshold: 15,
    escalateAsnWindow: 3600
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

      // L7 firewall-block enforcement (default on)
      try {
        const fw = await apiGet('/api/traefik/fw-block')
        fwBlockEnabled = fw?.enabled !== false
      } catch { fwBlockEnabled = true }

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

      // Panel direct-IP access
      webCloudflareOnly = settings.web_cloudflare_only === true
      webCloudflareOnlyAvailable = settings.web_cloudflare_only_available === true

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
        lockedRanges = traefikConfig.lockedRanges || []
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
      sessionChoices = settings.session_timeout_choices || []
      idleChoices = settings.idle_lock_choices || []
      idleLock = String(settings.idle_lock_minutes ?? 0)
      metricsRetention = String(settings.metrics_retention_days || 90)
      displayTimezone = settings.display_timezone || 'browser'
      setDisplayTimezone(displayTimezone)
      originalSession = { timeout: sessionTimeout, idleLock, retention: metricsRetention, timezone: displayTimezone }

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
          ip2location_variant: settings.geo.ip2location_variant || 'DB1',
          ip2proxy_variant: settings.geo.ip2proxy_variant || '12',
          asn_enabled: settings.geo.asn_enabled || false,
          proxy_enabled: settings.geo.proxy_enabled || false
        }
        originalGeoSettings = { ...geoSettings }
        geoProviders = settings.geo.providers || null
      }
      if (settings.geo_status) {
        geoStatus = settings.geo_status
      }
      loadEnrichment()

      // UI (from localStorage)
      itemsPerPage = localStorage.getItem('settings_items_per_page') || '25'

      // Load independent resources in parallel - each can fail without blocking others
      const [watcherRes, jailsRes, fwStatusRes, logFilesRes] = await Promise.allSettled([
        apiGet('/api/logs/status'),
        apiGet('/api/fw/jails'),
        apiGet('/api/fw/status'),
        apiGet('/api/fw/log-files')
      ])

      if (watcherRes.status === 'fulfilled') watcherStatuses = watcherRes.value
      if (jailsRes.status === 'fulfilled') jails = jailsRes.value.jails || jailsRes.value || []
      if (fwStatusRes.status === 'fulfilled' && fwStatusRes.value?.sshPort) sshPort = fwStatusRes.value.sshPort
      if (logFilesRes.status === 'fulfilled') logFileOptions = logFilesRes.value.files || []
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
    sessionChanged = sessionTimeout !== originalSession.timeout || idleLock !== originalSession.idleLock || metricsRetention !== originalSession.retention || displayTimezone !== originalSession.timezone
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
      const res = await withStepUp((extra) => apiPost('/api/setup/generate-apikey', { ...extra }),
        { title: 'Regenerate the Headscale API key', message: 'Confirm your password to issue a new key.', confirmText: 'Regenerate' })
      if (res === STEPUP_CANCELLED) return
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
        session_timeout: sessionTimeout,
        idle_lock_minutes: parseInt(idleLock, 10),
        metrics_retention_days: parseInt(metricsRetention, 10),
        display_timezone: displayTimezone
      })
      setDisplayTimezone(displayTimezone)
      originalSession = { timeout: sessionTimeout, idleLock, retention: metricsRetention, timezone: displayTimezone }
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
      // A new trusted network asks for the password (the server answers 428).
      const res = await withStepUp((extra) => apiPut('/api/traefik/config', {
        rateLimitAverage: traefikForm.rateLimitAverage,
        rateLimitBurst: traefikForm.rateLimitBurst,
        strictRateAverage: traefikForm.strictRateAverage,
        strictRateBurst: traefikForm.strictRateBurst,
        ipAllowlist: traefikForm.ipAllowlist,
        dashboardEnabled: traefikForm.dashboardEnabled,
        ...extra
      }), { title: 'Add a trusted network', message: 'Confirm your password to let a new network past the VPN-only and Cloudflare-only gates.', confirmText: 'Save' })
      if (res === STEPUP_CANCELLED) return
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
      loadEnrichment()
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
      loadEnrichment()
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
      const res = await withStepUp((extra) => apiDelete('/api/vpn/router', extra),
        { title: 'Remove VPN router', message: 'Headscale clients lose the routes it advertises.', confirmText: 'Remove', variant: 'destructive' })
      if (res === STEPUP_CANCELLED) return
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
      // Switching it off asks for the password (the server answers 428).
      const res = await withStepUp((extra) => apiPost('/api/traefik/vpn-only', { mode, ...extra }),
        { title: 'Turn VPN-only off', message: 'The panel will be reachable from the internet. Confirm your password.', confirmText: 'Turn off', variant: 'destructive' })
      if (res === STEPUP_CANCELLED) return
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

  // Toggle L7 firewall-block enforcement
  async function setFWBlock(enabled) {
    fwBlockLoading = true
    try {
      await apiPost('/api/traefik/fw-block', { enabled })
      fwBlockEnabled = enabled
      toast(enabled ? 'Firewall enforcement enabled on proxied traffic' : 'Firewall enforcement disabled on proxied traffic', 'success')
    } catch (e) {
      fwBlockEnabled = !enabled // revert the switch
      toast('Failed to update firewall enforcement: ' + e.message, 'error')
    } finally {
      fwBlockLoading = false
    }
  }

  async function setWebCloudflareOnly(enabled) {
    // Restricting the web ports to Cloudflare can cut off all web access — confirm, and be explicit.
    if (enabled) {
      const ok = await confirm({
        title: 'Restrict web ports to Cloudflare?',
        message: 'HTTPS (443) will be dropped at the firewall for any source that is not Cloudflare, and on HTTP (80) they get no answer — localhost, Traefik and the VPNs still work, and Let\'s Encrypt can still renew certificates. Your domain must be proxied through Cloudflare (orange cloud), or visitors will be blocked. Continue?',
        confirmText: 'Restrict to Cloudflare', variant: 'danger',
      })
      if (!ok) { webCloudflareOnly = false; return } // revert the switch
    }
    cfOnlyLoading = true
    try {
      await apiPut('/api/settings', { web_cloudflare_only: enabled })
      webCloudflareOnly = enabled
      toast(enabled ? 'Web ports now restricted to Cloudflare' : 'Cloudflare-only web access disabled — web ports open to all', 'success')
    } catch (e) {
      webCloudflareOnly = !enabled // revert on failure (e.g. no SSL domain configured)
      toast(e.message || 'Failed to update Cloudflare-only web access', 'error')
    } finally {
      cfOnlyLoading = false
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
      escalateWindow: 3600,
      escalateAsn: false,
      escalateAsnThreshold: 15,
      escalateAsnWindow: 3600
    }
    logFileCustom = false // default /var/log/auth.log is a listed option
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
      escalateWindow: jail.escalateWindow || 3600,
      escalateAsn: jail.escalateAsn || false,
      escalateAsnThreshold: jail.escalateAsnThreshold || 15,
      escalateAsnWindow: jail.escalateAsnWindow || 3600
    }
    // Custom-input mode when the jail's log path isn't one of the discovered files.
    logFileCustom = !logFileOptions.some(f => f.path === jail.logFile)
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
        escalateWindow: parseInt(jailForm.escalateWindow) || 3600,
        escalateAsn: jailForm.escalateAsn,
        escalateAsnThreshold: parseInt(jailForm.escalateAsnThreshold) || 15,
        escalateAsnWindow: parseInt(jailForm.escalateAsnWindow) || 3600
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
    // confirm() is async and takes an options object — a bare `if (!confirm('...'))` never
    // returns (a Promise is always truthy), so it would delete without ever asking.
    const confirmed = await confirm({
      title: 'Delete jail',
      message: `Delete jail "${jail.name}"?`,
      description: 'Its ban rules will be removed.',
      confirmText: 'Delete'
    })
    if (!confirmed) return
    try {
      await apiDelete(`/api/fw/jails/${jail.name}`)
      toast(`Jail "${jail.name}" deleted`, 'success')
      jails = jails.filter(j => j.id !== jail.id)
    } catch (e) {
      toast('Failed to delete jail: ' + e.message, 'error')
    }
  }

  // toggleJail starts or stops a jail. Stopping lowers protection (its IPs aren't banned any more
  // until it's back on), so that direction asks first.
  async function toggleJail(jail) {
    if (jail.enabled) {
      const ok = await confirm({
        title: `Turn off jail "${jail.name}"?`,
        message: 'It stops banning IPs until you turn it back on.',
        description: 'IPs it already banned stay banned until their ban ends.',
        confirmText: 'Turn off',
        variant: 'destructive',
      })
      if (!ok) return
    }
    try {
      await apiPut(`/api/fw/jails/${jail.name}`, { ...jail, enabled: !jail.enabled })
      jails = jails.map(j => j.id === jail.id ? { ...j, enabled: !j.enabled } : j)
      toast(`Jail "${jail.name}" ${!jail.enabled ? 'enabled' : 'disabled'}`, 'success')
    } catch (e) {
      toast('Failed to toggle jail: ' + e.message, 'error')
    }
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
      const res = await withStepUp((extra) => apiPost('/api/fw/ssh', { port, ...extra }),
        { title: 'Change SSH port', message: `SSH moves to port ${port}; the old port closes once SSH answers on the new one.`, confirmText: 'Change port' })
      if (res === STEPUP_CANCELLED) return
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

  // ── Backup & migrate ────────────────────────────────────────────────────────
  // Export: a passphrase-encrypted file carrying the panel config (+ opt-in tiers).
  let bkPass = $state('')
  let bkPass2 = $state('')
  let bkUsers = $state(false)
  let bkFleet = $state(false)
  let bkExporting = $state(false)
  let bkGenerated = $state('')   // last generated passphrase, shown once so it can be saved

  // generateBackupPassphrase fills both fields with a strong random passphrase (client-side,
  // never sent anywhere) so the backup — which seals every secret — isn't protected by a weak
  // human-chosen phrase. 24 chars from a 65-char set ≈ 140+ bits.
  function generateBackupPassphrase() {
    const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*'
    const buf = new Uint32Array(24)
    crypto.getRandomValues(buf)
    let out = ''
    for (let i = 0; i < buf.length; i++) out += charset[buf[i] % charset.length]
    bkPass = out
    bkPass2 = out
    bkGenerated = out
    navigator.clipboard?.writeText(out).catch(() => {})
    toast('Strong passphrase generated & copied — save it now; the backup is unrecoverable without it', 'success')
  }

  async function exportBackup() {
    if (bkPass.length < 16) return toast('Passphrase must be at least 16 characters', 'error')
    if (bkPass !== bkPass2) return toast('Passphrases do not match', 'error')
    const su = await stepUpConfirm({ title: 'Export backup', description: 'A backup can contain decrypted secrets (incl. 2FA seeds). Re-authenticate to export.' })
    if (!su?.confirmed) return
    bkExporting = true
    try {
      const { blob, filename } = await apiPostBlob('/api/backup/export', { passphrase: bkPass, users: bkUsers, fleet: bkFleet, currentPassword: su.password, totpCode: su.totp })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      toast('Backup downloaded — keep it and its passphrase safe', 'success')
      bkPass = ''
      bkPass2 = ''
      bkGenerated = ''
    } catch (e) {
      toast(e.message || 'Export failed', 'error')
    } finally {
      bkExporting = false
    }
  }

  // Import: read the file locally, preview what it would replace, then apply.
  let impFileText = $state('')
  let impFileName = $state('')
  let impPass = $state('')
  let impPreview = $state(null)
  let impLoading = $state(false)
  let impApplying = $state(false)

  function onImportFile(e) {
    const f = e.target.files?.[0]
    if (!f) return
    impFileName = f.name
    impPreview = null
    const reader = new FileReader()
    reader.onload = () => (impFileText = String(reader.result || ''))
    reader.readAsText(f)
  }

  async function previewImport() {
    if (!impFileText) return toast('Choose a backup file', 'error')
    if (!impPass) return toast('Enter the backup passphrase', 'error')
    impLoading = true
    try {
      impPreview = await apiPost('/api/backup/preview', { passphrase: impPass, backup: impFileText })
    } catch (e) {
      impPreview = null
      toast(e.message || 'Could not read backup', 'error')
    } finally {
      impLoading = false
    }
  }

  async function applyImport() {
    const ok = await confirm({
      title: 'Replace config from backup',
      message: 'This wipes and reloads the listed tables on THIS panel from the backup, then re-applies firewall / WireGuard / ACL state. It cannot be undone.',
      description: (impPreview?.warnings || []).join(' '),
      confirmText: 'Replace & reconcile',
      variant: 'destructive',
      alert: true,
    })
    if (!ok) return
    const su = await stepUpConfirm({ title: 'Replace config from backup', description: 'Importing replaces admin users and panel config. Re-authenticate to apply.' })
    if (!su?.confirmed) return
    impApplying = true
    try {
      const res = await apiPost('/api/backup/import', { passphrase: impPass, backup: impFileText, confirm: true, currentPassword: su.password, totpCode: su.totp })
      toast('Backup applied' + (res.reconciled?.length ? ' — reconciled ' + res.reconciled.join(', ') : ''), 'success')
      impPreview = null
      impFileText = ''
      impFileName = ''
      impPass = ''
      // Replacing admin users invalidates this session — reload into the login flow.
      setTimeout(() => location.reload(), 900)
    } catch (e) {
      toast(e.message || 'Import failed', 'error')
    } finally {
      impApplying = false
    }
  }

  onMount(() => {
    loadSettings()
    // the Certificates section loads this itself when it's the one open
    if (hasRole($currentUser, 'admin') && section !== 'certificates') {
      apiGet('/api/certs').then((o) => (certAttention = o.attention)).catch(() => {})
    }
  })
</script>

<div>
  {#if loading}
    <LoadingSpinner centered size="lg" />
  {:else}
    <div class="flex flex-col gap-4 lg:min-h-[calc(100dvh-8rem)] lg:flex-row">
      <SectionNav items={SECTIONS} active={section} onselect={go} label="Settings sections" mobile="bottom" />
      <div class="min-w-0 flex-1 space-y-4">
      <InfoCard icon={current.icon} title={current.label} description={current.description} />
      {#if section === 'team'}
        <TeamSettings />
      {/if}
      {#if section === 'general'}
      <div class="space-y-4">
      <!-- Session & Interface Settings -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-icon text-primary"><Icon name="settings" size={17} /></span>
          <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Preferences</div>
        </div>
        <div class="space-y-3">
          <div class="grid grid-cols-2 gap-3">
            <Select
              label="Session Timeout"
              helperText="How long a sign-in lasts before you have to sign in again."
              bind:value={sessionTimeout}
              options={sessionChoices.map((h) => ({ value: String(h), label: hoursLabel(h) }))}
            />
            <Select
              label="Idle lock"
              helperText="Locks the screen for everyone after this long without activity; re-entering the password (and 2FA code) unlocks it."
              bind:value={idleLock}
              options={idleChoices.map((m) => ({ value: String(m), label: idleLabel(m) }))}
            />
            <Select
              label="Items per page"
              helperText="Rows per page in paged lists such as Logs. Applies at once."
              bind:value={itemsPerPage}
              onchange={saveUISettings}
              options={[
                { value: '10', label: '10' },
                { value: '25', label: '25' },
                { value: '50', label: '50' },
                { value: '100', label: '100' }
              ]}
            />
            <Select
              label="Analytics retention"
              helperText="How long analytics history and fleet/firewall metrics are kept. Lowering it prunes older data on save."
              bind:value={metricsRetention}
              options={[
                { value: '30', label: '30 days' },
                { value: '60', label: '60 days' },
                { value: '90', label: '90 days' },
                { value: '180', label: '180 days' },
                { value: '365', label: '1 year' }
              ]}
            />
            <SearchableSelect
              label="Timezone"
              helperText="How dates and times are shown across the panel. “Browser” uses each viewer's own zone."
              bind:value={displayTimezone}
              onchange={() => setDisplayTimezone(displayTimezone)}
              options={TZ_OPTIONS}
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
        <div class="panel-foot">
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
      </div>
      {/if}
      {#if section === 'headscale'}
      <div class="space-y-4">
      <!-- Headscale Settings -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-icon text-primary"><Icon name="server" size={17} /></span>
          <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Headscale</div>
        </div>
        <div class="space-y-3">
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
                <span class="flex-1"></span>
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
        <div class="panel-foot">
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
      <!-- Cross-Network Router -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-icon text-primary"><Icon name="route" size={17} /></span>
          <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Cross-Network Router</div>
          {#if routerStatus?.status === 'running'}
            <Badge variant="success" size="sm">Running</Badge>
          {:else if routerStatus?.status === 'starting'}
            <Badge variant="warning" size="sm">Starting</Badge>
          {:else}
            <Badge variant="muted" size="sm">Disabled</Badge>
          {/if}
        </div>
        <div class="space-y-3">
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
        <div class="panel-foot">
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
      </div>
      {/if}
      {#if section === 'agents'}
      <div class="space-y-4">
      <AgentListener>
        {#if hasRole($currentUser, 'admin')}<CertLifetime />{/if}
      </AgentListener>
      </div>
      {/if}
      {#if section === 'certificates'}
      <div class="space-y-4">
      <Certificates onload={(o) => (certAttention = o.attention)} />
      </div>
      {/if}
      {#if section === 'networks'}
      <div class="space-y-4">
      <NetworkList />
      </div>
      {/if}
      {#if section === 'firewall'}
      <div class="space-y-4">
      <!-- Port Scanner Settings -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-icon text-primary"><Icon name="scan" size={17} /></span>
          <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Port Scanner</div>
        </div>
        <div class="space-y-3">
          <p class="text-[10px] text-muted-foreground">
            Default settings for scanning VPN client ports in Domain Routes.
          </p>
          <div class="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
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
        <div class="panel-foot">
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
      <!-- Jails (Intrusion Detection) -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-icon text-primary"><Icon name="shield-lock" size={17} /></span>
          <div class="min-w-0 flex-1">
            <div class="panel-title">Jails</div>
            <div class="panel-sub">intrusion detection: block IPs that keep failing, from log patterns</div>
          </div>
          <div class="kt-btn-group">
            <Button onclick={openSSHModal} variant="outline" icon="key">
              SSH: {sshPort}
            </Button>
            <Button onclick={openCreateJail} variant="outline" icon="plus">
              Add Jail
            </Button>
          </div>
        </div>
        <div>
          {#if jails.length > 0}
            <ul class="grid grid-cols-1 gap-2 lg:grid-cols-2">
              {#each jails as jail (jail.id)}
                {@const banned = jail.currentlyBanned || 0}
                <TileRow value={formatNumber(banned)} unit="banned" hint="{banned.toLocaleString()} banned" tone={!jail.enabled ? 'muted' : banned ? 'destructive' : 'success'} dim={!jail.enabled}
                  title={jail.name.charAt(0).toUpperCase() + jail.name.slice(1)} subIcon="clock"
                  sub="{jail.maxRetry} tries in {formatBanTime(jail.findTime)} → ban {formatBanTime(jail.banTime)}">
                  {#snippet actions()}
                    <SegmentedAction icon="edit" tooltip="Edit" label="Edit {jail.name}" onclick={() => openEditJail(jail)} />
                    <SegmentedAction icon="trash" tooltip="Delete" label="Delete {jail.name}" danger onclick={() => deleteJail(jail)} />
                  {/snippet}
                  <Segmented size="sm" class="shrink-0" label="Jail {jail.name}" value={jail.enabled ? 'on' : 'off'} onchange={() => toggleJail(jail)} trailing={actions}
                    options={[{ value: 'on', label: 'On', tone: 'success' }, { value: 'off', label: 'Off' }]} />
                </TileRow>
              {/each}
            </ul>
          {:else}
            <p class="text-xs text-muted-foreground italic">No jails configured</p>
          {/if}
        </div>
      </div>
      <AllowedPorts />
      </div>
      {/if}
      {#if section === 'web'}
      <div class="space-y-4">
      <!-- Traefik Settings - Full width -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-icon text-primary"><Icon name="route" size={17} /></span>
          <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Traefik</div>
        </div>
        <div class="space-y-4">
          <!-- Rate Limiting -->
          <div>
            <ContentBlock variant="header" title="Rate Limiting" description="Standard: for your sites that use the rate-limit middleware. Strict: the Headscale API and the agent installer. The panel itself limits each visitor on its own." />
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
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

          <!-- Access Control: two columns so the switches fill the width -->
          <div>
            <ContentBlock variant="header" title="Access Control" />
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-3">
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
            <div class="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-3 mt-3">
              <ContentBlock title="Enforce Firewall on Proxied Traffic" description="Apply the firewall block list at the proxy, so blocks work behind Cloudflare too">
                <div class="flex items-center gap-2">
                  {#if fwBlockLoading}
                    <span class="w-3 h-3 border-2 border-primary border-t-transparent rounded-full animate-spin"></span>
                  {/if}
                  <Checkbox variant="switch" bind:checked={fwBlockEnabled} disabled={fwBlockLoading} onchange={() => setFWBlock(fwBlockEnabled)} />
                </div>
              </ContentBlock>
              <ContentBlock title="Cloudflare-Only Web Access" description={webCloudflareOnlyAvailable ? "Allow only Cloudflare to reach the web ports. Blocks anyone hitting the raw server IP to bypass Cloudflare (localhost, Traefik and the VPNs still work); Let's Encrypt can still renew certificates." : 'Available only when your domain is proxied through Cloudflare (set at setup).'}>
                <div class="flex items-center gap-2">
                  {#if cfOnlyLoading}
                    <span class="w-3 h-3 border-2 border-primary border-t-transparent rounded-full animate-spin"></span>
                  {/if}
                  <Checkbox variant="switch" bind:checked={webCloudflareOnly} disabled={cfOnlyLoading || (!webCloudflareOnlyAvailable && !webCloudflareOnly)} onchange={() => setWebCloudflareOnly(webCloudflareOnly)} />
                </div>
              </ContentBlock>
            </div>
          </div>

          <!-- IP Allowlist - Full width -->
          <div class="border-t border-border pt-3">
            <h4 class="text-xs font-medium text-foreground mb-0.5">Sentinel VPN Middleware</h4>
            <p class="text-[10px] text-muted-foreground mb-2">Who can open the panel in VPN-only mode. Also never auto-banned. The VPN ranges are always included.</p>
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
                    {#if lockedRanges.includes(ip)}
                      <span class="p-0.5 text-muted-foreground" title="VPN range, always included" aria-label="{ip} is a VPN range, always included"><Icon name="lock" size={12} /></span>
                    {:else}
                      <button type="button" onclick={() => removeTraefikIP(ip)} class="p-0.5 hover:text-destructive cursor-pointer" title="Remove" aria-label="Remove {ip}"><Icon name="x" size={12} /></button>
                    {/if}
                  </div>
                {/each}
              </div>
            {:else}
              <p class="text-[10px] text-muted-foreground italic pt-2">No IP ranges configured</p>
            {/if}
          </div>
        </div>
        <div class="panel-foot justify-end">
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
      </div>
      {/if}
      {#if section === 'general' && hasRole($currentUser, 'admin')}
      <!-- Email (SMTP) for alerts, admin-only like its API. Per-user alert RULES live in Profile → Notifications. -->
      <SmtpSettings />
      {/if}
      {#if section === 'general'}
      <div class="space-y-4">
      <!-- Logs Watchers -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-icon text-primary"><Icon name="file-text" size={17} /></span>
          <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Log Watchers</div>
        </div>
        <div class="space-y-3">
          <p class="text-[10px] text-muted-foreground mb-3">
            Enable or disable log collection from various sources.
          </p>
          {#if watcherStatuses.length > 0}
            <div class="grid grid-cols-1 gap-2 lg:grid-cols-2">
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
      </div>
      {/if}
      {#if section === 'general'}
      <div class="space-y-4">
      <!-- About - Full width -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-icon text-primary"><Icon name="info-circle" size={17} /></span>
          <div class="min-w-0 flex-1 panel-title flex items-center gap-2">About</div>
        </div>
        <div class="flex items-center justify-between">
          <div class="text-xs text-muted-foreground">
            <p class="font-medium text-foreground">Motte</p>
            <p class="mt-0.5">Your infrastructure. Your stronghold.</p>
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
      </div>
      {/if}
      {#if section === 'web'}
      <div class="space-y-4">
      <!-- Geolocation Settings - Full width -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-icon text-primary"><Icon name="world" size={17} /></span>
          <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Geolocation</div>
        </div>
        <div class="space-y-3">
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
                  <!-- Owner (ASN) enrichment toggle — sits under the Download Token -->
                  <ContentBlock title="Owner (ASN)" description="Who owns each IP" class="mt-3">
                    <Checkbox variant="switch" bind:checked={geoSettings.asn_enabled} />
                  </ContentBlock>
                {/if}

                <!-- All database statuses in one place -->
                {#if geoSettings.lookup_provider !== 'none'}
                  <div class="mt-3 p-2 bg-muted/50 rounded text-[10px] space-y-1">
                    <div class="font-medium text-muted-foreground uppercase tracking-wide">Databases</div>
                    <div class="flex items-center justify-between gap-2">
                      <span>Country</span>
                      {#if geoStatus?.providers?.[geoSettings.lookup_provider]?.available}
                        <span class="text-success">{(geoStatus.providers[geoSettings.lookup_provider].file_size / 1024 / 1024).toFixed(1)}MB{#if geoStatus.providers[geoSettings.lookup_provider].last_update} · {geoStatus.providers[geoSettings.lookup_provider].last_update}{/if}</span>
                      {:else}
                        <span class="text-warning">not downloaded</span>
                      {/if}
                    </div>
                    {#if geoSettings.lookup_provider === 'ip2location' && geoSettings.asn_enabled}
                      <div class="flex items-center justify-between gap-2">
                        <span>Owner (ASN)</span>
                        {#if enrichment?.asn?.available}
                          <span class="text-success">{(enrichment.asn.file_size / 1024 / 1024).toFixed(1)}MB{#if enrichment.asn.loaded} · {enrichment.asn.ranges.toLocaleString()} ranges{/if}</span>
                        {:else}
                          <span class="text-warning">not downloaded</span>
                        {/if}
                      </div>
                    {/if}
                    {#if geoSettings.lookup_provider === 'ip2location' && geoSettings.proxy_enabled}
                      <div class="flex items-center justify-between gap-2">
                        <span>Proxy / VPN</span>
                        {#if enrichment?.proxy?.available}
                          <span class="text-success">{(enrichment.proxy.file_size / 1024 / 1024).toFixed(1)}MB{#if enrichment.proxy.loaded} · {enrichment.proxy.ranges.toLocaleString()} ranges{/if}</span>
                        {:else}
                          <span class="text-warning">not downloaded</span>
                        {/if}
                      </div>
                    {/if}
                    <div class="text-muted-foreground pt-0.5">Turn on what you want, Save, then "Update Now" downloads everything enabled.</div>
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

                <!-- Proxy / VPN enrichment toggle — sits under Update Time (IP2Location only) -->
                {#if geoSettings.lookup_provider === 'ip2location'}
                  <ContentBlock title="Proxy / VPN" description="Flag VPN / Tor / data-center">
                    <Checkbox variant="switch" bind:checked={geoSettings.proxy_enabled} />
                  </ContentBlock>
                  {#if geoSettings.proxy_enabled && geoProviders?.ip2location?.proxy_variants}
                    <div class="pl-1">
                      <Select
                        label="Detail level"
                        bind:value={geoSettings.ip2proxy_variant}
                        options={geoProviders.ip2location.proxy_variants.map(v => ({ value: v.id, label: v.name }))}
                      />
                      <div class="text-[10px] text-muted-foreground mt-1">
                        {geoProviders.ip2location.proxy_variants.find(v => v.id === geoSettings.ip2proxy_variant)?.description || ''}
                      </div>
                    </div>
                  {/if}
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
        <div class="panel-foot justify-between">
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
      </div>
      {/if}
      {#if section === 'web'}
      <div class="space-y-4">
      <!-- AdGuard Settings (trial of the panel style used on the machine page) -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-icon text-primary"><Icon name="shield" size={17} /></span>
          <div class="min-w-0 flex-1">
            <div class="panel-title">AdGuard Home</div>
            <div class="panel-sub">sign-in · query log · dashboard</div>
          </div>
          <Button
            onclick={regenerateAdguardCredentials}
            variant="outline"
            icon="wand"
            title="Generate random secure credentials"
          >
            Generate
          </Button>
        </div>
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
        <div class="mt-4 grid grid-cols-2 gap-3 border-t border-dashed border-border pt-4">
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
        <div class="panel-foot">
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
            <a href={adguardDashboardURL} target="_blank" rel="noopener noreferrer" class="kt-btn kt-btn-secondary kt-btn-sm">
              <Icon name="link" size={14} />
              Open Dashboard
            </a>
          {/if}
        </div>
      </div>
      </div>
      {/if}
      {#if section === 'web'}
        <TraefikOverview />
      {/if}
      {#if section === 'docker'}
        <DockerSettings />
      {/if}
      {#if section === 'backups'}
      <div class="space-y-4">
      <!-- Backup & migrate - Full width -->
      <div class="panel">
        <div class="panel-head">
          <span class="panel-icon text-primary"><Icon name="database" size={17} /></span>
          <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Backup &amp; migrate</div>
        </div>
        <div class="space-y-3">
          <p class="text-xs text-muted-foreground mb-4">
            Export the whole panel configuration as one passphrase-encrypted file, then restore it here or on a fresh host. The file holds your secrets (peer keys, CA, credentials) sealed by the passphrase — keep both safe: there's no recovery without the passphrase.
          </p>
          <div class="grid gap-6 lg:grid-cols-2">
            <!-- EXPORT -->
            <div class="space-y-3">
              <div class="flex items-center gap-2 text-sm font-medium"><Icon name="download" size={15} class="text-muted-foreground" /> Export</div>
              <Input label="Passphrase" type="password" prefixIcon="lock" bind:value={bkPass} placeholder="At least 16 characters" />
              <Input label="Confirm passphrase" type="password" prefixIcon="lock" bind:value={bkPass2} placeholder="Repeat passphrase" />
              <button type="button" onclick={generateBackupPassphrase}
                class="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-dashed border-info/40 text-info text-xs py-2 hover:bg-info/5 transition cursor-pointer">
                <Icon name="wand" size={14} /> Generate a strong passphrase for me
              </button>
              {#if bkGenerated}
                <div class="rounded-lg border border-info/40 bg-info/5 p-2.5 text-xs">
                  <div class="text-muted-foreground mb-1">Save this now — it was copied to your clipboard. The backup can't be opened without it:</div>
                  <code class="block font-mono break-all select-all text-foreground">{bkGenerated}</code>
                </div>
              {/if}
              <div class="space-y-2 pt-1">
                <label class="flex items-center justify-between gap-3 text-sm cursor-pointer">
                  <span><span class="font-medium">Include admin users</span><span class="block text-xs text-muted-foreground">Accounts, password hashes &amp; 2FA</span></span>
                  <Checkbox variant="switch" bind:checked={bkUsers} />
                </label>
                <label class="flex items-center justify-between gap-3 text-sm cursor-pointer">
                  <span><span class="font-medium">Include fleet</span><span class="block text-xs text-muted-foreground">Agent CA + enrolled machines</span></span>
                  <Checkbox variant="switch" bind:checked={bkFleet} />
                </label>
              </div>
              <p class="text-xs text-muted-foreground">Core config — VPN peers &amp; ACLs, firewall, routes, settings — is always included.</p>
              <Button variant="primary" icon="download" loading={bkExporting} onclick={exportBackup} disabled={bkPass.length < 12 || bkPass !== bkPass2}>Download backup</Button>
            </div>
            <!-- IMPORT -->
            <div class="space-y-3 lg:border-l lg:border-border lg:pl-6">
              <div class="flex items-center gap-2 text-sm font-medium"><Icon name="upload" size={15} class="text-muted-foreground" /> Import</div>
              <div>
                <span class="kt-label">Backup file</span>
                <label class="mt-1 flex items-center gap-2 rounded-lg border border-border bg-background px-3 py-2 text-sm cursor-pointer hover:bg-muted transition">
                  <Icon name="file-text" size={15} class="text-muted-foreground shrink-0" />
                  <span class="truncate {impFileName ? 'text-foreground' : 'text-muted-foreground'}">{impFileName || 'Choose .wgbackup file…'}</span>
                  <input type="file" accept=".wgbackup,application/json" class="hidden" onchange={onImportFile} />
                </label>
              </div>
              <Input label="Passphrase" type="password" prefixIcon="lock" bind:value={impPass} placeholder="Backup passphrase" />
              <Button variant="outline" icon="eye" loading={impLoading} onclick={previewImport} disabled={!impFileText || !impPass}>Preview changes</Button>

              {#if impPreview}
                <div class="rounded-lg border border-border bg-muted/30 p-3 space-y-2">
                  <div class="text-xs text-muted-foreground">
                    Backup from {impPreview.header?.created_at ? new Date(impPreview.header.created_at).toLocaleString(undefined, withTz()) : 'unknown date'} · includes {(impPreview.header?.includes || []).join(', ')}
                  </div>
                  <div class="divide-y divide-border">
                    {#each impPreview.plan as p}
                      <div class="flex items-center justify-between gap-2 py-1 text-xs">
                        <span class="font-medium">{p.label}</span>
                        {#if p.missing}
                          <span class="text-muted-foreground">skipped — not on this host</span>
                        {:else}
                          <span class="tabular-nums text-muted-foreground">{p.existing} <Icon name="arrow-right" size={11} class="inline" /> <span class="text-foreground font-medium">{p.incoming}</span></span>
                        {/if}
                      </div>
                    {/each}
                  </div>
                  {#if impPreview.warnings?.length}
                    <div class="rounded-md bg-warning/10 border border-warning/30 p-2 text-[11px] text-warning space-y-1">
                      {#each impPreview.warnings as wmsg}
                        <div class="flex gap-1.5"><Icon name="alert-triangle" size={12} class="shrink-0 mt-0.5" /><span>{wmsg}</span></div>
                      {/each}
                    </div>
                  {/if}
                  <Button variant="destructive" icon="refresh-alert" loading={impApplying} onclick={applyImport} class="w-full">Replace &amp; reconcile</Button>
                </div>
              {/if}
            </div>
          </div>
        </div>
      </div>
      <OffhostBackup />
      </div>
      {/if}
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
        prefixIcon="tag"
        placeholder="e.g. sshd, portscan"
        disabled={!!jailForm.id}
      />
      <Select label="Status" prefixIcon="power" bind:value={jailForm.enabled}>
        <option value={true}>Enabled</option>
        <option value={false}>Disabled</option>
      </Select>
    </div>

    <div>
      <Select
        label="Log File"
        prefixIcon="file-text"
        value={logFileCustom ? '__custom__' : jailForm.logFile}
        onchange={(e) => {
          if (e.target.value === '__custom__') { logFileCustom = true }
          else { logFileCustom = false; jailForm.logFile = e.target.value }
        }}
      >
        {#each logFileOptions as f}
          <option value={f.path}>{f.path}</option>
        {/each}
        <option value="__custom__">Custom path…</option>
      </Select>
      {#if logFileCustom}
        <Input
          bind:value={jailForm.logFile}
          prefixIcon="folder"
          placeholder="/var/log/auth.log"
          class="mt-2 font-mono"
          helperText="Must be under /var/log, /home, /var/lib/docker, or the data dir"
        />
      {/if}
    </div>

    <Input
      label="Filter Regex"
      bind:value={jailForm.filterRegex}
      prefixIcon="code"
      placeholder="e.g. Failed password.*from (\d+\.\d+\.\d+\.\d+)"
      class="font-mono"
      helperText="Must contain at least one capture group for the IP address"
    />

    <div class="grid grid-cols-3 gap-4">
      <Input
        label="Max Retry"
        type="number"
        bind:value={jailForm.maxRetry}
        prefixIcon="refresh"
        min="1"
        max="100"
      />
      <Select label="Find Time" prefixIcon="clock" bind:value={jailForm.findTime}>
        <option value={300}>5 minutes</option>
        <option value={600}>10 minutes</option>
        <option value={1800}>30 minutes</option>
        <option value={3600}>1 hour</option>
        <option value={7200}>2 hours</option>
        <option value={86400}>24 hours</option>
      </Select>
      <Select label="Ban Time" prefixIcon="ban" bind:value={jailForm.banTime}>
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
        prefixIcon="plug"
        placeholder="all or specific port"
      />
      <Select label="Action" prefixIcon="hand-stop" bind:value={jailForm.action}>
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
            prefixIcon="hash"
            min="2"
            max="20"
            helperText="Block /24 when this many IPs blocked"
          />
          <Select label="Time Window" prefixIcon="clock-hour-4" bind:value={jailForm.escalateWindow}>
            <option value={1800}>30 minutes</option>
            <option value={3600}>1 hour</option>
            <option value={7200}>2 hours</option>
            <option value={14400}>4 hours</option>
            <option value={86400}>24 hours</option>
          </Select>
        </div>

        <!-- Escalate to the whole ASN (provider) -->
        <div class="mt-3 p-3 rounded-lg border border-warning/30 bg-warning/5 space-y-3">
          <div class="flex items-center justify-between gap-3">
            <div class="min-w-0">
              <span class="text-sm font-medium">Also escalate to ASN (provider)</span>
              <p class="text-[11px] text-muted-foreground">When its own threshold is hit within one provider, block the <strong>whole provider</strong>, not just a /24. A provider spans many /24s, so keep this higher. Powerful — off by default. Needs the ASN database downloaded.</p>
            </div>
            <Checkbox variant="switch" bind:checked={jailForm.escalateAsn} />
          </div>
          {#if jailForm.escalateAsn}
            <div class="grid grid-cols-2 gap-4 pt-1">
              <Input
                label="ASN Threshold"
                type="number"
                bind:value={jailForm.escalateAsnThreshold}
                prefixIcon="network"
                min="2"
                max="100"
                helperText="Block the provider after this many IPs"
              />
              <Select label="ASN Time Window" prefixIcon="clock-hour-4" bind:value={jailForm.escalateAsnWindow}>
                <option value={1800}>30 minutes</option>
                <option value={3600}>1 hour</option>
                <option value={7200}>2 hours</option>
                <option value={14400}>4 hours</option>
                <option value={86400}>24 hours</option>
              </Select>
            </div>
          {/if}
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
