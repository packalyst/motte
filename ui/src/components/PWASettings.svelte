<script>
  import { onMount } from 'svelte'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Checkbox from './Checkbox.svelte'
  import ContentBlock from './ContentBlock.svelte'
  import Badge from './Badge.svelte'
  import { toast } from '../stores/app.js'
  import {
    platform,
    isInstalled,
    capabilities,
    permissions,
    pushEnabled,
    pushSubscription,
    notificationPreferences,
    loading,
    refreshPermissions,
    requestAndRefresh,
    refreshPushState,
    refreshPreferences
  } from '../stores/pwa.js'
  import {
    PermissionType,
    PermissionState,
    isPushSupported,
    detectPlatform,
    Platform,
    requestPermission,
    markGeolocationGranted,
    clearGeolocationGranted
  } from '../lib/pwa/permissions'
  import {
    subscribeToPush,
    unsubscribeFromPush,
    getSubscriptions,
    updatePreferences,
    deleteSubscription,
    getCurrentSubscription,
    sendTestNotification,
    storeLocation,
    getLocations
  } from '../lib/pwa/push'
  import LocationMap from './LocationMap.svelte'
  import { pwaSubscriptionsStore } from '../stores/websocket.js'

  let subscriptions = $state([])
  let currentEndpoint = $state(null)
  let loadingSubscriptions = $state(false)
  let togglingPush = $state(false)
  let savingPrefs = $state(false)
  let revokingId = $state(null)
  let testingNotification = $state(false)
  let requestingLocation = $state(false)
  let showLocationModal = $state(false)
  let currentLocation = $state(null)
  let loadingLocation = $state(false)

  // Local copy of preferences for editing (keys match API: snake_case)
  let prefs = $state({
    node_offline: true,
    node_online: false,
    firewall_alert: true,
    login_new_device: true,
    system_alert: true
  })

  // Track if preferences have changed
  const prefsChanged = $derived.by(() => {
    return prefs.node_offline !== $notificationPreferences.node_offline ||
           prefs.node_online !== $notificationPreferences.node_online ||
           prefs.firewall_alert !== $notificationPreferences.firewall_alert ||
           prefs.login_new_device !== $notificationPreferences.login_new_device ||
           prefs.system_alert !== $notificationPreferences.system_alert
  })

  // Sync local prefs with store
  $effect(() => {
    prefs = { ...$notificationPreferences }
  })

  // React to WebSocket subscription updates
  $effect(() => {
    if ($pwaSubscriptionsStore) {
      subscriptions = $pwaSubscriptionsStore

      // Check if current device was removed from list
      if (currentEndpoint) {
        const stillExists = $pwaSubscriptionsStore.some(s => s.endpoint === currentEndpoint)
        if (!stillExists) {
          // Current device was removed from server, update UI state
          pushSubscription.set(null)
          currentEndpoint = null
        }
      }
    }
  })

  // Detect device type from user agent
  function getDeviceInfo(userAgent) {
    if (!userAgent) return { icon: 'device', type: 'Unknown' }
    const ua = userAgent.toLowerCase()

    // Device type
    if (ua.includes('iphone')) return { icon: 'device-mobile', type: 'iPhone' }
    if (ua.includes('ipad')) return { icon: 'device-tablet', type: 'iPad' }
    if (ua.includes('android') && ua.includes('mobile')) return { icon: 'device-mobile', type: 'Android' }
    if (ua.includes('android')) return { icon: 'device-tablet', type: 'Android Tablet' }
    if (ua.includes('macintosh') || ua.includes('mac os')) return { icon: 'device-laptop', type: 'Mac' }
    if (ua.includes('windows')) return { icon: 'device-desktop', type: 'Windows' }
    if (ua.includes('linux')) return { icon: 'device-desktop', type: 'Linux' }
    return { icon: 'device', type: 'Unknown' }
  }

  // Detect browser from user agent
  function getBrowser(userAgent) {
    if (!userAgent) return ''
    const ua = userAgent.toLowerCase()
    if (ua.includes('edg/')) return 'Edge'
    if (ua.includes('chrome/') && !ua.includes('edg/')) return 'Chrome'
    if (ua.includes('firefox/')) return 'Firefox'
    if (ua.includes('safari/') && !ua.includes('chrome/')) return 'Safari'
    return ''
  }

  async function loadSubscriptions() {
    loadingSubscriptions = true
    try {
      // Get current device's subscription endpoint
      const currentSub = await getCurrentSubscription()
      currentEndpoint = currentSub?.endpoint || null

      subscriptions = await getSubscriptions()
    } catch (e) {
      // Ignore errors (user may not be authenticated)
    } finally {
      loadingSubscriptions = false
    }
  }

  async function revokeSubscription(id) {
    revokingId = id
    try {
      await deleteSubscription(id)
      toast('Device revoked successfully', 'success')
      await loadSubscriptions()
    } catch (e) {
      toast('Failed to revoke device: ' + e.message, 'error')
    } finally {
      revokingId = null
    }
  }

  async function togglePush() {
    if (togglingPush) return
    togglingPush = true

    try {
      if ($pushEnabled) {
        await unsubscribeFromPush()
        toast('Push notifications disabled', 'info')
      } else {
        await subscribeToPush()
        toast('Push notifications enabled', 'success')
      }
      await refreshPushState()
      await loadSubscriptions()
    } catch (e) {
      toast(e.message || 'Failed to toggle push notifications', 'error')
    } finally {
      togglingPush = false
    }
  }

  async function savePreferences() {
    savingPrefs = true
    try {
      await updatePreferences(prefs)
      await refreshPreferences()
      toast('Notification preferences saved', 'success')
    } catch (e) {
      toast('Failed to save preferences: ' + e.message, 'error')
    } finally {
      savingPrefs = false
    }
  }

  async function testNotification() {
    testingNotification = true
    try {
      await sendTestNotification()
      toast('Test notification sent', 'success')
    } catch (e) {
      toast('Failed to send test notification: ' + e.message, 'error')
    } finally {
      testingNotification = false
    }
  }

  async function requestLocation() {
    requestingLocation = true
    try {
      // Get current position (this triggers permission prompt)
      const position = await new Promise((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, {
          timeout: 10000,
          maximumAge: 0,
          enableHighAccuracy: true
        })
      })

      // Permission granted - store location to backend
      await storeLocation(position)
      markGeolocationGranted()
      toast('Location enabled and saved', 'success')
      await refreshPermissions()
    } catch (e) {
      if (e.code === 1) { // PERMISSION_DENIED
        clearGeolocationGranted() // Clear flag if permission was revoked
        toast('Location permission denied', 'warning')
      } else if (e.code === 2) { // POSITION_UNAVAILABLE
        toast('Location unavailable', 'error')
      } else if (e.code === 3) { // TIMEOUT
        toast('Location request timed out', 'error')
      } else {
        toast('Failed to get location: ' + e.message, 'error')
      }
      await refreshPermissions()
    } finally {
      requestingLocation = false
    }
  }

  async function openLocationMap() {
    loadingLocation = true
    try {
      // Quick permission check - if revoked, this will fail
      await new Promise((resolve, reject) => {
        navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 3000, maximumAge: 60000 })
      })
    } catch (e) {
      if (e.code === 1) { // PERMISSION_DENIED
        clearGeolocationGranted()
        await refreshPermissions()
        toast('Location permission was revoked', 'warning')
        loadingLocation = false
        return
      }
      // Other errors (timeout, unavailable) - continue to show stored data
    }

    try {
      const locations = await getLocations({ latest: true })
      if (locations && locations.length > 0) {
        // API returns camelCase
        const loc = locations[0]
        currentLocation = {
          latitude: loc.latitude,
          longitude: loc.longitude,
          accuracy: loc.accuracy,
          device_name: loc.deviceName,
          recorded_at: loc.recordedAt
        }
        showLocationModal = true
      } else {
        toast('No location data found. Click Update to save your location.', 'warning')
      }
    } catch (e) {
      toast('Failed to load location: ' + e.message, 'error')
    } finally {
      loadingLocation = false
    }
  }

  async function handleLocationUpdate() {
    showLocationModal = false
    await requestLocation()
    // Reopen modal with new data
    await openLocationMap()
  }

  function formatDate(dateStr) {
    if (!dateStr) return '—'
    const date = new Date(dateStr)
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }

  function getPermissionBadge(state) {
    switch (state) {
      case PermissionState.GRANTED:
        return { variant: 'success', text: 'Allowed' }
      case PermissionState.DENIED:
        return { variant: 'destructive', text: 'Blocked' }
      case PermissionState.PROMPT:
        return { variant: 'warning', text: 'Not Set' }
      default:
        return { variant: 'muted', text: 'N/A' }
    }
  }

  onMount(async () => {
    await refreshPermissions()
    await refreshPushState()
    await refreshPreferences()
    await loadSubscriptions()
  })
</script>

<div class="kt-panel">
  <div class="kt-panel-header">
    <h3 class="kt-panel-title">
      <Icon name="bell" size={16} />
      Push Notifications
    </h3>
    {#if $pushEnabled}
      <Badge variant="success" size="sm">Enabled</Badge>
    {:else if $permissions[PermissionType.NOTIFICATIONS] === PermissionState.DENIED}
      <Badge variant="destructive" size="sm">Blocked</Badge>
    {:else}
      <Badge variant="muted" size="sm">Disabled</Badge>
    {/if}
  </div>
  <div class="kt-panel-body">
    <!-- Platform & Installation Status -->
    <div class="grid grid-cols-2 gap-3 mb-4">
      <div class="p-2 bg-muted/50 rounded-lg border border-dashed border-border flex items-center justify-between">
        <div>
          <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Platform</div>
          <span class="text-sm text-foreground">{$platform.charAt(0).toUpperCase() + $platform.slice(1)}</span>
        </div>
        <Icon name={$platform === 'ios' ? 'brand-apple' : $platform === 'android' ? 'brand-android' : 'device-desktop'} size={20} class="text-muted-foreground" />
      </div>
      <div class="p-2 bg-muted/50 rounded-lg border border-dashed border-border flex items-center justify-between">
        <div>
          <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Installation</div>
          <span class="text-sm text-foreground">{$isInstalled ? 'Installed (PWA)' : 'Browser'}</span>
        </div>
        <Icon name={$isInstalled ? 'app-window' : 'browser'} size={20} class="text-muted-foreground" />
      </div>
    </div>

    <!-- Location -->
    <div class="flex items-center justify-between p-3 bg-muted/30 rounded-lg border border-dashed border-border">
      <div class="flex items-center gap-3">
        <div class="flex-shrink-0 w-10 h-10 rounded-full bg-info/10 flex items-center justify-center">
          <Icon name="map-pin" size={20} class="text-info" />
        </div>
        <div>
          <div class="flex items-center gap-2">
            <span class="text-xs font-medium text-foreground">Location</span>
            <Badge variant={getPermissionBadge($permissions[PermissionType.GEOLOCATION]).variant} size="xs">
              {getPermissionBadge($permissions[PermissionType.GEOLOCATION]).text}
            </Badge>
          </div>
          <div class="text-[10px] text-muted-foreground">Track login locations for security</div>
        </div>
      </div>
      <div class="flex flex-col sm:flex-row gap-2">
        {#if $permissions[PermissionType.GEOLOCATION] === PermissionState.GRANTED}
          <Button
            onclick={openLocationMap}
            loading={loadingLocation}
            variant="secondary"
            size="xs"
            icon="map"
          >
            View
          </Button>
          <Button
            onclick={requestLocation}
            loading={requestingLocation}
            variant="secondary"
            size="xs"
            icon="refresh"
          >
            Update
          </Button>
        {:else if $permissions[PermissionType.GEOLOCATION] === PermissionState.DENIED}
          <Badge variant="destructive" size="sm">Blocked</Badge>
        {:else}
          <Button
            onclick={requestLocation}
            loading={requestingLocation}
            variant="success"
            size="xs"
            icon="map-pin"
          >
            Enable
          </Button>
        {/if}
      </div>
    </div>

    <!-- Push Toggle -->
    {#if !isPushSupported()}
      <div class="p-3 bg-warning/10 border border-warning/20 rounded text-xs">
        <Icon name="alert-circle" size={14} class="inline mr-1 text-warning" />
        Push notifications are not supported on this platform.
        {#if $platform === Platform.IOS && !$isInstalled}
          <span class="block mt-1 text-muted-foreground">Install as PWA and use iOS 16.4+ for push support.</span>
        {/if}
      </div>
    {:else if $permissions[PermissionType.NOTIFICATIONS] === PermissionState.DENIED}
      <div class="p-3 bg-destructive/10 border border-destructive/20 rounded text-xs">
        <Icon name="alert-triangle" size={14} class="inline mr-1 text-destructive" />
        Notifications are blocked. Please enable them in your browser/device settings.
      </div>
    {:else}
      <div class="flex items-center justify-between p-3 bg-muted/30 rounded-lg border border-dashed border-border">
        <div class="flex items-center gap-3">
          <div class="flex-shrink-0 w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
            <Icon name="bell" size={20} class="text-primary" />
          </div>
          <div>
            <div class="flex items-center gap-2">
              <span class="text-xs font-medium text-foreground">Push Notifications</span>
              <Badge variant={getPermissionBadge($permissions[PermissionType.NOTIFICATIONS]).variant} size="xs">
                {getPermissionBadge($permissions[PermissionType.NOTIFICATIONS]).text}
              </Badge>
            </div>
            <div class="text-[10px] text-muted-foreground">Receive alerts on this device</div>
          </div>
        </div>
        <div class="flex flex-col sm:flex-row gap-2">
          {#if $pushEnabled}
            <Button
              onclick={testNotification}
              loading={testingNotification}
              variant="secondary"
              size="xs"
              icon="bell-ringing"
            >
              Test
            </Button>
          {/if}
          <Button
            onclick={togglePush}
            loading={togglingPush}
            variant={$pushEnabled ? 'destructive' : 'success'}
            size="xs"
            icon={$pushEnabled ? 'bell-off' : 'bell'}
          >
            {$pushEnabled ? 'Disable' : 'Enable'}
          </Button>
        </div>
      </div>
    {/if}

    <!-- Subscribed Devices -->
    {#if subscriptions.length > 0}
      <div class="mt-4 pt-4 border-t border-border">
        <span class="block text-xs font-medium text-foreground mb-2">Registered Devices ({subscriptions.length})</span>
        <div class="space-y-2">
          {#each subscriptions as sub}
            {@const deviceInfo = getDeviceInfo(sub.userAgent)}
            {@const browser = getBrowser(sub.userAgent)}
            {@const isCurrentDevice = currentEndpoint && sub.endpoint === currentEndpoint}
            <div class="flex items-center gap-3 p-2 bg-muted/30 rounded text-xs">
              <div class="flex-shrink-0 w-8 h-8 rounded-full bg-muted flex items-center justify-center">
                <Icon name={deviceInfo.icon} size={16} class="text-muted-foreground" />
              </div>
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2">
                  <span class="font-medium truncate">{sub.deviceName || deviceInfo.type}</span>
                  {#if browser}
                    <span class="text-[10px] text-muted-foreground">({browser})</span>
                  {/if}
                </div>
                <div class="flex items-center gap-2 text-[10px] text-muted-foreground mt-0.5">
                  <span>Added {formatDate(sub.createdAt)}</span>
                  {#if sub.lastUsedAt}
                    <span>• Last used {formatDate(sub.lastUsedAt)}</span>
                  {/if}
                </div>
              </div>
              {#if isCurrentDevice}
                <Badge variant="success" size="xs">This device</Badge>
              {:else}
                <Button
                  onclick={() => revokeSubscription(sub.id)}
                  loading={revokingId === sub.id}
                  variant="ghost"
                  size="xs"
                  icon="trash"
                  class="text-destructive hover:text-destructive hover:bg-destructive/10"
                />
              {/if}
            </div>
          {/each}
        </div>
      </div>
    {/if}
  </div>
</div>

<!-- Notification Preferences -->
<div class="kt-panel {!$pushEnabled ? 'opacity-50 pointer-events-none' : ''}">
  <div class="kt-panel-header">
    <h3 class="kt-panel-title">
      <Icon name="settings" size={16} />
      Notification Preferences
    </h3>
    {#if !$pushEnabled}
      <Badge variant="muted" size="xs">Enable push first</Badge>
    {/if}
  </div>
  <div class="kt-panel-body">
    <p class="text-[10px] text-muted-foreground mb-3">
      Choose which events trigger push notifications.
    </p>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
      <ContentBlock title="Node Offline" description="When a VPN node goes offline">
        <Checkbox variant="switch" bind:checked={prefs.node_offline} disabled={!$pushEnabled} />
      </ContentBlock>
      <ContentBlock title="Node Online" description="When a VPN node comes back online">
        <Checkbox variant="switch" bind:checked={prefs.node_online} disabled={!$pushEnabled} />
      </ContentBlock>
      <ContentBlock title="Firewall Alerts" description="Blocked connections and security events">
        <Checkbox variant="switch" bind:checked={prefs.firewall_alert} disabled={!$pushEnabled} />
      </ContentBlock>
      <ContentBlock title="New Device Login" description="Login from a new device or location">
        <Checkbox variant="switch" bind:checked={prefs.login_new_device} disabled={!$pushEnabled} />
      </ContentBlock>
      <ContentBlock title="System Alerts" description="Important system notifications">
        <Checkbox variant="switch" bind:checked={prefs.system_alert} disabled={!$pushEnabled} />
      </ContentBlock>
    </div>
  </div>
  <div class="kt-panel-footer">
    <Button
      onclick={savePreferences}
      loading={savingPrefs}
      disabled={!prefsChanged || !$pushEnabled}
      size="sm"
      icon="device-floppy"
    >
      Save Preferences
    </Button>
  </div>
</div>

<!-- Location Map Modal -->
<LocationMap
  bind:open={showLocationModal}
  location={currentLocation}
  onUpdate={handleLocationUpdate}
/>
