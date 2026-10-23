<script>
  // NotificationPrefs — which events notify the user, on whichever delivery channels they turned on
  // in Push Notifications (PWASettings), plus their resource alert rules. Greyed out until a
  // channel is on.
  import { onMount } from 'svelte'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Checkbox from './Checkbox.svelte'
  import ContentBlock from './ContentBlock.svelte'
  import Badge from './Badge.svelte'
  import AlertRules from './AlertRules.svelte'
  import { toast } from '../stores/app.js'
  import { notificationPreferences, refreshPreferences } from '../stores/pwa.js'
  import { updatePreferences } from '../lib/pwa/push'

  let { anyChannel = false } = $props()

  let savingPrefs = $state(false)
  // Local copy of preferences for editing (keys match API: snake_case)
  let prefs = $state({
    node_offline: true,
    node_online: false,
    firewall_alert: true,
    login_new_device: true,
    system_alert: true,
    resource_alert: true
  })

  // Track if preferences have changed
  const prefsChanged = $derived.by(() => {
    return prefs.node_offline !== $notificationPreferences.node_offline ||
           prefs.node_online !== $notificationPreferences.node_online ||
           prefs.firewall_alert !== $notificationPreferences.firewall_alert ||
           prefs.login_new_device !== $notificationPreferences.login_new_device ||
           prefs.system_alert !== $notificationPreferences.system_alert ||
           prefs.resource_alert !== $notificationPreferences.resource_alert
  })

  // Sync local prefs with store
  $effect(() => {
    prefs = { ...$notificationPreferences }
  })

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

  onMount(refreshPreferences)
</script>

<!-- Notification Preferences -->
<div class="panel {!anyChannel ? 'opacity-50 pointer-events-none' : ''}">
  <div class="panel-head">
    <span class="panel-icon text-primary"><Icon name="bell-ringing" size={17} /></span>
    <div class="min-w-0 flex-1">
      <div class="panel-title">Notification preferences</div>
      <div class="panel-sub">which events notify you, on every channel you enabled</div>
    </div>
    {#if !anyChannel}
      <Badge variant="muted" size="xs">Enable a channel first</Badge>
    {/if}
  </div>
  <div class="space-y-4">
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
      <ContentBlock title="Node Offline" description="When a VPN node goes offline">
        <Checkbox variant="switch" bind:checked={prefs.node_offline} />
      </ContentBlock>
      <ContentBlock title="Node Online" description="When a VPN node comes back online">
        <Checkbox variant="switch" bind:checked={prefs.node_online} />
      </ContentBlock>
      <ContentBlock title="Firewall Alerts" description="Blocked connections and security events">
        <Checkbox variant="switch" bind:checked={prefs.firewall_alert} />
      </ContentBlock>
      <ContentBlock title="New Device Login" description="Login from a new device or location">
        <Checkbox variant="switch" bind:checked={prefs.login_new_device} />
      </ContentBlock>
      <ContentBlock title="System Alerts" description="Important system notifications">
        <Checkbox variant="switch" bind:checked={prefs.system_alert} />
      </ContentBlock>
      <ContentBlock title="Resource Alerts" description="CPU/memory/disk threshold rules (below)">
        <Checkbox variant="switch" bind:checked={prefs.resource_alert} />
      </ContentBlock>
    </div>
    <div>
      <Button onclick={savePreferences} loading={savingPrefs} disabled={!prefsChanged} size="sm" icon="device-floppy">Save Preferences</Button>
    </div>

    <!-- Resource alert rules — same card, below the event preferences -->
    <div class="border-t border-border pt-4">
      <AlertRules />
    </div>
  </div>
</div>
