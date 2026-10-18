<script>
  // Resource alerts: threshold rules (CPU/memory/disk) that fire to a webhook and/or the panel's
  // push notifications. The webhook URL is write-only (may carry a token) — a redacted placeholder
  // is preserved on save unless changed.
  import { onMount } from 'svelte'
  import { apiGet, apiPut, apiPost, toast } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Input from './Input.svelte'
  import Select from './Select.svelte'
  import Checkbox from './Checkbox.svelte'

  const REDACTED = '__stored__'

  let rules = $state([])
  let webhookUrl = $state('')
  let hasStoredUrl = $state(false)
  let webhookEnabled = $state(false)
  let pushEnabled = $state(true)
  let loading = $state(true)
  let saving = $state(false)
  let testing = $state(false)

  const metricOptions = [
    { value: 'cpu', label: 'CPU %' },
    { value: 'mem', label: 'Memory %' },
    { value: 'disk', label: 'Disk %' },
  ]

  onMount(load)

  async function load() {
    loading = true
    try {
      const c = await apiGet('/api/alerts/config')
      rules = c.rules || []
      hasStoredUrl = c.webhookUrl === REDACTED
      webhookUrl = ''
      webhookEnabled = !!c.webhookEnabled
      pushEnabled = !!c.pushEnabled
    } catch (e) {
      toast(e.message || 'Could not load alerts', 'error')
    } finally {
      loading = false
    }
  }

  function addRule() {
    rules = [...rules, { id: crypto.randomUUID?.() || String(Date.now()), name: 'High CPU', metric: 'cpu', threshold: 90, forMin: 5, enabled: true }]
  }
  function removeRule(id) {
    rules = rules.filter((r) => r.id !== id)
  }

  function payload() {
    const url = webhookUrl !== '' ? webhookUrl : (hasStoredUrl ? REDACTED : '')
    return {
      rules: rules.map((r) => ({ ...r, threshold: Number(r.threshold), forMin: Number(r.forMin) })),
      webhookUrl: url, webhookEnabled, pushEnabled,
    }
  }

  async function save() {
    saving = true
    try {
      const saved = await apiPut('/api/alerts/config', payload())
      hasStoredUrl = saved.webhookUrl === REDACTED
      webhookUrl = ''
      toast('Alert settings saved', 'success')
    } catch (e) {
      toast(e.message || 'Save failed', 'error')
    } finally {
      saving = false
    }
  }

  async function test() {
    testing = true
    try {
      const url = webhookUrl !== '' ? webhookUrl : (hasStoredUrl ? REDACTED : '')
      const res = await apiPost('/api/alerts/test', { webhookUrl: url, webhookEnabled, pushEnabled })
      toast('Test sent — ' + Object.entries(res).map(([k, v]) => `${k}: ${v}`).join(', '), 'success')
    } catch (e) {
      toast(e.message || 'Test failed', 'error')
    } finally {
      testing = false
    }
  }
</script>

<div class="kt-panel">
  <div class="kt-panel-header">
    <h3 class="kt-panel-title"><Icon name="bell-ringing" size={16} /> Resource alerts</h3>
  </div>
  <div class="kt-panel-body space-y-4">
    <p class="text-xs text-muted-foreground">
      Get notified when CPU, memory or disk stays above a threshold. Alerts go to a webhook (Slack, Discord, ntfy, your own endpoint) and/or your panel push notifications (installed PWA, incl. iOS 16.4+).
    </p>

    {#if loading}
      <div class="text-sm text-muted-foreground">Loading…</div>
    {:else}
      <!-- Rules -->
      <div class="space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-sm font-medium">Rules</span>
          <Button variant="outline" size="xs" icon="plus" onclick={addRule}>Add rule</Button>
        </div>
        {#if rules.length === 0}
          <p class="text-xs text-muted-foreground">No rules yet — add one to start alerting.</p>
        {/if}
        {#each rules as r (r.id)}
          <div class="flex flex-wrap items-center gap-2 rounded-md border border-border p-2">
            <Checkbox checked={r.enabled} onchange={(e) => (r.enabled = e.target.checked)} />
            <Input bind:value={r.name} placeholder="Name" class="w-32" />
            <Select bind:value={r.metric} options={metricOptions} />
            <span class="text-xs text-muted-foreground">over</span>
            <Input type="number" bind:value={r.threshold} class="w-16" /><span class="text-xs">%</span>
            <span class="text-xs text-muted-foreground">for</span>
            <Input type="number" bind:value={r.forMin} class="w-16" /><span class="text-xs">min</span>
            <Button variant="ghost" size="xs" icon="trash" iconOnly class="ml-auto" onclick={() => removeRule(r.id)} />
          </div>
        {/each}
      </div>

      <!-- Channels -->
      <div class="space-y-2 border-t border-border pt-3">
        <Checkbox checked={pushEnabled} label="Send panel push notifications" onchange={(e) => (pushEnabled = e.target.checked)} />
        <Checkbox checked={webhookEnabled} label="Send to a webhook" onchange={(e) => (webhookEnabled = e.target.checked)} />
        {#if webhookEnabled}
          <Input type="password" bind:value={webhookUrl} placeholder={hasStoredUrl ? 'stored — leave blank to keep' : 'https://hooks.example.com/…'} autocomplete="off" />
        {/if}
      </div>
    {/if}
  </div>
  <div class="kt-panel-footer flex items-center justify-between">
    <Button variant="outline" icon="bell" loading={testing} disabled={loading} onclick={test}>Send test</Button>
    <Button variant="primary" icon="device-floppy" loading={saving} disabled={loading} onclick={save}>Save settings</Button>
  </div>
</div>
