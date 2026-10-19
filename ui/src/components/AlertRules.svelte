<script>
  // Resource alerts — PER USER. Each person owns their rules and delivery channels; alerts go to
  // THEIR push devices, their own webhook, and/or their email. A rule watches the panel host or a
  // specific fleet machine. Webhook URL is write-only (may carry a token).
  import { onMount } from 'svelte'
  import { apiGet, apiPut, apiPost, apiDelete, toast } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Input from './Input.svelte'
  import Select from './Select.svelte'
  import Checkbox from './Checkbox.svelte'

  const REDACTED = '__stored__'

  let rules = $state([])
  let machines = $state([])
  let ch = $state({ pushEnabled: true, webhookEnabled: false, webhookUrl: '', emailEnabled: false, email: '' })
  let hasStoredUrl = $state(false)
  let webhookInput = $state('')
  let loading = $state(true)
  let savingCh = $state(false)
  let testing = $state(false)

  const metricOptions = [
    { value: 'cpu', label: 'CPU %' },
    { value: 'mem', label: 'Memory %' },
    { value: 'disk', label: 'Disk %' },
  ]
  const scopeOptions = [
    { value: 'host', label: 'This panel' },
    { value: 'machine', label: 'A machine' },
  ]
  const machineOptions = $derived(machines.map((m) => ({ value: m.id, label: m.name || m.id })))

  onMount(load)

  async function load() {
    loading = true
    try {
      const [r, c, m] = await Promise.allSettled([
        apiGet('/api/alerts/rules'),
        apiGet('/api/alerts/channels'),
        apiGet('/api/fleet/machines'),
      ])
      rules = r.status === 'fulfilled' ? r.value || [] : []
      if (c.status === 'fulfilled' && c.value) {
        ch = c.value
        hasStoredUrl = c.value.webhookUrl === REDACTED
      }
      machines = m.status === 'fulfilled' ? m.value || [] : []
    } catch (e) {
      toast(e.message || 'Could not load alerts', 'error')
    } finally {
      loading = false
    }
  }

  function addRule() {
    rules = [...rules, { id: null, name: 'High CPU', metric: 'cpu', scope: 'host', machineId: '', threshold: 90, forMin: 5, enabled: true }]
  }

  async function saveRule(r) {
    const body = {
      name: r.name, metric: r.metric, scope: r.scope,
      machineId: r.scope === 'machine' ? r.machineId : '',
      threshold: Number(r.threshold), forMin: Number(r.forMin), enabled: !!r.enabled,
    }
    try {
      if (r.id) {
        await apiPut(`/api/alerts/rules/${r.id}`, body)
      } else {
        const created = await apiPost('/api/alerts/rules', body)
        r.id = created.id
      }
      toast('Rule saved', 'success')
    } catch (e) {
      toast(e.message || 'Save failed', 'error')
    }
  }

  async function removeRule(r) {
    if (!r.id) {
      rules = rules.filter((x) => x !== r)
      return
    }
    try {
      await apiDelete(`/api/alerts/rules/${r.id}`)
      rules = rules.filter((x) => x !== r)
    } catch (e) {
      toast(e.message || 'Delete failed', 'error')
    }
  }

  function channelPayload() {
    const url = webhookInput !== '' ? webhookInput : hasStoredUrl ? REDACTED : ''
    return {
      pushEnabled: ch.pushEnabled, webhookEnabled: ch.webhookEnabled, webhookUrl: url,
      emailEnabled: ch.emailEnabled, email: ch.email,
    }
  }

  async function saveChannels() {
    savingCh = true
    try {
      const saved = await apiPut('/api/alerts/channels', channelPayload())
      hasStoredUrl = saved.webhookUrl === REDACTED
      webhookInput = ''
      toast('Delivery channels saved', 'success')
    } catch (e) {
      toast(e.message || 'Save failed', 'error')
    } finally {
      savingCh = false
    }
  }

  async function test() {
    testing = true
    try {
      await apiPost('/api/alerts/test', channelPayload())
      toast('Test alert sent to your enabled channels', 'success')
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
      Get notified when CPU, memory or disk stays over a threshold — on this panel or a specific fleet machine. These rules are yours; alerts go to your own channels below.
    </p>

    {#if loading}
      <div class="text-sm text-muted-foreground">Loading…</div>
    {:else}
      <!-- Rules -->
      <div class="space-y-2">
        <div class="flex items-center justify-between">
          <span class="text-sm font-medium">My rules</span>
          <Button variant="outline" size="xs" icon="plus" onclick={addRule}>Add rule</Button>
        </div>
        {#if rules.length === 0}
          <p class="text-xs text-muted-foreground">No rules yet — add one to start alerting.</p>
        {/if}
        {#each rules as r (r.id ?? r)}
          <div class="flex flex-wrap items-center gap-2 rounded-md border border-border p-2">
            <Checkbox checked={r.enabled} onchange={(e) => (r.enabled = e.target.checked)} />
            <Input bind:value={r.name} placeholder="Name" class="w-28" />
            <Select bind:value={r.metric} options={metricOptions} />
            <span class="text-xs text-muted-foreground">on</span>
            <Select bind:value={r.scope} options={scopeOptions} />
            {#if r.scope === 'machine'}
              <Select bind:value={r.machineId} options={machineOptions} />
            {/if}
            <span class="text-xs text-muted-foreground">over</span>
            <Input type="number" bind:value={r.threshold} class="w-16" /><span class="text-xs">%</span>
            <span class="text-xs text-muted-foreground">for</span>
            <Input type="number" bind:value={r.forMin} class="w-16" /><span class="text-xs">min</span>
            <div class="ml-auto flex items-center gap-1">
              <Button variant="outline" size="xs" icon="device-floppy" onclick={() => saveRule(r)}>Save</Button>
              <Button variant="ghost" size="xs" icon="trash" iconOnly onclick={() => removeRule(r)} />
            </div>
          </div>
        {/each}
      </div>

      <!-- Delivery channels (per user) -->
      <div class="space-y-2 border-t border-border pt-3">
        <span class="text-sm font-medium">Deliver to me via</span>
        <Checkbox checked={ch.pushEnabled} label="Push notifications (my devices)" onchange={(e) => (ch.pushEnabled = e.target.checked)} />
        <Checkbox checked={ch.webhookEnabled} label="A webhook (Slack, Discord, ntfy, …)" onchange={(e) => (ch.webhookEnabled = e.target.checked)} />
        {#if ch.webhookEnabled}
          <Input type="password" bind:value={webhookInput} placeholder={hasStoredUrl ? 'stored — leave blank to keep' : 'https://hooks.example.com/…'} autocomplete="off" />
        {/if}
        <Checkbox checked={ch.emailEnabled} label="Email" onchange={(e) => (ch.emailEnabled = e.target.checked)} />
        {#if ch.emailEnabled}
          <Input type="email" bind:value={ch.email} placeholder="you@example.com" autocomplete="off" />
          <p class="text-[11px] text-muted-foreground">Email needs SMTP configured by an admin in Settings.</p>
        {/if}
      </div>
    {/if}
  </div>
  <div class="kt-panel-footer flex items-center justify-between">
    <Button variant="outline" icon="bell" loading={testing} disabled={loading} onclick={test}>Send test</Button>
    <Button variant="primary" icon="device-floppy" loading={savingCh} disabled={loading} onclick={saveChannels}>Save channels</Button>
  </div>
</div>
