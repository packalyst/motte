<script>
  // Global SMTP settings (admin) — the mail server used to deliver per-user alert emails. The
  // password is write-only: a redacted placeholder is kept on save unless changed. Per-user alert
  // rules and the choice to receive email live in Profile → Notifications.
  import { onMount } from 'svelte'
  import { apiGet, apiPut, toast } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Input from './Input.svelte'
  import Select from './Select.svelte'

  const REDACTED = '__stored__'

  let cfg = $state({ host: '', port: '587', user: '', pass: '', from: '', tls: 'starttls' })
  let passInput = $state('')
  let hasStoredPass = $state(false)
  let loading = $state(true)
  let saving = $state(false)

  const tlsOptions = [
    { value: 'starttls', label: 'STARTTLS (587)' },
    { value: 'tls', label: 'TLS (465)' },
    { value: 'none', label: 'None (plaintext)' },
  ]

  onMount(async () => {
    try {
      const c = await apiGet('/api/alerts/smtp')
      if (c) {
        cfg = { ...cfg, ...c, pass: '' }
        hasStoredPass = c.pass === REDACTED
      }
    } catch (e) {
      toast(e.message || 'Could not load SMTP settings', 'error')
    } finally {
      loading = false
    }
  })

  async function save() {
    saving = true
    try {
      const pass = passInput !== '' ? passInput : hasStoredPass ? REDACTED : ''
      await apiPut('/api/alerts/smtp', { ...cfg, pass })
      hasStoredPass = hasStoredPass || passInput !== ''
      passInput = ''
      toast('SMTP settings saved', 'success')
    } catch (e) {
      toast(e.message || 'Save failed', 'error')
    } finally {
      saving = false
    }
  }
</script>

<div class="kt-panel">
  <div class="kt-panel-header">
    <h3 class="kt-panel-title"><Icon name="mail" size={16} /> Email (SMTP)</h3>
  </div>
  <div class="kt-panel-body space-y-3">
    <p class="text-xs text-muted-foreground">
      Mail server for alert emails. Each person chooses whether to receive email (and their address) in Profile → Notifications.
    </p>
    {#if loading}
      <div class="text-sm text-muted-foreground">Loading…</div>
    {:else}
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <label class="space-y-1"><span class="text-xs font-medium">Host</span>
          <Input bind:value={cfg.host} placeholder="smtp.example.com" /></label>
        <label class="space-y-1"><span class="text-xs font-medium">Port</span>
          <Input bind:value={cfg.port} placeholder="587" /></label>
        <label class="space-y-1"><span class="text-xs font-medium">Username</span>
          <Input bind:value={cfg.user} placeholder="(optional)" autocomplete="off" /></label>
        <label class="space-y-1"><span class="text-xs font-medium">Password</span>
          <Input type="password" bind:value={passInput} placeholder={hasStoredPass ? 'stored — leave blank to keep' : '(optional)'} autocomplete="off" /></label>
        <label class="space-y-1"><span class="text-xs font-medium">From address</span>
          <Input type="email" bind:value={cfg.from} placeholder="panel@example.com" /></label>
        <label class="space-y-1"><span class="text-xs font-medium">Encryption</span>
          <Select bind:value={cfg.tls} options={tlsOptions} /></label>
      </div>
    {/if}
  </div>
  <div class="kt-panel-footer flex justify-end">
    <Button variant="primary" icon="device-floppy" loading={saving} disabled={loading} onclick={save}>Save SMTP</Button>
  </div>
</div>
