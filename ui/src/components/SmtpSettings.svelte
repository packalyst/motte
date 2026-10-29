<script>
  // Global SMTP settings (admin) — the mail server used to deliver per-user alert emails. The
  // password is write-only: a redacted placeholder is kept on save unless changed. A test email
  // uses the SAVED settings, so it's offered once changes are saved. Per-user alert rules and the
  // choice to receive email live in Profile → Notifications.
  import { onMount } from 'svelte'
  import { apiGet, apiPut, apiPost, toast } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Input from './Input.svelte'
  import Select from './Select.svelte'

  const REDACTED = '__stored__'

  let cfg = $state({ host: '', port: '587', user: '', pass: '', from: '', tls: 'starttls' })
  let saved = $state('') // the saved form, to tell unsaved changes apart
  let passInput = $state('')
  let hasStoredPass = $state(false)
  let loading = $state(true)
  let saving = $state(false)
  let testTo = $state('')
  let testing = $state(false)
  let testResult = $state(null) // { ok, text }

  const tlsOptions = [
    { value: 'starttls', label: 'STARTTLS (587)' },
    { value: 'tls', label: 'TLS (465)' },
    { value: 'none', label: 'None (plaintext)' },
  ]
  const snapshot = () => JSON.stringify({ ...cfg, pass: '' })
  const dirty = $derived(!loading && (snapshot() !== saved || passInput !== ''))
  const configured = $derived(!!(cfg.host && cfg.from))
  const canTest = $derived(configured && !dirty) // a test uses the saved settings

  onMount(async () => {
    try {
      const [c, ch] = await Promise.all([apiGet('/api/pwa/smtp'), apiGet('/api/pwa/channels').catch(() => null)])
      if (c) {
        cfg = { ...cfg, ...c, pass: '' }
        hasStoredPass = c.pass === REDACTED
      }
      testTo = ch?.email || ''
      saved = snapshot()
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
      await apiPut('/api/pwa/smtp', { ...cfg, pass })
      hasStoredPass = hasStoredPass || passInput !== ''
      passInput = ''
      saved = snapshot()
      toast('Email settings saved', 'success')
    } catch (e) {
      toast(e.message || 'Save failed', 'error')
    } finally {
      saving = false
    }
  }

  async function sendTest() {
    testing = true
    testResult = null
    try {
      const r = await apiPost('/api/pwa/smtp/test', { to: testTo.trim() })
      testResult = { ok: true, text: `Sent to ${r.sent_to} — check the inbox (and spam folder).` }
    } catch (e) {
      testResult = { ok: false, text: e.message || 'Sending failed' }
    } finally {
      testing = false
    }
  }
</script>

<div class="panel">
  <div class="panel-head">
    <span class="panel-icon text-primary"><Icon name="mail" size={17} /></span>
    <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Email (SMTP)</div>
  </div>
  <div class="space-y-3">
    {#if loading}
      <div class="text-sm text-muted-foreground">Loading…</div>
    {:else}
      <div class="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_8rem]">
        <Input label="Host" bind:value={cfg.host} placeholder="smtp.example.com" prefixIcon="server" />
        <Input label="Port" bind:value={cfg.port} placeholder="587" prefixIcon="plug" />
      </div>
      <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Select label="Encryption" bind:value={cfg.tls} options={tlsOptions} />
        <Input label="From address" type="email" bind:value={cfg.from} placeholder="panel@example.com" prefixIcon="mail" />
        <Input label="Username" bind:value={cfg.user} placeholder="optional" prefixIcon="user" autocomplete="off" />
        <Input label="Password" type="password" bind:value={passInput} placeholder={hasStoredPass ? 'stored — leave blank to keep' : 'optional'} prefixIcon="lock" autocomplete="new-password" />
      </div>
      <p class="text-[11px] text-muted-foreground">Each person chooses whether to receive alert emails, and their address, in Profile → Notifications.</p>

      <div class="space-y-2 border-t border-dashed border-border pt-3">
        <form class="flex flex-col gap-2 sm:flex-row sm:items-end" onsubmit={(e) => { e.preventDefault(); sendTest() }}>
          <div class="min-w-0 flex-1">
            <Input label="Send a test email to" type="email" bind:value={testTo} placeholder="you@example.com" prefixIcon="send" disabled={!canTest} />
          </div>
          <Button type="submit" variant="outline" icon="send" loading={testing} disabled={!canTest || !testTo.trim()}>Send test</Button>
        </form>
        {#if dirty}
          <p class="text-[11px] text-warning flex items-center gap-1.5"><Icon name="alert-triangle" size={12} />Save your changes first — the test uses the saved settings.</p>
        {:else if !configured}
          <p class="text-[11px] text-muted-foreground">Set a host and a From address first.</p>
        {/if}
        {#if testResult}
          <div class="flex items-start gap-2 rounded-lg px-3 py-2 text-xs {testResult.ok ? 'bg-success/10 text-success' : 'bg-destructive/10 text-destructive'}">
            <Icon name={testResult.ok ? 'circle-check' : 'alert-circle'} size={14} class="mt-0.5 shrink-0" />
            <span class="min-w-0 break-words">{testResult.text}</span>
          </div>
        {/if}
      </div>
    {/if}
  </div>
  <div class="panel-foot justify-end">
    <Button variant="primary" icon="device-floppy" loading={saving} disabled={loading || !dirty} onclick={save}>Save</Button>
  </div>
</div>
