<script>
  // Off-host backups: schedule + destinations (S3/SFTP) for the sealed backup bundle, plus a
  // manual run and a step-up-guarded restore. Secrets are write-only — the server returns a
  // redacted placeholder for a stored secret and preserves it on save unless the field is changed.
  import { onMount } from 'svelte'
  import { apiGet, apiPut, apiPost, toast, confirm, stepUpConfirm } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Input from './Input.svelte'
  import Select from './Select.svelte'
  import Checkbox from './Checkbox.svelte'

  const REDACTED = '__stored__'
  const isRedacted = (v) => v === REDACTED

  let cfg = $state({ enabled: false, hour: 3, includeUsers: false, includeFleet: false, keepN: 14, destinations: [] })
  let passphrase = $state('')
  let hasStoredPass = $state(false)
  let status = $state(null)
  let loading = $state(true)
  let saving = $state(false)
  let running = $state(false)
  let listing = $state({}) // destId -> array of archives
  let listingBusy = $state({})

  const hourOptions = Array.from({ length: 24 }, (_, h) => ({ value: String(h), label: `${String(h).padStart(2, '0')}:00` }))
  const keepOptions = [5, 7, 14, 30, 60].map((n) => ({ value: String(n), label: `${n} copies` }))

  onMount(load)

  async function load() {
    loading = true
    try {
      const c = await apiGet('/api/backup/offhost/config')
      hasStoredPass = isRedacted(c.passphrase)
      passphrase = ''
      cfg = { enabled: !!c.enabled, hour: c.hour ?? 3, includeUsers: !!c.includeUsers, includeFleet: !!c.includeFleet, keepN: c.keepN ?? 14, destinations: c.destinations || [] }
      await refreshStatus()
    } catch (e) {
      toast(e.message || 'Could not load off-host config', 'error')
    } finally {
      loading = false
    }
  }

  async function refreshStatus() {
    try { status = await apiGet('/api/backup/offhost/status') } catch { /* ignore */ }
  }

  function addDest(type) {
    const id = (crypto.randomUUID?.() || String(Date.now()))
    const base = { id, type, name: type === 's3' ? 'S3 bucket' : 'SFTP server' }
    cfg.destinations = [...cfg.destinations, type === 's3'
      ? { ...base, endpoint: '', region: '', bucket: '', prefix: '', accessKey: '', secretKey: '', useSSL: true }
      : { ...base, host: '', port: 22, user: '', password: '', privateKey: '', path: '', hostKey: '' }]
  }

  function removeDest(id) {
    cfg.destinations = cfg.destinations.filter((d) => d.id !== id)
  }

  // Resolve a write-only secret for the save payload: a blank field keeps the stored value.
  function payload() {
    const pass = passphrase !== '' ? passphrase : (hasStoredPass ? REDACTED : '')
    return { ...cfg, hour: Number(cfg.hour), keepN: Number(cfg.keepN), passphrase: pass }
  }

  async function save() {
    const su = await stepUpConfirm({ title: 'Save off-host backup config', description: 'This sets the passphrase + destination a scheduled full export uses. Re-authenticate to save.' })
    if (!su?.confirmed) return
    saving = true
    try {
      const saved = await apiPut('/api/backup/offhost/config', { ...payload(), currentPassword: su.password, totpCode: su.totp })
      hasStoredPass = isRedacted(saved.passphrase)
      passphrase = ''
      cfg.destinations = saved.destinations || []
      toast('Off-host backup settings saved', 'success')
    } catch (e) {
      toast(e.message || 'Save failed', 'error')
    } finally {
      saving = false
    }
  }

  async function test(d) {
    try {
      const r = await apiPost('/api/backup/offhost/test', d)
      toast(`Reached "${d.name}" — ${r.existing} existing backup(s)${r.hostKey ? ', host key pinned' : ''}`, 'success')
      if (r.hostKey && !d.hostKey) d.hostKey = r.hostKey
    } catch (e) {
      toast(e.message || 'Test failed', 'error')
    }
  }

  async function runNow() {
    const su = await stepUpConfirm({ title: 'Run off-host backup now', description: 'This exports decrypted secrets to the destination. Re-authenticate to run.' })
    if (!su?.confirmed) return
    running = true
    try {
      await apiPost('/api/backup/offhost/run', { currentPassword: su.password, totpCode: su.totp })
      toast('Backup started — this runs in the background', 'success')
      // Poll status a few times so the card reflects completion.
      for (let i = 0; i < 10; i++) {
        await new Promise((r) => setTimeout(r, 2000))
        await refreshStatus()
        if (status && !status.running) break
      }
    } catch (e) {
      toast(e.message || 'Could not start backup', 'error')
    } finally {
      running = false
    }
  }

  async function listBackups(d) {
    listingBusy = { ...listingBusy, [d.id]: true }
    try {
      listing = { ...listing, [d.id]: await apiGet('/api/backup/offhost/list?dest=' + encodeURIComponent(d.id)) }
    } catch (e) {
      toast(e.message || 'Could not list backups', 'error')
    } finally {
      listingBusy = { ...listingBusy, [d.id]: false }
    }
  }

  async function restore(d, archive) {
    const su = await stepUpConfirm({
      title: 'Restore from backup',
      message: `Restore ${archive.name} from "${d.name}"? This REPLACES this panel's configuration (and admin users / fleet if the backup includes them), then re-applies firewall, WireGuard and ACL state. It cannot be undone.`,
      confirmText: 'Restore',
      variant: 'destructive',
    })
    if (!su?.confirmed || !su?.password) return
    try {
      const res = await apiPost('/api/backup/offhost/restore', {
        dest: d.id, name: archive.name, currentPassword: su.password, totpCode: su.totp || '',
      })
      toast('Restore applied' + (res.reconciled?.length ? ' — reconciled ' + res.reconciled.join(', ') : ''), 'success')
    } catch (e) {
      toast(e.message || 'Restore failed', 'error')
    }
  }

  function fmtBytes(n) {
    if (!n) return '0 B'
    const u = ['B', 'KB', 'MB', 'GB']; let i = 0; let v = n
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++ }
    return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`
  }
</script>

<div class="kt-panel">
  <div class="kt-panel-header">
    <h3 class="kt-panel-title"><Icon name="cloud" size={16} /> Off-host backups</h3>
  </div>
  <div class="kt-panel-body space-y-4">
    <p class="text-xs text-muted-foreground">
      Automatically upload the sealed backup to storage you control, so a lost host is recoverable. The archive is the same passphrase-encrypted file as a manual export — keep the passphrase safe; there is no recovery without it.
    </p>

    {#if loading}
      <div class="text-sm text-muted-foreground">Loading…</div>
    {:else}
      <!-- Schedule + policy -->
      <div class="grid sm:grid-cols-2 gap-3">
        <div class="space-y-1.5">
          <Checkbox checked={cfg.enabled} label="Run a daily backup" onchange={(e) => (cfg.enabled = e.target.checked)} />
          <div class="flex items-center gap-2">
            <span class="text-xs text-muted-foreground">at</span>
            <Select bind:value={cfg.hour} options={hourOptions} />
            <span class="text-xs text-muted-foreground">keep</span>
            <Select bind:value={cfg.keepN} options={keepOptions} />
          </div>
        </div>
        <div class="space-y-1.5">
          <label class="text-sm font-medium" for="oh-pass">Backup passphrase</label>
          <Input id="oh-pass" type="password" bind:value={passphrase} placeholder={hasStoredPass ? 'stored — leave blank to keep' : 'at least 16 chars, 6+ distinct'} autocomplete="new-password" />
          <div class="flex gap-3 pt-1">
            <Checkbox checked={cfg.includeUsers} label="Include admin users" onchange={(e) => (cfg.includeUsers = e.target.checked)} />
            <Checkbox checked={cfg.includeFleet} label="Include fleet" onchange={(e) => (cfg.includeFleet = e.target.checked)} />
          </div>
        </div>
      </div>

      <!-- Destinations -->
      <div class="space-y-3">
        <div class="flex items-center justify-between">
          <span class="text-sm font-medium">Destinations</span>
          <div class="flex gap-2">
            <Button variant="outline" size="xs" icon="plus" onclick={() => addDest('s3')}>S3</Button>
            <Button variant="outline" size="xs" icon="plus" onclick={() => addDest('sftp')}>SFTP</Button>
          </div>
        </div>

        {#if cfg.destinations.length === 0}
          <p class="text-xs text-muted-foreground">No destinations yet — add an S3 bucket or an SFTP server.</p>
        {/if}

        {#each cfg.destinations as d (d.id)}
          <div class="rounded-md border border-border p-3 space-y-2">
            <div class="flex items-center gap-2">
              <span class="kt-badge kt-badge-outline text-[10px] uppercase">{d.type}</span>
              <Input bind:value={d.name} placeholder="Label" class="flex-1" />
              <Button variant="ghost" size="xs" icon="trash" iconOnly onclick={() => removeDest(d.id)} />
            </div>

            {#if d.type === 's3'}
              <div class="grid sm:grid-cols-2 gap-2">
                <Input bind:value={d.endpoint} placeholder="endpoint (s3.amazonaws.com)" />
                <Input bind:value={d.bucket} placeholder="bucket" />
                <Input bind:value={d.region} placeholder="region (optional)" />
                <Input bind:value={d.prefix} placeholder="prefix / folder (optional)" />
                <Input bind:value={d.accessKey} placeholder="access key" autocomplete="off" />
                <Input type="password" value={isRedacted(d.secretKey) ? '' : d.secretKey} oninput={(e) => (d.secretKey = e.target.value)} placeholder={isRedacted(d.secretKey) ? 'secret key — unchanged' : 'secret key'} autocomplete="off" />
              </div>
              <Checkbox checked={d.useSSL} label="Use TLS (https)" onchange={(e) => (d.useSSL = e.target.checked)} />
            {:else}
              <div class="grid sm:grid-cols-2 gap-2">
                <Input bind:value={d.host} placeholder="host" />
                <Input type="number" bind:value={d.port} placeholder="22" />
                <Input bind:value={d.user} placeholder="user" autocomplete="off" />
                <Input bind:value={d.path} placeholder="remote path (optional)" />
                <Input type="password" value={isRedacted(d.password) ? '' : d.password} oninput={(e) => (d.password = e.target.value)} placeholder={isRedacted(d.password) ? 'password — unchanged' : 'password (or use a key)'} autocomplete="off" />
                <Input type="password" value={isRedacted(d.privateKey) ? '' : d.privateKey} oninput={(e) => (d.privateKey = e.target.value)} placeholder={isRedacted(d.privateKey) ? 'private key — unchanged' : 'private key PEM (optional)'} autocomplete="off" />
              </div>
              {#if d.hostKey}<p class="text-[10px] text-muted-foreground truncate">host key pinned: {d.hostKey}</p>{/if}
            {/if}

            <div class="flex items-center gap-2 pt-1">
              <Button variant="outline" size="xs" icon="plug-connected" onclick={() => test(d)}>Test</Button>
              <Button variant="outline" size="xs" icon="list" loading={listingBusy[d.id]} onclick={() => listBackups(d)}>List backups</Button>
            </div>

            {#if listing[d.id]}
              {#if listing[d.id].length === 0}
                <p class="text-xs text-muted-foreground">No backups at this destination yet.</p>
              {:else}
                <div class="divide-y divide-border">
                  {#each listing[d.id] as a}
                    <div class="flex items-center justify-between gap-2 py-1 text-xs">
                      <span class="font-mono truncate">{a.name}</span>
                      <span class="flex items-center gap-2 shrink-0">
                        <span class="tabular-nums text-muted-foreground">{fmtBytes(a.size)}</span>
                        <Button variant="ghost" size="xs" icon="refresh-alert" onclick={() => restore(d, a)}>Restore</Button>
                      </span>
                    </div>
                  {/each}
                </div>
              {/if}
            {/if}
          </div>
        {/each}
      </div>

      {#if status?.lastTime}
        <div class="text-xs {status.lastOK ? 'text-muted-foreground' : 'text-destructive'}">
          Last run: {new Date(status.lastTime).toLocaleString()} — {status.lastOK ? `OK (${fmtBytes(status.lastSize)})` : `failed: ${status.lastError}`}
        </div>
      {/if}
    {/if}
  </div>
  <div class="kt-panel-footer flex items-center justify-between">
    <Button variant="outline" icon="player-play" loading={running} disabled={loading} onclick={runNow}>Back up now</Button>
    <Button variant="primary" icon="device-floppy" loading={saving} disabled={loading} onclick={save}>Save settings</Button>
  </div>
</div>
