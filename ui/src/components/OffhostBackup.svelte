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
  import GroupButton from './GroupButton.svelte'

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

<div class="panel">
  <div class="panel-head">
    <span class="panel-icon text-primary"><Icon name="cloud" size={17} /></span>
    <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Off-host backups</div>
    {#if status?.running}
      <span class="inline-flex items-center gap-1.5 text-xs text-info"><Icon name="loader-2" size={13} class="animate-spin" />Running…</span>
    {:else if status?.lastTime}
      <span class="inline-flex items-center gap-1.5 text-xs {status.lastOK ? 'text-success' : 'text-destructive'}" title={status.lastOK ? '' : status.lastError}>
        <Icon name={status.lastOK ? 'circle-check' : 'alert-circle'} size={13} />
        Last run {new Date(status.lastTime).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
        · {status.lastOK ? fmtBytes(status.lastSize) : 'failed'}
      </span>
    {:else}
      <span class="text-xs text-muted-foreground">Never run</span>
    {/if}
  </div>
  <div class="space-y-4">
    <p class="text-xs text-muted-foreground">
      Automatically upload the sealed backup to storage you control, so a lost host is recoverable. It's the same passphrase-encrypted file as a manual export — keep the passphrase safe; there is no recovery without it.
    </p>

    {#if loading}
      <div class="text-sm text-muted-foreground">Loading…</div>
    {:else}
      {#if status?.lastTime && !status.lastOK && status.lastError}
        <div class="flex items-start gap-2 rounded-lg bg-destructive/10 px-3 py-2 text-xs text-destructive">
          <Icon name="alert-circle" size={14} class="mt-0.5 shrink-0" /><span class="min-w-0 break-words">Last run failed: {status.lastError}</span>
        </div>
      {/if}

      <!-- Schedule + what goes in -->
      <div class="grid gap-4 lg:grid-cols-2">
        <div class="space-y-3 rounded-lg border border-border p-3">
          <div class="flex items-center justify-between gap-3">
            <div>
              <div class="text-sm font-medium text-foreground">Daily backup</div>
              <div class="text-[11px] text-muted-foreground">Runs every day at the hour below</div>
            </div>
            <Checkbox variant="switch" checked={cfg.enabled} onchange={(e) => (cfg.enabled = e.target.checked)} aria-label="Daily backup" />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <Select label="Time" bind:value={cfg.hour} options={hourOptions} />
            <Select label="Keep" bind:value={cfg.keepN} options={keepOptions} />
          </div>
        </div>
        <div class="space-y-3 rounded-lg border border-border p-3">
          <Input label="Backup passphrase" type="password" bind:value={passphrase} prefixIcon="lock"
            placeholder={hasStoredPass ? 'stored — leave blank to keep' : 'at least 16 characters, 6+ different'} autocomplete="new-password" />
          <div class="flex flex-wrap gap-x-4 gap-y-2">
            <Checkbox checked={cfg.includeUsers} label="Include admin users" onchange={(e) => (cfg.includeUsers = e.target.checked)} />
            <Checkbox checked={cfg.includeFleet} label="Include fleet" onchange={(e) => (cfg.includeFleet = e.target.checked)} />
          </div>
        </div>
      </div>

      <!-- Destinations -->
      <div class="space-y-3">
        <div class="flex items-center gap-3">
          <h4 class="flex min-w-0 flex-1 items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground after:h-px after:flex-1 after:bg-border">
            Destinations <span class="font-normal normal-case tracking-normal">{cfg.destinations.length}</span>
          </h4>
          <button type="button" class="link-action" onclick={() => addDest('s3')}><Icon name="plus" size={12} />S3 bucket</button>
          <button type="button" class="link-action" onclick={() => addDest('sftp')}><Icon name="plus" size={12} />SFTP server</button>
        </div>

        {#if cfg.destinations.length === 0}
          <div class="flex items-center gap-3 rounded-lg border border-dashed border-border px-4 py-4 text-sm text-muted-foreground">
            <Icon name="cloud" size={18} class="shrink-0" />No destinations yet — add an S3 bucket or an SFTP server.
          </div>
        {/if}

        {#each cfg.destinations as d (d.id)}
          <div class="rounded-lg border border-border">
            <div class="flex items-center gap-2 border-b border-border px-3 py-2">
              <span class="grid h-7 w-7 shrink-0 place-items-center rounded-md bg-info/10 text-info"><Icon name={d.type === 's3' ? 'cloud' : 'server'} size={14} /></span>
              <div class="min-w-0 flex-1"><Input bind:value={d.name} placeholder="Name" aria-label="Destination name" /></div>
              <span class="kt-badge kt-badge-outline text-[10px] uppercase">{d.type}</span>
              <div class="btn-group shrink-0">
                <GroupButton icon="plug-connected" tone="primary" tooltip="Test connection" onclick={() => test(d)} />
                <GroupButton icon="list" tooltip="List backups" disabled={listingBusy[d.id]} onclick={() => listBackups(d)} />
                <GroupButton icon="trash" tone="destructive" tooltip="Remove destination" onclick={() => removeDest(d.id)} />
              </div>
            </div>
            <div class="space-y-3 p-3">
              {#if d.type === 's3'}
                <div class="grid gap-3 sm:grid-cols-2">
                  <Input label="Endpoint" bind:value={d.endpoint} placeholder="s3.amazonaws.com" prefixIcon="world" />
                  <Input label="Bucket" bind:value={d.bucket} placeholder="my-backups" prefixIcon="database" />
                  <Input label="Region" bind:value={d.region} placeholder="optional" prefixIcon="map-pin" />
                  <Input label="Folder" bind:value={d.prefix} placeholder="optional" prefixIcon="folder" />
                  <Input label="Access key" bind:value={d.accessKey} prefixIcon="key" autocomplete="off" />
                  <Input label="Secret key" type="password" value={isRedacted(d.secretKey) ? '' : d.secretKey} oninput={(e) => (d.secretKey = e.target.value)}
                    placeholder={isRedacted(d.secretKey) ? 'stored — leave blank to keep' : ''} prefixIcon="lock" autocomplete="off" />
                </div>
                <Checkbox checked={d.useSSL} label="Use TLS (https)" onchange={(e) => (d.useSSL = e.target.checked)} />
              {:else}
                <div class="grid gap-3 sm:grid-cols-[1fr_7rem]">
                  <Input label="Host" bind:value={d.host} placeholder="backup.example.com" prefixIcon="server" />
                  <Input label="Port" type="number" bind:value={d.port} placeholder="22" prefixIcon="plug" />
                </div>
                <div class="grid gap-3 sm:grid-cols-2">
                  <Input label="User" bind:value={d.user} prefixIcon="user" autocomplete="off" />
                  <Input label="Remote folder" bind:value={d.path} placeholder="optional" prefixIcon="folder" />
                  <Input label="Password" type="password" value={isRedacted(d.password) ? '' : d.password} oninput={(e) => (d.password = e.target.value)}
                    placeholder={isRedacted(d.password) ? 'stored — leave blank to keep' : 'or use a key'} prefixIcon="lock" autocomplete="off" />
                  <Input label="Private key" type="password" value={isRedacted(d.privateKey) ? '' : d.privateKey} oninput={(e) => (d.privateKey = e.target.value)}
                    placeholder={isRedacted(d.privateKey) ? 'stored — leave blank to keep' : 'PEM, optional'} prefixIcon="key" autocomplete="off" />
                </div>
                {#if d.hostKey}<p class="flex items-center gap-1.5 truncate text-[11px] text-muted-foreground"><Icon name="lock" size={11} class="shrink-0" />Host key pinned: <span class="truncate font-mono">{d.hostKey}</span></p>{/if}
              {/if}

              {#if listing[d.id]}
                <div class="rounded-md border border-border">
                  {#if listing[d.id].length === 0}
                    <p class="px-3 py-2 text-xs text-muted-foreground">No backups at this destination yet.</p>
                  {:else}
                    <div class="divide-y divide-border">
                      {#each listing[d.id] as a}
                        <div class="flex items-center justify-between gap-2 px-3 py-1.5 text-xs">
                          <span class="truncate font-mono">{a.name}</span>
                          <span class="flex shrink-0 items-center gap-2">
                            <span class="tabular-nums text-muted-foreground">{fmtBytes(a.size)}</span>
                            <Button variant="ghost" size="xs" icon="refresh-alert" onclick={() => restore(d, a)}>Restore</Button>
                          </span>
                        </div>
                      {/each}
                    </div>
                  {/if}
                </div>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
  <div class="panel-foot justify-between">
    <Button variant="outline" icon="player-play" loading={running} disabled={loading} onclick={runNow}>Back up now</Button>
    <Button variant="primary" icon="device-floppy" loading={saving} disabled={loading} onclick={save}>Save settings</Button>
  </div>
</div>
