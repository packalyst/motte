<script>
  // Off-host backups: schedule + destinations (S3/SFTP) for the sealed backup bundle, plus a
  // manual run and a step-up-guarded restore. Secrets are write-only — the server returns a
  // redacted placeholder for a stored secret and preserves it on save unless the field is changed.
  import { onMount } from 'svelte'
  import { apiGet, apiPut, apiPost, toast, confirm, stepUpConfirm } from '../stores/app.js'
  import { formatBytes } from '$lib/utils/format.js'
  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import DropdownButton from './DropdownButton.svelte'
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
  let open = $state({}) // destId -> its form is shown
  let savedIds = $state(new Set()) // destinations the server has (listing needs a saved one)
  let savedSnapshot = $state('') // the payload as last loaded/saved, to tell unsaved changes

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
      markSaved()
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

  // What the server holds now: its destination ids, and the payload to compare edits against.
  function markSaved() {
    savedIds = new Set(cfg.destinations.map((d) => d.id))
    rememberStored()
    savedSnapshot = JSON.stringify(payload())
  }
  const dirty = $derived(!loading && JSON.stringify(payload()) !== savedSnapshot)

  function addDest(type) {
    const id = (crypto.randomUUID?.() || String(Date.now()))
    const base = { id, type, name: type === 's3' ? 'S3 bucket' : 'SFTP server' }
    cfg.destinations = [...cfg.destinations, type === 's3'
      ? { ...base, endpoint: '', region: '', bucket: '', prefix: '', accessKey: '', secretKey: '', useSSL: true }
      : { ...base, host: '', port: 22, user: '', password: '', privateKey: '', path: '', hostKey: '' }]
    open[id] = true
  }

  async function removeDest(d) {
    const ok = await confirm({
      title: 'Remove destination',
      message: `Remove ${d.name || 'this destination'}?`,
      description: savedIds.has(d.id)
        ? 'It stops getting new backups once you save. Backups already stored there are not deleted.'
        : "It hasn't been saved yet, so nothing changes on the server.",
      confirmText: 'Remove',
    })
    if (!ok) return
    cfg.destinations = cfg.destinations.filter((x) => x.id !== d.id)
    delete open[d.id]
    delete listing[d.id]
  }

  // Where a destination sends backups, in one line.
  function summary(d) {
    const where = d.type === 's3'
      ? [d.endpoint, d.bucket, d.prefix].filter(Boolean).join(' / ')
      : d.host && `${d.user ? d.user + '@' : ''}${d.host}:${d.port || 22}${d.path ? ' ' + d.path : ''}`
    return where || 'Not set up yet'
  }

  // A stored secret shows as an empty field: typing replaces it, and emptying the field again
  // keeps the stored one (never clears it by accident).
  function setSecret(d, key, value) {
    d[key] = value === '' && storedSecret(d.id, key) ? REDACTED : value
  }
  let storedKeys = $state(new Set()) // "id:key" of secrets the server holds
  const storedSecret = (id, key) => storedKeys.has(id + ':' + key)
  function rememberStored() {
    storedKeys = new Set(cfg.destinations.flatMap((d) => ['secretKey', 'password', 'privateKey'].filter((k) => isRedacted(d[k])).map((k) => d.id + ':' + k)))
  }

  // Resolve a write-only secret for the save payload: a blank field keeps the stored value.
  function payload() {
    const pass = passphrase !== '' ? passphrase : (hasStoredPass ? REDACTED : '')
    return { ...cfg, hour: Number(cfg.hour), keepN: Number(cfg.keepN), passphrase: pass }
  }

  async function save() {
    const url = '/api/backup/offhost/config'
    const su = await stepUpConfirm({ title: 'Save off-host backup config', description: 'This sets the passphrase + destination a scheduled full export uses. Re-authenticate to save.',
      action: { method: 'PUT', url } })
    if (!su?.proof) return
    saving = true
    try {
      const saved = await apiPut(url, { ...payload(), ...su.proof })
      hasStoredPass = isRedacted(saved.passphrase)
      passphrase = ''
      cfg.destinations = saved.destinations || []
      markSaved()
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
      if (r.hostKey) d.hostKey = r.hostKey // only sent for a server with no pinned key yet: pinned on save
    } catch (e) {
      toast(e.message || 'Test failed', 'error')
    }
  }

  async function runNow() {
    const url = '/api/backup/offhost/run'
    const su = await stepUpConfirm({ title: 'Run off-host backup now', description: 'This exports decrypted secrets to the destination. Re-authenticate to run.',
      action: { method: 'POST', url } })
    if (!su?.proof) return
    running = true
    try {
      await apiPost(url, su.proof)
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

  // A second click closes the list.
  async function listBackups(d) {
    if (listing[d.id]) { delete listing[d.id]; return }
    listingBusy = { ...listingBusy, [d.id]: true }
    try {
      listing = { ...listing, [d.id]: await apiGet('/api/backup/offhost/list?dest=' + encodeURIComponent(d.id)) }
    } catch (e) {
      toast(e.message || 'Could not list backups', 'error')
    } finally {
      listingBusy = { ...listingBusy, [d.id]: false }
    }
  }

  const RESTORE_URL = '/api/backup/offhost/restore'
  async function restore(d, archive) {
    const su = await stepUpConfirm({
      title: 'Restore from backup',
      message: `Restore ${archive.name} from "${d.name}"? This REPLACES this panel's configuration (and admin users / fleet if the backup includes them), then re-applies firewall, WireGuard and ACL state. It cannot be undone.`,
      confirmText: 'Restore',
      variant: 'destructive',
      action: { method: 'POST', url: RESTORE_URL },
    })
    if (!su?.proof) return
    try {
      const res = await apiPost(RESTORE_URL, { dest: d.id, name: archive.name, ...su.proof })
      toast('Restore applied' + (res.reconciled?.length ? ' — reconciled ' + res.reconciled.join(', ') : ''), 'success')
    } catch (e) {
      toast(e.message || 'Restore failed', 'error')
    }
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
        · {status.lastOK ? formatBytes(status.lastSize) : 'failed'}
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
          {@const isOpen = !!open[d.id]}
          {@const canList = savedIds.has(d.id)}
          {@const shown = listing[d.id]}
          <div class="rounded-lg border border-border">
            <!-- the card: type, name and where it goes; the form and the backup list open under it -->
            <div class="flex items-center gap-3 px-3 py-2.5">
              <span class="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-info/10 text-info"><Icon name={d.type === 's3' ? 'cloud' : 'server'} size={16} /></span>
              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2">
                  <span class="min-w-0 truncate text-sm font-semibold text-foreground">{d.name || 'Unnamed'}</span>
                  <Badge variant="secondary" size="sm">{d.type.toUpperCase()}</Badge>
                  {#if !canList}<Badge variant="warning" size="sm">Not saved</Badge>{/if}
                </div>
                <div class="truncate font-mono text-[11px] text-muted-foreground">{summary(d)}</div>
              </div>
              <!-- phone: open/close, and the rest behind ⋯ -->
              <div class="kt-btn-group shrink-0 sm:hidden">
                <Button variant="outline" size="xs" icon="chevron-down" iconClass="transition-transform {isOpen ? 'rotate-180' : ''}"
                  aria-label={`${isOpen ? 'Close' : 'Edit'} ${d.name}`} aria-expanded={isOpen} onclick={() => (open[d.id] = !isOpen)} />
                <DropdownButton variant="outline" size="xs" ariaLabel={`Actions for ${d.name}`} items={[
                  { label: 'Test connection', icon: 'plug-connected', onclick: () => test(d) },
                  { label: shown ? 'Hide backups' : 'List backups', icon: 'list', disabled: !canList || listingBusy[d.id], onclick: () => listBackups(d) },
                  { label: 'Remove', icon: 'trash', variant: 'destructive', onclick: () => removeDest(d) },
                ]} />
              </div>
              <!-- desktop: test, list, remove and open/close as one group -->
              <div class="kt-btn-group hidden shrink-0 sm:flex">
                <Button variant="outline" size="xs" icon="plug-connected" class="text-primary hover:bg-primary/10" tooltip="Test connection" aria-label={`Test connection to ${d.name}`} onclick={() => test(d)} />
                <Button variant="outline" size="xs" icon="list" class={shown ? 'bg-primary/15' : ''} tooltip={canList ? (shown ? 'Hide backups' : 'List backups') : 'Save first to list its backups'}
                  aria-label={`Backups on ${d.name}`} aria-pressed={!!shown} disabled={!canList || listingBusy[d.id]} onclick={() => listBackups(d)} />
                <Button variant="outline" size="xs" icon="trash" class="text-destructive hover:bg-destructive/10" tooltip="Remove destination" aria-label={`Remove ${d.name}`} onclick={() => removeDest(d)} />
                <Button variant="outline" size="xs" icon="chevron-down" iconClass="transition-transform {isOpen ? 'rotate-180' : ''}"
                  tooltip={isOpen ? 'Close' : 'Edit'} aria-label={`${isOpen ? 'Close' : 'Edit'} ${d.name}`} aria-expanded={isOpen} onclick={() => (open[d.id] = !isOpen)} />
              </div>
            </div>

            {#if shown}
              <!-- the backups stored there -->
              <div class="border-t border-dashed border-border">
                {#if shown.length === 0}
                  <p class="px-3 py-2.5 text-xs text-muted-foreground">No backups at this destination yet.</p>
                {:else}
                  <div class="divide-y divide-border">
                    {#each shown as a}
                      <div class="flex items-center justify-between gap-2 px-3 py-1.5 text-xs">
                        <span class="truncate font-mono">{a.name}</span>
                        <span class="flex shrink-0 items-center gap-2">
                          <span class="tabular-nums text-muted-foreground">{formatBytes(a.size)}</span>
                          <Button variant="ghost" size="xs" icon="refresh-alert" onclick={() => restore(d, a)}>Restore</Button>
                        </span>
                      </div>
                    {/each}
                  </div>
                {/if}
              </div>
            {/if}

            {#if isOpen}
              <div class="space-y-3 border-t border-dashed border-border bg-muted/10 p-3">
                <Input label="Name" bind:value={d.name} placeholder="e.g. Offsite bucket" prefixIcon="tag" />
                {#if d.type === 's3'}
                  <div class="grid gap-3 sm:grid-cols-2">
                    <Input label="Endpoint" bind:value={d.endpoint} placeholder="s3.amazonaws.com" prefixIcon="world" />
                    <Input label="Bucket" bind:value={d.bucket} placeholder="my-backups" prefixIcon="database" />
                    <Input label="Region" bind:value={d.region} placeholder="optional" prefixIcon="map-pin" />
                    <Input label="Folder" bind:value={d.prefix} placeholder="optional" prefixIcon="folder" />
                    <Input label="Access key" bind:value={d.accessKey} prefixIcon="key" autocomplete="off" />
                    <Input label="Secret key" type="password" value={isRedacted(d.secretKey) ? '' : d.secretKey} oninput={(e) => setSecret(d, 'secretKey', e.target.value)}
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
                    <Input label="Password" type="password" value={isRedacted(d.password) ? '' : d.password} oninput={(e) => setSecret(d, 'password', e.target.value)}
                      placeholder={isRedacted(d.password) ? 'stored — leave blank to keep' : 'or use a key'} prefixIcon="lock" autocomplete="off" />
                    <Input label="Private key" type="password" value={isRedacted(d.privateKey) ? '' : d.privateKey} oninput={(e) => setSecret(d, 'privateKey', e.target.value)}
                      placeholder={isRedacted(d.privateKey) ? 'stored — leave blank to keep' : 'PEM, optional'} prefixIcon="key" autocomplete="off" />
                  </div>
                  {#if d.hostKey}<p class="flex items-center gap-1.5 truncate text-[11px] text-muted-foreground"><Icon name="lock" size={11} class="shrink-0" />Host key pinned: <span class="truncate font-mono">{d.hostKey}</span></p>{/if}
                {/if}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>
  <div class="panel-foot justify-between">
    <Button variant="outline" icon="player-play" loading={running} disabled={loading} onclick={runNow}>Back up now</Button>
    <div class="flex items-center gap-3">
      {#if dirty}<span class="text-xs text-warning">Unsaved changes</span>{/if}
      <Button variant="primary" icon="device-floppy" loading={saving} disabled={loading} onclick={save}>Save settings</Button>
    </div>
  </div>
</div>
