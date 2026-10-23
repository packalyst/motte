<script>
  // TeamSettings — panel accounts and roles (Settings → Team, admin-only; the server enforces it).
  import { apiGet, apiPost, toast, stepUpConfirm, currentUser } from '../stores/app.js'
  import Button from './Button.svelte'
  import Select from './Select.svelte'
  import Icon from './Icon.svelte'
  import Modal from './Modal.svelte'
  import Input from './Input.svelte'
  import StepUpFields from './StepUpFields.svelte'

  let me = $state(null)      // current operator (for role-gated options)
  let users = $state([])
  let error = $state('')
  let showAdd = $state(false)

  // Add-user form
  let addUsername = $state('')
  let addPassword = $state('')
  let addRole = $state('viewer')
  let addCurrentPw = $state('')
  let addTotp = $state('')
  let addBusy = $state(false)

  // Scope editor
  let scopeUser = $state(null)
  let scopeKind = $state('all')
  let scopeValues = $state('')
  let scopeCurrentPw = $state('')
  let scopeTotp = $state('')
  let scopeBusy = $state(false)

  // Whether the signed-in operator has 2FA — step-up then also needs a fresh authenticator code.
  const needsTotp = $derived(!!$currentUser?.totpEnabled)
  const totpOk = (v) => !needsTotp || v.length === 6
  const scopeKindOptions = [
    { value: 'all', label: 'All machines' },
    { value: 'tag', label: 'By tag' },
    { value: 'host', label: 'By machine ID' },
  ]

  const ROLE_BADGE = {
    owner:    'bg-destructive/10 text-destructive',
    admin:    'bg-primary/10 text-primary',
    operator: 'bg-warning/10 text-warning',
    viewer:   'bg-muted text-muted-foreground',
  }
  const ROLE_DESC = {
    owner:    'Full control, incl. managing admins. Always at least one.',
    admin:    'Full control except managing owners/admins.',
    operator: 'Operational actions (fleet, firewall) within scope.',
    viewer:   'Read-only.',
  }

  // Roles the current operator may assign: only an owner may grant owner/admin.
  const assignableRoles = $derived(
    me?.role === 'owner'
      ? ['owner', 'admin', 'operator', 'viewer']
      : ['operator', 'viewer']
  )
  const roleOptions = $derived(assignableRoles.map(r => ({ value: r, label: r[0].toUpperCase() + r.slice(1) })))

  function scopeLabel(u) {
    if (u.role === 'owner' || u.role === 'admin') return 'all machines'
    if (!u.scopeKind || u.scopeKind === 'all') return 'all machines'
    return `${u.scopeKind}: ${u.scopeValues || '—'}`
  }

  async function load() {
    try {
      me = await apiGet('/api/auth/me')
      const res = await apiGet('/api/auth/users')
      users = res.users || []
      error = ''
    } catch (e) {
      error = e?.message || 'Failed to load users'
    }
  }

  // Step-up: prompt for the operator's password (and 2FA code when enabled). Returns
  // { password, totp } or null if cancelled.
  async function stepUp(message) {
    const r = await stepUpConfirm({
      title: 'Confirm your password',
      message,
      confirmText: 'Authorize',
      variant: 'destructive',
    })
    return r?.confirmed && r?.password ? { password: r.password, totp: r.totp || '' } : null
  }

  async function addUser() {
    if (!addUsername.trim() || !addPassword || !addCurrentPw || !totpOk(addTotp)) return
    addBusy = true
    try {
      await apiPost('/api/auth/users', {
        username: addUsername.trim(),
        password: addPassword,
        role: addRole,
        currentPassword: addCurrentPw,
        totpCode: addTotp,
      })
      toast(`User "${addUsername.trim()}" created`, 'success')
      showAdd = false
      addUsername = addPassword = addCurrentPw = addTotp = ''
      addRole = 'viewer'
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      addBusy = false
    }
  }

  async function changeRole(u, role) {
    if (role === u.role) return
    const su = await stepUp(`Change ${u.username}'s role from ${u.role} to ${role}?`)
    if (!su) { await load(); return } // reload to reset the select if cancelled
    try {
      await apiPost('/api/auth/users/role', { user_id: u.id, role, currentPassword: su.password, totpCode: su.totp })
      toast(`${u.username} is now ${role}`, 'success')
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
      await load()
    }
  }

  function openScope(u) {
    scopeUser = u
    scopeKind = u.scopeKind || 'all'
    scopeValues = u.scopeValues || ''
    scopeCurrentPw = ''
    scopeTotp = ''
  }

  async function saveScope() {
    if (!scopeUser || !scopeCurrentPw || !totpOk(scopeTotp)) return
    scopeBusy = true
    try {
      await apiPost('/api/auth/users/scope', {
        user_id: scopeUser.id,
        scope_kind: scopeKind,
        scope_values: scopeKind === 'all' ? '' : scopeValues.trim(),
        currentPassword: scopeCurrentPw,
        totpCode: scopeTotp,
      })
      toast(`Scope updated for ${scopeUser.username}`, 'success')
      scopeUser = null
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      scopeBusy = false
    }
  }

  async function removeUser(u) {
    const su = await stepUp(`Delete the account "${u.username}" (${u.role})? This cannot be undone.`)
    if (!su) return
    try {
      await apiPost('/api/auth/users/delete', { user_id: u.id, currentPassword: su.password, totpCode: su.totp })
      toast(`Deleted ${u.username}`, 'success')
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // Can the current operator modify this target? Owners may touch anyone; others only
  // strictly-lower roles. (The backend enforces this too; this just hides dead controls.)
  function canModify(u) {
    if (!me) return false
    if (me.id === u.id) return false
    if (me.role === 'owner') return true
    const rank = { viewer: 1, operator: 2, admin: 3, owner: 4 }
    return rank[me.role] > rank[u.role]
  }

  $effect(() => { load() })
</script>

<div class="space-y-4">
  <div class="panel">
    <div class="panel-head">
      <span class="panel-icon text-primary"><Icon name="shield-lock" size={17} /></span>
      <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Accounts</div>
      <Button onclick={() => (showAdd = true)} variant="primary" size="sm" icon="plus">Add user</Button>
    </div>
    <div class="space-y-3">
      {#if error}
        <div class="text-xs text-warning flex items-center gap-1.5 py-4">
          <Icon name="alert-triangle" size={13} />{error}
        </div>
      {:else if users.length === 0}
        <div class="text-sm text-muted-foreground py-6 text-center">No users.</div>
      {:else}
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-[11px] uppercase tracking-wide text-muted-foreground border-b border-border">
                <th class="py-2 pr-3 font-medium">User</th>
                <th class="py-2 pr-3 font-medium">Role</th>
                <th class="py-2 pr-3 font-medium">Fleet scope</th>
                <th class="py-2 pr-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-border">
              {#each users as u (u.id)}
                <tr>
                  <td class="py-2.5 pr-3">
                    <span class="font-medium text-foreground">{u.username}</span>
                    {#if me && me.id === u.id}<span class="ml-1.5 text-[11px] text-muted-foreground">(you)</span>{/if}
                  </td>
                  <td class="py-2.5 pr-3">
                    <span class="inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium capitalize {ROLE_BADGE[u.role] || ROLE_BADGE.viewer}" title={ROLE_DESC[u.role] || ''}>{u.role}</span>
                  </td>
                  <td class="py-2.5 pr-3 text-muted-foreground text-xs">{scopeLabel(u)}</td>
                  <td class="py-2.5 pr-3">
                    <div class="flex items-center justify-end gap-2">
                      {#if canModify(u)}
                        <Select
                          value={u.role}
                          options={roleOptions}
                          class="w-28"
                          onchange={(e) => changeRole(u, e.target.value)}
                        />
                        {#if u.role === 'operator' || u.role === 'viewer'}
                          <Button variant="ghost" size="xs" iconOnly icon="filter" onclick={() => openScope(u)} title="Set fleet machine scope" />
                        {/if}
                        <Button variant="ghost-danger" size="xs" iconOnly icon="trash" onclick={() => removeUser(u)} title="Delete user" />
                      {:else}
                        <span class="text-[11px] text-muted-foreground">—</span>
                      {/if}
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </div>
  </div>
</div>

{#if showAdd}
  <Modal open={showAdd} title="Add panel user" size="sm" onclose={() => (showAdd = false)}>
    <div class="space-y-3">
      <Input id="tu-username" label="Username" prefixIcon="user" bind:value={addUsername} placeholder="at least 3 characters" autocomplete="off" />
      <Input id="tu-password" label="Password" type="password" prefixIcon="lock" bind:value={addPassword} placeholder="8+ chars, mixed case, number, symbol" autocomplete="new-password" />
      <Select id="tu-role" label="Role" bind:value={addRole} options={roleOptions} helperText={ROLE_DESC[addRole]} />
      <div class="pt-3 border-t border-border">
        <StepUpFields id="tu-stepup" label="Confirm with your password" bind:password={addCurrentPw} bind:totp={addTotp} {needsTotp} onsubmit={addUser} />
      </div>
    </div>
    {#snippet footer()}
      <Button onclick={() => (showAdd = false)} variant="secondary" disabled={addBusy}>Cancel</Button>
      <Button onclick={addUser} variant="primary" disabled={addBusy || !addUsername.trim() || !addPassword || !addCurrentPw || !totpOk(addTotp)}>
        {#if addBusy}<Icon name="refresh" size={14} class="animate-spin mr-1" />{/if}
        Create user
      </Button>
    {/snippet}
  </Modal>
{/if}

{#if scopeUser}
  <Modal open={!!scopeUser} title="Fleet machine scope — {scopeUser.username}" size="sm" onclose={() => (scopeUser = null)}>
    <div class="space-y-3">
      <p class="text-xs text-muted-foreground">Which fleet machines this user may see and act on. Owners and admins always see all machines.</p>
      <Select id="sc-kind" label="Scope" bind:value={scopeKind} options={scopeKindOptions} />
      {#if scopeKind !== 'all'}
        <Input id="sc-values" label="{scopeKind === 'tag' ? 'Tags' : 'Machine IDs'} (comma-separated)" prefixIcon="filter"
          bind:value={scopeValues} placeholder={scopeKind === 'tag' ? 'prod, db' : 'id1, id2'} autocomplete="off" />
      {/if}
      <div class="pt-3 border-t border-border">
        <StepUpFields id="sc-stepup" label="Confirm with your password" bind:password={scopeCurrentPw} bind:totp={scopeTotp} {needsTotp} onsubmit={saveScope} />
      </div>
    </div>
    {#snippet footer()}
      <Button onclick={() => (scopeUser = null)} variant="secondary" disabled={scopeBusy}>Cancel</Button>
      <Button onclick={saveScope} variant="primary" disabled={scopeBusy || !scopeCurrentPw || !totpOk(scopeTotp) || (scopeKind !== 'all' && !scopeValues.trim())}>
        {#if scopeBusy}<Icon name="refresh" size={14} class="animate-spin mr-1" />{/if}
        Save scope
      </Button>
    {/snippet}
  </Modal>
{/if}
