<script>
  import { apiGet, apiPost, toast, confirm } from '../stores/app.js'
  import InfoCard from '../components/InfoCard.svelte'
  import Button from '../components/Button.svelte'
  import Select from '../components/Select.svelte'
  import Icon from '../components/Icon.svelte'
  import Modal from '../components/Modal.svelte'

  let { loading = $bindable(true) } = $props()

  let me = $state(null)      // current operator (for role-gated options)
  let users = $state([])
  let error = $state('')
  let showAdd = $state(false)

  // Add-user form
  let addUsername = $state('')
  let addPassword = $state('')
  let addRole = $state('viewer')
  let addCurrentPw = $state('')
  let addBusy = $state(false)

  // Scope editor
  let scopeUser = $state(null)
  let scopeKind = $state('all')
  let scopeValues = $state('')
  let scopeCurrentPw = $state('')
  let scopeBusy = $state(false)
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
    loading = true
    try {
      me = await apiGet('/api/auth/me')
      const res = await apiGet('/api/auth/users')
      users = res.users || []
      error = ''
    } catch (e) {
      error = e?.message || 'Failed to load users'
    } finally {
      loading = false
    }
  }

  // Step-up: prompt for the operator's password, returns it or null if cancelled.
  async function stepUp(message) {
    const r = await confirm({
      title: 'Confirm your password',
      message,
      confirmText: 'Authorize',
      variant: 'destructive',
      passwordPrompt: { label: 'Your password' },
    })
    return r?.confirmed && r?.password ? r.password : null
  }

  async function addUser() {
    if (!addUsername.trim() || !addPassword || !addCurrentPw) return
    addBusy = true
    try {
      await apiPost('/api/auth/users', {
        username: addUsername.trim(),
        password: addPassword,
        role: addRole,
        currentPassword: addCurrentPw,
      })
      toast(`User "${addUsername.trim()}" created`, 'success')
      showAdd = false
      addUsername = addPassword = addCurrentPw = ''
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
    const pw = await stepUp(`Change ${u.username}'s role from ${u.role} to ${role}?`)
    if (!pw) { await load(); return } // reload to reset the select if cancelled
    try {
      await apiPost('/api/auth/users/role', { user_id: u.id, role, currentPassword: pw })
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
  }

  async function saveScope() {
    if (!scopeUser || !scopeCurrentPw) return
    scopeBusy = true
    try {
      await apiPost('/api/auth/users/scope', {
        user_id: scopeUser.id,
        scope_kind: scopeKind,
        scope_values: scopeKind === 'all' ? '' : scopeValues.trim(),
        currentPassword: scopeCurrentPw,
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
    const pw = await stepUp(`Delete the account "${u.username}" (${u.role})? This cannot be undone.`)
    if (!pw) return
    try {
      await apiPost('/api/auth/users/delete', { user_id: u.id, currentPassword: pw })
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
  <InfoCard
    icon="users"
    title="Panel users & roles"
    description="Accounts that can sign in to this panel. Roles set what each may do; owner is the break-glass role and can't be the last one removed."
  />

  <div class="kt-panel">
    <div class="kt-panel-header">
      <h3 class="kt-panel-title">
        <Icon name="shield-lock" size={16} class="text-muted-foreground" />
        Accounts
      </h3>
      <Button onclick={() => (showAdd = true)} variant="primary" size="sm" icon="plus">Add user</Button>
    </div>
    <div class="kt-panel-body">
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
                          <button onclick={() => openScope(u)} class="custom_btns" title="Set fleet machine scope">
                            <Icon name="filter" size={14} />
                          </button>
                        {/if}
                        <button onclick={() => removeUser(u)} class="custom_btns text-destructive hover:bg-destructive/10" title="Delete user">
                          <Icon name="trash" size={14} />
                        </button>
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
      <div class="space-y-1">
        <label class="text-sm font-medium" for="tu-username">Username</label>
        <div class="kt-input"><Icon name="user" class="text-muted-foreground" /><input id="tu-username" bind:value={addUsername} placeholder="at least 3 characters" autocomplete="off" /></div>
      </div>
      <div class="space-y-1">
        <label class="text-sm font-medium" for="tu-password">Password</label>
        <div class="kt-input"><Icon name="lock" class="text-muted-foreground" /><input id="tu-password" type="password" bind:value={addPassword} placeholder="8+ chars, mixed case, number, symbol" autocomplete="new-password" /></div>
      </div>
      <div class="space-y-1">
        <label class="text-sm font-medium" for="tu-role">Role</label>
        <Select id="tu-role" bind:value={addRole} options={roleOptions} />
        <p class="text-[11px] text-muted-foreground">{ROLE_DESC[addRole]}</p>
      </div>
      <div class="space-y-1 pt-1 border-t border-border">
        <label class="text-sm font-medium" for="tu-stepup">Confirm with your password</label>
        <div class="kt-input"><Icon name="shield-lock" class="text-muted-foreground" /><input id="tu-stepup" type="password" bind:value={addCurrentPw} placeholder="your current password" autocomplete="current-password" /></div>
      </div>
    </div>
    {#snippet footer()}
      <Button onclick={() => (showAdd = false)} variant="secondary" disabled={addBusy}>Cancel</Button>
      <Button onclick={addUser} variant="primary" disabled={addBusy || !addUsername.trim() || !addPassword || !addCurrentPw}>
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
      <div class="space-y-1">
        <label class="text-sm font-medium" for="sc-kind">Scope</label>
        <Select id="sc-kind" bind:value={scopeKind} options={scopeKindOptions} />
      </div>
      {#if scopeKind !== 'all'}
        <div class="space-y-1">
          <label class="text-sm font-medium" for="sc-values">{scopeKind === 'tag' ? 'Tags' : 'Machine IDs'} (comma-separated)</label>
          <div class="kt-input"><Icon name="filter" class="text-muted-foreground" /><input id="sc-values" bind:value={scopeValues} placeholder={scopeKind === 'tag' ? 'prod, db' : 'id1, id2'} autocomplete="off" /></div>
        </div>
      {/if}
      <div class="space-y-1 pt-1 border-t border-border">
        <label class="text-sm font-medium" for="sc-stepup">Confirm with your password</label>
        <div class="kt-input"><Icon name="shield-lock" class="text-muted-foreground" /><input id="sc-stepup" type="password" bind:value={scopeCurrentPw} placeholder="your current password" autocomplete="current-password" /></div>
      </div>
    </div>
    {#snippet footer()}
      <Button onclick={() => (scopeUser = null)} variant="secondary" disabled={scopeBusy}>Cancel</Button>
      <Button onclick={saveScope} variant="primary" disabled={scopeBusy || !scopeCurrentPw || (scopeKind !== 'all' && !scopeValues.trim())}>
        {#if scopeBusy}<Icon name="refresh" size={14} class="animate-spin mr-1" />{/if}
        Save scope
      </Button>
    {/snippet}
  </Modal>
{/if}
