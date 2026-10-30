<script>
  /**
   * HsUsers — the Users section of the Headscale page: one card per Headscale user with their
   * devices. users and nodes come from the page; after a change onchange() reloads them. search
   * filters by name; stats reports { total, shown } to the page. Adding, renaming and deleting are
   * admin-only (as on the server), so those actions show to admins only; the colour and avatar are
   * this browser's own and open to anyone.
   */
  import { toast, apiPost, apiPut, apiDelete, stepUpConfirm, setConfirmLoading, currentUser, hasRole } from '../../stores/app.js'
  import { formatRelativeDate, formatDate } from '$lib/utils/format.js'
  import Icon from '../Icon.svelte'
  import Input from '../Input.svelte'
  import Button from '../Button.svelte'
  import Badge from '../Badge.svelte'
  import Modal from '../Modal.svelte'
  import GroupHeading from '../GroupHeading.svelte'
  import EmptyState from '../EmptyState.svelte'

  let { users = [], nodes = [], panelRouter = null, search = '', stats = $bindable(null), onchange } = $props()
  const isAdmin = $derived(hasRole($currentUser, 'admin'))
  $effect(() => { stats = { total: users.length, shown: filteredUsers.length } })
  // The panel's own router joins Headscale as a user of its own name; deleting it cuts Tailscale off
  // from WireGuard, so it is marked and its delete warns.
  const isRouterUser = (user) => !!panelRouter?.name && user.name === panelRouter.name

  // Modals
  let showCreateModal = $state(false)
  let showEditModal = $state(false)
  let editingUser = $state(null)

  // Form state
  let newUserName = $state('')
  let creating = $state(false)
  let selectedColor = $state('')
  let selectedAvatar = $state('')
  let customizationVersion = $state(0) // Force reactivity on customization changes

  // Color and emoji options
  const colors = [
    '#6366f1', '#8b5cf6', '#a855f7', '#d946ef',
    '#ec4899', '#f43f5e', '#ef4444', '#f97316',
    '#eab308', '#84cc16', '#22c55e', '#14b8a6',
    '#06b6d4', '#3b82f6', '#64748b', '#1e293b'
  ]

  const emojis = ['😀', '😎', '🤖', '👨‍💻', '👩‍💻', '🦊', '🐱', '🐶', '🦁', '🐯', '🦄', '🐸', '🌟', '⚡', '🔥', '💎']

  // LocalStorage for user customizations
  function getUserCustomization(userName) {
    try {
      const data = localStorage.getItem(`user_custom_${userName}`)
      return data ? JSON.parse(data) : null
    } catch {
      return null
    }
  }

  function saveUserCustomization(userName, data) {
    localStorage.setItem(`user_custom_${userName}`, JSON.stringify(data))
  }

  function getDefaultColor(name) {
    let hash = 0
    for (let i = 0; i < name.length; i++) {
      hash = name.charCodeAt(i) + ((hash << 5) - hash)
    }
    return colors[Math.abs(hash) % colors.length]
  }

  function getUserColor(userName, _version) {
    const custom = getUserCustomization(userName)
    return custom?.color || getDefaultColor(userName)
  }

  function getUserAvatar(userName, _version) {
    const custom = getUserCustomization(userName)
    return custom?.avatar || ''
  }

  // Each user's devices, counted once per list rather than per card.
  const devices = $derived.by(() => {
    const m = new Map()
    for (const n of nodes) {
      const c = m.get(n.user?.name) || { total: 0, online: 0 }
      c.total++
      if (n.online) c.online++
      m.set(n.user?.name, c)
    }
    return m
  })
  const devicesOf = (name) => devices.get(name) || { total: 0, online: 0 }

  // Filtered users
  const filteredUsers = $derived(
    users.filter(u =>
      u.name.toLowerCase().includes(search.trim().toLowerCase())
    )
  )

  async function createUser() {
    if (!newUserName.trim()) return
    creating = true
    try {
      await apiPost('/api/hs/users', { name: newUserName })
      toast('User created', 'success')
      showCreateModal = false
      newUserName = ''
      onchange?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      creating = false
    }
  }

  async function renameUser(user) {
    const newName = prompt('New name:', user.name)
    if (!newName || newName === user.name) return
    try {
      await apiPut(`/api/hs/users/${encodeURIComponent(user.name)}/rename/${encodeURIComponent(newName)}`)
      toast('User renamed', 'success')
      onchange?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function confirmDeleteUser(user) {
    const count = devicesOf(user.name).total
    const description = (isRouterUser(user) ? 'This is the panel router: Tailscale devices lose access to WireGuard clients. ' : '') +
      (count > 0 ? `This also removes ${count} device${count > 1 ? 's' : ''} from the VPN. ` : '') + 'This action cannot be undone.'

    // One step-up for the whole delete: the server removes the user's devices, then the user.
    const su = await stepUpConfirm({
      title: 'Delete User',
      message: `Delete ${user.name}?`,
      description,
      confirmText: 'Delete',
      variant: 'destructive',
    })
    if (!su?.confirmed || !su?.password) return
    const body = { currentPassword: su.password, totpCode: su.totp || '' }

    setConfirmLoading(true)
    try {
      await apiDelete(`/api/hs/users/${encodeURIComponent(user.name)}`, body)
      toast(count > 0 ? 'User and devices deleted' : 'User deleted', 'success')
      onchange?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }

  function openEditModal(user) {
    editingUser = user
    selectedColor = getUserColor(user.name)
    selectedAvatar = getUserAvatar(user.name)
    showEditModal = true
  }

  function saveCustomization() {
    if (!editingUser) return
    saveUserCustomization(editingUser.name, {
      color: selectedColor,
      avatar: selectedAvatar
    })
    customizationVersion++ // Trigger reactivity
    showEditModal = false
    editingUser = null
    toast('User customization saved', 'success')
  }
</script>

<section class="space-y-2" aria-label="Users">
  <GroupHeading title="Users" color="var(--color-primary)" note="{users.length} {users.length === 1 ? 'user' : 'users'}"
    action={isAdmin ? { label: 'Add user', onclick: () => (showCreateModal = true) } : undefined} />

  {#if filteredUsers.length > 0}
    <ul class="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {#each filteredUsers as user (user.id)}
        {@const d = devicesOf(user.name)}
        {@const userColor = getUserColor(user.name, customizationVersion)}
        {@const userAvatar = getUserAvatar(user.name, customizationVersion)}
        <li class="panel flex items-center gap-3 p-3">
          <span class="grid h-9 w-9 shrink-0 place-items-center rounded-full text-base font-medium text-white" style="background-color: {userColor}">
            {userAvatar || user.name.charAt(0).toUpperCase()}
          </span>
          <div class="min-w-0 flex-1">
            <div class="flex min-w-0 items-center gap-2">
              <span class="truncate text-sm font-semibold text-foreground">{user.name}</span>
              {#if isRouterUser(user)}<Badge variant="primary" size="sm">Panel router</Badge>{/if}
            </div>
            <div class="flex flex-wrap items-center gap-x-1.5 text-[11px] text-muted-foreground">
              <span>{d.total} {d.total === 1 ? 'device' : 'devices'}</span>
              {#if d.total}
                <span>·</span>
                <span class="inline-flex items-center gap-1.5 {d.online ? 'text-success' : ''}"><span class="status-dot {d.online ? 'status-dot-success' : 'status-dot-muted'}"></span>{d.online} online</span>
              {/if}
              {#if user.createdAt}<span>·</span><span title={formatDate(user.createdAt)}>added {formatRelativeDate(user.createdAt)}</span>{/if}
            </div>
          </div>
          <div class="kt-btn-group shrink-0">
            <Button variant="outline" size="xs" icon="palette" tooltip="Colour and avatar" aria-label="Colour and avatar of {user.name}" onclick={() => openEditModal(user)} />
            {#if isAdmin}
              <Button variant="outline" size="xs" icon="edit" tooltip="Rename" aria-label="Rename {user.name}" onclick={() => renameUser(user)} />
              <Button variant="outline" size="xs" icon="trash" class="text-destructive hover:bg-destructive/10" tooltip="Delete" aria-label="Delete {user.name}" onclick={() => confirmDeleteUser(user)} />
            {/if}
          </div>
        </li>
      {/each}
    </ul>
  {/if}

  {#if filteredUsers.length === 0 && users.length === 0}
    <EmptyState
      icon="users"
      title="No users yet"
      description="Create users to organize nodes and generate auth keys"
    >
      {#if isAdmin}
        <Button onclick={() => showCreateModal = true} size="sm">
          <Icon name="plus" size={14} />
          Add User
        </Button>
      {/if}
    </EmptyState>
  {/if}
</section>

<!-- Create User Modal -->
<Modal bind:open={showCreateModal} title="Create User" size="sm">
  <Input
    bind:value={newUserName}
    label="Username"
    placeholder="Enter username"
    disabled={creating}
  />

  {#snippet footer()}
    <Button onclick={() => showCreateModal = false} variant="secondary">Cancel</Button>
    <Button onclick={createUser} disabled={creating}>
      {creating ? 'Creating...' : 'Create'}
    </Button>
  {/snippet}
</Modal>

<!-- Edit User Modal -->
<Modal bind:open={showEditModal} title={editingUser ? `Customize "${editingUser.name}"` : 'Customize User'} size="sm">
  {#if editingUser}
    <div class="space-y-6">
      <div>
        <span class="kt-label">Color</span>
        <div class="grid grid-cols-8 gap-2">
          {#each colors as color}
            <button
              type="button"
              onclick={() => selectedColor = color}
              class="w-8 h-8 rounded-full transition-transform hover:scale-110 {selectedColor === color ? 'ring-2 ring-offset-2 ring-primary ring-offset-card' : ''}"
              style="background-color: {color}"
              aria-label="Select color {color}"
            ></button>
          {/each}
        </div>
      </div>

      <div>
        <span class="kt-label">Avatar (optional)</span>
        <div class="grid grid-cols-8 gap-2">
          <button
            type="button"
            onclick={() => selectedAvatar = ''}
            class="w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium text-white transition-transform hover:scale-110 {!selectedAvatar ? 'ring-2 ring-offset-2 ring-primary ring-offset-card' : ''}"
            style="background-color: {selectedColor}"
          >
            {editingUser.name.charAt(0).toUpperCase()}
          </button>
          {#each emojis as emoji}
            <button
              type="button"
              onclick={() => selectedAvatar = emoji}
              class="w-8 h-8 rounded-full bg-muted flex items-center justify-center text-lg transition-transform hover:scale-110 {selectedAvatar === emoji ? 'ring-2 ring-offset-2 ring-primary ring-offset-card' : ''}"
            >
              {emoji}
            </button>
          {/each}
        </div>
      </div>

      <div>
        <span class="kt-label">Preview</span>
        <div class="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
          <div
            class="w-12 h-12 rounded-full flex items-center justify-center text-xl font-medium text-white"
            style="background-color: {selectedColor}"
          >
            {selectedAvatar || editingUser.name.charAt(0).toUpperCase()}
          </div>
          <span class="font-medium text-foreground">{editingUser.name}</span>
        </div>
      </div>
    </div>
  {/if}

  {#snippet footer()}
    <Button onclick={() => showEditModal = false} variant="secondary">Cancel</Button>
    <Button onclick={saveCustomization}>Save</Button>
  {/snippet}
</Modal>

