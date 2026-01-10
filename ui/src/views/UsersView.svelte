<script>
  import { toast, apiGet, apiPost, apiPut, apiDelete, confirm, setConfirmLoading } from '../stores/app.js'
  import { formatRelativeDate } from '$lib/utils/format.js'
  import { useDataLoader } from '$lib/composables/index.js'
  import { filterByFields } from '$lib/utils/data.js'
  import Icon from '../components/Icon.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import EmptyState from '../components/EmptyState.svelte'

  let { loading = $bindable(true) } = $props()

  // Multi-source data loading
  const loader = useDataLoader([
    { fn: () => apiGet('/api/hs/users'), key: 'users', extract: 'users', isArray: true },
    { fn: () => apiGet('/api/hs/nodes'), key: 'nodes', extract: 'nodes', isArray: true }
  ])

  const users = $derived(loader.data.users || [])
  const nodes = $derived(loader.data.nodes || [])

  // Sync loading state to parent
  $effect(() => { loading = loader.loading })

  // Modals
  let showCreateModal = $state(false)
  let showEditModal = $state(false)
  let editingUser = $state(null)

  // Form state
  let newUserName = $state('')
  let creating = $state(false)
  let selectedColor = $state('')
  let selectedAvatar = $state('')
  let searchQuery = $state('')
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

  function getNodeCount(userName) {
    return nodes.filter(n => n.user?.name === userName).length
  }

  function getOnlineCount(userName) {
    const userNodes = nodes.filter(n => n.user?.name === userName)
    return userNodes.filter(n => n.online).length
  }

  // Filtered users
  const filteredUsers = $derived(
    users.filter(u =>
      u.name.toLowerCase().includes(searchQuery.toLowerCase())
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
      loader.reload()
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
      await apiPut(`/api/hs/users/${user.name}/rename/${newName}`)
      toast('User renamed', 'success')
      loader.reload()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  function getUserNodes(userName) {
    return nodes.filter(n => n.user?.name === userName)
  }

  async function confirmDeleteUser(user) {
    const userNodeCount = getNodeCount(user.name)
    const description = userNodeCount > 0
      ? `This will also delete ${userNodeCount} node${userNodeCount > 1 ? 's' : ''}. This action cannot be undone.`
      : 'This action cannot be undone.'

    const confirmed = await confirm({
      title: 'Delete User',
      message: `Delete ${user.name}?`,
      description,
      confirmText: 'Delete'
    })
    if (!confirmed) return

    setConfirmLoading(true)
    try {
      // First delete all nodes belonging to this user
      const userNodes = getUserNodes(user.name)
      for (const node of userNodes) {
        await apiDelete(`/api/hs/nodes/${node.id}`)
      }
      // Then delete the user
      await apiDelete(`/api/hs/users/${user.name}`)
      toast('User and nodes deleted', 'success')
      loader.reload()
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

<div class="space-y-4">
  <InfoCard
    icon="users"
    title="Users"
    description="Organize your network with users. Each user can own multiple nodes and have their own pre-auth keys. Customize avatars and colors for easy identification."
  />

  <!-- Toolbar -->
  <Toolbar bind:search={searchQuery} placeholder="Search users..." />

  <!-- Users grid -->
  {#if filteredUsers.length > 0}
    <div class="grid-cards">
      {#each filteredUsers as user (user.id)}
        {@const nodeCount = getNodeCount(user.name)}
        {@const onlineCount = getOnlineCount(user.name)}
        {@const userColor = getUserColor(user.name, customizationVersion)}
        {@const userAvatar = getUserAvatar(user.name, customizationVersion)}

        <div class="bg-card border border-border rounded-lg overflow-hidden hover:border-primary/50 transition-colors shadow-sm">
          <!-- Header -->
          <div class="flex items-center gap-3 p-3">
            <div
              class="w-10 h-10 rounded-full flex items-center justify-center text-lg font-medium text-white flex-shrink-0"
              style="background-color: {userColor}"
            >
              {userAvatar || user.name.charAt(0).toUpperCase()}
            </div>
            <div class="flex-1 min-w-0">
              <div class="text-sm font-semibold text-foreground truncate">{user.name}</div>
              <div class="text-[11px] text-muted-foreground flex items-center gap-1">
                <Icon name="clock" size={11} />
                {formatRelativeDate(user.createdAt)}
              </div>
            </div>
          </div>

          <!-- Stats grid -->
          <div class="grid grid-cols-2 gap-x-3 border-t border-border px-3 py-2.5 text-[11px]">
            <div class="flex items-center gap-1.5">
              <Icon name="server" size={12} class="text-dim" />
              <span class="text-muted-foreground">{nodeCount} nodes</span>
            </div>
            <div class="flex items-center gap-1.5">
              <span class="status-dot {onlineCount > 0 ? 'status-dot-success' : 'status-dot-muted'}"></span>
              <span class="{onlineCount > 0 ? 'text-success' : 'text-muted-foreground'}">{onlineCount} online</span>
            </div>
          </div>

          <!-- Actions -->
          <div class="flex items-center justify-end gap-0.5 px-2 py-1.5 border-t border-border bg-muted/30">
            <button
              onclick={() => openEditModal(user)}
              class="icon-btn"
              title="Customize"
            >
              <Icon name="settings" size={14} />
            </button>
            <button
              onclick={() => renameUser(user)}
              class="icon-btn"
              title="Rename"
            >
              <Icon name="edit" size={14} />
            </button>
            <button
              onclick={() => confirmDeleteUser(user)}
              class="icon-btn-destructive"
              title="Delete"
            >
              <Icon name="trash" size={14} />
            </button>
          </div>
        </div>
      {/each}

      <!-- Add user card -->
      <div
        onclick={() => showCreateModal = true}
        onkeydown={(e) => e.key === 'Enter' && (showCreateModal = true)}
        role="button"
        tabindex="0"
        class="add-item-card"
      >
        <div class="flex h-8 w-8 items-center justify-center rounded-full bg-secondary text-foreground">
          <Icon name="plus" size={16} />
        </div>
        <div class="font-medium text-foreground">Add new user</div>
        <p class="max-w-[200px] text-muted-foreground">
          Create users to organize nodes and generate auth keys
        </p>
      </div>
    </div>
  {:else if users.length > 0}
    <EmptyState
      icon="search"
      title="No users found"
      description="Try a different search term"
    />
  {/if}

  {#if filteredUsers.length === 0 && users.length === 0}
    <EmptyState
      icon="users"
      title="No users yet"
      description="Create users to organize nodes and generate auth keys"
    >
      <Button onclick={() => showCreateModal = true} size="sm">
        <Icon name="plus" size={14} />
        Add User
      </Button>
    </EmptyState>
  {/if}
</div>

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

