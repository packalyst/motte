<script>
  // Passkeys (WebAuthn) — passwordless sign-in. Register device-bound credentials and manage them.
  // Additive: password + 2FA still work; a passkey is just a faster, phishing-resistant way in.
  // A modal opened from Profile → Security; `count` reports how many exist for that card.
  import { onMount } from 'svelte'
  import { apiGet, apiDelete, toast, confirm, stepUpConfirm } from '../stores/app.js'
  import { passkeyRegister, passkeysSupported } from '../lib/webauthn.js'
  import { formatDate } from '../lib/utils/format.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Input from './Input.svelte'
  import Modal from './Modal.svelte'

  let { open = $bindable(false), count = $bindable(0) } = $props()

  let passkeys = $state([])
  let loading = $state(true)
  let registering = $state(false)
  let newName = $state('')
  const supported = passkeysSupported()

  onMount(load)

  async function load() {
    loading = true
    try {
      passkeys = (await apiGet('/api/auth/passkeys')) || []
      count = passkeys.length
    } catch (e) {
      toast(e.message || 'Could not load passkeys', 'error')
    } finally {
      loading = false
    }
  }

  async function register() {
    const su = await stepUpConfirm({ title: 'Add passkey', description: 'Adding a passkey is a sensitive change. Re-authenticate to continue.' })
    if (!su?.confirmed) return
    registering = true
    try {
      await passkeyRegister(newName.trim() || 'Passkey', { currentPassword: su.password, totpCode: su.totp })
      newName = ''
      toast('Passkey added', 'success')
      await load()
    } catch (e) {
      if (e?.name !== 'NotAllowedError' && e?.name !== 'AbortError') {
        toast(e.message || 'Could not add passkey', 'error')
      }
    } finally {
      registering = false
    }
  }

  async function remove(pk) {
    if (!(await confirm(`Remove passkey "${pk.name}"?`))) return
    try {
      await apiDelete(`/api/auth/passkeys/${pk.id}`)
      toast('Passkey removed', 'success')
      await load()
    } catch (e) {
      toast(e.message || 'Could not remove passkey', 'error')
    }
  }
</script>

<Modal bind:open title="Passkeys" size="md">
  <div class="space-y-4">
    {#if !supported}
      <p class="text-sm text-muted-foreground">
        This browser or connection doesn't support passkeys. They need the panel to be opened over HTTPS on its domain.
      </p>
    {:else}
      <p class="text-xs text-muted-foreground">
        Sign in without a password using your device's fingerprint, face, PIN or a security key. Phishing-resistant and per-device.
      </p>

      <div class="flex items-end gap-2">
        <div class="flex-1">
          <label for="pk-name" class="block text-xs font-medium text-foreground mb-1">Name this passkey</label>
          <Input id="pk-name" bind:value={newName} placeholder="e.g. My laptop" class="w-full" />
        </div>
        <Button icon="plus" loading={registering} onclick={register}>Add passkey</Button>
      </div>

      {#if loading}
        <div class="text-sm text-muted-foreground">Loading…</div>
      {:else if passkeys.length === 0}
        <p class="text-xs text-muted-foreground">No passkeys yet.</p>
      {:else}
        <div class="divide-y divide-border rounded-md border border-border">
          {#each passkeys as pk (pk.id)}
            <div class="flex items-center justify-between gap-3 p-3">
              <div class="flex items-center gap-2.5 min-w-0">
                <Icon name="key" size={16} class="text-muted-foreground flex-shrink-0" />
                <div class="min-w-0">
                  <div class="text-sm font-medium truncate">{pk.name}</div>
                  <div class="text-[11px] text-muted-foreground">
                    Added {formatDate(pk.createdAt)}{pk.lastUsedAt ? ` · last used ${formatDate(pk.lastUsedAt)}` : ''}
                  </div>
                </div>
              </div>
              <Button size="xs" variant="ghost" icon="trash" iconOnly onclick={() => remove(pk)} />
            </div>
          {/each}
        </div>
      {/if}
    {/if}
  </div>
</Modal>
