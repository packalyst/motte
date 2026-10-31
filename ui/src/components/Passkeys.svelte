<script>
  // Passkeys (WebAuthn) — passwordless sign-in. Register device-bound credentials and manage them.
  // Additive: password + 2FA still work; a passkey is just a faster, phishing-resistant way in.
  // A modal opened from Profile → Security; `count` reports how many exist for that card.
  import { onMount } from 'svelte'
  import { apiGet, apiDelete, toast, confirm, stepUpConfirm, currentUser } from '../stores/app.js'
  import { passkeyRegister, passkeysSupported } from '../lib/webauthn.js'
  import { formatDate } from '../lib/utils/format.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Input from './Input.svelte'
  import Modal from './Modal.svelte'
  import GroupButton from './GroupButton.svelte'

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
      // Step-up prompts offer "Use passkey" from the first one added, without a reload.
      currentUser.update((u) => (u ? { ...u, hasPasskey: count > 0 } : u))
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
      <div class="flex items-start gap-2.5 rounded-lg border border-border p-3 text-sm text-muted-foreground">
        <Icon name="lock" size={16} class="mt-0.5 shrink-0" />
        This browser or connection doesn't support passkeys. They need the panel opened over HTTPS on its domain.
      </div>
    {:else}
      <p class="text-xs text-muted-foreground">
        Sign in without a password using your device's fingerprint, face, PIN or a security key. Phishing-resistant and per-device.
      </p>

      <form class="flex flex-col gap-2 sm:flex-row" onsubmit={(e) => { e.preventDefault(); register() }}>
        <div class="min-w-0 flex-1"><Input bind:value={newName} placeholder="Name it, e.g. My laptop" prefixIcon="device-laptop" aria-label="Passkey name" /></div>
        <Button type="submit" icon="plus" loading={registering}>Add passkey</Button>
      </form>

      <div>
        <div class="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground after:h-px after:flex-1 after:bg-border">
          Your passkeys <span class="font-normal normal-case tracking-normal">{passkeys.length}</span>
        </div>
        {#if loading}
          <div class="text-sm text-muted-foreground">Loading…</div>
        {:else if passkeys.length === 0}
          <div class="flex items-center gap-3 rounded-lg border border-dashed border-border px-4 py-4 text-xs text-muted-foreground">
            <Icon name="key" size={16} class="shrink-0" />No passkeys yet — add one on each device you use.
          </div>
        {:else}
          <div class="divide-y divide-border rounded-lg border border-border">
            {#each passkeys as pk (pk.id)}
              <div class="flex items-center gap-3 px-3 py-2.5">
                <span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-success/10 text-success"><Icon name="key" size={15} /></span>
                <div class="min-w-0 flex-1">
                  <div class="truncate text-sm font-medium text-foreground">{pk.name}</div>
                  <div class="flex flex-wrap gap-x-3 text-[11px] text-muted-foreground">
                    <span class="inline-flex items-center gap-1"><Icon name="calendar" size={11} />Added {formatDate(pk.createdAt)}</span>
                    <span class="inline-flex items-center gap-1"><Icon name="clock" size={11} />{pk.lastUsedAt ? `Last used ${formatDate(pk.lastUsedAt)}` : 'Never used'}</span>
                  </div>
                </div>
                <div class="btn-group shrink-0">
                  <GroupButton icon="trash" tone="destructive" tooltip="Remove passkey" onclick={() => remove(pk)} />
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}
  </div>
</Modal>
