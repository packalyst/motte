<script>
  /**
   * StepUpFields — the re-authentication fields every sensitive prompt uses: the operator's
   * password, plus a 6-digit authenticator code when they have 2FA. Shared by the confirm modal
   * and the idle lock so they look and behave the same. Enter in the password
   * (or completing the code) calls onsubmit once both are filled.
   *
   * Given passkey ({ method, url }: the one request being confirmed), it also offers "Use passkey"
   * under the password; it starts only when tapped. onpasskey(answer) gets the passkey answer for
   * that request.
   *
   * The fields sit in their own form with the signed-in username beside the password (hidden), so a
   * password manager fills these two and leaves the page's other inputs (a search box) alone.
   */
  import Input from './Input.svelte'
  import OtpInput from './OtpInput.svelte'
  import Button from './Button.svelte'
  import Icon from './Icon.svelte'
  import { passkeyStepUp } from '$lib/webauthn.js'
  import { currentUser } from '../stores/app.js'

  let {
    password = $bindable(''),
    totp = $bindable(''),
    needsTotp = false,
    label = 'Your password',
    placeholder = 'Your password',
    id = 'stepup',
    autofocus = false,
    onsubmit = undefined,
    passkey = null,
    onpasskey = undefined,
  } = $props()

  let passkeyBusy = $state(false)
  let passkeyError = $state('')
  async function usePasskey() {
    if (!passkey || passkeyBusy) return
    passkeyBusy = true
    passkeyError = ''
    try {
      onpasskey?.(await passkeyStepUp(passkey))
    } catch (e) {
      // Cancelled: the button stays for another go, the password field too.
      if (e?.name !== 'NotAllowedError' && e?.name !== 'AbortError') passkeyError = e?.message || 'Passkey failed'
    } finally {
      passkeyBusy = false
    }
  }

  const ready = $derived(!!password && (!needsTotp || totp.length === 6))
  function submit() {
    if (ready) onsubmit?.()
  }

  $effect(() => {
    if (autofocus) document.getElementById(id + '-password')?.focus()
  })
</script>

<!-- Enter is handled on the fields; the form only scopes autofill and must never navigate. -->
<form class="space-y-3" onsubmit={(e) => e.preventDefault()}>
  <input class="sr-only" type="text" name="username" autocomplete="username" value={$currentUser?.username || ''}
    readonly tabindex="-1" aria-hidden="true" />
  <Input id="{id}-password" name="password" type="password" {label} prefixIcon="lock" bind:value={password} {placeholder}
    autocomplete="current-password" onkeydown={(e) => e.key === 'Enter' && submit()} />
  {#if needsTotp}
    <div>
      <span class="block text-xs font-medium text-foreground mb-1">Authenticator code</span>
      <OtpInput bind:value={totp} onComplete={(v) => { totp = v; submit() }} />
    </div>
  {/if}
  {#if passkey}
    <Button type="button" onclick={usePasskey} variant="secondary" class="w-full" disabled={passkeyBusy}>
      <Icon name={passkeyBusy ? 'loader-2' : 'fingerprint'} size={16} class={passkeyBusy ? 'animate-spin mr-1' : 'mr-1'} />
      Use passkey
    </Button>
    {#if passkeyError}<p class="text-xs text-destructive">{passkeyError}</p>{/if}
  {/if}
</form>
