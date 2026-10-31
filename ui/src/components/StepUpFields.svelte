<script>
  /**
   * StepUpFields — the re-authentication fields every sensitive prompt uses: the operator's
   * password, plus a 6-digit authenticator code when they have 2FA. Shared by the confirm modal,
   * the idle lock and the team dialogs so they look and behave the same. Enter in the password
   * (or completing the code) calls onsubmit once both are filled.
   *
   * Given passkey ({ method, url }: the one request being confirmed), it offers "Use passkey"
   * instead, and (autoPasskey) starts it once by itself; a browser that wants a tap first (Safari)
   * just leaves the button there. onpasskey(answer) gets the passkey answer for that request.
   */
  import { onMount } from 'svelte'
  import Input from './Input.svelte'
  import OtpInput from './OtpInput.svelte'
  import Button from './Button.svelte'
  import Icon from './Icon.svelte'
  import { passkeyStepUp } from '$lib/webauthn.js'

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
    autoPasskey = true,
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
      // Cancelled, or no tap yet: the button stays for another go, the password field too.
      if (e?.name !== 'NotAllowedError' && e?.name !== 'AbortError') passkeyError = e?.message || 'Passkey failed'
    } finally {
      passkeyBusy = false
    }
  }
  onMount(() => { if (passkey && autoPasskey) usePasskey() })

  const ready = $derived(!!password && (!needsTotp || totp.length === 6))
  function submit() {
    if (ready) onsubmit?.()
  }

  $effect(() => {
    if (autofocus && !passkey) document.getElementById(id + '-password')?.focus() // a passkey prompt has the focus
  })
</script>

<div class="space-y-3">
  {#if passkey}
    <Button onclick={usePasskey} variant="primary" class="w-full" disabled={passkeyBusy}>
      <Icon name={passkeyBusy ? 'loader-2' : 'fingerprint'} size={16} class={passkeyBusy ? 'animate-spin mr-1' : 'mr-1'} />
      Use passkey
    </Button>
    {#if passkeyError}<p class="text-xs text-destructive">{passkeyError}</p>{/if}
    <p class="text-[11px] text-muted-foreground text-center">or use your password</p>
  {/if}
  <Input id="{id}-password" type="password" {label} prefixIcon="lock" bind:value={password} {placeholder}
    autocomplete="current-password" onkeydown={(e) => e.key === 'Enter' && submit()} />
  {#if needsTotp}
    <div>
      <span class="block text-xs font-medium text-foreground mb-1">Authenticator code</span>
      <OtpInput bind:value={totp} onComplete={(v) => { totp = v; submit() }} />
    </div>
  {/if}
</div>
