<script>
  /**
   * StepUpFields — the re-authentication fields every sensitive prompt uses: the operator's
   * password, plus a 6-digit authenticator code when they have 2FA. Shared by the confirm modal,
   * the idle lock and the team dialogs so they look and behave the same. Enter in the password
   * (or completing the code) calls onsubmit once both are filled.
   */
  import Input from './Input.svelte'
  import OtpInput from './OtpInput.svelte'

  let {
    password = $bindable(''),
    totp = $bindable(''),
    needsTotp = false,
    label = 'Your password',
    placeholder = 'Your password',
    id = 'stepup',
    autofocus = false,
    onsubmit = undefined,
  } = $props()

  const ready = $derived(!!password && (!needsTotp || totp.length === 6))
  function submit() {
    if (ready) onsubmit?.()
  }

  $effect(() => {
    if (autofocus) document.getElementById(id + '-password')?.focus()
  })
</script>

<div class="space-y-3">
  <Input id="{id}-password" type="password" {label} prefixIcon="lock" bind:value={password} {placeholder}
    autocomplete="current-password" onkeydown={(e) => e.key === 'Enter' && submit()} />
  {#if needsTotp}
    <div>
      <span class="block text-xs font-medium text-foreground mb-1">Authenticator code</span>
      <OtpInput bind:value={totp} onComplete={(v) => { totp = v; submit() }} />
    </div>
  {/if}
</div>
