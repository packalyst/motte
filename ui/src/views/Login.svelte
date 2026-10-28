<script>
  import { theme, toast } from '../stores/app.js'
  import { passkeyLogin, passkeysSupported } from '../lib/webauthn.js'
  import Icon from '../components/Icon.svelte'
  import Logo from '../components/Logo.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import OtpInput from '../components/OtpInput.svelte'

  let { onLogin } = $props()

  let username = $state('')
  let password = $state('')
  let totpCode = $state('')
  let requires2FA = $state(false)
  let loading = $state(false)
  let passkeyLoading = $state(false)
  let error = $state('')
  const canPasskey = passkeysSupported()

  async function handlePasskeyLogin() {
    error = ''
    passkeyLoading = true
    try {
      const data = await passkeyLogin()
      toast('Login successful', 'success')
      if (onLogin) onLogin(data.user)
    } catch (e) {
      // A user cancelling the browser prompt throws NotAllowedError — don't nag about that.
      if (e?.name !== 'NotAllowedError' && e?.name !== 'AbortError') {
        error = e.message || 'Passkey login failed'
      }
    } finally {
      passkeyLoading = false
    }
  }

  function toggleTheme() {
    theme.update(t => t === 'dark' ? 'light' : 'dark')
  }

  async function handleLogin() {
    error = ''
    loading = true

    try {
      const payload = { username, password }
      if (requires2FA && totpCode) {
        payload.totpCode = totpCode
      }

      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      const data = await res.json().catch(() => ({}))

      // Correct password, 2FA on: the server answers 428 and the code step opens
      if (res.status === 428) {
        requires2FA = true
        error = ''
        loading = false
        return
      }

      if (!res.ok) {
        throw new Error(data.error || data.message || 'Login failed')
      }

      // The session is set by the server as an HttpOnly cookie (not readable here); the
      // browser sends it automatically on subsequent requests. Nothing to store client-side.
      toast('Login successful', 'success')

      // Notify parent component
      if (onLogin) onLogin(data.user)
    } catch (e) {
      error = e.message || 'Login failed'
    } finally {
      loading = false
    }
  }

  function backToLogin() {
    requires2FA = false
    totpCode = ''
    error = ''
  }
</script>

<div class="min-h-screen flex flex-col lg:flex-row">
  <!-- Mobile Header - Only visible on mobile -->
  <div class="lg:hidden bg-gradient-to-br from-[#0f1419] via-[#1a1f37] to-[#1a1f37] text-white px-6 pt-12 pb-16 text-center relative overflow-hidden">
    <!-- Decorative gradient -->
    <div class="absolute top-0 right-0 w-64 h-64 bg-primary/10 rounded-full blur-3xl"></div>
    <div class="absolute bottom-0 left-0 w-64 h-64 bg-primary/10 rounded-full blur-3xl"></div>

    <div class="relative z-10">
      <div class="flex items-center justify-center gap-3 mb-6">
        <Logo size={44} />
      </div>
      <h1 class="text-2xl font-bold mb-2">Welcome Back</h1>
      <p class="text-sm text-muted-foreground">Sign in to Motte</p>
    </div>
  </div>

  <!-- Left Panel - Desktop only -->
  <div class="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-[#0f1419] via-[#1a1f37] to-[#1a1f37] text-white p-16 flex-col justify-center relative overflow-hidden">
    <!-- Decorative gradient orbs -->
    <div class="absolute top-0 right-0 w-[600px] h-[600px] bg-primary/5 rounded-full blur-3xl"></div>
    <div class="absolute bottom-0 left-0 w-[600px] h-[600px] bg-primary/5 rounded-full blur-3xl"></div>

    <div class="relative z-10 max-w-2xl mx-auto w-full">
      <!-- Header -->
      <div class="mb-12">
        <div class="flex items-center gap-3 mb-8">
          <Logo size={30} wordmark class="[--primary:#4c9deb]" />
        </div>

        <h2 class="text-4xl font-bold mb-3 leading-tight">
          Your infrastructure.<br/>Your stronghold.
        </h2>
        <p class="text-white/60 text-base leading-relaxed">
          VPN, firewall, DNS and your whole fleet of machines, self-hosted and run from one place
        </p>
      </div>

      <!-- Features Grid - 2 columns -->
      <div class="grid grid-cols-2 gap-4 mb-10">
        <div class="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-all group">
          <div class="flex items-center gap-3 mb-2">
            <div class="w-9 h-9 bg-primary/20 rounded-lg flex items-center justify-center flex-shrink-0 group-hover:bg-primary/30 transition-colors">
              <Icon name="network" size={18} class="text-primary" />
            </div>
            <h3 class="font-semibold text-sm">Private network</h3>
          </div>
          <p class="text-xs text-white/60 leading-relaxed">WireGuard and Headscale in one address space</p>
        </div>

        <div class="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-all group">
          <div class="flex items-center gap-3 mb-2">
            <div class="w-9 h-9 bg-primary/20 rounded-lg flex items-center justify-center flex-shrink-0 group-hover:bg-primary/30 transition-colors">
              <Icon name="shield-lock" size={18} class="text-primary" />
            </div>
            <h3 class="font-semibold text-sm">Firewall at the gate</h3>
          </div>
          <p class="text-xs text-white/60 leading-relaxed">Country and network blocking, automatic bans</p>
        </div>

        <div class="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-all group">
          <div class="flex items-center gap-3 mb-2">
            <div class="w-9 h-9 bg-primary/20 rounded-lg flex items-center justify-center flex-shrink-0 group-hover:bg-primary/30 transition-colors">
              <Icon name="server" size={18} class="text-primary" />
            </div>
            <h3 class="font-semibold text-sm">Fleet watch</h3>
          </div>
          <p class="text-xs text-white/60 leading-relaxed">Machine health, CVE scans and a browser console</p>
        </div>

        <div class="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-all group">
          <div class="flex items-center gap-3 mb-2">
            <div class="w-9 h-9 bg-primary/20 rounded-lg flex items-center justify-center flex-shrink-0 group-hover:bg-primary/30 transition-colors">
              <Icon name="world" size={18} class="text-primary" />
            </div>
            <h3 class="font-semibold text-sm">DNS and domains</h3>
          </div>
          <p class="text-xs text-white/60 leading-relaxed">Ad blocking and HTTPS routes to your services</p>
        </div>
      </div>

      <!-- Footer -->
      <div class="flex flex-wrap gap-6 text-xs text-white/60">
        <div class="flex items-center gap-2">
          <Icon name="key" size={12} />
          <span>Passkeys and 2FA</span>
        </div>
        <div class="flex items-center gap-2">
          <Icon name="server" size={12} />
          <span>Self-hosted</span>
        </div>
        <div class="flex items-center gap-2">
          <Icon name="code" size={12} />
          <span>Open source</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Right Panel / Form Section -->
  <div class="flex-1 bg-background flex items-center justify-center p-6 lg:p-12 relative -mt-8 lg:mt-0 rounded-t-3xl lg:rounded-none">
    <!-- Theme toggle -->
    <button
      onclick={toggleTheme}
      class="absolute top-4 right-4 lg:top-6 lg:right-6 w-9 h-9 rounded-lg flex items-center justify-center hover:bg-muted transition-colors text-muted-foreground"
    >
      {#if $theme === 'dark'}
        <Icon name="sun" size={18} />
      {:else}
        <Icon name="moon" size={18} />
      {/if}
    </button>

    <div class="w-full max-w-lg">
      <!-- Header -->
      <div class="hidden lg:block mb-4">
        <p class="text-sm font-medium text-primary mb-2">Sign in to your account</p>
        <h1 class="text-3xl font-bold text-foreground">Welcome back</h1>
      </div>

      <!-- Login Card -->
      <div class="bg-card border border-border rounded-2xl p-6 ">
        {#if error}
          <div class="flex items-center gap-2.5 px-3.5 py-3 bg-destructive/10 border border-destructive/20 rounded-xl text-sm text-destructive mb-5">
            <Icon name="alert-circle" size={18} class="flex-shrink-0" />
            <span>{error}</span>
          </div>
        {/if}

        <form onsubmit={(e) => { e.preventDefault(); handleLogin() }} class="space-y-6">
          {#if requires2FA}
            <!-- 2FA Step -->
            <div class="text-center mb-6">
              <div class="w-16 h-16 bg-gradient-to-br from-primary/20 to-primary/10 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-lg shadow-primary/10">
                <Icon name="shield-check" size={32} class="text-primary" />
              </div>
              <h3 class="text-xl font-semibold text-foreground">Two-Factor Authentication</h3>
              <p class="text-sm text-muted-foreground mt-2">Enter the 6-digit code from your authenticator app</p>
            </div>

            <div class="mb-6">
              <OtpInput bind:value={totpCode} onComplete={handleLogin} size="lg" disabled={loading} />
            </div>

            {#if loading}
              <div class="flex justify-center py-2">
                <span class="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin"></span>
              </div>
            {/if}

            <div class="flex items-center justify-center pt-2">
              <Button variant="secondary" size="sm" icon="arrow-left" onclick={backToLogin}>
                Back to login
              </Button>
            </div>
          {:else}
            <!-- Username Field -->
            <div>
              <label for="username" class="block text-sm font-medium text-foreground mb-2.5">Username</label>
              <Input
                id="username"
                type="text"
                bind:value={username}
                placeholder="Enter your username"
                autocomplete="username"
                prefixIcon="user"
                class="w-full"
                size="default"
                required
              />
            </div>

            <!-- Password Field -->
            <div>
              <label for="password" class="block text-sm font-medium text-foreground mb-2.5">Password</label>
              <Input
                id="password"
                type="password"
                bind:value={password}
                placeholder="Enter your password"
                autocomplete="current-password"
                prefixIcon="lock"
                class="w-full"
                size="default"
                required
              />
            </div>

            <!-- Remember me & Submit -->
            <div class="flex items-center justify-between pt-2">
              <Checkbox variant="switch" label="Remember me" labelPosition="right" />
              <Button type="submit" loading={loading}>
                {#if loading}
                  Signing in...
                {:else}
                  Sign In
                  <Icon name="arrow-right" size={16} class="ml-2" />
                {/if}
              </Button>
            </div>

            {#if canPasskey}
              <!-- Passwordless passkey login -->
              <div class="flex items-center gap-3 pt-2">
                <span class="h-px flex-1 bg-border"></span>
                <span class="text-xs text-muted-foreground">or</span>
                <span class="h-px flex-1 bg-border"></span>
              </div>
              <Button
                type="button"
                variant="secondary"
                class="w-full"
                icon="key"
                loading={passkeyLoading}
                onclick={handlePasskeyLogin}
              >
                Sign in with a passkey
              </Button>
            {/if}
          {/if}
        </form>
      </div>

    </div>
  </div>
</div>
