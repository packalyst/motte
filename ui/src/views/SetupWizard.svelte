<script>
  import { theme, toast, apiPost, apiGet } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Input from '../components/Input.svelte'
  import Button from '../components/Button.svelte'

  let { onComplete } = $props()

  let step = $state(1)
  let loading = $state(false)
  let error = $state('')

  // Step 1: Admin user
  let adminUsername = $state('')
  let adminPassword = $state('')
  let adminPasswordConfirm = $state('')

  // Step 2: Headscale
  let headscaleApiUrl = $state('')  // Internal API URL (auto-detected, readonly)
  let headscaleUrl = $state('')     // Public URL for Tailscale clients (user input)
  let headscaleApiKey = $state('')
  let detectingUrl = $state(false)
  let generatingKey = $state(false)
  let testingConnection = $state(false)
  let connectionValid = $state(false)

  function toggleTheme() {
    theme.update(t => t === 'dark' ? 'light' : 'dark')
  }

  // Password strength calculation
  function getPasswordStrength(password) {
    if (!password) return { score: 0, label: '', color: '' }

    let score = 0
    const checks = {
      length: password.length >= 8,
      upper: /[A-Z]/.test(password),
      lower: /[a-z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    }

    if (checks.length) score++
    if (checks.upper) score++
    if (checks.lower) score++
    if (checks.number) score++
    if (checks.special) score++

    const labels = ['', 'Very Weak', 'Weak', 'Fair', 'Good', 'Strong']
    const colors = ['', 'bg-red-500', 'bg-orange-500', 'bg-yellow-500', 'bg-blue-500', 'bg-green-500']

    return { score, label: labels[score], color: colors[score], checks }
  }

  let passwordStrength = $derived(getPasswordStrength(adminPassword))

  function validateStep1() {
    if (adminUsername.length < 3) {
      error = 'Username must be at least 3 characters'
      return false
    }
    if (adminPassword.length < 8) {
      error = 'Password must be at least 8 characters'
      return false
    }
    if (!/[A-Z]/.test(adminPassword)) {
      error = 'Password must contain at least one uppercase letter'
      return false
    }
    if (!/[a-z]/.test(adminPassword)) {
      error = 'Password must contain at least one lowercase letter'
      return false
    }
    if (!/[0-9]/.test(adminPassword)) {
      error = 'Password must contain at least one number'
      return false
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(adminPassword)) {
      error = 'Password must contain at least one special character'
      return false
    }
    if (adminPassword !== adminPasswordConfirm) {
      error = 'Passwords do not match'
      return false
    }
    error = ''
    return true
  }

  async function nextStep() {
    if (step === 1 && validateStep1()) {
      step = 2
      // Auto-detect URL and generate key when entering step 2
      await initHeadscale()
    }
  }

  function prevStep() {
    if (step > 1) {
      step--
      error = ''
    }
  }

  async function initHeadscale() {
    error = ''

    // Auto-detect internal API URL
    if (!headscaleApiUrl) {
      detectingUrl = true
      try {
        const res = await apiGet('/api/setup/detect-headscale')
        headscaleApiUrl = res.url
      } catch (e) {
        error = 'Failed to detect Headscale: ' + e.message
      } finally {
        detectingUrl = false
      }
    }

    // Auto-generate API key (or get existing pending)
    if (!headscaleApiKey) {
      generatingKey = true
      try {
        const res = await apiPost('/api/setup/generate-apikey', {})
        headscaleApiKey = res.apiKey
      } catch (e) {
        error = 'Failed to generate API key: ' + e.message
      } finally {
        generatingKey = false
      }
    }
  }

  async function testHeadscale() {
    if (!headscaleApiUrl || !headscaleApiKey) {
      error = 'Headscale API URL and API key are required'
      return
    }

    testingConnection = true
    connectionValid = false
    error = ''

    try {
      await apiPost('/api/setup/test-headscale', { url: headscaleApiUrl, apiKey: headscaleApiKey })
      connectionValid = true
      toast('Connection successful', 'success')
    } catch (e) {
      error = 'Connection failed: ' + (e.message || 'Check Headscale is running')
      connectionValid = false
    } finally {
      testingConnection = false
    }
  }

  async function completeSetup() {
    if (!connectionValid) {
      error = 'Please test the Headscale connection first'
      return
    }
    if (!headscaleUrl) {
      error = 'Please enter the public Headscale URL'
      return
    }

    loading = true
    error = ''

    try {
      await apiPost('/api/setup/complete', {
        adminUsername,
        adminPassword,
        headscaleApiUrl,
        headscaleUrl,
        headscaleApiKey
      })

      toast('Setup completed successfully', 'success')

      // Auto-login the admin user
      try {
        const data = await apiPost('/api/auth/login', {
          username: adminUsername,
          password: adminPassword
        })
        localStorage.setItem('session_token', data.token)
        localStorage.setItem('session_expires', data.expiresAt)
        if (onComplete) onComplete(data.user)
      } catch {
        // Setup done but login failed, user will need to login manually
        if (onComplete) onComplete(null)
      }
    } catch (e) {
      error = e.message || 'Setup failed'
    } finally {
      loading = false
    }
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
        <div class="w-12 h-12 bg-primary rounded-xl flex items-center justify-center shadow-lg shadow-primary/20">
          <Icon name="shield" size={24} class="text-white" />
        </div>
      </div>
      <h1 class="text-2xl font-bold mb-2">Initial Setup</h1>
      <p class="text-sm text-muted-foreground">Configure Wire Panel</p>
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
          <div class="w-11 h-11 bg-primary rounded-xl flex items-center justify-center shadow-lg shadow-primary/20">
            <Icon name="shield" size={22} class="text-white" />
          </div>
          <span class="text-lg font-semibold tracking-tight">Wire Panel</span>
        </div>

        <h2 class="text-4xl font-bold mb-3 leading-tight">
          Welcome to<br/>Wire Panel
        </h2>
        <p class="text-muted-foreground text-base leading-relaxed">
          Let's get you set up in just a few steps. We'll create your admin account and connect to Headscale.
        </p>
      </div>

      <!-- Setup Steps Preview -->
      <div class="grid grid-cols-2 gap-4 mb-10">
        <div class="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-4">
          <div class="flex items-center gap-3 mb-2">
            <div class="w-9 h-9 bg-primary/20 rounded-lg flex items-center justify-center flex-shrink-0">
              <Icon name="user-plus" size={18} class="text-primary" />
            </div>
            <h3 class="font-semibold text-sm">Admin Account</h3>
          </div>
          <p class="text-xs text-muted-foreground leading-relaxed">Create your administrator credentials</p>
        </div>

        <div class="bg-white/5 backdrop-blur-sm border border-white/10 rounded-xl p-4">
          <div class="flex items-center gap-3 mb-2">
            <div class="w-9 h-9 bg-primary/20 rounded-lg flex items-center justify-center flex-shrink-0">
              <Icon name="server" size={18} class="text-primary" />
            </div>
            <h3 class="font-semibold text-sm">Headscale</h3>
          </div>
          <p class="text-xs text-muted-foreground leading-relaxed">Connect to your VPN server</p>
        </div>
      </div>

      <!-- Footer -->
      <div class="flex flex-wrap gap-6 text-xs text-muted-foreground">
        <div class="flex items-center gap-2">
          <div class="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
          <span>Secure Setup</span>
        </div>
        <div class="flex items-center gap-2">
          <div class="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
          <span>Auto-Configuration</span>
        </div>
        <div class="flex items-center gap-2">
          <div class="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
          <span>Quick & Easy</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Right Panel / Form Section -->
  <div class="flex-1 bg-card flex items-center justify-center p-6 lg:p-8 relative -mt-8 lg:mt-0 rounded-t-3xl lg:rounded-none">
    <div class="w-full max-w-md">
      <!-- Desktop Header -->
      <div class="hidden lg:block mb-8">
        <h1 class="text-2xl font-semibold mb-2">Initial Setup</h1>
        <p class="text-sm text-muted-foreground">Configure Wire Panel</p>
      </div>

      <!-- Step Header -->
      <div class="mb-8">
        <!-- Step indicator -->
        <div class="flex items-center gap-3 mb-4">
          <div class="flex items-center gap-2">
            <div class="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
              <span class="text-sm font-semibold text-primary">{step}</span>
            </div>
            <div class="h-px flex-1 w-12 bg-border"></div>
            <div class="w-8 h-8 rounded-full {step === 2 ? 'bg-primary/10' : 'bg-muted'} flex items-center justify-center">
              <span class="text-sm font-semibold {step === 2 ? 'text-primary' : 'text-muted-foreground'}">2</span>
            </div>
          </div>
          <span class="text-xs font-medium text-muted-foreground ml-auto">Step {step} of 2</span>
        </div>

        <!-- Step title and description -->
        {#if step === 1}
          <div class="space-y-1">
            <h2 class="text-xl font-semibold">Create Admin Account</h2>
            <p class="text-sm text-muted-foreground">Set up your administrator credentials to manage the VPN panel</p>
          </div>
        {:else}
          <div class="space-y-1">
            <h2 class="text-xl font-semibold">Headscale Configuration</h2>
            <p class="text-sm text-muted-foreground">Connect to your WireGuard control server</p>
          </div>
        {/if}
      </div>

      <!-- Error -->
      {#if error}
        <div class="mb-6 flex items-center gap-2 px-3 py-2.5 bg-destructive/10 border border-destructive/20 rounded-lg text-sm text-destructive">
          <Icon name="alert-circle" size={16} />
          {error}
        </div>
      {/if}

      <!-- Step 1: Admin User -->
      {#if step === 1}
        <div class="space-y-4">

          <Input
            id="adminUsername"
            label="Username"
            labelClass="block text-sm font-medium mb-1.5"
            type="text"
            bind:value={adminUsername}
            placeholder="admin"
            prefixIcon="user"
            class="w-full"
            autocomplete="username"
            required
          />

          <Input
            id="adminPassword"
            label="Password"
            labelClass="block text-sm font-medium mb-1.5"
            type="password"
            bind:value={adminPassword}
            placeholder="Min 8 chars, upper, lower, number, special"
            prefixIcon="lock"
            class="w-full"
            autocomplete="new-password"
            required
          />

          <!-- Password Strength Indicator -->
          {#if adminPassword}
            <div class="space-y-2">
              <div class="flex gap-1">
                {#each [1, 2, 3, 4, 5] as i}
                  <div class="h-1 flex-1 rounded-full transition-colors {i <= passwordStrength.score ? passwordStrength.color : 'bg-muted'}"></div>
                {/each}
              </div>
              <div class="flex justify-between items-center">
                <span class="text-xs {passwordStrength.score >= 4 ? 'text-green-500' : passwordStrength.score >= 3 ? 'text-yellow-500' : 'text-red-500'}">
                  {passwordStrength.label}
                </span>
                <div class="flex gap-2 text-[10px] text-muted-foreground">
                  <span class={passwordStrength.checks?.length ? 'text-green-500' : ''}>8+</span>
                  <span class={passwordStrength.checks?.upper ? 'text-green-500' : ''}>A-Z</span>
                  <span class={passwordStrength.checks?.lower ? 'text-green-500' : ''}>a-z</span>
                  <span class={passwordStrength.checks?.number ? 'text-green-500' : ''}>0-9</span>
                  <span class={passwordStrength.checks?.special ? 'text-green-500' : ''}>!@#</span>
                </div>
              </div>
            </div>
          {/if}

          <Input
            id="adminPasswordConfirm"
            label="Confirm Password"
            labelClass="block text-sm font-medium mb-1.5"
            type="password"
            bind:value={adminPasswordConfirm}
            placeholder="Repeat password"
            prefixIcon="lock"
            class="w-full"
            autocomplete="new-password"
            required
          />

          <Button
            onclick={nextStep}
            class="w-full justify-center mt-6"
          >
            Continue
            <Icon name="arrow-right" size={18} />
          </Button>
        </div>
      {/if}

      <!-- Step 2: Headscale -->
      {#if step === 2}
        <div class="space-y-4">
          <!-- Loading state -->
          {#if detectingUrl || generatingKey}
            <div class="flex flex-col items-center py-8 gap-3">
              <span class="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin"></span>
              <p class="text-sm text-muted-foreground">
                {#if detectingUrl}Detecting Headscale...{:else}Generating API key...{/if}
              </p>
            </div>
          {:else}
            <Input
              id="headscaleApiUrl"
              label="Internal API URL"
              labelClass="block text-sm font-medium mb-1.5"
              helperText="Auto-detected from Docker (used for API calls)"
              helperClass="text-xs text-muted-foreground mt-1"
              type="url"
              value={headscaleApiUrl}
              prefixIcon="server"
              class="w-full"
              disabled
            />

            <Input
              id="headscaleApiKey"
              label="API Key"
              labelClass="block text-sm font-medium mb-1.5"
              helperText="Auto-generated (valid for 90 days)"
              helperClass="text-xs text-muted-foreground mt-1"
              type="password"
              value={headscaleApiKey}
              prefixIcon="key"
              suffixIcon={headscaleApiKey ? "check" : undefined}
              class="w-full"
              disabled
            />

            <!-- Test connection -->
            <Button
              onclick={testHeadscale}
              loading={testingConnection}
              disabled={!headscaleApiUrl || !headscaleApiKey}
              variant="secondary"
              class="w-full justify-center"
            >
              {#if testingConnection}
                Testing...
              {:else if connectionValid}
                <Icon name="circle-check" size={18} class="text-success" />
                Connection Valid
              {:else}
                <Icon name="plug" size={18} />
                Test Connection
              {/if}
            </Button>

            <!-- Public URL input -->
            <div class="border-t border-border pt-4">
              <Input
                id="headscaleUrl"
                label="Public URL"
                labelClass="block text-sm font-medium mb-1.5"
                helperText="External URL for Tailscale clients to connect"
                helperClass="text-xs text-muted-foreground mt-1"
                type="url"
                bind:value={headscaleUrl}
                placeholder="http://your-server-ip:8080"
                prefixIcon="globe"
                class="w-full"
              />
            </div>

            <div class="flex gap-3 pt-2">
              <Button
                onclick={prevStep}
                variant="secondary"
                class="flex-1 justify-center"
              >
                <Icon name="arrow-left" size={18} />
                Back
              </Button>
              <Button
                onclick={completeSetup}
                loading={loading}
                disabled={!connectionValid || !headscaleUrl}
                class="flex-1 justify-center"
              >
                {#if loading}
                  Completing...
                {:else}
                  Complete Setup
                  <Icon name="check" size={18} />
                {/if}
              </Button>
            </div>
          {/if}
        </div>
      {/if}
    </div>
  </div>
</div>
