<script>
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPost, apiPut } from '../stores/app.js'
  import { lookupIPs } from '../stores/geo.js'
  import { formatDate } from '../lib/utils/format.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import Input from '../components/Input.svelte'
  import Badge from '../components/Badge.svelte'
  import Modal from '../components/Modal.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import ContentBlock from '../components/ContentBlock.svelte'
  import OtpInput from '../components/OtpInput.svelte'
  import CountryFlag from '../components/CountryFlag.svelte'

  let { loading = $bindable(true) } = $props()

  // Geo data for session IPs
  let geoData = $state({})

  // User info
  let user = $state(null)
  let sessions = $state([])
  let loadingSessions = $state(false)

  // Password change
  let showPasswordModal = $state(false)
  let passwordForm = $state({
    current: '',
    new: '',
    confirm: ''
  })
  let changingPassword = $state(false)

  // 2FA state
  let twoFactorEnabled = $state(false)
  let show2FASetupModal = $state(false)
  let show2FADisableModal = $state(false)
  let twoFASetup = $state({ qrCode: '', secret: '' })
  let twoFAVerifyCode = $state('')
  let twoFADisableForm = $state({ password: '', code: '' })
  let settingUp2FA = $state(false)
  let disabling2FA = $state(false)

  async function loadProfile() {
    loading = true
    try {
      const [userData, sessionsData, twoFAStatus] = await Promise.all([
        apiGet('/api/auth/me'),
        apiGet('/api/auth/sessions').catch(() => ({ sessions: [] })),
        apiGet('/api/auth/2fa/status').catch(() => ({ enabled: false }))
      ])
      user = userData.user || userData
      sessions = sessionsData.sessions || []
      twoFactorEnabled = twoFAStatus.enabled || false

      // Look up geo data for session IPs
      if (sessions.length > 0) {
        const ips = sessions.map(s => s.ipAddress).filter(Boolean)
        geoData = await lookupIPs(ips)
      }
    } catch (e) {
      // 401 errors are handled globally - just show other errors
      if (!e.message?.includes('expired') && !e.message?.includes('Session')) {
        toast('Failed to load profile: ' + e.message, 'error')
      }
    } finally {
      loading = false
    }
  }

  async function changePassword() {
    if (passwordForm.new !== passwordForm.confirm) {
      toast('Passwords do not match', 'error')
      return
    }
    if (passwordForm.new.length < 8) {
      toast('Password must be at least 8 characters', 'error')
      return
    }

    changingPassword = true
    try {
      await apiPost('/api/auth/change-password', {
        currentPassword: passwordForm.current,
        newPassword: passwordForm.new
      })
      toast('Password changed successfully', 'success')
      showPasswordModal = false
      passwordForm = { current: '', new: '', confirm: '' }
    } catch (e) {
      toast('Failed to change password: ' + e.message, 'error')
    } finally {
      changingPassword = false
    }
  }

  async function revokeSession(sessionId) {
    try {
      await apiPost(`/api/auth/sessions/${sessionId}/revoke`)
      sessions = sessions.filter(s => s.id !== sessionId)
      toast('Session revoked', 'success')
    } catch (e) {
      toast('Failed to revoke session: ' + e.message, 'error')
    }
  }

  async function revokeAllOtherSessions() {
    try {
      await apiPost('/api/auth/sessions/revoke-others')
      // Reload sessions
      const sessionsData = await apiGet('/api/auth/sessions').catch(() => ({ sessions: [] }))
      sessions = sessionsData.sessions || []
      toast('All other sessions revoked', 'success')
    } catch (e) {
      toast('Failed to revoke sessions: ' + e.message, 'error')
    }
  }

  function getDeviceIcon(userAgent) {
    if (!userAgent) return 'device-desktop'
    const ua = userAgent.toLowerCase()
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) return 'device-mobile'
    if (ua.includes('tablet') || ua.includes('ipad')) return 'device-tablet'
    return 'device-desktop'
  }

  function getBrowserName(userAgent) {
    if (!userAgent) return 'Unknown browser'
    if (userAgent.includes('Firefox')) return 'Firefox'
    if (userAgent.includes('Chrome')) return 'Chrome'
    if (userAgent.includes('Safari')) return 'Safari'
    if (userAgent.includes('Edge')) return 'Edge'
    return 'Browser'
  }

  // 2FA functions
  async function start2FASetup() {
    settingUp2FA = true
    try {
      const data = await apiPost('/api/auth/2fa/setup')
      twoFASetup = { qrCode: data.qrCode, secret: data.secret }
      twoFAVerifyCode = ''
      show2FASetupModal = true
    } catch (e) {
      toast('Failed to start 2FA setup: ' + e.message, 'error')
    } finally {
      settingUp2FA = false
    }
  }

  async function enable2FA() {
    if (!twoFAVerifyCode || twoFAVerifyCode.length !== 6) {
      toast('Please enter a 6-digit code', 'error')
      return
    }

    settingUp2FA = true
    try {
      await apiPost('/api/auth/2fa/enable', { code: twoFAVerifyCode })
      toast('Two-factor authentication enabled', 'success')
      twoFactorEnabled = true
      show2FASetupModal = false
      twoFASetup = { qrCode: '', secret: '' }
      twoFAVerifyCode = ''
    } catch (e) {
      toast('Failed to enable 2FA: ' + e.message, 'error')
    } finally {
      settingUp2FA = false
    }
  }

  async function disable2FA() {
    if (!twoFADisableForm.password || !twoFADisableForm.code) {
      toast('Please enter your password and 2FA code', 'error')
      return
    }

    disabling2FA = true
    try {
      await apiPost('/api/auth/2fa/disable', {
        password: twoFADisableForm.password,
        code: twoFADisableForm.code
      })
      toast('Two-factor authentication disabled', 'success')
      twoFactorEnabled = false
      show2FADisableModal = false
      twoFADisableForm = { password: '', code: '' }
    } catch (e) {
      toast('Failed to disable 2FA: ' + e.message, 'error')
    } finally {
      disabling2FA = false
    }
  }

  onMount(() => {
    loadProfile()
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="user"
    title="Profile"
    description="Manage your account settings, security options, and active sessions."
  />

  {#if loading}
    <LoadingSpinner centered size="lg" />
  {:else}
    <div class="grid gap-4 lg:grid-cols-2">
      <!-- Account Info -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="user" size={16} />
            Account
          </h3>
        </div>
        <div class="kt-panel-body">
          <div class="grid grid-cols-2 gap-3">
            <ContentBlock variant="data" label="Username" value={user?.username || 'admin'} mono padding="sm" />
            <ContentBlock variant="data" label="Last Login" value={formatDate(user?.lastLogin)} padding="sm" />
          </div>
        </div>
      </div>

      <!-- Security -->
      <div class="kt-panel">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="shield-lock" size={16} />
            Security
          </h3>
        </div>
        <div class="kt-panel-body space-y-3">
          <ContentBlock title="Password" description="Change your account password">
            <Button size="sm" variant="secondary" icon="lock" onclick={() => showPasswordModal = true}>
              Change
            </Button>
          </ContentBlock>

          <ContentBlock title="Two-Factor Authentication" description={twoFactorEnabled ? 'Enabled - Your account is protected' : 'Not configured'} activeBorder={twoFactorEnabled} inactiveBorder={!twoFactorEnabled}>
            {#if twoFactorEnabled}
              <div class="flex items-center gap-2">
                <Badge variant="success" size="sm">Enabled</Badge>
                <Button size="sm" variant="ghost" icon="x" onclick={() => show2FADisableModal = true}>
                  Disable
                </Button>
              </div>
            {:else}
              <Button size="sm" variant="secondary" icon="shield-check" onclick={start2FASetup} loading={settingUp2FA}>
                Enable
              </Button>
            {/if}
          </ContentBlock>
        </div>
      </div>

      <!-- Active Sessions - Full width -->
      <div class="kt-panel lg:col-span-2">
        <div class="kt-panel-header">
          <h3 class="kt-panel-title">
            <Icon name="device-desktop" size={16} />
            Active Sessions
          </h3>
          {#if sessions.length > 1}
            <Button size="xs" variant="ghost" icon="logout" onclick={revokeAllOtherSessions}>
              Revoke All Others
            </Button>
          {/if}
        </div>
        <div class="kt-panel-body">
          {#if sessions.length === 0}
            <div class="text-center py-6 text-muted-foreground text-sm">
              <Icon name="device-desktop" size={24} class="mx-auto mb-2 opacity-50" />
              <p>No active sessions found</p>
            </div>
          {:else}
            <div class="space-y-2">
              {#each sessions as session}
                {@const geo = geoData[session.ipAddress]}
                {@const country = geo?.country_code}
                <ContentBlock
                  icon={getDeviceIcon(session.userAgent)}
                  title={getBrowserName(session.userAgent)}
                  active={session.current}
                >
                  {#snippet descriptionSlot()}
                    <div class="flex items-center gap-2 text-xs text-muted-foreground">
                      <CountryFlag code={country} size="sm" />
                      <span>{session.ipAddress || 'Unknown IP'}</span>
                      <span>·</span>
                      <span>Last active {formatDate(session.lastActive)}</span>
                      {#if session.current}
                        <Badge variant="success" size="sm">Current</Badge>
                      {/if}
                    </div>
                  {/snippet}
                  {#if !session.current}
                    <Button
                      size="xs"
                      variant="ghost"
                      icon="x"
                      onclick={() => revokeSession(session.id)}
                    >
                      Revoke
                    </Button>
                  {/if}
                </ContentBlock>
              {/each}
            </div>
          {/if}
        </div>
      </div>
    </div>
  {/if}
</div>

<!-- Change Password Modal -->
<Modal bind:open={showPasswordModal} title="Change Password" size="sm">
  <form onsubmit={(e) => { e.preventDefault(); changePassword() }} class="space-y-4">
    <Input
      label="Current Password"
      type="password"
      bind:value={passwordForm.current}
      placeholder="Enter current password"
      prefixIcon="lock"
      required
    />
    <Input
      label="New Password"
      type="password"
      bind:value={passwordForm.new}
      placeholder="Enter new password"
      prefixIcon="lock"
      helperText="Minimum 8 characters"
      required
    />
    <Input
      label="Confirm New Password"
      type="password"
      bind:value={passwordForm.confirm}
      placeholder="Confirm new password"
      prefixIcon="lock"
      required
    />
  </form>

  {#snippet footer()}
    <Button variant="secondary" onclick={() => showPasswordModal = false}>Cancel</Button>
    <Button onclick={changePassword} loading={changingPassword} icon="check">
      Change Password
    </Button>
  {/snippet}
</Modal>

<!-- 2FA Setup Modal -->
<Modal bind:open={show2FASetupModal} title="Enable Two-Factor Authentication" size="lg">
  <div class="flex flex-col sm:flex-row gap-6">
    <!-- Left: QR Code -->
    <div class="flex-shrink-0 flex flex-col items-center">
      {#if twoFASetup.qrCode}
        <div class="bg-white p-4 rounded-xl shadow-sm">
          <img src={twoFASetup.qrCode} alt="2FA QR Code" class="w-[180px] h-[180px]" />
        </div>
      {:else}
        <div class="w-[212px] h-[212px] bg-muted rounded-xl flex items-center justify-center">
          <span class="w-8 h-8 border-2 border-muted-foreground border-t-transparent rounded-full animate-spin"></span>
        </div>
      {/if}
      <p class="text-xs text-muted-foreground mt-3 text-center">Scan with your authenticator app</p>
    </div>

    <!-- Right: Instructions and Input -->
    <div class="flex-1 space-y-4">
      <div>
        <h4 class="font-medium text-foreground mb-2">Setup Instructions</h4>
        <ol class="text-sm text-muted-foreground space-y-2">
          <li class="flex gap-2">
            <span class="flex-shrink-0 w-5 h-5 rounded-full bg-primary/10 text-primary text-xs flex items-center justify-center font-medium">1</span>
            <span>Install an authenticator app like <strong class="text-foreground">Google Authenticator</strong> or <strong class="text-foreground">Authy</strong></span>
          </li>
          <li class="flex gap-2">
            <span class="flex-shrink-0 w-5 h-5 rounded-full bg-primary/10 text-primary text-xs flex items-center justify-center font-medium">2</span>
            <span>Scan the QR code or enter the secret key manually</span>
          </li>
          <li class="flex gap-2">
            <span class="flex-shrink-0 w-5 h-5 rounded-full bg-primary/10 text-primary text-xs flex items-center justify-center font-medium">3</span>
            <span>Enter the 6-digit code from your app below</span>
          </li>
        </ol>
      </div>

      <ContentBlock variant="data" label="Secret key (manual entry)" value={twoFASetup.secret} copyable mono />

      <div>
        <span class="block text-sm font-medium text-foreground mb-2">Verification Code</span>
        <OtpInput bind:value={twoFAVerifyCode} onComplete={enable2FA} />
      </div>
    </div>
  </div>

  {#snippet footer()}
    <Button variant="secondary" onclick={() => { show2FASetupModal = false; twoFASetup = { qrCode: '', secret: '' }; twoFAVerifyCode = '' }}>Cancel</Button>
    <Button onclick={enable2FA} loading={settingUp2FA} disabled={twoFAVerifyCode.length !== 6} icon="shield-check">
      Enable 2FA
    </Button>
  {/snippet}
</Modal>

<!-- 2FA Disable Modal -->
<Modal bind:open={show2FADisableModal} title="Disable Two-Factor Authentication" size="sm">
  <div class="space-y-4">
    <ContentBlock variant="indicator" color="destructive" icon="alert-triangle" title="Warning" description="Disabling 2FA will make your account less secure. You can re-enable it anytime." />

    <Input
      label="Password"
      type="password"
      bind:value={twoFADisableForm.password}
      placeholder="Enter your password"
      prefixIcon="lock"
    />

    <div>
      <span class="block text-sm font-medium text-foreground mb-2">2FA Code</span>
      <OtpInput bind:value={twoFADisableForm.code} />
    </div>
  </div>

  {#snippet footer()}
    <Button variant="secondary" onclick={() => { show2FADisableModal = false; twoFADisableForm = { password: '', code: '' } }}>Cancel</Button>
    <Button variant="destructive" onclick={disable2FA} loading={disabling2FA} disabled={!twoFADisableForm.password || twoFADisableForm.code.length !== 6} icon="x">
      Disable 2FA
    </Button>
  {/snippet}
</Modal>
