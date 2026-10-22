<script>
  // Idle lock: a client-side screen lock that arms only when the admin has set a positive
  // idle_lock_minutes (surfaced on the user via /api/auth/me). After that many minutes with no
  // user interaction it covers the app and requires re-authentication (password, plus a fresh
  // 2FA code when the user has 2FA) via POST /api/auth/unlock. It is walk-up protection, not a
  // server boundary — the session's absolute expiry remains the hard limit — and always offers a
  // "Log out" escape so no one can get stuck.
  import { currentUser, apiPost, setGlobalLockHandler } from '../stores/app.js'
  import { connect as wsConnect, disconnect as wsDisconnect, stopReconnect as wsStopReconnect } from '../stores/websocket.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import StepUpFields from './StepUpFields.svelte'

  let { onLogout } = $props()

  let locked = $state(false)
  let password = $state('')
  let totp = $state('')
  let error = $state('')
  let busy = $state(false)
  let lastActivity = Date.now()

  const minutes = $derived($currentUser?.idleLockMinutes || 0)
  const needsTotp = $derived(!!$currentUser?.totpEnabled)
  const canSubmit = $derived(!!password && (!needsTotp || totp.length === 6))

  function bump() {
    // Only user interaction counts as activity; cheap timestamp, checked by the interval below.
    if (!locked) lastActivity = Date.now()
  }

  // Enter the locked state: show the overlay and cut the live WebSocket so stats don't keep
  // streaming behind the blur (the server also refuses a locked session's WS handshake). No
  // reconnect while locked; unlock() re-establishes it.
  function suspendLiveData() {
    try { wsStopReconnect(); wsDisconnect() } catch (_) { /* best-effort */ }
  }

  // Arm the lock. Persists it server-side so a refresh (or any API call) stays locked until an
  // unlock — the lock is a real boundary, not just this overlay. Idempotent; network errors are
  // swallowed because the overlay is already up.
  async function armLock() {
    locked = true
    suspendLiveData()
    try {
      await apiPost('/api/auth/lock')
    } catch (_) {
      /* already visually locked; server will also lock on next request's 423 path */
    }
  }

  async function unlock() {
    if (!canSubmit || busy) return
    error = ''
    busy = true
    try {
      await apiPost('/api/auth/unlock', { currentPassword: password, totpCode: totp })
      password = ''
      totp = ''
      locked = false
      lastActivity = Date.now()
      // Clear the store flag so the restore effect below doesn't immediately re-lock.
      currentUser.update((u) => (u ? { ...u, locked: false } : u))
      // Bring the live WebSocket back now that the session is unlocked.
      try { wsConnect() } catch (_) { /* store will connect on next use */ }
    } catch (e) {
      // A true 401 (session actually expired) already triggered the global logout inside api();
      // anything else (e.g. 428 wrong credential) just re-prompts here.
      error = e?.message || 'Unlock failed'
    } finally {
      busy = false
    }
  }

  // Restore a server-side lock on load/refresh: if /api/auth/me reported the session locked, the
  // overlay comes straight back up (this is what defeats the F5 bypass). Also re-arm when any
  // request hits 423.
  $effect(() => {
    if ($currentUser?.locked && !locked) {
      locked = true
      suspendLiveData()
    }
  })
  $effect(() => {
    setGlobalLockHandler(() => {
      if (!locked) {
        locked = true
        suspendLiveData()
      }
    })
    return () => setGlobalLockHandler(null)
  })

  $effect(() => {
    const events = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'wheel']
    events.forEach((ev) => window.addEventListener(ev, bump, { passive: true }))
    const iv = setInterval(() => {
      if (minutes > 0 && !locked && Date.now() - lastActivity >= minutes * 60000) {
        armLock()
      }
    }, 5000)
    return () => {
      events.forEach((ev) => window.removeEventListener(ev, bump))
      clearInterval(iv)
    }
  })

</script>

{#if locked}
  <div class="fixed inset-0 z-[100] flex items-center justify-center bg-background/80 backdrop-blur-md">
    <div class="w-full max-w-sm mx-4 rounded-lg border border-border bg-card p-6 shadow-xl space-y-4">
      <div class="flex items-center gap-3">
        <div class="flex-shrink-0 w-10 h-10 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center">
          <Icon name="lock" size={20} class="text-primary" />
        </div>
        <div>
          <p class="font-semibold text-foreground">Session locked</p>
          <p class="text-sm text-muted-foreground">Locked after {minutes} min idle — re-enter your credentials to continue.</p>
        </div>
      </div>

      <StepUpFields id="idle" label="Password" bind:password bind:totp {needsTotp} autofocus onsubmit={unlock} />

      {#if error}
        <p class="text-sm text-destructive">{error}</p>
      {/if}

      <div class="flex gap-2 pt-1">
        <Button onclick={onLogout} variant="secondary" class="flex-1">Log out</Button>
        <Button onclick={unlock} variant="primary" class="flex-1" disabled={!canSubmit || busy}>
          {#if busy}<Icon name="refresh" size={14} class="animate-spin mr-1" />{/if}
          Unlock
        </Button>
      </div>
    </div>
  </div>
{/if}
