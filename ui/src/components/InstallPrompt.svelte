<script>
  import { onMount } from 'svelte'
  import { toast } from '../stores/app.js'
  import { copyToClipboard } from '../lib/utils/clipboard.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'

  let show = $state(false)
  let deferredPrompt = $state(null)
  let isIOS = $state(false)
  let isSafari = $state(false)
  let isStandalone = $state(false)

  onMount(() => {
    // Check if already installed (standalone mode)
    isStandalone = window.matchMedia('(display-mode: standalone)').matches
      || window.navigator.standalone === true

    // Don't show if already installed
    if (isStandalone) return

    // Don't show if dismissed in the last 7 days
    const dismissed = localStorage.getItem('pwa-install-dismissed')
    if (dismissed) {
      const dismissedTime = parseInt(dismissed, 10)
      const sevenDays = 7 * 24 * 60 * 60 * 1000
      if (Date.now() - dismissedTime < sevenDays) return
    }

    // Check if iOS (includes Chrome on iOS which uses WebKit)
    isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent)
      || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)

    // Check if Safari (not Chrome/Firefox/etc on iOS)
    const ua = navigator.userAgent
    isSafari = isIOS && /Safari/.test(ua) && !/CriOS|FxiOS|OPiOS|EdgiOS/.test(ua)

    // Show for iOS Safari immediately
    if (isIOS) {
      show = true
      return
    }

    // For Chrome/Android, capture the install prompt
    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault()
      deferredPrompt = e
      show = true
    })
  })

  async function install() {
    if (isIOS) {
      dismiss()
      return
    }

    if (!deferredPrompt) return

    deferredPrompt.prompt()
    const { outcome } = await deferredPrompt.userChoice

    if (outcome === 'accepted') {
      show = false
    }
    deferredPrompt = null
  }

  function dismiss() {
    show = false
    localStorage.setItem('pwa-install-dismissed', Date.now().toString())
  }
</script>

{#if show}
  <!-- Backdrop with blur -->
  <div
    class="fixed inset-0 bg-black/20 backdrop-blur-[2px] z-50 animate-fade-in"
    onclick={dismiss}
  ></div>

  <!-- Modal -->
  <div class="fixed inset-x-4 bottom-4 sm:inset-auto sm:left-1/2 sm:top-1/2 sm:-translate-x-1/2 sm:-translate-y-1/2 sm:w-[420px] z-50 animate-slide-up">
    <div class="bg-card border border-border rounded-2xl shadow-2xl overflow-hidden">
      <!-- Header -->
      <div class="relative bg-gradient-to-br from-primary/20 via-success/10 to-info/20 px-6 py-6">
        <button
          onclick={dismiss}
          class="absolute top-4 right-4 p-2 rounded-lg bg-black/20 text-white/70 hover:text-white hover:bg-black/30 transition-colors"
        >
          <Icon name="x" size={18} />
        </button>

        <div class="flex items-center gap-4">
          <div class="w-16 h-16 bg-card rounded-2xl flex items-center justify-center shadow-lg">
            <Icon name="shield-check" size={32} class="text-success" />
          </div>
          <div>
            <h2 class="text-xl font-bold text-foreground">Install Wire Panel</h2>
            <p class="text-sm text-muted-foreground">Get the full app experience</p>
          </div>
        </div>
      </div>

      <!-- Content -->
      <div class="px-6 py-5">
        {#if isIOS}
          {#if isSafari}
            <!-- Safari on iOS -->
            <p class="text-sm text-muted-foreground mb-4">
              Install this app on your iPhone for quick access and a native app experience.
            </p>

            <div class="space-y-3 mb-4">
              <div class="flex items-center gap-4 p-3 rounded-xl bg-muted/50">
                <div class="w-10 h-10 rounded-xl bg-primary/20 flex items-center justify-center flex-shrink-0">
                  <Icon name="share" size={20} class="text-primary" />
                </div>
                <div class="flex-1">
                  <p class="text-sm font-medium text-foreground">1. Tap Share</p>
                  <p class="text-xs text-muted-foreground">Find the share icon in Safari's toolbar</p>
                </div>
              </div>

              <div class="flex items-center gap-4 p-3 rounded-xl bg-muted/50">
                <div class="w-10 h-10 rounded-xl bg-success/20 flex items-center justify-center flex-shrink-0">
                  <Icon name="square-plus" size={20} class="text-success" />
                </div>
                <div class="flex-1">
                  <p class="text-sm font-medium text-foreground">2. Add to Home Screen</p>
                  <p class="text-xs text-muted-foreground">Scroll down and tap "Add to Home Screen"</p>
                </div>
              </div>
            </div>

            <Button onclick={dismiss} variant="secondary" class="w-full">
              Got it
            </Button>
          {:else}
            <!-- Chrome/Firefox on iOS -->
            <div class="flex items-start gap-4 p-4 rounded-xl bg-warning/10 border border-warning/20 mb-4">
              <div class="w-10 h-10 rounded-xl bg-warning/20 flex items-center justify-center flex-shrink-0">
                <Icon name="alert-triangle" size={20} class="text-warning" />
              </div>
              <div>
                <p class="text-sm font-medium text-foreground mb-1">Safari Required</p>
                <p class="text-xs text-muted-foreground">iOS only allows app installation from Safari. Copy this URL and open it in Safari to install.</p>
              </div>
            </div>

            <div class="flex gap-3">
              <Button onclick={dismiss} variant="ghost" class="flex-1">
                Maybe later
              </Button>
              <Button onclick={() => { copyToClipboard(window.location.href); toast('URL copied!', 'success') }} icon="copy" class="flex-1">
                Copy URL
              </Button>
            </div>
          {/if}
        {:else}
          <!-- Android / Desktop -->
          <div class="space-y-3 mb-5">
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-success/20 flex items-center justify-center">
                <Icon name="bolt" size={16} class="text-success" />
              </div>
              <p class="text-sm text-foreground">Quick access from your home screen</p>
            </div>
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-info/20 flex items-center justify-center">
                <Icon name="wifi-off" size={16} class="text-info" />
              </div>
              <p class="text-sm text-foreground">Works offline with cached data</p>
            </div>
            <div class="flex items-center gap-3">
              <div class="w-8 h-8 rounded-lg bg-primary/20 flex items-center justify-center">
                <Icon name="device-mobile" size={16} class="text-primary" />
              </div>
              <p class="text-sm text-foreground">Native app-like experience</p>
            </div>
          </div>

          <div class="flex gap-3">
            <Button onclick={dismiss} variant="ghost" class="flex-1">
              Not now
            </Button>
            <Button onclick={install} icon="download" class="flex-1">
              Install App
            </Button>
          </div>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  @keyframes slide-up {
    from {
      opacity: 0;
      transform: translateY(30px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }
  @keyframes fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  .animate-slide-up {
    animation: slide-up 0.3s ease-out;
  }
  .animate-fade-in {
    animation: fade-in 0.2s ease-out;
  }

  @media (min-width: 640px) {
    .animate-slide-up {
      animation: none;
      animation: scale-in 0.3s ease-out;
    }
  }

  @keyframes scale-in {
    from {
      opacity: 0;
      transform: translate(-50%, -50%) scale(0.95);
    }
    to {
      opacity: 1;
      transform: translate(-50%, -50%) scale(1);
    }
  }
</style>
