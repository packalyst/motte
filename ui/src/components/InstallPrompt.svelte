<script>
  import { onMount } from 'svelte'
  import { toast } from '../stores/app.js'
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

    if (isStandalone) return

    // Only show on mobile devices
    const isMobile = /Android|iPhone|iPad|iPod|webOS|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)
      || (navigator.maxTouchPoints > 0 && window.innerWidth < 768)

    if (!isMobile) return

    // Check if iOS (includes Chrome on iOS which uses WebKit)
    isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent)
      || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)

    // Check if Safari (not Chrome/Firefox/etc on iOS)
    const ua = navigator.userAgent
    isSafari = isIOS && /Safari/.test(ua) && !/CriOS|FxiOS|OPiOS|EdgiOS/.test(ua)

    // Check if dismissed recently (24h cooldown)
    const dismissed = localStorage.getItem('pwa-install-dismissed')
    if (dismissed && Date.now() - parseInt(dismissed) < 24 * 60 * 60 * 1000) return

    // For Chrome/Android, capture the install prompt
    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault()
      deferredPrompt = e
      // Show banner when browser says PWA is installable
      setTimeout(() => show = true, 1500)
    })

    // For iOS, show instructions after delay (no beforeinstallprompt on iOS)
    if (isIOS) {
      setTimeout(() => show = true, 2000)
    }
  })

  async function install() {
    if (isIOS) {
      // Can't programmatically install on iOS, just dismiss
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
  <div class="fixed bottom-4 left-4 right-4 sm:left-auto sm:right-4 sm:w-80 z-50 animate-slide-up">
    <div class="bg-card border border-border rounded-xl shadow-xl overflow-hidden">
      <!-- Header with gradient -->
      <div class="bg-gradient-to-r from-primary/20 to-success/20 px-4 py-3 flex items-center gap-3">
        <div class="w-10 h-10 bg-card rounded-xl flex items-center justify-center shadow-sm">
          <Icon name="shield" size={20} class="text-success" />
        </div>
        <div class="flex-1">
          <div class="font-semibold text-sm text-foreground">Install Wire Panel</div>
          <div class="text-xs text-muted-foreground">Add to your home screen</div>
        </div>
        <button onclick={dismiss} class="p-1 text-muted-foreground hover:text-foreground transition-colors">
          <Icon name="x" size={16} />
        </button>
      </div>

      <!-- Content -->
      <div class="px-4 py-3">
        {#if isIOS}
          {#if isSafari}
            <!-- Safari on iOS - can install -->
            <p class="text-xs text-muted-foreground mb-3">
              To install this app on your iPhone:
            </p>
            <div class="flex items-center gap-3 text-xs">
              <div class="flex items-center gap-2 flex-1">
                <div class="w-7 h-7 rounded-lg bg-primary/20 flex items-center justify-center flex-shrink-0">
                  <Icon name="logout" size={14} class="text-primary rotate-[-90deg]" />
                </div>
                <span class="text-foreground">Tap <strong>Share</strong></span>
              </div>
              <Icon name="chevron-right" size={14} class="text-muted-foreground/30" />
              <div class="flex items-center gap-2 flex-1">
                <div class="w-7 h-7 rounded-lg bg-success/20 flex items-center justify-center flex-shrink-0">
                  <Icon name="plus" size={14} class="text-success" />
                </div>
                <span class="text-foreground"><strong>Add to Home</strong></span>
              </div>
            </div>
            <p class="text-[11px] text-muted-foreground mt-3 text-center">
              Tap <Icon name="logout" size={10} class="inline rotate-[-90deg]" /> in Safari's toolbar, then "Add to Home Screen"
            </p>
          {:else}
            <!-- Chrome/Firefox on iOS - must switch to Safari -->
            <div class="flex items-start gap-3">
              <div class="w-9 h-9 rounded-lg bg-warning/20 flex items-center justify-center flex-shrink-0">
                <Icon name="alert-triangle" size={18} class="text-warning" />
              </div>
              <div class="text-xs">
                <p class="text-foreground font-medium mb-1">Open in Safari to install</p>
                <p class="text-muted-foreground">iOS only allows app installation from Safari. Copy this URL and open it in Safari.</p>
              </div>
            </div>
            <Button onclick={() => { navigator.clipboard.writeText(window.location.href); toast('URL copied to clipboard', 'success') }} size="sm" variant="secondary" icon="copy" class="w-full mt-3">
              Copy URL
            </Button>
          {/if}
        {:else}
          <p class="text-xs text-muted-foreground">
            Install for quick access, works offline, and feels like a native app.
          </p>
          <div class="flex gap-2 mt-3">
            <Button onclick={dismiss} variant="ghost" size="sm" class="flex-1">
              Not now
            </Button>
            <Button onclick={install} size="sm" icon="download" class="flex-1">
              Install
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
      transform: translateY(20px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }
  .animate-slide-up {
    animation: slide-up 0.3s ease-out;
  }
</style>
