<script>
  /**
   * SecurityGlance — the Overview's security lead: a plain-language verdict banner
   * plus four "did anyone get in?" tiles (server logins, panel sessions, attackers,
   * active bans). Links out to the Server page for the full host detail.
   */
  import { onMount } from 'svelte'
  import { apiGet, currentView } from '../stores/app.js'
  import Icon from './Icon.svelte'

  let fw = $state(null)       // /api/fw/overview
  let sessions = $state(null) // /api/auth/sessions
  let host = $state(null)     // /api/server/security

  async function load() {
    const [a, b, c] = await Promise.allSettled([
      apiGet('/api/fw/overview'),
      apiGet('/api/auth/sessions'),
      apiGet('/api/server/security'),
    ])
    if (a.status === 'fulfilled') fw = a.value
    if (b.status === 'fulfilled') sessions = b.value
    if (c.status === 'fulfilled') host = c.value
  }
  onMount(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t) })

  function isLocal(ip) {
    return !ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')
  }
  const logins = $derived(host?.logins?.recent || [])
  const unknownLogins = $derived(logins.filter(l => l.root && l.ip && !isLocal(l.ip)).length)
  const sessionCount = $derived(Array.isArray(sessions) ? sessions.length : (sessions?.sessions?.length ?? 0))

  // Worst of the firewall status and the host status drives the banner.
  const rank = { calm: 0, elevated: 1, under_attack: 2 }
  const status = $derived.by(() => {
    const s = [fw?.status, host?.status].filter(Boolean)
    return s.sort((a, b) => (rank[b] ?? 0) - (rank[a] ?? 0))[0] || 'calm'
  })
  const V = {
    calm:         { dot: 'bg-success', title: 'All clear — no break-in, defenses holding.' },
    elevated:     { dot: 'bg-warning', title: 'Elevated — heavy probing, but no break-in.' },
    under_attack: { dot: 'bg-destructive', title: 'Warning — possible intrusion. Check the Server page.' },
  }
  const verdict = $derived(V[status] || V.calm)
  const sub = $derived(
    `${fw?.attackers ?? 0} attackers blocked this hour · ${unknownLogins === 0 ? 'no unknown logins' : unknownLogins + ' unknown login(s)'} · ${sessionCount} panel session${sessionCount === 1 ? '' : 's'}.`
  )
</script>

<div class="space-y-3">
  <!-- Verdict banner -->
  <div class="bg-card border border-border rounded-xl p-4 flex items-center gap-4">
    <span class="w-3 h-3 rounded-full {verdict.dot} shrink-0"></span>
    <div class="min-w-0">
      <div class="text-sm font-semibold text-foreground">{verdict.title}</div>
      <div class="text-xs text-muted-foreground">{sub}</div>
    </div>
    <button onclick={() => currentView.set('server')} class="ml-auto shrink-0 text-xs text-primary font-medium hover:underline flex items-center gap-1 cursor-pointer">
      Server detail <Icon name="chevron-right" size={13} />
    </button>
  </div>

  <!-- Breach glance tiles -->
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
    <button onclick={() => currentView.set('server')} class="bg-card border border-border rounded-xl p-3.5 text-left hover:border-primary transition cursor-pointer">
      <div class="flex items-start justify-between">
        <div>
          {#if unknownLogins > 0}<div class="text-2xl font-bold tabular-nums text-destructive">{unknownLogins}</div>
          {:else}<div class="text-2xl font-bold text-success">✓</div>{/if}
          <div class="text-xs text-muted-foreground mt-1">Server logins</div>
        </div>
        <Icon name="terminal-2" size={18} class="text-muted-foreground" />
      </div>
      <div class="text-[11px] text-muted-foreground mt-1.5">{logins.length} recent · {unknownLogins} unknown</div>
    </button>

    <div class="bg-card border border-border rounded-xl p-3.5">
      <div class="flex items-start justify-between">
        <div>
          <div class="text-2xl font-bold tabular-nums text-foreground">{sessionCount}</div>
          <div class="text-xs text-muted-foreground mt-1">Panel sessions</div>
        </div>
        <Icon name="lock" size={18} class="text-muted-foreground" />
      </div>
      <div class="text-[11px] text-muted-foreground mt-1.5">signed in now</div>
    </div>

    <div class="bg-card border border-border rounded-xl p-3.5">
      <div class="flex items-start justify-between">
        <div>
          <div class="text-2xl font-bold tabular-nums text-foreground">{(fw?.attackers ?? 0).toLocaleString()}</div>
          <div class="text-xs text-muted-foreground mt-1">Attackers now</div>
        </div>
        <Icon name="skull" size={18} class="text-muted-foreground" />
      </div>
      <div class="text-[11px] text-muted-foreground mt-1.5">blocked · last hour</div>
    </div>

    <div class="bg-card border border-border rounded-xl p-3.5">
      <div class="flex items-start justify-between">
        <div>
          <div class="text-2xl font-bold tabular-nums text-foreground">{(fw?.auto_bans ?? 0).toLocaleString()}</div>
          <div class="text-xs text-muted-foreground mt-1">Active bans</div>
        </div>
        <Icon name="ban" size={18} class="text-muted-foreground" />
      </div>
      <div class="text-[11px] text-muted-foreground mt-1.5">live blocklist size</div>
    </div>
  </div>
</div>
