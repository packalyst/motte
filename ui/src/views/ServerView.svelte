<script>
  import { onMount } from 'svelte'
  import { apiGet } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import StatCard from '../components/StatCard.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import { timeAgo } from '$lib/utils/format.js'

  // loading is bound by the Dashboard shell — clear it once we've loaded (or failed).
  let { loading = $bindable(true), onLogout } = $props()
  let data = $state(null)
  let error = $state(null)

  async function load() {
    try {
      data = await apiGet('/api/server/security')
      error = null
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }
  onMount(() => {
    load()
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  })

  // Verdict styling + one-line summary.
  const verdict = $derived.by(() => {
    const s = data?.status || 'calm'
    const failed = data?.logins?.failed_1h ?? 0
    const logins = data?.logins?.recent?.length ?? 0
    const rootLogin = (data?.logins?.recent || []).some(l => l.root && l.ip && !isLocal(l.ip))
    const map = {
      calm: { dot: 'bg-success', text: 'text-success', title: 'Host looks clean — no unauthorized access.' },
      elevated: { dot: 'bg-warning', text: 'text-warning', title: 'Elevated — worth a look.' },
      under_attack: { dot: 'bg-destructive', text: 'text-destructive', title: 'Warning — possible intrusion signal.' },
    }
    const v = map[s] || map.calm
    let sub = `${logins} shell login${logins === 1 ? '' : 's'}, ${failed} SSH brute-force attempt${failed === 1 ? '' : 's'} blocked this hour.`
    if (rootLogin) sub = 'A root login from a non-local address was seen recently — investigate. ' + sub
    return { ...v, sub }
  })

  function isLocal(ip) {
    return !ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')
  }
  function methodIcon(m) {
    if (m === 'publickey') return 'key'
    if (m === 'password') return 'lock'
    return 'login'
  }
  function certColor(status) {
    return status === 'expired' || status === 'critical' ? 'text-destructive'
      : status === 'warning' ? 'text-warning' : 'text-success'
  }
  function fmtUptime(secs) {
    if (!secs) return '—'
    const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600)
    return d > 0 ? `${d}d ${h}h` : `${h}h ${Math.floor((secs % 3600) / 60)}m`
  }
</script>

<div class="space-y-4">
  <InfoCard
    icon="shield-lock"
    title="Server"
    description="What's happening on the host itself: who logged in, privileged actions, what's exposed, and system health. Read-only, from the server's own logs."
  />

  {#if error && !data}
    <div class="bg-destructive/10 border border-destructive/30 rounded-xl p-4 text-sm text-destructive">
      Couldn't load server security data: {error}
    </div>
  {:else if data}
    <!-- Verdict -->
    <div class="bg-card border border-border rounded-xl p-4 flex items-center gap-4">
      <span class="w-3 h-3 rounded-full {verdict.dot} shrink-0 shadow-[0_0_0_4px] shadow-current/20"></span>
      <div>
        <div class="text-sm font-semibold text-foreground">{verdict.title}</div>
        <div class="text-xs text-muted-foreground">{verdict.sub}</div>
      </div>
    </div>

    <!-- Breach watch: SSH / shell logins -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div class="bg-card border border-border rounded-xl p-4 lg:col-span-2">
        <h3 class="text-sm font-semibold text-foreground mb-0.5 flex items-center gap-2"><Icon name="terminal-2" size={16} class="text-primary" />Successful shell logins</h3>
        <p class="text-[11px] text-muted-foreground mb-3">From <span class="font-mono">/var/log/auth.log</span>. An unfamiliar user, IP, or a root login means someone's inside.</p>
        {#if data.logins.recent.length === 0}
          <div class="text-sm text-muted-foreground py-4 text-center">No shell logins recorded recently.</div>
        {:else}
          <div class="divide-y divide-border">
            {#each data.logins.recent.slice().reverse() as l}
              {@const alarm = l.root && l.ip && !isLocal(l.ip)}
              <div class="flex items-center gap-3 py-2.5 {alarm ? 'bg-destructive/10 -mx-2 px-2 rounded-lg' : ''}">
                <Icon name={methodIcon(l.method)} size={16} class={alarm ? 'text-destructive shrink-0' : 'text-muted-foreground shrink-0'} />
                <div class="min-w-0 flex-1">
                  <div class="text-sm font-medium flex items-center gap-2 {alarm ? 'text-destructive' : 'text-foreground'}">
                    {l.user}
                    {#if l.root}<span class="text-[10px] px-1.5 py-0.5 rounded-full {alarm ? 'bg-destructive/20 text-destructive' : 'bg-muted text-muted-foreground'}">{alarm ? 'unexpected root' : 'root'}</span>{/if}
                  </div>
                  <div class="text-[11px] text-muted-foreground font-mono truncate">
                    {isLocal(l.ip) ? 'local' : l.ip}{l.country ? ' · ' + l.country : ''}{l.owner ? ' · ' + l.owner : ''} · {l.method} · {timeAgo(l.when)}
                  </div>
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>
      <div class="bg-card border border-border rounded-xl p-4">
        <h3 class="text-sm font-semibold text-foreground mb-0.5 flex items-center gap-2"><Icon name="hammer" size={16} class="text-destructive" />Brute-force blocked</h3>
        <p class="text-[11px] text-muted-foreground mb-3">Failed SSH — last hour.</p>
        <div class="text-3xl font-bold tabular-nums text-destructive">{data.logins.failed_1h.toLocaleString()}</div>
        <div class="text-xs text-muted-foreground mt-1">
          from {data.logins.failed_ips_1h} IP{data.logins.failed_ips_1h === 1 ? '' : 's'}
          {#if data.logins.failed_prev_1h > 0}· prev hour {data.logins.failed_prev_1h}{/if}
        </div>
      </div>
    </div>

    <!-- Privilege & accounts -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div class="bg-card border border-border rounded-xl p-4">
        <h3 class="text-sm font-semibold text-foreground mb-0.5 flex items-center gap-2"><Icon name="key" size={16} class="text-primary" />Privileged actions</h3>
        <p class="text-[11px] text-muted-foreground mb-3">Recent sudo commands · failures.</p>
        <div class="flex items-center justify-between text-sm py-1.5 border-b border-border">
          <span class="text-muted-foreground">Failed sudo (24h)</span>
          <span class="tabular-nums font-medium {data.sudo.failures_24h > 0 ? 'text-warning' : 'text-success'}">{data.sudo.failures_24h}</span>
        </div>
        {#if data.sudo.recent.length === 0}
          <div class="text-xs text-muted-foreground py-3 text-center">No sudo activity recorded.</div>
        {:else}
          <div class="divide-y divide-border">
            {#each data.sudo.recent.slice().reverse().slice(0, 6) as sd}
              <div class="py-2">
                <div class="text-xs font-medium text-foreground">{sd.user}</div>
                <div class="text-[11px] text-muted-foreground font-mono truncate">{sd.command}</div>
              </div>
            {/each}
          </div>
        {/if}
      </div>
      <div class="bg-card border border-border rounded-xl p-4">
        <h3 class="text-sm font-semibold text-foreground mb-0.5 flex items-center gap-2"><Icon name="user-plus" size={16} class="text-primary" />New accounts</h3>
        <p class="text-[11px] text-muted-foreground mb-3">Users / groups added recently.</p>
        <div class="flex items-center justify-between text-sm py-1.5 border-b border-border">
          <span class="text-muted-foreground">New users</span>
          <span class="tabular-nums font-medium {data.accounts.new_users.length > 0 ? 'text-warning' : 'text-success'}">{data.accounts.new_users.length}</span>
        </div>
        <div class="flex items-center justify-between text-sm py-1.5">
          <span class="text-muted-foreground">New groups</span>
          <span class="tabular-nums font-medium {data.accounts.new_groups.length > 0 ? 'text-warning' : 'text-success'}">{data.accounts.new_groups.length}</span>
        </div>
        {#each data.accounts.new_users as u}
          <div class="text-[11px] text-warning font-mono mt-1">+ user {u.name} · {timeAgo(u.when)}</div>
        {/each}
      </div>
      <div class="bg-card border border-border rounded-xl p-4">
        <h3 class="text-sm font-semibold text-foreground mb-0.5 flex items-center gap-2"><Icon name="package" size={16} class="text-primary" />Package changes</h3>
        <p class="text-[11px] text-muted-foreground mb-3">Recent installs / upgrades / removes.</p>
        {#if data.packages.length === 0}
          <div class="text-xs text-muted-foreground py-3 text-center">No package changes recorded.</div>
        {:else}
          <div class="divide-y divide-border">
            {#each data.packages.slice().reverse().slice(0, 7) as p}
              <div class="flex items-center justify-between py-1.5 text-xs">
                <span class="font-mono text-foreground truncate">{p.package}</span>
                <span class="text-muted-foreground shrink-0 ml-2">{p.action} · {timeAgo(p.when)}</span>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    </div>

    <!-- Exposure: listening ports -->
    <div class="bg-card border border-border rounded-xl p-4">
      <h3 class="text-sm font-semibold text-foreground mb-0.5 flex items-center gap-2"><Icon name="door" size={16} class="text-primary" />Exposure — listening ports</h3>
      <p class="text-[11px] text-muted-foreground mb-3">{data.ports.public} public-facing · {data.ports.listening.length} total. Public listeners are reachable from other machines — make sure each is intentional.</p>
      <div class="overflow-x-auto">
        <table class="w-full text-xs">
          <thead>
            <tr class="text-left text-muted-foreground border-b border-border">
              <th class="py-1.5 pr-3 font-medium">Port</th><th class="py-1.5 pr-3 font-medium">Proto</th><th class="py-1.5 pr-3 font-medium">Bind</th><th class="py-1.5 pr-3 font-medium">Process</th><th class="py-1.5 font-medium">Scope</th>
            </tr>
          </thead>
          <tbody>
            {#each data.ports.listening.slice().sort((a,b) => (b.public - a.public) || (a.port - b.port)) as p}
              <tr class="border-b border-border/50">
                <td class="py-1.5 pr-3 font-mono tabular-nums text-foreground">{p.port}</td>
                <td class="py-1.5 pr-3 text-muted-foreground">{p.proto}</td>
                <td class="py-1.5 pr-3 font-mono text-muted-foreground">{p.address}</td>
                <td class="py-1.5 pr-3 text-muted-foreground">{p.process || '—'}</td>
                <td class="py-1.5">
                  {#if p.public}<span class="text-[10px] px-1.5 py-0.5 rounded-full bg-warning/15 text-warning">public</span>
                  {:else}<span class="text-[10px] px-1.5 py-0.5 rounded-full bg-muted text-muted-foreground">local</span>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Health & history -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard icon="clock" color="primary" value={fmtUptime(data.host.uptime_seconds)} label="Host uptime" />
      <StatCard icon="refresh" color={data.host.reboot_recent ? 'warning' : 'info'} value={data.host.boot_time ? timeAgo(data.host.boot_time) : '—'} label="Last reboot" />
      <div class="bg-card border border-border rounded-xl p-4">
        <div class="text-xs text-muted-foreground mb-2 flex items-center gap-1.5"><Icon name="certificate" size={14} />TLS certificates</div>
        {#if !data.certs || data.certs.length === 0}
          <div class="text-xs text-muted-foreground">None managed</div>
        {:else}
          {#each data.certs.slice(0, 4) as c}
            <div class="flex items-center justify-between text-xs py-0.5">
              <span class="truncate text-foreground">{c.domain}</span>
              <span class="shrink-0 ml-2 tabular-nums {certColor(c.status)}">{c.daysLeft}d</span>
            </div>
          {/each}
        {/if}
      </div>
      <div class="bg-card border border-border rounded-xl p-4 flex flex-col justify-center">
        <div class="text-xs text-muted-foreground mb-1 flex items-center gap-1.5"><Icon name="info-circle" size={14} />Coming next</div>
        <div class="text-[11px] text-muted-foreground">Phone-home watch, cron/SSH-key changes, and pending OS updates.</div>
      </div>
    </div>
  {/if}
</div>
