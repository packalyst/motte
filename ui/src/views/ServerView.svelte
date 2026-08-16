<script>
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import StatCard from '../components/StatCard.svelte'
  import { timeAgo } from '$lib/utils/format.js'

  let { loading = $bindable(true), onLogout } = $props()
  let data = $state(null)
  let error = $state(null)

  async function load() {
    try { data = await apiGet('/api/server/security'); error = null }
    catch (e) { error = e.message }
    finally { loading = false }
  }
  onMount(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t) })

  async function banIP(ip) {
    if (!ip) return
    try {
      await apiPost('/api/fw/entries', { type: 'ip', value: ip, action: 'block', direction: 'inbound', reason: 'sudo escalation (manual)' })
      toast(`Blocked ${ip}`, 'success')
    } catch (e) { toast('Failed to block: ' + e.message, 'error') }
  }

  function isLocal(ip) {
    return !ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')
  }
  function methodIcon(m) { return m === 'publickey' ? 'key' : m === 'password' ? 'lock' : 'login' }
  function certColor(s) { return s === 'expired' || s === 'critical' ? 'text-destructive' : s === 'warning' ? 'text-warning' : 'text-success' }
  function fmtUptime(secs) {
    if (!secs) return '—'
    const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600)
    return d > 0 ? `${d}d ${h}h` : `${h}h ${Math.floor((secs % 3600) / 60)}m`
  }

  const verdict = $derived.by(() => {
    const s = data?.status || 'calm'
    const m = {
      calm: { dot: 'bg-success', title: 'Host looks clean — no unauthorized access.' },
      elevated: { dot: 'bg-warning', title: 'Elevated — worth a look.' },
      under_attack: { dot: 'bg-destructive', title: 'Warning — possible intrusion. Check the logins and sudo failures below.' },
    }
    return m[s] || m.calm
  })
  const sectionH = 'text-xs uppercase tracking-wide text-muted-foreground font-semibold'
  const card = 'bg-card border border-border rounded-xl p-4'
</script>

<div class="space-y-4">
  <InfoCard icon="shield-lock" title="Server" description="What's happening on the host itself: who logged in, privileged actions, what's exposed, and system health. Read-only, from the server's own logs." />

  {#if error && !data}
    <div class="bg-destructive/10 border border-destructive/30 rounded-xl p-4 text-sm text-destructive">Couldn't load server security data: {error}</div>
  {:else if data}
    <!-- Verdict -->
    <div class="{card} flex items-center gap-4">
      <span class="w-3 h-3 rounded-full {verdict.dot} shrink-0"></span>
      <div class="text-sm font-semibold text-foreground">{verdict.title}</div>
    </div>

    <!-- SSH logins -->
    <h2 class="{sectionH} mt-2 mb-2 flex items-center gap-2">Logins to the server (SSH / shell)
      <span class="normal-case tracking-normal text-[10px] px-1.5 py-0.5 rounded-full bg-destructive/10 text-destructive font-semibold">breach watch</span></h2>
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div class="{card} lg:col-span-2">
        <h3 class="text-sm font-semibold mb-0.5 flex items-center gap-2"><Icon name="terminal-2" size={16} class="text-primary" />Successful shell logins</h3>
        <p class="text-[11px] text-muted-foreground mb-3">From the system journal. An unfamiliar user, IP, or a root login from outside means someone's inside.</p>
        {#if !data.logins.recent.length}
          <div class="flex flex-col items-center justify-center py-8 text-center text-muted-foreground">
            <Icon name="terminal-2" size={26} class="opacity-40 mb-2" />
            <div class="text-sm">No shell logins in the last 30 days.</div>
          </div>
        {:else}
          <div class="divide-y divide-border">
            {#each data.logins.recent.slice().reverse() as l}
              {@const alarm = l.root && l.ip && !isLocal(l.ip)}
              <div class="flex items-center gap-3 py-2.5 {alarm ? 'bg-destructive/10 -mx-2 px-2 rounded-lg' : ''}">
                <Icon name={methodIcon(l.method)} size={16} class={alarm ? 'text-destructive shrink-0' : 'text-muted-foreground shrink-0'} />
                <div class="min-w-0 flex-1">
                  <div class="text-sm font-medium flex items-center gap-2 {alarm ? 'text-destructive' : 'text-foreground'}">{l.user}
                    {#if l.root}<span class="text-[10px] px-1.5 py-0.5 rounded-full {alarm ? 'bg-destructive/20 text-destructive' : 'bg-muted text-muted-foreground'}">{alarm ? 'unexpected root' : 'root'}</span>{/if}</div>
                  <div class="text-[11px] text-muted-foreground font-mono truncate">{isLocal(l.ip) ? 'local' : l.ip}{l.country ? ' · ' + l.country : ''}{l.owner ? ' · ' + l.owner : ''} · {l.method} · {timeAgo(l.when)}</div>
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>
      <div class="{card}">
        <h3 class="text-sm font-semibold mb-0.5 flex items-center gap-2"><Icon name="hammer" size={16} class="text-destructive" />Brute-force blocked</h3>
        <p class="text-[11px] text-muted-foreground mb-3">Failed SSH logins — last hour.</p>
        <div class="text-3xl font-bold tabular-nums text-destructive">{data.logins.failed_1h.toLocaleString()}</div>
        <div class="text-xs text-muted-foreground mt-1">from {data.logins.failed_ips_1h} IP{data.logins.failed_ips_1h === 1 ? '' : 's'}{#if data.logins.failed_prev_1h} · prev hour {data.logins.failed_prev_1h}{/if}</div>
        <div class="text-[11px] text-muted-foreground mt-3 pt-3 border-t border-dashed border-border">0 here is normal if SSH is firewalled — attackers are dropped at L3 before sshd logs them.</div>
      </div>
    </div>

    <!-- Sudo failures (escalation) — only when there are any -->
    {#if data.sudo.failed?.length}
      <h2 class="{sectionH} mt-2 mb-2 flex items-center gap-2">Sudo failures — privilege escalation
        <span class="normal-case tracking-normal text-[10px] px-1.5 py-0.5 rounded-full bg-warning/10 text-warning font-semibold">someone inside tried to become root</span></h2>
      <div class="{card}">
        <p class="text-[11px] text-muted-foreground mb-3">Failed <span class="font-mono">sudo</span>, tied to the session it came from. Unfamiliar IP = investigate and ban; your own IP = probably you mistyping.</p>
        <div class="divide-y divide-border">
          {#each data.sudo.failed as f}
            {@const remote = f.ip && !isLocal(f.ip)}
            <div class="flex items-center gap-3 py-2.5">
              <Icon name="alert-triangle" size={16} class={remote ? 'text-destructive shrink-0' : 'text-warning shrink-0'} />
              <div class="min-w-0 flex-1">
                <div class="text-sm font-medium text-foreground">{f.user || 'unknown'}{#if f.command} <span class="text-muted-foreground font-normal">→ {f.command}</span>{/if}</div>
                <div class="text-[11px] text-muted-foreground font-mono truncate">{f.tty || '—'} · {f.ip ? (isLocal(f.ip) ? 'local' : f.ip) : 'session closed (no IP)'} · {timeAgo(f.when)}</div>
              </div>
              {#if remote}<button onclick={() => banIP(f.ip)} class="shrink-0 text-xs px-3 py-1.5 rounded-lg border border-destructive/40 text-destructive hover:bg-destructive/10">Ban {f.ip}</button>{/if}
            </div>
          {/each}
        </div>
      </div>
    {/if}

    <!-- Privilege & persistence -->
    <h2 class="{sectionH} mt-2 mb-2 flex items-center gap-2">Privilege &amp; persistence
      <span class="normal-case tracking-normal text-[10px] px-1.5 py-0.5 rounded-full bg-success/10 text-success font-semibold">from logs you already have</span></h2>
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div class="{card}">
        <h3 class="text-sm font-semibold mb-0.5 flex items-center gap-2"><Icon name="key" size={16} class="text-primary" />Privileged actions</h3>
        <p class="text-[11px] text-muted-foreground mb-3">Recent sudo, failed sudo, new accounts.</p>
        <div class="flex items-center justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Failed sudo (24h)</span><span class="tabular-nums font-medium {data.sudo.failures_24h > 0 ? 'text-warning' : 'text-success'}">{data.sudo.failures_24h}</span></div>
        <div class="flex items-center justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">New users / groups</span><span class="tabular-nums font-medium {(data.accounts.new_users.length + data.accounts.new_groups.length) > 0 ? 'text-warning' : 'text-success'}">{data.accounts.new_users.length + data.accounts.new_groups.length}</span></div>
        {#if data.sudo.recent.length}
          <div class="divide-y divide-border mt-1">
            {#each data.sudo.recent.slice().reverse().slice(0, 5) as sd}
              <div class="py-1.5"><div class="text-xs font-medium text-foreground">{sd.user}</div><div class="text-[11px] text-muted-foreground font-mono truncate">{sd.command}</div></div>
            {/each}
          </div>
        {:else}
          <div class="text-xs text-muted-foreground py-3 text-center">No sudo activity recorded.</div>
        {/if}
      </div>

      <div class="{card}">
        <h3 class="text-sm font-semibold mb-0.5 flex items-center gap-2"><Icon name="network" size={16} class="text-primary" />Phone-home watch</h3>
        <p class="text-[11px] text-muted-foreground mb-3">External hosts the server is connected to right now — catches an obvious reverse shell / C2.</p>
        <div class="text-2xl font-bold tabular-nums {data.phone_home.external > 0 ? 'text-foreground' : 'text-success'}">{data.phone_home.external}</div>
        <div class="text-xs text-muted-foreground mt-0.5">external destination{data.phone_home.external === 1 ? '' : 's'}</div>
        {#if data.phone_home.destinations?.length}
          <div class="mt-2 pt-2 border-t border-dashed border-border space-y-1">
            {#each data.phone_home.destinations.slice(0, 5) as d}
              <div class="text-[11px] font-mono text-muted-foreground truncate">{d.ip}{d.owner ? ' · ' + d.owner : ''}{d.country ? ' · ' + d.country : ''}</div>
            {/each}
          </div>
        {/if}
      </div>

      <div class="{card}">
        <h3 class="text-sm font-semibold mb-0.5 flex items-center gap-2"><Icon name="clock" size={16} class="text-primary" />Persistence watch</h3>
        <p class="text-[11px] text-muted-foreground mb-3">Footholds an intruder plants to survive a reboot.</p>
        <div class="flex items-center justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Cron files changed (7d)</span><span class="tabular-nums font-medium {data.persistence.cron_recent > 0 ? 'text-warning' : 'text-success'}">{data.persistence.cron_recent}</span></div>
        <div class="flex items-center justify-between text-sm py-1.5"><span class="text-muted-foreground">Packages installed (7d)</span><span class="tabular-nums font-medium text-foreground">{data.persistence.packages_installed}</span></div>
        <div class="text-[11px] text-muted-foreground mt-2">from dpkg.log · cron files</div>
      </div>
    </div>

    <!-- Package changes -->
    <h2 class="{sectionH} mt-2 mb-2">Package changes</h2>
    <div class="{card}">
      {#if data.packages.length}
        <div class="divide-y divide-border">
          {#each data.packages.slice().reverse() as p}
            <div class="flex items-center justify-between py-1.5 text-xs"><span class="font-mono text-foreground truncate">{p.package} <span class="text-muted-foreground">{p.version}</span></span><span class="text-muted-foreground shrink-0 ml-2">{p.action} · {timeAgo(p.when)}</span></div>
          {/each}
        </div>
      {:else}
        <div class="flex flex-col items-center justify-center py-6 text-center text-muted-foreground">
          <Icon name="package" size={24} class="opacity-40 mb-2" />
          <div class="text-sm">No packages installed, upgraded, or removed in the last 7 days.</div>
          <div class="text-[11px] mt-1">New rows appear here (from <span class="font-mono">dpkg.log</span>) whenever apt installs or updates something — a good tripwire for an intruder installing tools.</div>
        </div>
      {/if}
    </div>

    <!-- Exposure -->
    <h2 class="{sectionH} mt-2 mb-2">Exposure — listening ports</h2>
    <div class="{card}">
      <p class="text-[11px] text-muted-foreground mb-3">{data.ports.public} public-facing · {data.ports.listening.length} total. Public listeners are reachable from other machines — make sure each is intentional.</p>
      <div class="overflow-x-auto">
        <table class="w-full text-xs">
          <thead><tr class="text-left text-muted-foreground border-b border-border"><th class="py-1.5 pr-3 font-medium">Port</th><th class="py-1.5 pr-3 font-medium">Proto</th><th class="py-1.5 pr-3 font-medium">Bind</th><th class="py-1.5 pr-3 font-medium">Process</th><th class="py-1.5 font-medium">Scope</th></tr></thead>
          <tbody>
            {#each data.ports.listening.slice().sort((a,b) => (b.public - a.public) || (a.port - b.port)) as p}
              <tr class="border-b border-border/50">
                <td class="py-1.5 pr-3 font-mono tabular-nums text-foreground">{p.port}</td>
                <td class="py-1.5 pr-3 text-muted-foreground">{p.proto}</td>
                <td class="py-1.5 pr-3 font-mono text-muted-foreground">{p.address}</td>
                <td class="py-1.5 pr-3 text-muted-foreground">{p.process || '—'}</td>
                <td class="py-1.5">{#if p.public}<span class="text-[10px] px-1.5 py-0.5 rounded-full bg-warning/15 text-warning">public</span>{:else}<span class="text-[10px] px-1.5 py-0.5 rounded-full bg-muted text-muted-foreground">local</span>{/if}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Health & history -->
    <h2 class="{sectionH} mt-2 mb-2">Health &amp; history</h2>
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard icon="clock" color="primary" value={fmtUptime(data.host.uptime_seconds)} label="Host uptime" />
      <StatCard icon="refresh" color={data.host.reboot_recent ? 'warning' : 'info'} value={data.host.boot_time ? timeAgo(data.host.boot_time) : '—'} label="Last reboot" />
      <div class="{card}">
        <div class="text-xs text-muted-foreground mb-2 flex items-center gap-1.5"><Icon name="certificate" size={14} />TLS certificates</div>
        {#if !data.certs?.length}<div class="text-xs text-muted-foreground">None managed</div>
        {:else}{#each data.certs.slice(0, 4) as c}<div class="flex items-center justify-between text-xs py-0.5"><span class="truncate text-foreground">{c.domain}</span><span class="shrink-0 ml-2 tabular-nums {certColor(c.status)}">{c.daysLeft}d</span></div>{/each}{/if}
      </div>
      <StatCard icon="network" color={data.phone_home.external > 0 ? 'warning' : 'success'} value={data.phone_home.external} label="Outbound destinations" />
    </div>
  {/if}
</div>
