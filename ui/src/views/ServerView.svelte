<script>
  import { onMount } from 'svelte'
  import { apiGet, apiPost, apiDelete, toast } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import StatCard from '../components/StatCard.svelte'
  import Button from '../components/Button.svelte'
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
      await apiPost('/api/fw/entries', { type: 'ip', value: ip, action: 'block', direction: 'inbound', reason: 'server escalation (manual)' })
      toast(`Blocked ${ip}`, 'success')
    } catch (e) { toast('Failed to block: ' + e.message, 'error') }
  }
  async function forget(id) {
    try {
      await apiDelete(`/api/server/sudo-failure/${id}`)
      if (data?.sudo?.failed) data.sudo.failed = data.sudo.failed.filter(f => f.id !== id)
    } catch (e) { toast('Failed: ' + e.message, 'error') }
  }

  function isLocal(ip) { return !ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.') }
  function methodIcon(m) { return m === 'publickey' ? 'key' : m === 'password' ? 'lock' : 'terminal-2' }
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
      under_attack: { dot: 'bg-destructive', title: 'Warning — possible intrusion. Check the access list below.' },
    }
    return m[s] || m.calm
  })
  const sectionH = 'text-xs uppercase tracking-wide text-muted-foreground font-semibold'
  const card = 'bg-card border border-border rounded-xl p-4'
  const av = 'w-8 h-8 rounded-lg bg-muted/60 border border-border grid place-items-center shrink-0'
  const chip = 'text-[10px] px-1.5 py-0.5 rounded-full font-medium whitespace-nowrap'
  const l2 = 'text-[11px] text-muted-foreground font-mono truncate'
</script>

<div class="space-y-4">
  <InfoCard icon="shield-lock" title="Server" description="What's happening on the host itself: who logged in, privilege use, what's exposed, and system health. Read-only, from the server's own logs." />

  {#if error && !data}
    <div class="bg-destructive/10 border border-destructive/30 rounded-xl p-4 text-sm text-destructive">Couldn't load server security data: {error}</div>
  {:else if data}
    <!-- Verdict -->
    <div class="{card} flex items-center gap-4">
      <span class="w-3 h-3 rounded-full {verdict.dot} shrink-0"></span>
      <div class="text-sm font-semibold text-foreground">{verdict.title}</div>
    </div>

    <!-- Who touched the server: logins + sudo escalation, combined -->
    <h2 class="{sectionH} mt-2 mb-2 flex items-center gap-2">Who touched the server
      <span class="normal-case tracking-normal text-[10px] px-1.5 py-0.5 rounded-full bg-destructive/10 text-destructive font-semibold">breach watch</span></h2>
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div class="{card} lg:col-span-2">
        <h3 class="text-sm font-semibold mb-3 flex items-center gap-2"><Icon name="terminal-2" size={16} class="text-primary" />Access &amp; escalation</h3>
        {#if !data.logins.recent.length && !data.sudo.failed?.length}
          <div class="flex flex-col items-center justify-center py-8 text-center text-muted-foreground">
            <Icon name="terminal-2" size={26} class="opacity-40 mb-2" />
            <div class="text-sm">No shell logins or sudo failures recorded.</div>
          </div>
        {:else}
          <div class="divide-y divide-border">
            <!-- successful logins -->
            {#each data.logins.recent.slice().reverse() as l}
              {@const alarm = l.root && l.ip && !isLocal(l.ip)}
              <div class="flex items-center gap-2.5 py-2 {alarm ? 'bg-destructive/10 -mx-2 px-2 rounded-lg' : ''}">
                <span class="{av} {alarm ? 'border-destructive/50 text-destructive' : 'text-muted-foreground'}"><Icon name={methodIcon(l.method)} size={15} /></span>
                <div class="flex-1 min-w-0">
                  <div class="text-[13px] font-medium flex items-center gap-1.5 {alarm ? 'text-destructive' : 'text-foreground'}">{l.user}
                    <span class="{chip} bg-muted text-muted-foreground">{l.method}</span>
                    {#if l.root}<span class="{chip} {alarm ? 'bg-destructive/15 text-destructive' : 'bg-muted text-muted-foreground'}">{alarm ? 'unexpected root' : 'root'}</span>{/if}
                    {#if isLocal(l.ip)}<span class="{chip} bg-success/15 text-success">local</span>{/if}</div>
                  <div class="{l2}">{isLocal(l.ip) ? 'local session' : l.ip}{l.country ? ' · ' + l.country : ''}{l.owner ? ' · ' + l.owner : ''} · {timeAgo(l.when)}</div>
                </div>
                {#if alarm}<Button variant="destructive" size="xs" icon="ban" onclick={() => banIP(l.ip)}>Ban</Button>{/if}
              </div>
            {/each}
            <!-- sudo failures (escalation) -->
            {#each data.sudo.failed || [] as f}
              {@const remote = f.ip && !isLocal(f.ip)}
              <div class="flex items-center gap-2.5 py-2 {remote ? 'bg-destructive/10 -mx-2 px-2 rounded-lg' : ''}">
                <span class="{av} {remote ? 'border-destructive/50 text-destructive' : 'text-warning'}"><Icon name="alert-triangle" size={15} /></span>
                <div class="flex-1 min-w-0">
                  <div class="text-[13px] font-medium flex items-center gap-1.5 text-foreground">{f.user || 'unknown'}
                    <span class="{chip} bg-warning/15 text-warning">sudo failed</span>
                    {#if f.command}<span class="text-muted-foreground font-normal text-xs truncate">→ {f.command}</span>{/if}</div>
                  <div class="{l2}">{f.tty || '—'} · {f.ip ? (isLocal(f.ip) ? 'local' : f.ip) : 'session closed'} · {timeAgo(f.when)}</div>
                </div>
                <div class="flex items-center gap-1.5 shrink-0">
                  {#if remote}<Button variant="destructive" size="xs" icon="ban" onclick={() => banIP(f.ip)}>Ban</Button>{/if}
                  <Button variant="ghost" size="xs" icon="x" onclick={() => forget(f.id)}>Forget</Button>
                </div>
              </div>
            {/each}
          </div>
        {/if}
      </div>

      <div class="{card}">
        <h3 class="text-sm font-semibold mb-0.5 flex items-center gap-2"><Icon name="hammer" size={16} class="text-destructive" />Brute-force blocked</h3>
        <p class="text-[11px] text-muted-foreground mb-3">Failed SSH — last hour.</p>
        <div class="text-3xl font-bold tabular-nums text-destructive">{data.logins.failed_1h.toLocaleString()}</div>
        <div class="text-xs text-muted-foreground mt-1">from {data.logins.failed_ips_1h} IP{data.logins.failed_ips_1h === 1 ? '' : 's'}{#if data.logins.failed_prev_1h} · prev hour {data.logins.failed_prev_1h}{/if}</div>
        <div class="text-[11px] text-muted-foreground mt-3 pt-3 border-t border-dashed border-border">0 is normal if SSH is firewalled — attackers are dropped at L3 before sshd logs them.</div>
      </div>
    </div>

    <!-- Privilege & persistence -->
    <h2 class="{sectionH} mt-2 mb-2 flex items-center gap-2">Privilege &amp; persistence
      <span class="normal-case tracking-normal text-[10px] px-1.5 py-0.5 rounded-full bg-success/10 text-success font-semibold">from logs you already have</span></h2>
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <div class="{card}">
        <h3 class="text-sm font-semibold mb-3 flex items-center gap-2"><Icon name="key" size={16} class="text-primary" />Privileged actions</h3>
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
        <p class="text-[11px] text-muted-foreground mb-2">Where the server is reaching out — a reverse shell / beacon shows here.</p>
        <div class="flex items-baseline gap-2">
          <span class="text-2xl font-bold tabular-nums {data.phone_home.external > 0 ? 'text-foreground' : 'text-success'}">{data.phone_home.external}</span>
          <span class="text-xs text-muted-foreground">external destination{data.phone_home.external === 1 ? '' : 's'}</span>
        </div>
        {#if data.phone_home.destinations?.length}
          <div class="mt-2 pt-2 border-t border-dashed border-border divide-y divide-border/60">
            {#each data.phone_home.destinations.slice(0, 6) as d}
              <div class="flex items-center gap-2 py-1.5">
                <Icon name="arrow-up-right" size={13} class="text-muted-foreground shrink-0" />
                <div class="min-w-0 flex-1"><div class="text-xs font-mono text-foreground truncate">{d.ip}</div>{#if d.owner || d.country}<div class="text-[11px] text-muted-foreground truncate">{d.owner || ''}{d.country ? ' · ' + d.country : ''}</div>{/if}</div>
              </div>
            {/each}
          </div>
        {:else}
          <div class="text-xs text-muted-foreground py-2">No outbound connections to external hosts.</div>
        {/if}
      </div>

      <div class="{card}">
        <h3 class="text-sm font-semibold mb-3 flex items-center gap-2"><Icon name="clock" size={16} class="text-primary" />Persistence watch</h3>
        <div class="flex items-center justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Cron files changed (7d)</span><span class="tabular-nums font-medium {data.persistence.cron_recent > 0 ? 'text-warning' : 'text-success'}">{data.persistence.cron_recent}</span></div>
        <div class="flex items-center justify-between text-sm py-1.5"><span class="text-muted-foreground">Packages installed (7d)</span><span class="tabular-nums font-medium text-foreground">{data.persistence.packages_installed}</span></div>
        <div class="text-[11px] text-muted-foreground mt-2">footholds an intruder plants to survive a reboot · from dpkg.log + cron files</div>
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
          <div class="text-[11px] mt-1">Rows appear here (from <span class="font-mono">dpkg.log</span>) when apt installs or updates something — a tripwire for an intruder installing tools.</div>
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
                <td class="py-1.5">{#if p.public}<span class="{chip} bg-warning/15 text-warning">public</span>{:else}<span class="{chip} bg-muted text-muted-foreground">local</span>{/if}</td>
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
