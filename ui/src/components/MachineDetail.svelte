<script>
  /**
   * MachineDetail — the structured view of one enrolled machine, laid out as the fleet
   * mockup: a grid of cards, each with an icon header, its data, and a plain-language
   * note explaining what it means. Sources (CrowdSec / osquery / Trivy) are labelled so
   * the detection split stays visible. Pulls the full report + polls it.
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast, confirm } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Badge from './Badge.svelte'
  import Input from './Input.svelte'
  import EmptyState from './EmptyState.svelte'
  import { timeAgo } from '$lib/utils/format.js'
  import { usageColor, sevVariant, statusInfo, round, fmtUptime } from '$lib/fleet.js'

  let { machine, onback, ondeleted, onviewcves } = $props()

  let report = $state(null)
  let loading = $state(true)
  let blockIP = $state('')

  const st = $derived(statusInfo(machine))
  const dryRun = $derived(report?.dry_run ?? true)
  const m = $derived(report?.metrics || {})
  const cves = $derived(report?.cves || null)
  const intr = $derived(report?.intrusion || null)
  const facts = $derived(report?.facts || null)

  // merged security feed: bans first (most severe), then FIM changes.
  const feed = $derived.by(() => {
    const out = []
    for (const d of intr?.decisions || []) {
      out.push({ tone: 'crit', body: `Banned ${d.value}`, meta: d.scenario || d.type || 'ban', src: 'crowdsec' })
    }
    for (const f of (facts?.fim || []).slice().reverse()) {
      out.push({ tone: f.action === 'DELETED' ? 'crit' : 'warn', body: `${f.action || 'changed'} ${f.path}`, meta: '', src: 'osquery' })
    }
    return out
  })

  let commands = $state([])
  async function load() {
    try {
      report = await apiGet('/api/fleet/report?id=' + encodeURIComponent(machine.id))
    } catch {
      report = null
    } finally {
      loading = false
    }
    try { commands = (await apiGet('/api/fleet/machine/commands?machine_id=' + encodeURIComponent(machine.id))) || [] } catch { /* keep last */ }
  }
  onMount(() => { load(); const t = setInterval(load, 10000); return () => clearInterval(t) })

  const cmdStatus = { pending: 'text-warning', delivered: 'text-info', done: 'text-success', error: 'text-destructive' }

  async function cmd(type, payload = null, opts = {}) {
    const ok = await confirm({
      title: `${opts.title || type} · ${machine.name}`,
      message: opts.message || `Queue "${type}" for ${machine.name}? It runs on the machine's next check-in (~10s).`,
      confirmText: opts.confirmText || 'Queue',
      variant: opts.variant || 'primary',
      alert: opts.alert || false,
    })
    if (!ok) return
    try {
      const res = await apiPost(opts.endpoint || '/api/fleet/command',
        opts.endpoint ? { machine_id: machine.id } : { machine_id: machine.id, type, payload })
      toast(opts.done ? opts.done(res) : `${type} queued`, 'success')
      if (opts.after) opts.after()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function blockOn() {
    const ip = blockIP.trim()
    if (!ip) return
    await cmd('block', { ip }, { title: 'Block IP', message: `Block ${ip} on ${machine.name}?`, after: () => (blockIP = '') })
  }

  const pushBlocks = () => cmd('sync-blocks', null, {
    endpoint: '/api/fleet/push-blocks', title: 'Push panel blocklist',
    message: `Push the panel's current blocklist (its manually + auto-blocked IPs and ranges) onto ${machine.name}? It drops them in its own nftables. Country/ASN mega-lists are excluded.`,
    done: (r) => `Pushing ${r.count} blocks to ${machine.name}`,
  })
  const applyUpdates = () => cmd('apply-updates', null, { title: 'Apply updates', message: `Run system package updates on ${machine.name}? OS-package CVEs are fixed by this; a kernel CVE also needs a reboot.` })
  const setDryRun = (enabled) => cmd('set-dry-run', { enabled }, {
    title: enabled ? 'Switch to dry-run' : 'Go live',
    message: enabled
      ? `Put ${machine.name} in DRY-RUN? It will LOG firewall/update actions instead of applying them.`
      : `Take ${machine.name} LIVE? It will enforce firewall blocks and apply updates for real.`,
    confirmText: enabled ? 'Dry-run' : 'Go live', variant: enabled ? 'primary' : 'destructive',
  })
  const rescan = () => cmd('rescan', null, { title: 'Rescan', message: `Re-run the Trivy CVE scan on ${machine.name} now?` })

  async function del() {
    await cmd(null, null, {
      endpoint: '/api/fleet/machine/delete', title: `Delete ${machine.name}`,
      message: `Delete ${machine.name} for good? Its certificate is invalidated immediately — the agent can no longer connect and must re-enroll with a fresh token to return. Queued commands are removed too.`,
      confirmText: 'Delete machine', variant: 'destructive', alert: true,
      done: () => `${machine.name} deleted`, after: () => ondeleted?.(),
    })
  }

  const toneDot = { crit: 'bg-destructive', warn: 'bg-warning', ok: 'bg-success' }

  // Well-known port → service label (client-side; the agent only sends addr/port/proto).
  const PORT_NAMES = {
    22: 'SSH', 53: 'DNS', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS', 123: 'NTP',
    3306: 'MySQL', 5432: 'Postgres', 6379: 'Redis', 27017: 'MongoDB', 11211: 'Memcached',
    9100: 'node_exporter', 8420: 'CrowdSec', 51820: 'WireGuard', 3000: 'app', 8080: 'HTTP-alt',
  }
  const proto = (p) => (p === '6' ? 'tcp' : p === '17' ? 'udp' : p || '')
  const scopeOf = (addr) =>
    !addr || addr === '0.0.0.0' || addr === '::' ? 'exposed'
    : addr === '127.0.0.1' || addr === '::1' ? 'local' : 'iface'
  // Group listening ports by exposure so "what's open to the world" reads at a glance.
  const portGroups = $derived.by(() => {
    const g = { exposed: [], iface: [], local: [] }
    for (const p of facts?.ports || []) (g[scopeOf(p.address)] ||= []).push(p)
    return g
  })
  const scopeMeta = {
    exposed: { label: 'Exposed (all interfaces)', tone: 'text-warning', dot: 'bg-warning' },
    iface: { label: 'Bound to an interface', tone: 'text-info', dot: 'bg-info' },
    local: { label: 'Local only', tone: 'text-success', dot: 'bg-success' },
  }
</script>

<!-- one listening-port pill with a service name when we know it -->
{#snippet portPill(p)}
  <span class="inline-flex items-center gap-1 font-mono text-[11px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
    <span class="text-foreground">{p.address || '*'}:{p.port}</span>
    <span class="opacity-60">/{proto(p.protocol)}</span>
    {#if PORT_NAMES[+p.port]}<span class="not-italic text-[9px] px-1 rounded bg-background text-muted-foreground">{PORT_NAMES[+p.port]}</span>{/if}
  </span>
{/snippet}

<!-- card header: icon tile + title + source subtitle -->
{#snippet head(icon, title, sub, tint = 'text-muted-foreground')}
  <div class="flex items-center gap-2.5 mb-3">
    <span class="w-9 h-9 rounded-lg grid place-items-center bg-muted border border-border shrink-0 {tint}"><Icon name={icon} size={17} /></span>
    <div class="min-w-0">
      <div class="text-[13px] font-semibold text-foreground">{title}</div>
      {#if sub}<div class="text-[11px] text-muted-foreground truncate">{sub}</div>{/if}
    </div>
  </div>
{/snippet}

<!-- persistent plain-language note (mockup's dashed footer) -->
{#snippet note(text)}
  <div class="text-[11px] text-muted-foreground mt-3 pt-3 border-t border-dashed border-border">{text}</div>
{/snippet}

<div class="space-y-4">
  <!-- Header -->
  <div class="flex items-center gap-3 flex-wrap">
    <button onclick={onback} title="Back to fleet"
      class="h-8 w-8 grid place-items-center rounded-lg border border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground transition cursor-pointer shrink-0">
      <Icon name="arrow-left" size={16} />
    </button>
    <span class="w-2.5 h-2.5 rounded-full shrink-0 {st.dot}"></span>
    <div class="min-w-0 flex-1">
      <div class="text-lg font-semibold text-foreground truncate leading-tight">{machine.name || machine.id}</div>
      <div class="text-[11px] text-muted-foreground font-mono truncate">
        {st.label}{machine.last_seen ? ` · seen ${timeAgo(machine.last_seen)}` : ''}{report?.agent ? ` · agent ${report.agent}` : ''}
      </div>
    </div>
    <!-- grouped actions -->
    <div class="flex items-center rounded-lg border border-border overflow-hidden shrink-0 divide-x divide-border">
      <button onclick={load} class="flex items-center gap-1.5 px-3 py-1.5 text-xs text-muted-foreground hover:bg-muted hover:text-foreground transition cursor-pointer">
        <Icon name="refresh" size={14} />Refresh
      </button>
      <button onclick={del} class="flex items-center gap-1.5 px-3 py-1.5 text-xs text-destructive hover:bg-destructive/10 transition cursor-pointer">
        <Icon name="trash" size={14} />Delete
      </button>
    </div>
  </div>

  {#if loading && !report}
    <div class="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">Loading report…</div>
  {:else if !report}
    <div class="bg-card border border-border rounded-xl p-8">
      <EmptyState icon="clock" title="No report yet"
        description="This machine hasn't checked in with a report. It appears once the agent's first metrics/scan cycle completes." />
    </div>
  {:else}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">

      <!-- AGENT -->
      <div class="bg-card border border-border rounded-xl p-4 lg:col-span-2">
        {@render head('robot', 'Agent', report?.agent ? `wgscout ${report.agent}` : 'wgscout')}
        <div class="flex flex-wrap items-center gap-3">
          <div class="flex items-center gap-2">
            <span class="w-2 h-2 rounded-full {dryRun ? 'bg-warning' : 'bg-success'}"></span>
            <span class="text-sm font-medium">{dryRun ? 'Dry-run' : 'Live'}</span>
            <span class="text-[11px] text-muted-foreground">{dryRun ? '— logs actions, does not enforce' : '— enforcing for real'}</span>
          </div>
          <div class="ml-auto">
            {#if dryRun}
              <Button variant="destructive" size="sm" icon="bolt" onclick={() => setDryRun(false)}>Go live</Button>
            {:else}
              <Button variant="outline" size="sm" icon="player-pause" onclick={() => setDryRun(true)}>Switch to dry-run</Button>
            {/if}
          </div>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-x-4 mt-3">
          {#each [['Enrolled', machine.enrolled_at ? timeAgo(machine.enrolled_at) : '—'], ['Host', report?.host || '—'], ['Cert', (machine.cert_fp || '').replace('sha256:', '').slice(0, 12) || '—']] as [k, v]}
            <div class="flex justify-between gap-2 py-1.5 border-t border-border sm:border-t-0 text-sm">
              <span class="text-muted-foreground">{k}</span><span class="font-mono truncate">{v}</span>
            </div>
          {/each}
        </div>
        {#if commands.length}
          <div class="text-[11px] text-muted-foreground mt-3 mb-1">Recent commands</div>
          <div class="max-h-40 overflow-y-auto -mr-1 pr-1">
            {#each commands as c}
              <div class="flex items-center gap-2 py-1 border-t border-border first:border-t-0 text-xs">
                <span class="font-mono">{c.type}</span>
                <span class="capitalize {cmdStatus[c.status] || 'text-muted-foreground'}">{c.status}</span>
                {#if c.result}<span class="text-muted-foreground truncate flex-1" title={c.result}>· {c.result}</span>{/if}
                <span class="text-[10px] text-muted-foreground ml-auto shrink-0">{timeAgo(c.done_at || c.created_at)}</span>
              </div>
            {/each}
          </div>
        {/if}
        {@render note('Dry-run logs actions; Live enforces. Changes apply on the next check-in (~10s).')}
      </div>

      <!-- LIVE USAGE -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('activity', 'Live usage', '')}
        <div class="space-y-2.5">
          {#each [['CPU', m.cpu], ['Memory', m.mem], ['Disk', m.disk]] as [lbl, val]}
            <div class="flex items-center gap-3 text-xs">
              <span class="w-14 text-muted-foreground">{lbl}</span>
              <span class="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                <span class="block h-full rounded-full {usageColor(round(val))}" style="width:{Math.min(round(val), 100)}%"></span>
              </span>
              <span class="w-10 text-right tabular-nums font-medium">{round(val)}%</span>
            </div>
          {/each}
        </div>
        <div class="flex gap-6 mt-3 text-xs">
          <span class="text-muted-foreground">Uptime <span class="text-foreground font-medium">{fmtUptime(m.uptime)}</span></span>
          <span class="text-muted-foreground">Load <span class="text-foreground font-medium tabular-nums">{(m.load1 ?? 0).toFixed(2)}</span></span>
        </div>
        {@render note('Live resource use reported by the agent. A sustained CPU spike often tracks attack traffic.')}
      </div>

      <!-- SECURITY EVENTS -->
      <div class="bg-card border rounded-xl p-4 {feed.some((e) => e.tone === 'crit') ? 'border-destructive/40' : 'border-border'}">
        {@render head('shield-lock', 'Security events', 'CrowdSec bans + osquery FIM', 'text-warning')}
        {#if feed.length}
          <div class="max-h-72 overflow-y-auto -mr-1 pr-1">
            {#each feed.slice(0, 100) as e}
              <div class="flex items-baseline gap-2.5 py-1.5 border-t border-border first:border-t-0 text-sm">
                <span class="w-1.5 h-1.5 rounded-full shrink-0 self-center {toneDot[e.tone]}"></span>
                <span class="flex-1 min-w-0 break-all"><span class="font-mono text-xs">{e.body}</span>{#if e.meta}<span class="text-muted-foreground text-xs"> — {e.meta}</span>{/if}</span>
                <span class="text-[9px] text-muted-foreground shrink-0">{e.src}</span>
              </div>
            {/each}
          </div>
        {:else}
          <div class="text-sm text-success flex items-center gap-2 py-2"><Icon name="circle-check" size={15} />No bans and no file-integrity changes.</div>
        {/if}
        {@render note('CrowdSec bans attackers on-host automatically. The FIM lines (a watched file changed) are the "someone got in" signals worth investigating.')}
      </div>

      <!-- VULNERABILITIES (summary — full list is the drill-down) -->
      <div class="bg-card border border-border rounded-xl p-4">
        <!-- header: title/subtitle left, total upper-right -->
        <div class="flex items-start gap-2.5 mb-3">
          <span class="w-9 h-9 rounded-lg grid place-items-center bg-muted border border-border shrink-0 text-warning"><Icon name="package" size={17} /></span>
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <span class="text-[13px] font-semibold text-foreground">Vulnerabilities</span>
              <span class="ml-auto text-[11px] text-muted-foreground shrink-0">{(cves?.total ?? 0).toLocaleString()} total{cves?.scanned_at ? ` · ${timeAgo(cves.scanned_at)}` : ''}</span>
            </div>
            <div class="text-[11px] text-muted-foreground">Trivy · OS packages + app lockfiles</div>
          </div>
        </div>
        <!-- severity badges below -->
        {#if cves?.total}
          <div class="flex flex-wrap gap-1.5">
            {#each ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as sev}
              {#if cves?.counts?.[sev]}<Badge variant={sevVariant(sev)} size="sm">{cves.counts[sev].toLocaleString()} {sev.toLowerCase()}</Badge>{/if}
            {/each}
          </div>
          <!-- top preview (full list is the drill-down) -->
          {#if cves?.top?.length}
            <div class="mt-3 border-t border-border pt-1">
              {#each cves.top.slice(0, 12) as v}
                <div class="flex items-center gap-2.5 py-1 text-xs">
                  <Badge variant={sevVariant(v.severity)} size="sm">{(v.severity || '').toLowerCase()}</Badge>
                  <span class="font-mono whitespace-nowrap" title={v.title}>{v.id}</span>
                  <span class="text-muted-foreground truncate flex-1">{v.pkg}</span>
                  <span class="shrink-0 font-mono text-[11px]">{#if v.fixed}<span class="text-success">→ {v.fixed}</span>{:else}<span class="text-muted-foreground">no fix</span>{/if}</span>
                </div>
              {/each}
              {#if cves.total > 12}<div class="text-[11px] text-muted-foreground pt-1">+ {(cves.total - 12).toLocaleString()} more — “View all & fix”.</div>{/if}
            </div>
          {/if}
        {:else}
          <div class="text-sm text-success flex items-center gap-2 py-1"><Icon name="circle-check" size={15} />No known vulnerabilities found.</div>
        {/if}
        <div class="flex items-center gap-2 mt-3 flex-wrap">
          {#if cves?.total}<Button variant="primary" size="sm" icon="list-details" onclick={() => onviewcves?.(machine)}>View all & fix</Button>{/if}
          <Button variant="outline" size="sm" icon="refresh-alert" onclick={applyUpdates}>Apply all updates</Button>
          <Button variant="outline" size="sm" icon="scan" onclick={rescan}>Rescan</Button>
        </div>
        {@render note('“Apply all updates” upgrades every OS package (apt; a kernel CVE also needs a reboot). Use “View all & fix” to see the full list grouped by OS/project and upgrade only selected packages.')}
      </div>

      <!-- HOST & EXPOSURE -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('server', 'Host & exposure', 'osquery inventory')}
        <div>
          {#each [['device-desktop', 'OS', [facts?.os?.name, facts?.os?.version].filter(Boolean).join(' ')], ['cpu', 'CPU', facts?.system?.cpu_brand], ['key', 'WG pubkey', machine.wg_pubkey], ['clock', 'Last report', report.time ? timeAgo(report.time) : '']] as [ic, k, val]}
            <div class="flex items-center gap-2.5 py-2 border-t border-border first:border-t-0 text-sm">
              <Icon name={ic} size={14} class="text-muted-foreground shrink-0" />
              <span class="text-muted-foreground w-24 shrink-0">{k}</span>
              <span class="font-mono truncate text-right flex-1 {val ? 'text-foreground' : 'text-muted-foreground'}">{val || '—'}</span>
            </div>
          {/each}
        </div>

        {#if facts?.ports?.length}
          <div class="mt-3 space-y-2">
            {#each ['exposed', 'iface', 'local'] as scope}
              {#if portGroups[scope].length}
                <div>
                  <div class="flex items-center gap-1.5 mb-1">
                    <span class="w-1.5 h-1.5 rounded-full {scopeMeta[scope].dot}"></span>
                    <span class="text-[11px] font-medium {scopeMeta[scope].tone}">{scopeMeta[scope].label}</span>
                    <span class="text-[10px] text-muted-foreground">· {portGroups[scope].length}</span>
                  </div>
                  <div class="flex flex-wrap gap-1.5">
                    {#each portGroups[scope] as p}{@render portPill(p)}{/each}
                  </div>
                </div>
              {/if}
            {/each}
          </div>
        {/if}

        {#if facts?.users?.length}
          <div class="text-[11px] text-muted-foreground mt-3 mb-1">Logged-in users</div>
          {#each facts.users as u}
            <div class="flex items-center gap-2 py-1 text-sm">
              <span class="font-medium">{u.user}</span>
              {#if u.tty}<span class="text-[11px] text-muted-foreground font-mono">{u.tty}</span>{/if}
              <span class="text-xs text-muted-foreground font-mono ml-auto">{u.host ? `from ${u.host}` : 'local console'}</span>
            </div>
          {/each}
        {/if}
        {@render note('“Exposed” ports are open on all interfaces (reachable from the internet unless firewalled); “local” ones only from the box itself. An unexpected exposed port is worth a look.')}
      </div>

      <!-- BLOCKING -->
      <div class="bg-card border border-border rounded-xl p-4 lg:col-span-2">
        {@render head('ban', 'Blocking', 'push blocks to this host over mTLS', 'text-destructive')}
        <div class="flex flex-wrap items-center gap-2">
          <div class="flex-1 min-w-[220px]">
            <Input bind:value={blockIP} prefixIcon="world" placeholder="IP to block on this host" class="font-mono"
              onkeydown={(e) => e.key === 'Enter' && blockOn()}
              suffixAddonBtn={{ icon: 'ban', label: 'Block', variant: 'destructive', onclick: blockOn, disabled: !blockIP.trim() }} />
          </div>
          <Button variant="outline" size="sm" icon="arrow-down" onclick={pushBlocks}>Push panel blocklist</Button>
        </div>
        {@render note("Block one IP, or push the panel's whole blocklist down so this host drops the same attackers the panel already knows about.")}
      </div>
    </div>
  {/if}
</div>
