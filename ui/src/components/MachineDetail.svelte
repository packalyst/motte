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
  import EmptyState from './EmptyState.svelte'
  import { timeAgo } from '$lib/utils/format.js'
  import { usageColor, sevVariant, statusInfo, round, fmtUptime } from '$lib/fleet.js'

  let { machine, onback, ondeleted } = $props()

  let report = $state(null)
  let loading = $state(true)
  let blockIP = $state('')

  const st = $derived(statusInfo(machine))
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

  async function load() {
    try {
      report = await apiGet('/api/fleet/report?id=' + encodeURIComponent(machine.id))
    } catch {
      report = null
    } finally {
      loading = false
    }
  }
  onMount(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t) })

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
</script>

<!-- card header: icon tile + title + source subtitle -->
{#snippet head(icon, title, sub, tint = 'text-muted-foreground')}
  <div class="flex items-center gap-2.5 mb-3">
    <span class="w-9 h-9 rounded-lg grid place-items-center bg-muted border border-border shrink-0 {tint}"><Icon name={icon} size={17} /></span>
    <div class="min-w-0">
      <div class="text-[13px] font-semibold text-foreground">{title}</div>
      <div class="text-[11px] text-muted-foreground truncate">{sub}</div>
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
    <Button variant="ghost" size="xs" icon="arrow-left" onclick={onback}>Fleet</Button>
    <span class="w-2.5 h-2.5 rounded-full shrink-0 {st.dot}"></span>
    <div class="min-w-0">
      <div class="text-lg font-semibold text-foreground truncate">{machine.name || machine.id}</div>
      <div class="text-[11px] text-muted-foreground font-mono truncate">
        {st.label}{machine.last_seen ? ` · seen ${timeAgo(machine.last_seen)}` : ''}{report?.agent ? ` · agent ${report.agent}` : ''}
      </div>
    </div>
    <div class="ml-auto flex items-center gap-2">
      <Button variant="ghost" size="xs" icon="refresh" onclick={load}>Refresh</Button>
      <Button variant="destructive" size="xs" icon="trash" onclick={del}>Delete</Button>
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

      <!-- LIVE USAGE -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('activity', 'Live usage', 'node metrics over WireGuard')}
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
        {@render note('Live resource use pulled from the agent over the WG tunnel. A sustained CPU spike often tracks attack traffic.')}
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

      <!-- VULNERABILITIES -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('package', 'Vulnerabilities / updates', 'Trivy · OS packages + app lockfiles', 'text-warning')}
        <div class="flex flex-wrap items-center gap-1.5 mb-3">
          {#each ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as sev}
            {#if cves?.counts?.[sev]}<Badge variant={sevVariant(sev)} size="sm">{cves.counts[sev]} {sev.toLowerCase()}</Badge>{/if}
          {/each}
          <span class="text-[11px] text-muted-foreground ml-auto">{cves?.total ?? 0} total{cves?.scanned_at ? ` · ${timeAgo(cves.scanned_at)}` : ''}</span>
        </div>
        {#if cves?.top?.length}
          <div class="max-h-72 overflow-y-auto -mr-1 pr-1">
            {#each cves.top as v}
              <div class="flex items-center gap-2.5 py-1.5 border-t border-border first:border-t-0 text-xs">
                <Badge variant={sevVariant(v.severity)} size="sm">{(v.severity || '').toLowerCase()}</Badge>
                <span class="font-mono whitespace-nowrap" title={v.title}>{v.id}</span>
                <span class="text-muted-foreground truncate flex-1">{v.pkg} {v.installed || ''}</span>
                <span class="shrink-0 font-mono text-[11px]">{#if v.fixed}<span class="text-success">fix {v.fixed}</span>{:else}<span class="text-muted-foreground">no fix</span>{/if}</span>
              </div>
            {/each}
          </div>
          {#if cves.total > cves.top.length}<div class="text-[11px] text-muted-foreground mt-1.5">Showing the {cves.top.length} worst of {cves.total}.</div>{/if}
        {:else}
          <div class="text-sm text-success flex items-center gap-2 py-2"><Icon name="circle-check" size={15} />No known vulnerabilities found.</div>
        {/if}
        <div class="flex items-center gap-2 mt-3">
          <Button variant="primary" size="sm" icon="refresh-alert" onclick={applyUpdates}>Apply updates</Button>
          <Button variant="outline" size="sm" icon="scan" onclick={rescan}>Rescan</Button>
        </div>
        {@render note('Apply updates fixes OS-package CVEs (apt); a kernel CVE also needs a reboot. App-dependency CVEs come from lockfiles and are fixed by the app owner. Rescan to confirm.')}
      </div>

      <!-- HOST & EXPOSURE -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('server', 'Host & exposure', 'osquery inventory')}
        <div class="text-sm">
          <div class="flex justify-between gap-3 py-1.5 border-t border-border first:border-t-0"><span class="text-muted-foreground">OS</span><span class="font-mono">{[facts?.os?.name, facts?.os?.version].filter(Boolean).join(' ') || '—'}</span></div>
          <div class="flex justify-between gap-3 py-1.5 border-t border-border"><span class="text-muted-foreground">CPU</span><span class="font-mono truncate max-w-[62%] text-right">{facts?.system?.cpu_brand || '—'}</span></div>
          <div class="flex justify-between gap-3 py-1.5 border-t border-border"><span class="text-muted-foreground">WG pubkey</span><span class="font-mono text-xs truncate max-w-[58%] text-right">{machine.wg_pubkey || '—'}</span></div>
          <div class="flex justify-between gap-3 py-1.5 border-t border-border"><span class="text-muted-foreground">Last report</span><span class="font-mono">{report.time ? timeAgo(report.time) : '—'}</span></div>
        </div>
        {#if facts?.ports?.length}
          <div class="text-[11px] text-muted-foreground mt-3 mb-1">Listening ports</div>
          <div class="max-h-40 overflow-y-auto -mr-1 pr-1 flex flex-wrap gap-1.5">
            {#each facts.ports as p}
              <span class="font-mono text-[11px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">{p.address || '*'}:{p.port}/{p.protocol === '6' ? 'tcp' : p.protocol === '17' ? 'udp' : p.protocol}</span>
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
        {@render note('Agents bind to the WG interface only — reachable through the tunnel, invisible to the internet. An unexpected public port is worth a look.')}
      </div>

      <!-- BLOCKING -->
      <div class="bg-card border border-border rounded-xl p-4 lg:col-span-2">
        {@render head('ban', 'Blocking', 'push blocks to this host over mTLS', 'text-destructive')}
        <div class="flex flex-wrap items-center gap-2">
          <input bind:value={blockIP} placeholder="IP to block on this host" onkeydown={(e) => e.key === 'Enter' && blockOn()}
            class="flex-1 min-w-[180px] bg-background border border-border rounded-lg px-3 py-2 text-sm font-mono" />
          <Button variant="destructive" size="sm" icon="ban" onclick={blockOn} disabled={!blockIP.trim()}>Block IP</Button>
          <Button variant="outline" size="sm" icon="arrow-down" onclick={pushBlocks}>Push panel blocklist</Button>
        </div>
        {@render note("Block one IP, or push the panel's whole blocklist down so this host drops the same attackers the panel already knows about.")}
      </div>
    </div>
  {/if}
</div>
