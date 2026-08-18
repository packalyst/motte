<script>
  /**
   * MachineDetail — the structured view of one enrolled machine. Pulls the full
   * report (metrics, CrowdSec decisions, osquery facts/FIM, Trivy CVEs) and lays it
   * out across tabs, with per-tab actions (apply updates, rescan, block, push the
   * panel's blocklist). Data sources are labelled so the CrowdSec / osquery / Trivy
   * split stays visible.
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast, confirm } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Badge from './Badge.svelte'
  import Tabs from './Tabs.svelte'
  import Explain from './Explain.svelte'
  import EmptyState from './EmptyState.svelte'
  import { timeAgo } from '$lib/utils/format.js'
  import { usageColor, sevVariant, statusInfo, round, fmtUptime } from '$lib/fleet.js'

  let { machine, onback, ondeleted } = $props()

  let report = $state(null)
  let loading = $state(true)
  let activeTab = $state('overview')
  let blockIP = $state('')

  const st = $derived(statusInfo(machine))
  const m = $derived(report?.metrics || {})
  const cves = $derived(report?.cves || null)
  const intr = $derived(report?.intrusion || null)
  const facts = $derived(report?.facts || null)

  const tabs = $derived([
    { id: 'overview', label: 'Overview', icon: 'gauge' },
    { id: 'security', label: 'Security', icon: 'shield', badge: intr?.active_bans || (facts?.fim?.length ?? 0) || null },
    { id: 'cves', label: 'Vulnerabilities', icon: 'bug', badge: cves?.total || null },
    { id: 'host', label: 'Host', icon: 'server' },
  ])

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
    })
    if (!ok) return
    try {
      const res = await apiPost(opts.endpoint || '/api/fleet/command',
        opts.endpoint ? { machine_id: machine.id } : { machine_id: machine.id, type, payload })
      toast(opts.done ? opts.done(res) : `${type} queued`, 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function blockOn() {
    const ip = blockIP.trim()
    if (!ip) return
    await cmd('block', { ip }, { title: 'Block IP', message: `Block ${ip} on ${machine.name}?` })
    blockIP = ''
  }

  async function pushBlocks() {
    await cmd('sync-blocks', null, {
      endpoint: '/api/fleet/push-blocks',
      title: 'Push panel blocklist',
      message: `Push the panel's current blocklist (its manually/auto-blocked IPs and ranges) onto ${machine.name}? The machine will drop those in its own nftables.`,
      done: (r) => `Pushing ${r.count} blocks to ${machine.name}`,
    })
  }

  async function del() {
    const ok = await confirm({
      title: `Delete ${machine.name}`,
      message: `Delete ${machine.name} for good? Its certificate is invalidated immediately — the agent can no longer connect and must re-enroll with a fresh token to return. Queued commands are removed too.`,
      confirmText: 'Delete machine',
      variant: 'destructive',
      alert: true,
    })
    if (!ok) return
    try {
      await apiPost('/api/fleet/machine/delete', { machine_id: machine.id })
      toast(`${machine.name} deleted`, 'success')
      ondeleted?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  const kvRow = 'flex justify-between gap-3 py-2 border-t border-border first:border-t-0 text-sm'
</script>

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
    <Tabs {tabs} bind:activeTab size="sm" />

    <!-- OVERVIEW -->
    {#if activeTab === 'overview'}
      <div class="space-y-4">
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {#each [['CPU', m.cpu], ['Memory', m.mem], ['Disk', m.disk]] as [label, val]}
            <div class="bg-card border border-border rounded-lg p-4">
              <div class="text-2xl font-bold tabular-nums text-foreground">{round(val)}%</div>
              <div class="text-[11px] text-muted-foreground mb-2">{label}</div>
              <div class="h-1.5 rounded-full bg-muted overflow-hidden">
                <div class="h-full rounded-full {usageColor(round(val))}" style="width:{Math.min(round(val), 100)}%"></div>
              </div>
            </div>
          {/each}
          <div class="bg-card border border-border rounded-lg p-4">
            <div class="text-2xl font-bold tabular-nums text-foreground">{fmtUptime(m.uptime)}</div>
            <div class="text-[11px] text-muted-foreground mb-2">Uptime</div>
            <div class="text-[11px] text-muted-foreground">load {(m.load1 ?? 0).toFixed(2)}</div>
          </div>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div class="bg-card border border-border rounded-lg p-4">
            <div class="text-xs text-muted-foreground mb-1">Vulnerabilities</div>
            <div class="text-xl font-bold text-foreground">{cves?.total ?? 0}
              {#if cves?.counts?.CRITICAL}<span class="text-sm font-medium text-destructive">· {cves.counts.CRITICAL} critical</span>{/if}
            </div>
          </div>
          <div class="bg-card border border-border rounded-lg p-4">
            <div class="text-xs text-muted-foreground mb-1">Active bans</div>
            <div class="text-xl font-bold text-foreground">{intr?.active_bans ?? 0}
              <span class="text-sm font-medium text-muted-foreground">· {intr?.enforced ?? 0} enforced</span>
            </div>
          </div>
          <div class="bg-card border border-border rounded-lg p-4">
            <div class="text-xs text-muted-foreground mb-1">FIM events</div>
            <div class="text-xl font-bold text-foreground">{facts?.fim?.length ?? 0}</div>
          </div>
        </div>
      </div>

    <!-- SECURITY -->
    {:else if activeTab === 'security'}
      <div class="space-y-4">
        <!-- CrowdSec decisions -->
        <div class="bg-card border border-border rounded-xl p-4">
          <div class="flex items-center gap-2 mb-3">
            <Icon name="shield-lock" size={16} class="text-warning" />
            <h3 class="text-sm font-semibold">Intrusions & bans</h3>
            <Explain tip="CrowdSec reads this host's logs, matches attack patterns, and bans the source IPs. The agent enforces those bans in the host's own nftables." />
            <span class="ml-auto text-[11px] text-muted-foreground">CrowdSec</span>
          </div>
          {#if intr?.decisions?.length}
            <div class="space-y-1">
              {#each intr.decisions.slice(0, 50) as d}
                <div class="flex items-center gap-2 py-1.5 border-t border-border first:border-t-0 text-sm">
                  <Badge variant="danger" size="sm">{d.type || 'ban'}</Badge>
                  <span class="font-mono text-xs">{d.value}</span>
                  <span class="text-muted-foreground text-xs truncate flex-1">{d.scenario || ''}</span>
                  {#if d.duration}<span class="text-[11px] text-muted-foreground font-mono">{d.duration}</span>{/if}
                </div>
              {/each}
            </div>
          {:else}
            <div class="text-sm text-success flex items-center gap-2"><Icon name="check" size={15} />No active bans — CrowdSec hasn't detected an attack.</div>
          {/if}
        </div>

        <!-- FIM feed -->
        <div class="bg-card border border-border rounded-xl p-4">
          <div class="flex items-center gap-2 mb-3">
            <Icon name="file-alert" size={16} class="text-info" />
            <h3 class="text-sm font-semibold">File integrity (FIM)</h3>
            <Explain tip="osquery watches sensitive paths (/etc, SSH keys, system binaries). A change here on a server you didn't touch is a 'someone got in' signal worth investigating." />
            <span class="ml-auto text-[11px] text-muted-foreground">osquery</span>
          </div>
          {#if facts?.fim?.length}
            <div class="space-y-1">
              {#each facts.fim.slice().reverse().slice(0, 60) as f}
                <div class="flex items-baseline gap-2 py-1.5 border-t border-border first:border-t-0 text-sm">
                  <Badge variant={f.action === 'DELETED' ? 'danger' : 'warning'} size="sm">{f.action || 'changed'}</Badge>
                  <span class="font-mono text-xs break-all flex-1">{f.path}</span>
                </div>
              {/each}
            </div>
          {:else}
            <div class="text-sm text-success flex items-center gap-2"><Icon name="check" size={15} />No file-integrity changes recorded.</div>
          {/if}
        </div>

        <!-- Block controls -->
        <div class="bg-card border border-border rounded-xl p-4 space-y-3">
          <h3 class="text-sm font-semibold">Blocking</h3>
          <div class="flex flex-wrap items-center gap-2">
            <input bind:value={blockIP} placeholder="IP to block on this host" onkeydown={(e) => e.key === 'Enter' && blockOn()}
              class="flex-1 min-w-[160px] bg-background border border-border rounded-lg px-3 py-2 text-sm font-mono" />
            <Button variant="destructive" size="sm" icon="ban" onclick={blockOn} disabled={!blockIP.trim()}>Block</Button>
          </div>
          <div class="flex items-center gap-2 pt-1">
            <Button variant="outline" size="sm" icon="arrow-down" onclick={pushBlocks}>Push panel blocklist</Button>
            <Explain tip="Sends the panel's own blocked IPs/ranges (manual + escalated) down to this machine, so it drops them in its local nftables too. Country/ASN mega-lists are excluded." />
          </div>
        </div>
      </div>

    <!-- VULNERABILITIES -->
    {:else if activeTab === 'cves'}
      <div class="space-y-4">
        <div class="bg-card border border-border rounded-xl p-4">
          <div class="flex items-center gap-2 flex-wrap mb-3">
            <Icon name="bug" size={16} class="text-warning" />
            <h3 class="text-sm font-semibold">Vulnerabilities</h3>
            <Explain tip="Trivy scans installed OS packages AND app dependencies against the CVE feed. 'Fix' is the version that patches it. Apply updates to fix OS packages; a kernel CVE also needs a reboot. Then Rescan to confirm." />
            <div class="ml-auto flex items-center gap-1.5">
              {#each ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as sev}
                {#if cves?.counts?.[sev]}<Badge variant={sevVariant(sev)} size="sm">{cves.counts[sev]} {sev.toLowerCase()}</Badge>{/if}
              {/each}
            </div>
          </div>
          <div class="flex items-center gap-2 mb-3">
            <Button variant="primary" size="sm" icon="refresh-alert" onclick={() => cmd('apply-updates', null, { title: 'Apply updates', message: `Run system package updates on ${machine.name}? (Kernel CVEs also need a reboot afterwards.)` })}>Apply updates</Button>
            <Button variant="outline" size="sm" icon="scan" onclick={() => cmd('rescan', null, { title: 'Rescan', message: `Re-run the Trivy CVE scan on ${machine.name} now?` })}>Rescan</Button>
            <span class="text-[11px] text-muted-foreground">Trivy{cves?.scanned_at ? ` · scanned ${timeAgo(cves.scanned_at)}` : ''}</span>
          </div>

          {#if cves?.top?.length}
            <div class="overflow-x-auto">
              <table class="w-full text-sm">
                <thead>
                  <tr class="text-[11px] text-muted-foreground text-left border-b border-border">
                    <th class="py-2 pr-3 font-medium">Severity</th>
                    <th class="py-2 pr-3 font-medium">CVE</th>
                    <th class="py-2 pr-3 font-medium">Package</th>
                    <th class="py-2 pr-3 font-medium">Installed → Fix</th>
                  </tr>
                </thead>
                <tbody>
                  {#each cves.top as v}
                    <tr class="border-b border-border/60">
                      <td class="py-2 pr-3"><Badge variant={sevVariant(v.severity)} size="sm">{(v.severity || '').toLowerCase()}</Badge></td>
                      <td class="py-2 pr-3 font-mono text-xs whitespace-nowrap" title={v.title}>{v.id}</td>
                      <td class="py-2 pr-3 text-xs">{v.pkg}</td>
                      <td class="py-2 pr-3 text-xs font-mono whitespace-nowrap">
                        <span class="text-muted-foreground">{v.installed || '?'}</span>
                        {#if v.fixed}<span class="text-success"> → {v.fixed}</span>{:else}<span class="text-muted-foreground"> → no fix</span>{/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
            {#if cves.total > cves.top.length}
              <div class="text-[11px] text-muted-foreground mt-2">Showing the {cves.top.length} worst of {cves.total} findings.</div>
            {/if}
          {:else}
            <div class="text-sm text-success flex items-center gap-2"><Icon name="check" size={15} />No known vulnerabilities found.</div>
          {/if}
        </div>
      </div>

    <!-- HOST -->
    {:else if activeTab === 'host'}
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div class="bg-card border border-border rounded-xl p-4">
          <div class="flex items-center gap-2 mb-2"><Icon name="server" size={16} /><h3 class="text-sm font-semibold">System</h3><span class="ml-auto text-[11px] text-muted-foreground">osquery</span></div>
          <div class="{kvRow}"><span class="text-muted-foreground">Hostname</span><span class="font-mono">{facts?.system?.hostname || report.host || '—'}</span></div>
          <div class="{kvRow}"><span class="text-muted-foreground">OS</span><span class="font-mono">{[facts?.os?.name, facts?.os?.version].filter(Boolean).join(' ') || '—'}</span></div>
          <div class="{kvRow}"><span class="text-muted-foreground">CPU</span><span class="font-mono truncate max-w-[60%] text-right">{facts?.system?.cpu_brand || '—'}</span></div>
          <div class="{kvRow}"><span class="text-muted-foreground">Uptime</span><span class="font-mono">{fmtUptime(m.uptime)}</span></div>
          <div class="{kvRow}"><span class="text-muted-foreground">WG pubkey</span><span class="font-mono text-xs truncate max-w-[55%] text-right">{machine.wg_pubkey || '—'}</span></div>
          <div class="{kvRow}"><span class="text-muted-foreground">Last report</span><span class="font-mono">{report.time ? timeAgo(report.time) : '—'}</span></div>
        </div>

        <div class="bg-card border border-border rounded-xl p-4">
          <div class="flex items-center gap-2 mb-2"><Icon name="plug-connected" size={16} /><h3 class="text-sm font-semibold">Listening ports</h3>
            <Explain tip="Ports this host has open. Agents (osquery, CrowdSec) bind to the WG interface only — an unexpected public port is worth a look." />
            <span class="ml-auto text-[11px] text-muted-foreground">osquery</span></div>
          {#if facts?.ports?.length}
            <div class="max-h-64 overflow-y-auto">
              {#each facts.ports as p}
                <div class="flex items-center gap-2 py-1.5 border-t border-border first:border-t-0 text-sm">
                  <span class="font-mono text-xs">{p.address || '*'}:{p.port}</span>
                  <span class="text-[11px] text-muted-foreground uppercase">{p.protocol === '6' ? 'tcp' : p.protocol === '17' ? 'udp' : p.protocol}</span>
                </div>
              {/each}
            </div>
          {:else}
            <div class="text-sm text-muted-foreground">No port data.</div>
          {/if}
        </div>

        {#if facts?.users?.length}
          <div class="bg-card border border-border rounded-xl p-4 lg:col-span-2">
            <div class="flex items-center gap-2 mb-2"><Icon name="users" size={16} /><h3 class="text-sm font-semibold">Logged-in users</h3><span class="ml-auto text-[11px] text-muted-foreground">osquery</span></div>
            {#each facts.users as u}
              <div class="flex items-center gap-3 py-1.5 border-t border-border first:border-t-0 text-sm">
                <span class="font-medium">{u.user}</span>
                {#if u.tty}<span class="text-[11px] text-muted-foreground font-mono">{u.tty}</span>{/if}
                <span class="text-xs text-muted-foreground font-mono ml-auto">{u.host ? `from ${u.host}` : 'local console'}</span>
              </div>
            {/each}
          </div>
        {/if}
      </div>
    {/if}
  {/if}
</div>
