<script>
  /**
   * MachinesView — the fleet page. Turn the agent-listener on/off (+ port) right
   * here, add machines (mint a one-time token → one-command install, with a
   * WG-vs-public address picker), watch each host report in, and issue commands.
   * No env vars: the panel reads the toggle/port from Settings and opens its own
   * firewall port; the install command's address is whichever host you pick.
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast, confirm } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Button from '../components/Button.svelte'
  import { timeAgo } from '$lib/utils/format.js'

  let { loading = $bindable(true) } = $props()

  let machines = $state([])
  let ep = $state(null) // { enabled, port, listening, hosts:[], fingerprint }
  let error = $state(null)

  // listener config
  let cfgEnabled = $state(false)
  let cfgPort = $state(8443)
  let savingCfg = $state(false)

  // add-machine
  let newLabel = $state('')
  let selectedHost = $state('')
  let creating = $state(false)
  let lastToken = $state(null)

  // per-machine
  let blockIP = $state({})
  let reportFor = $state(null)
  let report = $state(null)

  async function load() {
    try {
      const [m, e] = await Promise.allSettled([apiGet('/api/fleet/machines'), apiGet('/api/fleet/endpoints')])
      if (m.status === 'fulfilled') machines = m.value || []
      if (e.status === 'fulfilled') {
        ep = e.value
        if (!savingCfg) { cfgEnabled = ep.enabled; cfgPort = ep.port }
        if (!selectedHost && ep.hosts?.length) selectedHost = ep.hosts[0]
      }
      error = null
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }
  onMount(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t) })

  async function saveConfig() {
    savingCfg = true
    try {
      ep = { ...ep, ...(await apiPost('/api/fleet/config', { enabled: cfgEnabled, port: Number(cfgPort) })) }
      toast(cfgEnabled ? `Fleet listener on :${ep.port}` : 'Fleet listener off', 'success')
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      savingCfg = false
    }
  }

  async function addMachine() {
    if (!newLabel.trim()) return
    creating = true
    try {
      lastToken = await apiPost('/api/fleet/token', { label: newLabel.trim(), ttl_seconds: 3600, panel_host: selectedHost })
      newLabel = ''
      toast('Enrollment token created — one-time, expires in 1h', 'success')
    } catch (e) {
      toast('Failed to create token: ' + e.message, 'error')
    } finally {
      creating = false
    }
  }

  async function sendCommand(m, type, payload = null) {
    const ok = await confirm({
      title: `${type} · ${m.name}`,
      message: `Queue "${type}" for ${m.name}? It runs on the machine's next check-in.`,
      confirmText: 'Queue',
      variant: type === 'restart' ? 'destructive' : 'primary',
    })
    if (!ok) return
    try {
      await apiPost('/api/fleet/command', { machine_id: m.id, type, payload })
      toast(`${type} queued for ${m.name}`, 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function blockOn(m) {
    const ip = (blockIP[m.id] || '').trim()
    if (!ip) return
    await sendCommand(m, 'block', { ip })
    blockIP[m.id] = ''
  }

  async function viewReport(m) {
    if (reportFor === m.id) { reportFor = null; report = null; return }
    reportFor = m.id
    report = null
    try { report = await apiGet('/api/fleet/report?id=' + encodeURIComponent(m.id)) } catch { report = null }
  }

  function statusDot(m) {
    if (m.revoked) return 'bg-destructive'
    if (!m.last_seen) return 'bg-muted-foreground'
    const mins = (Date.now() - new Date(m.last_seen)) / 60000
    return mins < 2 ? 'bg-success' : mins < 10 ? 'bg-warning' : 'bg-muted-foreground'
  }
  function statusText(m) {
    if (m.revoked) return 'revoked'
    if (!m.last_seen) return 'never reported'
    return 'seen ' + timeAgo(m.last_seen)
  }

  const chip = 'text-[11px] px-1.5 py-0.5 rounded font-medium'
  const inputCls = 'bg-background border border-border rounded-lg px-3 py-2 text-sm'
</script>

<div class="space-y-4">
  <InfoCard icon="device-desktop" title="Machines"
    description="Enrolled wgscout agents. Turn the listener on, add a machine for a one-command install, and push commands over the encrypted channel." />

  {#if error}
    <div class="bg-destructive/10 border border-destructive/30 text-destructive rounded-xl p-3 text-sm">{error}</div>
  {/if}

  <!-- Listener config -->
  <div class="bg-card border border-border rounded-xl p-4">
    <div class="flex flex-wrap items-center gap-3">
      <label class="flex items-center gap-2 text-sm font-medium cursor-pointer">
        <input type="checkbox" bind:checked={cfgEnabled} class="w-4 h-4 accent-primary" />
        Agent listener
      </label>
      <span class="w-1.5 h-1.5 rounded-full {ep?.listening ? 'bg-success' : 'bg-muted-foreground'}"></span>
      <span class="text-xs text-muted-foreground">{ep?.listening ? `on · :${ep.port}` : 'off'}</span>
      <div class="flex items-center gap-1.5 ml-auto">
        <span class="text-xs text-muted-foreground">port</span>
        <input type="number" bind:value={cfgPort} min="1" max="65535" class="{inputCls} w-24 py-1.5" />
        <Button size="xs" icon="device-floppy" onclick={saveConfig} disabled={savingCfg}>Save</Button>
      </div>
    </div>
    <p class="text-[11px] text-muted-foreground mt-2">
      Turning this on opens the port through the firewall automatically and starts the mutual-TLS listener. Nothing to edit in env or compose.
    </p>
  </div>

  <!-- Add machine -->
  <div class="bg-card border border-border rounded-xl p-4">
    <h3 class="text-sm font-semibold mb-3 flex items-center gap-2"><Icon name="plus" size={16} class="text-primary" />Add a machine</h3>
    <div class="flex flex-wrap items-center gap-2">
      <input bind:value={newLabel} placeholder="label (e.g. web-01)" onkeydown={(e) => e.key === 'Enter' && addMachine()}
        class="flex-1 min-w-[150px] {inputCls}" />
      {#if ep?.hosts?.length}
        <label class="text-xs text-muted-foreground">reachable at</label>
        <select bind:value={selectedHost} class="{inputCls} py-2">
          {#each ep.hosts as h}<option value={h}>{h}</option>{/each}
        </select>
      {/if}
      <Button icon="key" onclick={addMachine} disabled={creating || !newLabel.trim()}>Generate install command</Button>
    </div>
    {#if !ep?.enabled}
      <div class="text-[11px] text-warning mt-2">Turn the agent listener on (above) so machines can enroll.</div>
    {/if}

    {#if lastToken}
      <div class="mt-3 border-t border-dashed border-border pt-3">
        <div class="text-xs text-muted-foreground mb-1.5">Run this on the new machine (one-time, expires {timeAgo(lastToken.expires_at)}):</div>
        {#if lastToken.install_command}
          <div class="flex items-start gap-2">
            <pre class="flex-1 bg-background border border-border rounded-lg p-2.5 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap break-all">{lastToken.install_command}</pre>
            <Button variant="ghost" size="xs" icon="copy" copyText={lastToken.install_command} title="Copy" />
          </div>
        {:else}
          <div class="text-xs text-warning">Pick an address above so the install command can be built. Token: <span class="font-mono">{lastToken.token}</span></div>
        {/if}
      </div>
    {/if}
  </div>

  <!-- Machine list -->
  {#if machines.length === 0}
    <div class="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">
      No machines enrolled yet. Add one above.
    </div>
  {:else}
    <div class="space-y-2.5">
      {#each machines as m (m.id)}
        <div class="bg-card border border-border rounded-xl p-4">
          <div class="flex items-center gap-3">
            <span class="w-2.5 h-2.5 rounded-full shrink-0 {statusDot(m)}"></span>
            <div class="min-w-0 flex-1">
              <div class="text-sm font-semibold text-foreground flex items-center gap-2">{m.name || m.id}
                {#if m.revoked}<span class="{chip} bg-destructive/15 text-destructive">revoked</span>{/if}</div>
              <div class="text-[11px] text-muted-foreground font-mono truncate">{m.id} · {statusText(m)}</div>
            </div>
            <Button variant="ghost" size="xs" icon={reportFor === m.id ? 'chevron-down' : 'chevron-right'} onclick={() => viewReport(m)}>Report</Button>
          </div>

          <div class="flex flex-wrap items-center gap-2 mt-3">
            <input bind:value={blockIP[m.id]} placeholder="IP to block"
              class="w-[130px] bg-background border border-border rounded-lg px-2 py-1 text-xs font-mono" />
            <Button variant="destructive" size="xs" icon="ban" onclick={() => blockOn(m)} disabled={!(blockIP[m.id] || '').trim()}>Block</Button>
            <Button variant="ghost" size="xs" icon="refresh" onclick={() => sendCommand(m, 'apply-updates')}>Updates</Button>
            <Button variant="ghost" size="xs" icon="tool" onclick={() => sendCommand(m, 'restart', { target: 'tools' })}>Restart tools</Button>
          </div>

          {#if reportFor === m.id}
            <div class="mt-3 border-t border-dashed border-border pt-3">
              {#if !report}
                <div class="text-xs text-muted-foreground">No report yet.</div>
              {:else}
                <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                  <div><div class="text-lg font-bold tabular-nums">{report.metrics?.cpu ?? 0}%</div><div class="text-[11px] text-muted-foreground">CPU</div></div>
                  <div><div class="text-lg font-bold tabular-nums">{report.metrics?.mem ?? 0}%</div><div class="text-[11px] text-muted-foreground">Memory</div></div>
                  <div><div class="text-lg font-bold tabular-nums">{report.metrics?.disk ?? 0}%</div><div class="text-[11px] text-muted-foreground">Disk</div></div>
                  <div><div class="text-lg font-bold tabular-nums">{report.blocked?.length ?? 0}</div><div class="text-[11px] text-muted-foreground">Blocked</div></div>
                </div>
                <div class="flex flex-wrap gap-2 mt-3 text-[11px]">
                  {#if report.cves?.total}<span class="{chip} bg-destructive/15 text-destructive">{report.cves.total} CVEs · {report.cves.counts?.CRITICAL ?? 0} critical</span>{/if}
                  {#if report.intrusion}<span class="{chip} bg-warning/15 text-warning">{report.intrusion.active_bans ?? 0} bans · {report.intrusion.enforced ?? 0} enforced</span>{/if}
                  {#if report.facts?.fim?.length}<span class="{chip} bg-muted text-muted-foreground">{report.facts.fim.length} FIM events</span>{/if}
                  <span class="{chip} bg-muted text-muted-foreground">agent {report.agent}</span>
                </div>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>
