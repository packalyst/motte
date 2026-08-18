<script>
  /**
   * MachinesView — the fleet page. A summary strip, the agent-listener control (on/off
   * + port, no env vars), the add-machine flow (one-time token → one-command install),
   * and a grid of machine cards (usage bars + threat chips from each host's latest
   * report). Click a card to open its structured detail page.
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Button from '../components/Button.svelte'
  import StatCard from '../components/StatCard.svelte'
  import Badge from '../components/Badge.svelte'
  import MachineDetail from '../components/MachineDetail.svelte'
  import { timeAgo } from '$lib/utils/format.js'
  import { usageColor, statusInfo, round } from '$lib/fleet.js'

  let { loading = $bindable(true) } = $props()

  let machines = $state([])
  let ep = $state(null) // { enabled, port, listening, hosts:[], fingerprint }
  let error = $state(null)
  let selected = $state(null) // machine object when a detail page is open

  // listener config
  let cfgEnabled = $state(false)
  let cfgPort = $state(9443)
  let savingCfg = $state(false)

  // add-machine
  let newLabel = $state('')
  let selectedHost = $state('')
  let creating = $state(false)
  let lastToken = $state(null)

  async function load() {
    try {
      const [mRes, eRes] = await Promise.allSettled([apiGet('/api/fleet/machines'), apiGet('/api/fleet/endpoints')])
      if (mRes.status === 'fulfilled') machines = mRes.value || []
      if (eRes.status === 'fulfilled') {
        ep = eRes.value
        if (!savingCfg) { cfgEnabled = ep.enabled; cfgPort = ep.port }
        if (!selectedHost && ep.hosts?.length) selectedHost = ep.hosts[0]
      }
      // keep the open detail's header fresh
      if (selected) selected = machines.find((x) => x.id === selected.id) || selected
      error = null
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }
  onMount(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t) })

  // fleet summary tiles
  const summary = $derived.by(() => {
    let online = 0, threats = 0, cves = 0
    for (const m of machines) {
      if (statusInfo(m).online) online++
      if ((m.summary?.bans ?? 0) > 0 || (m.summary?.fim ?? 0) > 0) threats++
      if ((m.summary?.cve_critical ?? 0) > 0) cves++
    }
    return { total: machines.length, online, threats, cves }
  })

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

  function openDetail(m) { selected = m }
  function closeDetail() { selected = null; load() }

  const inputCls = 'bg-background border border-border rounded-lg px-3 py-2 text-sm'
</script>

{#if selected}
  <MachineDetail machine={selected} onback={closeDetail} ondeleted={closeDetail} />
{:else}
<div class="space-y-4">
  <InfoCard icon="device-desktop" title="Machines"
    description="Enrolled wgscout agents. Turn the listener on, add a machine for a one-command install, and manage each host over the encrypted mutual-TLS channel." />

  {#if error}
    <div class="bg-destructive/10 border border-destructive/30 text-destructive rounded-xl p-3 text-sm">{error}</div>
  {/if}

  <!-- Summary -->
  {#if machines.length}
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <StatCard icon="device-desktop" color="primary" value={summary.total} label="Machines" />
      <StatCard icon="circle-check" color="success" value={summary.online} label="Online" />
      <StatCard icon="alert-triangle" color="warning" value={summary.cves} label="With critical CVEs" />
      <StatCard icon="skull" color="destructive" value={summary.threats} label="Active threats" />
    </div>
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

  <!-- Machine grid -->
  {#if machines.length === 0}
    <div class="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">
      No machines enrolled yet. Add one above.
    </div>
  {:else}
    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
      {#each machines as m (m.id)}
        {@const st = statusInfo(m)}
        {@const s = m.summary}
        <button type="button" onclick={() => openDetail(m)}
          class="text-left bg-card border rounded-xl p-4 transition hover:border-primary/50 hover:shadow-sm
                 {(s?.bans > 0 || s?.fim > 0) ? 'border-destructive/40' : 'border-border'}">
          <div class="flex items-center gap-2.5">
            <span class="w-2.5 h-2.5 rounded-full shrink-0 {st.dot}"></span>
            <div class="min-w-0 flex-1">
              <div class="text-sm font-semibold text-foreground truncate">{m.name || m.id}</div>
              <div class="text-[11px] text-muted-foreground truncate">{st.label}{m.last_seen ? ` · ${timeAgo(m.last_seen)}` : ''}</div>
            </div>
            {#if s?.os}<span class="text-[10px] px-2 py-0.5 rounded-full bg-muted text-muted-foreground border border-border shrink-0">{s.os}</span>{/if}
          </div>

          {#if s && st.online}
            <div class="mt-3 space-y-1.5">
              {#each [['CPU', s.cpu], ['MEM', s.mem], ['DISK', s.disk]] as [lbl, val]}
                <div class="flex items-center gap-2 text-[11px]">
                  <span class="w-8 text-muted-foreground">{lbl}</span>
                  <span class="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
                    <span class="block h-full rounded-full {usageColor(round(val))}" style="width:{Math.min(round(val), 100)}%"></span>
                  </span>
                  <span class="w-8 text-right tabular-nums text-muted-foreground">{round(val)}%</span>
                </div>
              {/each}
            </div>

            <div class="flex flex-wrap gap-1.5 mt-3">
              {#if s.bans > 0}
                <Badge variant="danger" size="sm">{s.bans} ban{s.bans > 1 ? 's' : ''}</Badge>
              {:else}
                <Badge variant="success" size="sm">no threats</Badge>
              {/if}
              {#if s.fim > 0}<Badge variant="warning" size="sm">FIM {s.fim}</Badge>{/if}
              {#if s.cve_total > 0}
                <Badge variant={s.cve_critical > 0 ? 'danger' : 'warning'} size="sm">{s.cve_total} CVE{s.cve_total > 1 ? 's' : ''}{s.cve_critical > 0 ? ` · ${s.cve_critical} crit` : ''}</Badge>
              {/if}
            </div>
          {:else}
            <div class="mt-3 text-[11px] text-muted-foreground py-3 text-center">
              {m.revoked ? 'Revoked' : m.last_seen ? 'Offline — no live metrics' : 'Waiting for first report'}
            </div>
          {/if}
        </button>
      {/each}
    </div>
  {/if}
</div>
{/if}
