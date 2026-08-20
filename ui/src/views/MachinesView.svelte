<script>
  /**
   * MachinesView — the fleet page. A summary strip, the agent-listener control (on/off
   * + port, no env vars), the add-machine flow (one-time token → one-command install),
   * and a grid of machine cards (usage bars + threat chips from each host's latest
   * report). Click a card to open its structured detail page.
   */
  import { onMount } from 'svelte'
  import { get } from 'svelte/store'
  import { apiGet, apiPost, toast, confirm } from '../stores/app.js'
  import { subscribe, unsubscribe, fleetStore, wsConnected } from '../stores/websocket.js'
  import Icon from '../components/Icon.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Button from '../components/Button.svelte'
  import StatCard from '../components/StatCard.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import Input from '../components/Input.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import Select from '../components/Select.svelte'
  import MachineDetail from '../components/MachineDetail.svelte'
  import MachineCVEs from '../components/MachineCVEs.svelte'
  import { timeAgo } from '$lib/utils/format.js'
  import { usageColor, statusInfo, round } from '$lib/fleet.js'

  let { loading = $bindable(true) } = $props()

  let machines = $state([])
  let ep = $state(null) // { enabled, port, listening, hosts:[], fingerprint }
  let error = $state(null)
  let selected = $state(null) // machine object when a detail page is open
  let cvesFor = $state(null)  // machine object when the CVE drill-down is open

  // listener config
  let cfgEnabled = $state(false)
  let cfgPort = $state(9443)
  let savingCfg = $state(false)

  // add-machine
  let selectedHost = $state('') // direct origin IP the agent dials for mTLS
  let creating = $state(false)
  let lastToken = $state(null)

  // Rate-limit refetches triggered by fleet check-in pushes so a busy fleet
  // can't hammer /api/fleet/machines — at most one refetch per ~8s, coalescing
  // simultaneous check-ins.
  let lastLoad = 0
  let refetchTimer = null
  function scheduleRefetch() {
    if (refetchTimer) return
    const wait = Math.max(500, 8000 - (Date.now() - lastLoad))
    refetchTimer = setTimeout(() => { refetchTimer = null; load() }, wait)
  }

  async function load() {
    lastLoad = Date.now()
    try {
      const [mRes, eRes] = await Promise.allSettled([apiGet('/api/fleet/machines'), apiGet('/api/fleet/endpoints')])
      if (mRes.status === 'fulfilled') machines = mRes.value || []
      if (eRes.status === 'fulfilled') {
        ep = eRes.value
        if (!savingCfg) { cfgEnabled = ep.enabled; cfgPort = ep.port }
        // Default the mTLS host to the first candidate (a public IP), not the domain.
        if (!selectedHost && ep.hosts?.length) selectedHost = ep.hosts[0]
      }
      // keep an open view's machine fresh; restore from the URL hash on refresh/direct link.
      if (cvesFor) cvesFor = machines.find((x) => x.id === cvesFor.id) || cvesFor
      else if (selected) selected = machines.find((x) => x.id === selected.id) || selected
      else restoreFromHash()
      error = null
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }
  onMount(() => {
    load()
    subscribe('fleet') // each agent check-in pushes its report → refetch the list live

    // Refetch on a check-in push (rate-limited). Skip the immediate on-subscribe
    // emission so we don't double-load right after the initial fetch.
    let firstFleet = true
    const unsub = fleetStore.subscribe((msg) => {
      if (firstFleet) { firstFleet = false; return }
      if (msg) scheduleRefetch()
    })

    // Baseline sweep: machines that go offline stop pushing, so still poll — but
    // only every ~60s when the socket is up (pushes do the live work); fall back
    // to the old 15s cadence when the socket is down.
    const t = setInterval(() => {
      if (!get(wsConnected)) load()
      else if (Date.now() - lastLoad > 60000) load()
    }, 15000)

    const onHash = () => restoreFromHash()
    window.addEventListener('hashchange', onHash)
    return () => {
      clearInterval(t)
      if (refetchTimer) clearTimeout(refetchTimer)
      unsub()
      unsubscribe('fleet')
      window.removeEventListener('hashchange', onHash)
    }
  })

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
    creating = true
    try {
      // The machine's real name comes from its hostname at enroll; this label is just a
      // one-time-token reference, so auto-generate it.
      const label = 'machine-' + Math.random().toString(36).slice(2, 8)
      lastToken = await apiPost('/api/fleet/token', { label, ttl_seconds: 3600, panel_host: selectedHost })
      toast('Install command ready — one-time, expires in 1h', 'success')
    } catch (e) {
      toast('Failed to create token: ' + e.message, 'error')
    } finally {
      creating = false
    }
  }

  // Deep-link the open machine in the URL hash (#m=<id>) so a refresh stays on it.
  const hashParams = () => (typeof window === 'undefined' ? new URLSearchParams() : new URLSearchParams(window.location.hash.slice(1)))
  function setHash(s) {
    if (typeof window === 'undefined') return
    if (s) window.location.hash = s
    else if (window.location.hash) history.replaceState(null, '', window.location.pathname)
  }
  function openDetail(m) { selected = m; cvesFor = null; setHash('m=' + encodeURIComponent(m.id)) }
  function openCves(m) { cvesFor = m; selected = null; setHash('cves=' + encodeURIComponent(m.id)) }
  function closeCves() { const m = cvesFor; cvesFor = null; selected = m; setHash('m=' + encodeURIComponent(m.id)) }
  // Restore the open view from the hash (refresh or direct link).
  function restoreFromHash() {
    const p = hashParams()
    const cid = p.get('cves'), mid = p.get('m')
    if (cid) { const m = machines.find((x) => x.id === cid); if (m) { cvesFor = m; selected = null } }
    else if (mid) { const m = machines.find((x) => x.id === mid); if (m) { selected = m; cvesFor = null } }
    else { selected = null; cvesFor = null }
  }
  async function deleteMachine(m) {
    const ok = await confirm({
      title: `Delete ${m.name || m.id}`,
      message: `Delete ${m.name || m.id}? Its certificate is invalidated immediately — the agent can no longer connect and must re-enroll with a fresh token to return.`,
      confirmText: 'Delete machine', variant: 'destructive', alert: true,
    })
    if (!ok) return
    try {
      await apiPost('/api/fleet/machine/delete', { machine_id: m.id })
      toast(`${m.name || m.id} deleted`, 'success')
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }
  function closeDetail() { selected = null; cvesFor = null; setHash(''); load() }

  const chipCls = {
    ok: 'bg-success/10 text-success',
    warn: 'bg-warning/10 text-warning',
    crit: 'bg-destructive/10 text-destructive',
    muted: 'bg-muted text-muted-foreground',
  }
</script>

<!-- Source-labelled status chip (matches the fleet mockup): a coloured pill with the
     data source (crowdsec / osquery / trivy) called out, so provenance stays visible. -->
{#snippet chip(variant, label, src)}
  <span class="inline-flex items-center gap-1 text-[10.5px] font-medium px-2 py-0.5 rounded-full {chipCls[variant]}">
    {label}{#if src}<span class="text-[9px] opacity-60 font-normal">{src}</span>{/if}
  </span>
{/snippet}

{#if cvesFor}
  <MachineCVEs machine={cvesFor} onback={closeCves} />
{:else if selected}
  <MachineDetail machine={selected} onback={closeDetail} ondeleted={closeDetail} onviewcves={openCves} />
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
    <div class="flex flex-wrap items-center gap-x-6 gap-y-3">
      <div class="flex items-center gap-2.5">
        <span class="w-9 h-9 rounded-lg grid place-items-center border {ep?.listening ? 'bg-success/10 border-success/30 text-success' : 'bg-muted border-border text-muted-foreground'}">
          <Icon name={ep?.listening ? 'lock-open' : 'lock'} size={17} />
        </span>
        <Checkbox variant="switch" bind:checked={cfgEnabled} onchange={saveConfig}
          label="Agent listener"
          helperText={ep?.listening ? `Door open · accepting agents on :${ep.port}` : 'Closed · no agents can connect'} />
      </div>
      <div class="ml-auto w-full sm:w-auto">
        <Input type="number" bind:value={cfgPort} min="1" max="65535" prefixIcon="plug-connected"
          class="w-40" label="Port"
          suffixAddonBtn={{ icon: 'device-floppy', label: 'Save', variant: 'primary', onclick: saveConfig, disabled: savingCfg }} />
      </div>
    </div>
    <p class="text-[11px] text-muted-foreground mt-3 pt-3 border-t border-dashed border-border flex items-start gap-1.5">
      <Icon name="info-circle" size={13} class="mt-0.5 shrink-0" />
      Turning this on opens the port through the firewall automatically and starts the mutual-TLS listener — nothing to edit in env or compose.
    </p>
  </div>

  <!-- Add machine — only once the listener is on (nothing can enroll otherwise) -->
  {#if ep?.enabled}
  <div class="bg-card border border-border rounded-xl p-4">
    <h3 class="text-sm font-semibold mb-3 flex items-center gap-2"><Icon name="plus" size={16} class="text-primary" />Add a machine</h3>
    <div class="flex flex-wrap items-end gap-2">
      {#if ep?.hosts?.length}
        <div class="flex-1 min-w-[200px]">
          <Select bind:value={selectedHost} label="Agent connects to" options={ep.hosts.map((h) => ({ value: h, label: h }))} />
        </div>
      {/if}
      <Button icon="key" onclick={addMachine} disabled={creating || !ep?.domain}>Generate install command</Button>
    </div>
    <div class="text-[11px] text-muted-foreground mt-1.5">Pick a directly-reachable IP — the mTLS channel can't go through Cloudflare.</div>
    {#if !ep?.domain}
      <div class="text-[11px] text-warning mt-2 flex items-center gap-1.5"><Icon name="alert-triangle" size={13} />Set a panel domain (SSL_DOMAIN) — the install downloads over the domain's HTTPS.</div>
    {/if}

    {#if lastToken}
      <div class="mt-3 border-t border-dashed border-border pt-3">
        <div class="text-xs text-muted-foreground mb-1.5">Run on the new machine (one-time, expires {timeAgo(lastToken.expires_at)}):</div>
        {#if lastToken.install_command}
          <Input value={lastToken.install_command} readonly class="font-mono text-[11px]"
            suffixAddonBtn={{ icon: 'copy', variant: 'outline', copyText: lastToken.install_command, title: 'Copy' }} />
        {:else}
          <div class="text-xs text-warning">Pick an address above so the install command can be built.</div>
        {/if}
      </div>
    {/if}
  </div>
  {/if}

  <!-- Machine grid -->
  {#if machines.length === 0}
    <div class="bg-card border border-border rounded-xl p-10">
      <EmptyState icon="device-desktop" title="No machines yet"
        description={ep?.enabled ? 'Add a machine above — you’ll get a one-command install to run on the box.' : 'Turn the agent listener on above, then add your first machine.'} />
    </div>
  {:else}
    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
      {#each machines as m (m.id)}
        {@const st = statusInfo(m)}
        {@const s = m.summary}
        <div class="bg-card border rounded-xl p-4 flex flex-col
                 {st.gone ? 'border-border opacity-60' : (s?.bans > 0 || s?.fim > 0) ? 'border-destructive/40' : 'border-border'}">
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
                {@render chip('crit', `⚠ ${s.bans} ban${s.bans > 1 ? 's' : ''}`, 'crowdsec')}
              {:else}
                {@render chip('ok', '✓ no threats', 'crowdsec')}
              {/if}
              {#if s.fim > 0}
                {@render chip('warn', `⚠ FIM ${s.fim}`, 'osquery')}
              {:else}
                {@render chip('ok', '✓ FIM clean', 'osquery')}
              {/if}
              {#if s.cve_total > 0}
                {@render chip(s.cve_critical > 0 ? 'crit' : 'warn', `${s.cve_total} CVE${s.cve_total > 1 ? 's' : ''}${s.cve_critical > 0 ? ` · ${s.cve_critical} crit` : ''}`, 'trivy')}
              {:else}
                {@render chip('ok', '✓ no CVEs', 'trivy')}
              {/if}
            </div>
          {:else}
            <div class="mt-3 text-[11px] text-muted-foreground py-4 text-center">
              {st.gone ? 'Agent uninstalled — delete to remove' : m.revoked ? 'Revoked' : m.last_seen ? `Offline · last seen ${timeAgo(m.last_seen)}` : 'Waiting for first report'}
            </div>
          {/if}

          <div class="mt-4 pt-3 border-t border-border">
            {#if st.gone}
              <button onclick={() => deleteMachine(m)} class="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-xs text-destructive hover:bg-destructive/10 transition cursor-pointer">
                <Icon name="trash" size={13} />Delete
              </button>
            {:else}
              <div class="flex items-center rounded-lg border border-border overflow-hidden divide-x divide-border">
                <button onclick={() => openDetail(m)} class="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs text-muted-foreground hover:bg-muted hover:text-foreground transition cursor-pointer">
                  <Icon name="settings" size={13} />Manage
                </button>
                <button onclick={() => deleteMachine(m)} class="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs text-destructive hover:bg-destructive/10 transition cursor-pointer">
                  <Icon name="trash" size={13} />Delete
                </button>
              </div>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>
{/if}
