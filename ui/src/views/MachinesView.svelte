<script>
  /**
   * MachinesView — the fleet page. A summary strip, the agent-listener control (on/off
   * + port, no env vars), the add-machine flow (one-time token → one-command install),
   * and a grid of machine cards (usage bars + threat chips from each host's latest
   * report). Click a card to open its structured detail page.
   */
  import { onMount } from 'svelte'
  import { get } from 'svelte/store'
  import { apiGet, apiPost, apiDelete, toast, confirm } from '../stores/app.js'
  import { subscribe, unsubscribe, fleetStore, wsConnected } from '../stores/websocket.js'
  import Modal from '../components/Modal.svelte'
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
  let showInstall = $state(false) // install-command modal
  let copied = $state(false)      // gate the modal's close until the command is copied
  let pendingTokens = $state([])  // outstanding enrollment tokens (waiting for an agent)
  let nowTick = $state(Date.now()) // 1s tick to drive the expiry countdowns

  async function loadTokens() {
    try { pendingTokens = (await apiGet('/api/fleet/tokens')) || [] } catch { pendingTokens = [] }
  }
  async function copyInstall() {
    if (!lastToken?.install_command) return
    try { await navigator.clipboard.writeText(lastToken.install_command); copied = true }
    catch { toast('Copy failed — select the text and copy manually', 'error') }
  }
  function closeInstall() {
    showInstall = false
    lastToken = null
    loadTokens() // the token is now outstanding → show its pending card
  }
  async function cancelToken(id) {
    try { await apiDelete('/api/fleet/tokens?id=' + id); pendingTokens = pendingTokens.filter((t) => t.id !== id) }
    catch (e) { toast('Failed to cancel: ' + e.message, 'error') }
  }
  // Compact "in 59m 30s" for a future ISO timestamp; '' once elapsed.
  function fmtCountdown(iso) {
    const ms = new Date(iso).getTime() - nowTick
    if (ms <= 0) return ''
    const s = Math.floor(ms / 1000), m = Math.floor(s / 60), h = Math.floor(m / 60)
    if (h > 0) return `${h}h ${m % 60}m`
    if (m > 0) return `${m}m ${s % 60}s`
    return `${s}s`
  }

  // Rate-limit refetches triggered by fleet check-in pushes so a busy fleet
  // can't hammer /api/fleet/machines — at most one refetch per ~8s, coalescing
  // simultaneous check-ins.
  let lastLoad = 0
  let refetchTimer = null
  function scheduleRefetch() {
    if (refetchTimer) return
    const wait = Math.max(500, 8000 - (Date.now() - lastLoad))
    refetchTimer = setTimeout(() => { refetchTimer = null; loadMachines() }, wait)
  }

  // Reconcile an open detail/CVE view + URL hash against the current list.
  function reconcileOpen() {
    if (cvesFor) cvesFor = machines.find((x) => x.id === cvesFor.id) || cvesFor
    else if (selected) selected = machines.find((x) => x.id === selected.id) || selected
    else restoreFromHash()
  }

  // Machines only — used by the periodic sweep (offline detection + summary) and
  // new-machine refetch. /api/fleet/endpoints is intentionally NOT fetched here;
  // it only changes on config save (saveConfig reloads it).
  async function loadMachines() {
    lastLoad = Date.now()
    try {
      machines = (await apiGet('/api/fleet/machines')) || []
      reconcileOpen()
      loadTokens()
      error = null
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }

  // Full load (machines + endpoints) — mount, config save, and WS-down fallback.
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
      reconcileOpen()
      loadTokens()
      error = null
    } catch (e) {
      error = e.message
    } finally {
      loading = false
    }
  }
  onMount(() => {
    load()
    const tick = setInterval(() => { nowTick = Date.now() }, 1000) // drive expiry countdowns
    subscribe('fleet') // each agent check-in pushes its report → refetch the list live

    // A check-in push already tells us the machine is alive, so update it in
    // place (mark it freshly seen → shows online) with NO HTTP request. Only a
    // machine we don't know yet (freshly enrolled) triggers a refetch. Skip the
    // immediate on-subscribe emission so we don't act on a stale message.
    let firstFleet = true
    const unsub = fleetStore.subscribe((msg) => {
      if (firstFleet) { firstFleet = false; return }
      if (!msg?.machine_id) return
      const idx = machines.findIndex((m) => m.id === msg.machine_id)
      if (idx === -1) {
        scheduleRefetch() // unknown machine — pull the list once (rate-limited)
        return
      }
      const now = new Date().toISOString()
      machines = machines.map((m, i) => (i === idx ? { ...m, last_seen: now } : m))
    })

    // Baseline sweep: machines that go offline stop pushing, so still poll — but
    // only every ~60s when the socket is up (pushes do the live work); fall back
    // to the old 15s cadence when the socket is down.
    const t = setInterval(() => {
      if (!get(wsConnected)) load()                             // WS down: full poll fallback
      else if (Date.now() - lastLoad > 60000) loadMachines()    // WS up: machines-only sweep
    }, 15000)

    const onHash = () => restoreFromHash()
    window.addEventListener('hashchange', onHash)
    return () => {
      clearInterval(t)
      clearInterval(tick)
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
      copied = false
      showInstall = true
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

  <!-- Listener + Add-machine, inline on desktop -->
  <div class="grid gap-4 {ep?.enabled ? 'lg:grid-cols-2' : ''} items-start">
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
    </div>
    {/if}
  </div>

  <!-- Install-command modal: no outside-click close; Close enabled only after Copy -->
  {#if showInstall && lastToken}
    <Modal open={showInstall} dismissible={false} showClose={copied} onclose={closeInstall} title="Install command" size="lg">
      <div class="space-y-3">
        <p class="text-sm text-muted-foreground">Run this on the new machine. One-time — expires in {fmtCountdown(lastToken.expires_at) || 'under a minute'}.</p>
        {#if lastToken.install_command}
          <pre class="bg-muted rounded-lg p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all border border-border">{lastToken.install_command}</pre>
          <div class="flex items-center gap-2">
            <Button icon={copied ? 'check' : 'copy'} variant="primary" onclick={copyInstall}>{copied ? 'Copied' : 'Copy command'}</Button>
            {#if !copied}<span class="text-[11px] text-muted-foreground">Copy the command to continue.</span>{/if}
          </div>
        {:else}
          <div class="text-sm text-warning">Pick an address in the Add-machine card so the install command can be built.</div>
        {/if}
      </div>
      {#snippet footer()}
        <Button variant="secondary" onclick={closeInstall} disabled={!copied}>Close</Button>
      {/snippet}
    </Modal>
  {/if}

  <!-- Pending enrollments: tokens waiting for an agent to redeem -->
  {#if pendingTokens.length}
    <div>
      <div class="text-xs uppercase tracking-wide text-muted-foreground font-semibold mb-2">Pending enrollments</div>
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        {#each pendingTokens as t (t.id)}
          {@const left = fmtCountdown(t.expires_at)}
          <div class="bg-card border border-dashed border-primary/40 rounded-xl p-4 flex flex-col gap-2">
            <div class="flex items-center gap-2.5">
              <Icon name="loader-2" size={16} class="animate-spin text-primary shrink-0" />
              <div class="min-w-0 flex-1">
                <div class="text-sm font-semibold text-foreground truncate">Waiting for agent…</div>
                <div class="text-[11px] text-muted-foreground truncate font-mono">{t.panel_host || t.label}</div>
              </div>
              <button onclick={() => cancelToken(t.id)} title="Cancel enrollment"
                class="h-7 w-7 grid place-items-center rounded-lg border border-border text-muted-foreground hover:bg-muted hover:text-destructive transition cursor-pointer shrink-0">
                <Icon name="x" size={14} />
              </button>
            </div>
            <div class="text-[11px] text-muted-foreground">
              {#if left}Run the install command on the box · expires in <span class="tabular-nums text-foreground">{left}</span>{:else}Expiring…{/if}
            </div>
          </div>
        {/each}
      </div>
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
