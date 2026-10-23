<script>
  /**
   * ClientsView — every client in one place: WireGuard peers, Tailscale nodes, agent machines and
   * LAN devices, grouped by type. One request (GET /api/clients) returns the merged, scope-filtered
   * list; the "clients" WS channel signals when something changed and the page refetches — no
   * polling. VPN clients open in the client modal, LAN devices in the device modal, machines on
   * their full detail page right here (#m=<id>, #cves=<id>). Networks are managed in Settings.
   */
  import { onMount, onDestroy, untrack } from 'svelte'
  import { apiGet, apiDelete, openView, currentUser, hasRole, hashParam, toast } from '../stores/app.js'
  import { loadState, saveState, copyWithToast } from '../stores/helpers.js'
  import { KINDS, isKind, clientsList, watchClients, reloadClients, clientsFilter } from '$lib/clients.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import Select from '../components/Select.svelte'
  import Segmented from '../components/Segmented.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import ClientCard from '../components/ClientCard.svelte'
  import ClientModal from '../components/ClientModal.svelte'
  import AddPeerModal from '../components/AddPeerModal.svelte'
  import CreateAuthKeyModal from '../components/CreateAuthKeyModal.svelte'
  import AddMachineModal from '../components/AddMachineModal.svelte'
  import MachineDetail from '../components/MachineDetail.svelte'
  import MachineCVEs from '../components/MachineCVEs.svelte'
  import LanDeviceModal from '../components/LanDeviceModal.svelte'
  import Checkbox from '../components/Checkbox.svelte'
  import { approveDevice, blockDevice, unblockDevice, setDeviceInternet } from '$lib/lan.js'
  import { toNode } from '$lib/nodes.js'
  import { timeAgo, formatBytes } from '$lib/utils/format.js'
  import { usageColor, fmtUptime } from '$lib/fleet.js'

  let { loading = $bindable(true) } = $props()

  // How each type is added: a modal here, except LAN devices — they join over DHCP on a network
  // (networks are set up in Settings → Networks).
  const ADD = {
    wireguard: { title: 'WireGuard peer', link: 'Add peer',
      desc: 'A phone or computer that connects with a WireGuard config or QR code.' },
    tailscale: { title: 'Tailscale node', link: 'Add node',
      desc: 'Create an auth key, then sign in on the device with the Tailscale app.' },
    machine: { title: 'Enroll a machine', link: 'Enroll machine',
      desc: 'Install the agent on a Linux server with one command.' },
    lan: { title: 'LAN device', link: 'Networks', view: 'settings', hash: 's=networks',
      desc: 'Plug it into a private network — it shows up here waiting for approval. Networks are set up in Settings.' },
  }
  let showAdd = $state(false)
  let showAddPeer = $state(false)
  let showAddKey = $state(false)
  let showAddMachine = $state(false)
  function startAdd(k) {
    showAdd = false
    if (k === 'wireguard') showAddPeer = true
    else if (k === 'tailscale') showAddKey = true
    else if (k === 'machine') showAddMachine = true
    else openView(ADD[k].view, ADD[k].hash)
  }

  const tint = (color, pct = 14) => `background: color-mix(in oklch, ${color} ${pct}%, transparent); color: ${color}`
  const SUBTITLE_ICON = { wireguard: 'user', tailscale: 'user', machine: 'device-desktop', lan: 'network' }

  const clients = $derived($clientsList.clients)
  const unavailable = $derived($clientsList.unavailable)
  // "now" for lease countdowns; ticks each minute so the time left stays current between refetches
  let now = $state(Date.now() / 1000)
  const tick = setInterval(() => (now = Date.now() / 1000), 60_000)

  // The list itself is shared and kept live (lib/clients.js); this refetches it now, after a change.
  const load = () => reloadClients().catch(() => {}) // a failure shows through the error effect below
  $effect(() => { if ($clientsList.loaded) loading = false })
  $effect(() => { if ($clientsList.error) untrack(() => toast('Could not load clients: ' + $clientsList.error, 'error')) })

  // VPN clients open in the client modal here; machines and LAN devices open on their own page.
  // The modal works on the full VPN records, loaded when a VPN client is opened (and after changes).
  let vpnClients = $state([])
  let routes = $state([])
  let selectedNode = $state(null)
  async function loadVpn() {
    const [v, r] = await Promise.allSettled([apiGet('/api/vpn/clients'), apiGet('/api/hs/routes')])
    vpnClients = v.status === 'fulfilled' ? v.value || [] : []
    routes = r.status === 'fulfilled' ? r.value?.routes || [] : []
  }
  function vpnChanged() {
    load()
    loadVpn()
  }

  // Machines open on their full detail page in place of the list. The hash holds which one
  // (#m=<id> or #cves=<id>), so refresh, links and the console's "close" land back on it.
  let machines = $state([]) // full fleet records, loaded when a machine's detail opens
  let latestAgent = $state(null)
  let detailMachine = $state(null)
  let cvesMachine = $state(null)
  // Arriving on a machine link (refresh, sidebar, Overview): show nothing until that machine is
  // resolved, so the list doesn't flash first. Clicking a card from the list keeps the list.
  let opening = $state(!!(hashParam('m') || hashParam('cves')))
  async function loadMachines() {
    const [m, e] = await Promise.allSettled([apiGet('/api/fleet/machines'), apiGet('/api/fleet/endpoints')])
    machines = m.status === 'fulfilled' ? m.value || [] : []
    latestAgent = e.status === 'fulfilled' ? e.value?.agent_version || null : null
  }
  async function showFromHash() {
    const mid = hashParam('m'), cid = hashParam('cves')
    try {
      if (!mid && !cid) { detailMachine = null; cvesMachine = null; return }
      await loadMachines()
      const m = machines.find((x) => x.id === (cid || mid)) || null
      if (!m) { toast('That machine is no longer available', 'error'); closeMachine(); return }
      cvesMachine = cid ? m : null
      detailMachine = cid ? null : m
    } finally {
      opening = false
    }
  }
  const openMachine = (id) => (window.location.hash = 'm=' + encodeURIComponent(id))
  const openCves = (m) => (window.location.hash = 'cves=' + encodeURIComponent(m.id))
  function closeMachine() {
    detailMachine = null
    cvesMachine = null
    if (window.location.hash) history.replaceState(history.state, '', window.location.pathname)
    load()
  }

  // Enrollment tokens waiting for an agent (admin-only on the server), shown as cards in Machines.
  let pendingTokens = $state([])
  async function loadTokens() {
    if (!isAdmin) return
    try { pendingTokens = (await apiGet('/api/fleet/tokens')) || [] } catch { pendingTokens = [] }
  }
  async function cancelToken(id) {
    try {
      await apiDelete('/api/fleet/tokens?id=' + id)
      pendingTokens = pendingTokens.filter((t) => t.id !== id)
    } catch (e) {
      toast('Failed to cancel: ' + e.message, 'error')
    }
  }
  // Loaded once; afterwards only while one is waiting, when the list changes (its agent enrolled).
  $effect(() => { if (isAdmin) untrack(loadTokens) })
  $effect(() => { $clientsList; untrack(() => { if (pendingTokens.length) loadTokens() }) })

  async function open(c, kind = c.kind) {
    if (kind === 'machine') return openMachine(c.open.machine)
    if (kind === 'lan') { lanNetwork = c.meta; lanDeviceId = c.open.lan; return }
    await loadVpn()
    selectedNode = vpnClients.map(toNode).find((n) => n.id === c.open.node) || null
    if (!selectedNode) toast(`${c.name} is no longer available`, 'error')
  }

  // LAN device actions on the card (admin-only on the server; the controls only show for admins).
  const isAdmin = $derived(hasRole($currentUser, 'admin'))
  let lanDeviceId = $state(null) // open in the device modal
  let lanNetwork = $state('')
  let busyKey = $state(null)
  async function lanAction(c, fn, done) {
    busyKey = c.key
    try {
      await fn(c.open.lan)
      toast(`${c.name} ${done}`, 'success')
      await load()
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      busyKey = null
    }
  }
  const approve = (c) => lanAction(c, approveDevice, 'approved')

  const saved = loadState('clients')
  let search = $state('')
  let status = $state(saved.status || 'all')
  let kind = $state(KINDS[saved.kind] ? saved.kind : '') // '' = all; ignores stale saved values
  $effect(() => saveState('clients', { status, kind }))

  const filtered = $derived(!!(search.trim() || kind || status !== 'all'))
  function clearFilters() {
    search = ''
    kind = ''
    status = 'all'
  }

  const online = $derived(clients.filter((c) => c.online).length)
  const counts = $derived(Object.fromEntries(Object.keys(KINDS).map((k) => [k, clients.filter((c) => isKind(c, k)).length])))
  const pending = $derived(clients.filter((c) => c.pending))
  const statusOptions = $derived([
    { value: 'all', label: 'All', count: clients.length },
    { value: 'online', label: 'Online', count: online },
    { value: 'offline', label: 'Offline', count: clients.length - online },
  ])
  const kindOptions = $derived([
    { value: '', label: `All types (${clients.length})` },
    ...Object.entries(KINDS).map(([k, meta]) => ({ value: k, label: `${meta.group} (${counts[k]})` })),
  ])
  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase()
    return clients.filter((c) =>
      (status === 'all' || (status === 'online') === c.online) &&
      (!kind || isKind(c, kind)) &&
      (!q || `${c.name} ${c.ip} ${c.meta || ''} ${KINDS[c.kind].label} ${(c.tags || []).join(' ')}`.toLowerCase().includes(q)))
  })
  // Waiting enrollments show in Machines unless the filters narrow the list.
  const waiting = $derived(
    !search.trim() && status === 'all' && (!kind || kind === 'machine')
      ? pendingTokens.filter((t) => new Date(t.expires_at).getTime() / 1000 > now)
      : [],
  )
  const groups = $derived(
    Object.entries(KINDS)
      .map(([k, meta]) => ({ k, meta, items: shown.filter((c) => c.kind === k) }))
      .filter((g) => g.items.length || (g.k === 'machine' && waiting.length)),
  )

  // Opened from elsewhere (sidebar, Overview) to show one kind — also from a machine's page here,
  // which then gives way to the list.
  $effect(() => {
    const k = $clientsFilter
    if (k === null) return
    untrack(() => {
      search = ''; status = 'all'; kind = KINDS[k] ? k : ''
      if (detailMachine || cvesMachine) {
        detailMachine = null
        cvesMachine = null
        history.replaceState(history.state, '', window.location.pathname)
      }
    })
    clientsFilter.set(null)
  })
  let release
  onMount(() => {
    release = watchClients() // fetches unless the list is already live (the sidebar watches it too)
    showFromHash()
    window.addEventListener('hashchange', showFromHash)
  })
  onDestroy(() => {
    release?.()
    clearInterval(tick)
    window.removeEventListener('hashchange', showFromHash)
  })
</script>

{#if cvesMachine}
  <MachineCVEs machine={cvesMachine} onback={() => openMachine(cvesMachine.id)} />
{:else if detailMachine}
  <MachineDetail machine={detailMachine} {latestAgent} onback={closeMachine} ondeleted={closeMachine} onviewcves={openCves} />
{:else if !opening}
<div class="space-y-4">
  <InfoCard icon="devices" title="All clients"
    description="WireGuard peers, Tailscale nodes, agent machines and LAN devices in one place. Open a client to manage it." />

  <!-- Summary: one surface, hairline dividers -->
  <section aria-label="Summary" class="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-border bg-border sm:grid-cols-3 lg:grid-cols-5">
    <div class="col-span-2 flex items-center gap-3 bg-card px-4 py-3 sm:col-span-1">
      <span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-success/10 text-success"><Icon name="circle-check" size={16} /></span>
      <div class="min-w-0 flex-1">
        <div class="text-xl font-bold leading-none tabular-nums text-foreground">{online}<span class="text-sm font-medium text-muted-foreground"> / {clients.length}</span></div>
        <div class="mt-1.5 h-1.5 overflow-hidden rounded-full bg-muted" title="{online} of {clients.length} online">
          <div class="h-full rounded-full bg-success transition-[width]" style="width: {clients.length ? (online / clients.length) * 100 : 0}%"></div>
        </div>
        <div class="mt-1 text-[11px] text-muted-foreground">online</div>
      </div>
    </div>
    {#each Object.entries(KINDS) as [k, meta] (k)}
      <div class="flex items-center gap-3 bg-card px-4 py-3">
        <span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg" style={tint(meta.color)}><Icon name={meta.icon} size={16} /></span>
        <div>
          <div class="text-xl font-bold leading-none tabular-nums text-foreground">{counts[k]}</div>
          <div class="mt-1 text-[11px] text-muted-foreground">{meta.group}</div>
        </div>
      </div>
    {/each}
  </section>

  {#if pending.length}
    <div role="status" class="flex items-center gap-2.5 rounded-lg border border-warning/30 bg-warning/10 px-3 py-2 text-sm text-foreground">
      <Icon name="alert-circle" size={16} class="shrink-0 text-warning" />
      <span class="min-w-0 flex-1 truncate">
        {#if pending.length === 1}
          <strong>{pending[0].name}</strong> is waiting for approval to join {pending[0].meta}.
        {:else}
          <strong>{pending.length} devices</strong> are waiting for approval to join your networks.
        {/if}
      </span>
      {#if isAdmin && pending.length === 1}
        <Button variant="primary" icon="check" loading={busyKey === pending[0].key} onclick={() => approve(pending[0])}>Approve</Button>
      {/if}
    </div>
  {/if}

  <Toolbar bind:search size="sm" placeholder="Search name, IP, user, OS, network or tag…">
    <div class="flex w-full min-w-0 flex-wrap items-center gap-2 md:w-auto">
      <!-- status: toggle group on desktop, dropdown on mobile; type: always a dropdown -->
      <div class="flex w-full gap-2 md:w-auto">
        <div class="hidden md:block"><Segmented size="sm" label="Status" bind:value={status} options={statusOptions} /></div>
        <Select bind:value={status} size="sm" aria-label="Status" class="min-w-0 flex-1 md:hidden"
          options={statusOptions.map((o) => ({ value: o.value, label: `${o.value === 'all' ? 'Any status' : o.label} (${o.count})` }))} />
        <Select bind:value={kind} size="sm" aria-label="Client type" class="min-w-0 flex-1 md:w-44 md:flex-none"
          options={kindOptions} />
        {#if isAdmin}
          <Button icon="plus" onclick={() => (showAdd = true)} class="shrink-0" tooltip="Add client"><span class="hidden sm:inline">Add client</span></Button>
        {/if}
      </div>
    </div>
  </Toolbar>

  {#if unavailable.length}
    <div class="flex items-center gap-2 text-xs text-muted-foreground">
      <Icon name="info-circle" size={14} /> Not shown (no access or service off): {unavailable.join(', ')}
    </div>
  {/if}

  {#each groups as g (g.k)}
    {@const on = g.items.filter((c) => c.online).length}
    <section class="space-y-2" aria-label={g.meta.group}>
      <div class="flex items-center gap-3">
        <h2 class="flex min-w-0 flex-1 items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground after:h-px after:flex-1 after:bg-border">
          <span class="h-2 w-2 rounded-sm" style="background: {g.meta.color}"></span>
          {g.meta.group}
          <span class="font-normal normal-case tracking-normal">{on}/{g.items.length} online</span>
        </h2>
        {#if isAdmin}
          <button type="button" onclick={() => startAdd(g.k)}
            class="link-action">
            <Icon name="plus" size={12} />{ADD[g.k].link}
          </button>
        {/if}
      </div>
      <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {#if g.k === 'machine'}
          {#each waiting as t (t.id)}
            {@const end = new Date(t.expires_at).getTime() / 1000}
            {@const span = end - new Date(t.created_at).getTime() / 1000}
            <!-- An enrollment token not redeemed yet: dashed, quiet, until the agent reports in -->
            <div class="flex flex-col divide-y divide-dashed divide-destructive/20 rounded-lg border border-dashed border-destructive/40 bg-card">
              <div class="flex items-center gap-3 p-3">
                <span class="grid h-9 w-9 shrink-0 place-items-center rounded-lg" style={tint(KINDS.machine.color)}>
                  <Icon name="loader-2" size={16} class="animate-spin" />
                </span>
                <div class="min-w-0 flex-1">
                  <div class="truncate text-sm font-semibold text-foreground">Waiting for agent…</div>
                  <div class="truncate font-mono text-[11px] text-muted-foreground">{t.panel_host || t.label}</div>
                </div>
                <button type="button" onclick={() => cancelToken(t.id)} aria-label="Cancel enrollment" data-kt-tooltip
                  class="grid h-7 w-7 shrink-0 cursor-pointer place-items-center rounded-lg border border-border text-muted-foreground transition hover:border-destructive/40 hover:bg-destructive/10 hover:text-destructive">
                  <Icon name="x" size={14} />
                  <span data-kt-tooltip-content class="kt-tooltip hidden">Cancel enrollment</span>
                </button>
              </div>
              <p class="flex flex-1 items-center gap-2 p-3 text-[11px] leading-relaxed text-muted-foreground">
                <Icon name="terminal-2" size={13} class="shrink-0" />
                Run the install command on the machine. It shows up here as soon as its agent reports in.
              </p>
              <div class="p-3">
                <div class="mb-1 flex items-center justify-between text-[11px] text-muted-foreground">
                  <span>Install command expires in</span>
                  <span class="tabular-nums text-foreground">{fmtUptime(Math.max(0, end - now))}</span>
                </div>
                <div class="h-1 overflow-hidden rounded-full bg-muted">
                  <div class="h-full rounded-full bg-destructive/60" style="width: {span > 0 ? Math.min(100, Math.max(0, ((end - now) / span) * 100)) : 0}%"></div>
                </div>
              </div>
            </div>
          {/each}
        {/if}
        {#each g.items as c (c.key)}
          <ClientCard
            name={c.name}
            icon={g.meta.icon}
            color={g.meta.color}
            online={c.online}
            subtitle={c.meta}
            subtitleIcon={SUBTITLE_ICON[c.kind]}
            flags={c.flags || []}
            tags={c.gone ? null : (c.tags || []).map((t) => t.replace(/^tag:/, ''))}
            emptyTags="No tags"
            highlight={c.pending}
            gone={c.gone}
            onopen={() => open(c)}
            openTitle={'Open in ' + KINDS[c.kind].label}
            info={c.gone ? [
              { icon: 'certificate', text: 'Certificate revoked' },
              { icon: 'clock', text: timeAgo(c.last_seen) },
            ] : [
              { icon: 'network', text: c.ip || '—', mono: true },
              { icon: 'clock', text: c.online ? 'Active now' : timeAgo(c.last_seen) },
            ]}
            stats={clientStats}
            footer={c.machine || (c.kind === 'lan' && isAdmin) ? cardFooter : undefined}
          />
          <!-- the type is in the group heading; this line shows what matters for that type -->
          {#snippet clientStats()}
            {#if c.tx != null}
              {@const total = c.tx + c.rx}
              <div class="text-[11px]">
                <div class="flex items-center justify-between gap-2 tabular-nums">
                  <span class="flex items-center gap-1 text-muted-foreground"><Icon name="arrow-up" size={12} class="text-primary" />Sent <b class="font-semibold text-foreground">{formatBytes(c.tx)}</b></span>
                  <span class="flex items-center gap-1 text-muted-foreground"><b class="font-semibold text-foreground">{formatBytes(c.rx)}</b> received<Icon name="arrow-down" size={12} class="text-muted-foreground" /></span>
                </div>
                <div class="mt-1.5 flex h-1 gap-px overflow-hidden rounded-full bg-muted" title="{total ? Math.round((c.tx / total) * 100) : 0}% sent">
                  {#if total}
                    <span class="h-full bg-primary" style="width: {(c.tx / total) * 100}%"></span>
                    <span class="h-full flex-1 bg-muted-foreground/40"></span>
                  {/if}
                </div>
              </div>
            {:else if c.cpu != null}
              <div class="grid grid-cols-3 gap-3 text-[11px]">
                {#each [['CPU', c.cpu], ['RAM', c.mem], ['Disk', c.disk]] as [label, pct] (label)}
                  <div>
                    <div class="flex items-center justify-between tabular-nums">
                      <span class="text-muted-foreground">{label}</span><b class="font-semibold text-foreground">{Math.round(pct)}%</b>
                    </div>
                    <div class="mt-1 h-1 overflow-hidden rounded-full bg-muted">
                      <div class="h-full rounded-full {usageColor(pct)}" style="width: {Math.min(pct, 100)}%"></div>
                    </div>
                  </div>
                {/each}
              </div>
            {:else if c.mac}
              {@const left = c.lease_expires ? Math.max(0, c.lease_expires - now) : 0}
              <div class="grid grid-cols-[auto_minmax(0,1fr)] gap-4 text-[11px]">
                <div class="min-w-0">
                  <div class="text-muted-foreground">MAC</div>
                  <button type="button" onclick={() => copyWithToast(c.mac, toast)} title="Copy MAC address"
                    class="relative z-10 mt-0.5 inline-flex max-w-full items-center gap-1 font-mono font-semibold text-foreground cursor-pointer hover:text-primary">
                    <span class="truncate">{c.mac}</span><Icon name="copy" size={11} class="shrink-0 text-dim" />
                  </button>
                </div>
                <div class="min-w-0 text-right">
                  <div class="flex items-center justify-between gap-2 whitespace-nowrap tabular-nums"
                    title={left ? `Address lease expires in ${fmtUptime(left)}` : undefined}>
                    <span class="text-muted-foreground">Lease</span>
                    <b class="font-semibold text-foreground">{left ? fmtUptime(left) : c.online ? 'Static' : 'Expired'}</b>
                  </div>
                  <div class="mt-1 h-1 overflow-hidden rounded-full bg-muted">
                    {#if left && c.lease_secs}
                      <div class="h-full rounded-full bg-[var(--client-lan)]" style="width: {Math.min(100, (left / c.lease_secs) * 100)}%"></div>
                    {/if}
                  </div>
                </div>
              </div>
            {:else if c.gone}
              <div class="text-[11px] text-muted-foreground">Agent removed and its data deleted. Open to remove it from the panel.</div>
            {:else}
              <div class="text-[11px] text-muted-foreground">No usage reported yet</div>
            {/if}
          {/snippet}
          {#snippet cardFooter()}
            {#if c.machine}
              <button type="button" onclick={() => open(c, 'machine')} title="Open the machine page"
                class="relative z-10 ml-auto inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium cursor-pointer hover:underline" style={tint(KINDS.machine.color)}>
                <Icon name="device-desktop" size={11} /> Machine
              </button>
            {/if}
            {#if c.kind === 'lan' && isAdmin}
              <div class="relative z-10 ml-auto flex items-center gap-1.5">
                {#if c.blocked}
                  <Button variant="outline" size="xs" icon="lock-open" loading={busyKey === c.key} onclick={() => lanAction(c, unblockDevice, 'unblocked')}>Unblock</Button>
                {:else if c.pending}
                  <Button variant="ghost-danger" size="xs" icon="ban" disabled={busyKey === c.key} onclick={() => lanAction(c, blockDevice, 'blocked')}>Block</Button>
                  <Button variant="primary" size="xs" icon="check" loading={busyKey === c.key} onclick={() => approve(c)}>Approve</Button>
                {:else}
                  <span class="text-[11px] text-muted-foreground">Internet</span>
                  <Checkbox variant="switch" aria-label="Internet access for {c.name}" checked={c.internet} disabled={busyKey === c.key}
                    onchange={() => lanAction(c, (id) => setDeviceInternet(id, !c.internet), c.internet ? 'internet off' : 'internet on')} />
                {/if}
              </div>
            {/if}
          {/snippet}
        {/each}
      </div>
    </section>
  {:else}
    {#if !loading}
      {#if filtered}
        <EmptyState icon="filter" title="No clients match"
          description="No {status !== 'all' ? status + ' ' : ''}{kind ? KINDS[kind].group.replace('Machines', 'machines') : 'clients'}{search.trim() ? ` match “${search.trim()}”` : ''}." large>
          <Button variant="outline" icon="x" onclick={clearFilters}>Clear filters</Button>
        </EmptyState>
      {:else}
        <EmptyState icon="devices" title="No clients yet"
          description="Clients show up here once you add VPN peers, enroll a machine or create a private network." large>
          <!-- adding is admin-only on the server; viewers/operators just get the description -->
          {#if isAdmin}
            <Button icon="plus" onclick={() => (showAdd = true)}>Add a client</Button>
          {/if}
        </EmptyState>
      {/if}
    {/if}
  {/each}
</div>

{/if}

<Modal bind:open={showAdd} title="Add a client" size="sm">
  <div class="space-y-2">
    {#each Object.entries(ADD) as [k, a] (k)}
      <button type="button" onclick={() => startAdd(k)}
        class="flex w-full items-center gap-3 rounded-lg border border-border p-3 text-left transition hover:border-primary/50 hover:bg-muted/40 cursor-pointer">
        <span class="grid h-9 w-9 shrink-0 place-items-center rounded-lg" style={tint(KINDS[k].color)}><Icon name={KINDS[k].icon} size={18} /></span>
        <span class="min-w-0 flex-1">
          <span class="block text-sm font-medium text-foreground">{a.title}</span>
          <span class="block text-[11px] text-muted-foreground">{a.desc}</span>
        </span>
        <Icon name="chevron-right" size={16} class="shrink-0 text-muted-foreground" />
      </button>
    {/each}
  </div>
</Modal>

<ClientModal bind:node={selectedNode} {vpnClients} {routes} onchanged={vpnChanged} />
<AddPeerModal bind:open={showAddPeer} oncreated={vpnChanged} />
<CreateAuthKeyModal bind:open={showAddKey} />
<AddMachineModal bind:open={showAddMachine} oncreated={loadTokens} />
<LanDeviceModal bind:deviceId={lanDeviceId} network={lanNetwork} onchanged={load} />
