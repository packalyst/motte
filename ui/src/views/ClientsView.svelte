<script>
  /**
   * ClientsView — every client in one place: WireGuard peers, Tailscale nodes, agent machines and
   * LAN devices, grouped by type. One request (GET /api/clients) returns the merged, scope-filtered
   * list; the "clients" WS channel signals when something changed and the page refetches — no
   * polling. Cards open the client on its own page (Nodes / Machines / Networks), which still owns
   * every action except approving a waiting LAN device.
   */
  import { onMount, onDestroy } from 'svelte'
  import { get } from 'svelte/store'
  import { apiGet, apiPost, openView, currentUser, toast } from '../stores/app.js'
  import { loadState, saveState } from '../stores/helpers.js'
  import { subscribe, unsubscribe, clientsStore } from '../stores/websocket.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import Segmented from '../components/Segmented.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import ClientCard from '../components/ClientCard.svelte'
  import { timeAgo, formatBytes } from '$lib/utils/format.js'

  let { loading = $bindable(true) } = $props()

  const KINDS = {
    wireguard: { label: 'WireGuard', group: 'WireGuard peers', icon: 'shield', color: 'var(--client-wg)' },
    tailscale: { label: 'Tailscale', group: 'Tailscale nodes', icon: 'cloud', color: 'var(--client-ts)' },
    machine: { label: 'Machine', group: 'Machines', icon: 'device-desktop', color: 'var(--client-mc)' },
    lan: { label: 'LAN device', group: 'LAN devices', icon: 'router', color: 'var(--client-lan)' },
  }
  const tint = (color, pct = 14) => `background: color-mix(in oklch, ${color} ${pct}%, transparent); color: ${color}`
  const SUBTITLE_ICON = { wireguard: 'user', tailscale: 'user', machine: 'device-desktop', lan: 'network' }

  let clients = $state([])
  let unavailable = $state([])

  async function load() {
    try {
      const res = await apiGet('/api/clients')
      clients = res.clients || []
      unavailable = res.unavailable || []
    } catch (e) {
      toast('Could not load clients: ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  // Open a client on its own page; a VPN client that is also a machine can open either.
  function open(c, kind = c.kind) {
    if (kind === 'machine') openView('fleet', 'm=' + encodeURIComponent(c.open.machine))
    else if (kind === 'lan') openView('networks', 'net=' + c.open.network)
    else openView('nodes', 'n=' + encodeURIComponent(c.open.node))
  }

  // Approving a LAN device is admin-only on the server; the button only shows for admins.
  const isAdmin = $derived(['admin', 'owner'].includes($currentUser?.role))
  let approving = $state(null)
  async function approve(c) {
    approving = c.key
    try {
      await apiPost(`/api/dhcp/clients/${c.open.lan}/approve`)
      toast(`${c.name} approved`, 'success')
      await load()
    } catch (e) {
      toast('Could not approve: ' + e.message, 'error')
    } finally {
      approving = null
    }
  }

  const isKind = (c, k) => c.kind === k || (k === 'machine' && c.machine)
  const saved = loadState('clients')
  let search = $state('')
  let status = $state(saved.status || 'all')
  let kind = $state(KINDS[saved.kind] ? saved.kind : null) // ignore stale values from older versions
  $effect(() => saveState('clients', { status, kind }))

  const online = $derived(clients.filter((c) => c.online).length)
  const counts = $derived(Object.fromEntries(Object.keys(KINDS).map((k) => [k, clients.filter((c) => isKind(c, k)).length])))
  const pending = $derived(clients.filter((c) => c.pending))
  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase()
    return clients.filter((c) =>
      (status === 'all' || (status === 'online') === c.online) &&
      (!kind || isKind(c, kind)) &&
      (!q || `${c.name} ${c.ip} ${c.meta || ''} ${KINDS[c.kind].label}`.toLowerCase().includes(q)))
  })
  const groups = $derived(
    Object.entries(KINDS)
      .map(([k, meta]) => ({ k, meta, items: shown.filter((c) => c.kind === k) }))
      .filter((g) => g.items.length),
  )

  // Live: the server signals changes on the clients channel; refetch on each signal.
  let seen = get(clientsStore)
  $effect(() => {
    const n = $clientsStore
    if (n > seen) { seen = n; load() }
  })
  onMount(() => { load(); subscribe('clients') })
  onDestroy(() => unsubscribe('clients'))
</script>

<div class="space-y-4">
  <InfoCard icon="devices" title="All clients"
    description="WireGuard peers, Tailscale nodes, agent machines and LAN devices in one place. Open a client to manage it on its own page." />

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
        <Button variant="primary" icon="check" loading={approving === pending[0].key} onclick={() => approve(pending[0])}>Approve</Button>
      {/if}
    </div>
  {/if}

  <Toolbar bind:search placeholder="Search name, IP, user, OS or network…">
    <div class="flex min-w-0 flex-wrap items-center gap-2">
      <Segmented label="Status" bind:value={status} options={[
        { value: 'all', label: 'All', count: clients.length },
        { value: 'online', label: 'Online', count: online },
        { value: 'offline', label: 'Offline', count: clients.length - online },
      ]} />
      {#each Object.entries(KINDS) as [k, meta] (k)}
        <button type="button" aria-pressed={kind === k} onclick={() => (kind = kind === k ? null : k)}
          class="kt-badge kt-badge-outline cursor-pointer {kind === k ? 'kt-badge-primary' : 'kt-badge-secondary'}">
          <span class="h-2 w-2 rounded-sm" style="background: {meta.color}"></span>
          {meta.label}
          <span class="kt-badge kt-badge-xs {kind === k ? 'kt-badge-primary' : 'kt-badge-secondary'}">{counts[k]}</span>
        </button>
      {/each}
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
      <h2 class="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground after:h-px after:flex-1 after:bg-border">
        <span class="h-2 w-2 rounded-sm" style="background: {g.meta.color}"></span>
        {g.meta.group}
        <span class="font-normal normal-case tracking-normal">{on}/{g.items.length} online</span>
      </h2>
      <div class="grid-cards">
        {#each g.items as c (c.key)}
          <ClientCard
            name={c.name}
            icon={g.meta.icon}
            color={g.meta.color}
            online={c.online}
            subtitle={c.meta}
            subtitleIcon={SUBTITLE_ICON[c.kind]}
            flags={c.flags || []}
            highlight={c.pending}
            onopen={() => open(c)}
            openTitle={'Open in ' + KINDS[c.kind].label}
            info={[
              { icon: 'network', text: c.ip || '—', mono: true },
              { icon: g.meta.icon, text: KINDS[c.kind].label },
              { icon: 'clock', text: c.online ? 'Active now' : timeAgo(c.last_seen) },
              c.tx != null && { icon: 'arrows-vertical', text: `↑ ${formatBytes(c.tx)}  ↓ ${formatBytes(c.rx)}` },
            ].filter(Boolean)}
            footer={c.machine || (c.pending && isAdmin) ? cardFooter : undefined}
          />
          {#snippet cardFooter()}
            {#if c.machine}
              <button type="button" onclick={() => open(c, 'machine')} title="Open the machine page"
                class="relative z-10 inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium cursor-pointer hover:underline" style={tint(KINDS.machine.color)}>
                <Icon name="device-desktop" size={11} /> Machine
              </button>
            {/if}
            {#if c.pending && isAdmin}
              <Button class="relative z-10 ml-auto" variant="primary" size="xs" icon="check" loading={approving === c.key} onclick={() => approve(c)}>Approve</Button>
            {/if}
          {/snippet}
        {/each}
      </div>
    </section>
  {:else}
    {#if !loading}
      <EmptyState icon="devices" title="No clients found"
        description={search || kind || status !== 'all' ? 'No clients match these filters.' : 'Add WireGuard peers or Tailscale nodes, enroll machines, or create a private network.'} large />
    {/if}
  {/each}
</div>
