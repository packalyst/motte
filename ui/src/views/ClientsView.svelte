<script>
  /**
   * ClientsView — every client in one list: WireGuard peers and Tailscale (Headscale) nodes, fleet
   * machines running the agent, and devices on the panel's private networks. Read-only overview; a
   * row opens the item on its own page (Nodes / Machines / Networks), which still own all actions.
   * A machine that reports over the VPN (its report's source address is a VPN client's IP) is shown
   * once, as that client, with a Machine chip.
   */
  import { onMount, onDestroy } from 'svelte'
  import { apiGet, openView } from '../stores/app.js'
  import { loadState, saveState } from '../stores/helpers.js'
  import { subscribe, unsubscribe, nodesUpdatedStore, fleetStore } from '../stores/websocket.js'
  import Icon from '../components/Icon.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import StatCard from '../components/StatCard.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import { timeAgo, formatBytes } from '$lib/utils/format.js'
  import { statusInfo } from '$lib/fleet.js'

  let { loading = $bindable(true) } = $props()

  // Each kind: label, icon, badge colour, and where its row opens.
  const KINDS = {
    wireguard: { label: 'WireGuard', icon: 'shield', badge: 'kt-badge-success', open: (r) => openView('nodes', 'n=' + encodeURIComponent(r.nodeId)) },
    tailscale: { label: 'Tailscale', icon: 'cloud', badge: 'kt-badge-info', open: (r) => openView('nodes', 'n=' + encodeURIComponent(r.nodeId)) },
    machine: { label: 'Machine', icon: 'device-desktop', badge: 'kt-badge-primary', open: (r) => openView('fleet', 'm=' + encodeURIComponent(r.machineId)) },
    lan: { label: 'LAN device', icon: 'router', badge: 'kt-badge-warning', open: (r) => openView('networks', 'net=' + r.networkId) },
  }

  let vpn = $state([])
  let machines = $state([])
  let lan = $state([]) // DHCP clients, each with its network attached
  let unavailable = $state([]) // sources that failed to load (no access / service off)

  async function load() {
    const [v, m, n] = await Promise.allSettled([
      apiGet('/api/vpn/clients'),
      apiGet('/api/fleet/machines'),
      apiGet('/api/dhcp/networks'),
    ])
    const missing = []
    if (v.status === 'fulfilled') vpn = Array.isArray(v.value) ? v.value : v.value?.clients || []
    else missing.push('VPN clients')
    if (m.status === 'fulfilled') machines = m.value || []
    else missing.push('Machines')
    if (n.status === 'fulfilled') {
      const nets = n.value?.networks || []
      const per = await Promise.allSettled(nets.map((net) => apiGet(`/api/dhcp/networks/${net.id}/clients`)))
      lan = per.flatMap((r, i) => (r.status === 'fulfilled' ? (r.value?.clients || []).map((c) => ({ ...c, net: nets[i] })) : []))
    } else missing.push('Networks')
    unavailable = missing
    loading = false
  }

  // One normalized row per real device.
  const rows = $derived.by(() => {
    const byIP = new Map(machines.filter((m) => m.last_ip).map((m) => [m.last_ip, m]))
    const merged = new Set()
    const out = []
    for (const c of vpn) {
      const raw = c.rawData || {}
      const kind = c.type === 'wireguard' ? 'wireguard' : 'tailscale'
      const m = byIP.get(c.ip)
      if (m) merged.add(m.id)
      const expired = kind === 'tailscale' && raw.expiry && !raw.expiry.startsWith('0001') && new Date(raw.expiry) < new Date()
      out.push({
        key: 'v' + c.id, kind, kinds: m ? [kind, 'machine'] : [kind],
        nodeId: kind === 'wireguard' ? 'wg-' + c.externalId : c.externalId,
        machineId: m?.id,
        name: kind === 'tailscale' ? raw.givenName || raw.name || c.name : c.name,
        ip: c.ip,
        online: !!raw.online,
        lastSeen: raw.lastHandshake || raw.lastSeen,
        where: kind === 'tailscale' ? raw.user?.name || '' : m?.summary?.os || '',
        tx: c.totalTx || 0, rx: c.totalRx || 0,
        flags: [
          expired && { label: 'Key expired', tone: 'destructive' },
          kind === 'wireguard' && raw.enabled === false && { label: 'Disabled', tone: 'warning' },
          c.blockInternet && { label: 'No internet', tone: 'destructive' },
          m?.summary?.cve_critical > 0 && { label: `${m.summary.cve_critical} critical CVE`, tone: 'destructive' },
        ].filter(Boolean),
      })
    }
    for (const m of machines) {
      if (merged.has(m.id) || m.status === 'uninstalled') continue
      const st = statusInfo(m)
      out.push({
        key: 'm' + m.id, kind: 'machine', kinds: ['machine'], machineId: m.id,
        name: m.name || m.id, ip: m.last_ip || '', online: st.online, lastSeen: m.last_seen,
        where: m.summary?.os || '', tx: null, rx: null,
        flags: [
          m.revoked && { label: 'Revoked', tone: 'destructive' },
          m.summary?.cve_critical > 0 && { label: `${m.summary.cve_critical} critical CVE`, tone: 'destructive' },
        ].filter(Boolean),
      })
    }
    for (const d of lan) {
      out.push({
        key: 'd' + d.id, kind: 'lan', kinds: ['lan'], networkId: d.network_id,
        name: d.name || d.mac, ip: d.ip, online: !!d.online, lastSeen: d.last_seen,
        where: `${d.net.iface} · ${d.net.cidr}`, tx: null, rx: null,
        flags: [!d.approved && { label: 'Not approved', tone: 'warning' }].filter(Boolean),
      })
    }
    return out.sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name))
  })

  const saved = loadState('clients')
  let search = $state('')
  let kindFilter = $state(saved.kind || 'all')
  let statusFilter = $state(saved.status || 'all')
  $effect(() => saveState('clients', { kind: kindFilter, status: statusFilter }))

  const counts = $derived(Object.fromEntries(Object.keys(KINDS).map((k) => [k, rows.filter((r) => r.kinds.includes(k)).length])))
  const online = $derived(rows.filter((r) => r.online).length)
  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase()
    return rows.filter((r) =>
      (kindFilter === 'all' || r.kinds.includes(kindFilter)) &&
      (statusFilter === 'all' || (statusFilter === 'online') === r.online) &&
      (!q || `${r.name} ${r.ip} ${r.where}`.toLowerCase().includes(q)))
  })

  // Live: VPN changes and agent check-ins refresh the list (debounced — check-ins can burst).
  let timer
  function soon() { clearTimeout(timer); timer = setTimeout(load, 1500) }
  let seenNodes = 0
  $effect(() => { const n = $nodesUpdatedStore; if (n > seenNodes) { if (seenNodes) soon(); seenNodes = n } })
  $effect(() => { if ($fleetStore) soon() })

  onMount(() => { load(); subscribe(['nodes_updated', 'fleet']) })
  onDestroy(() => { clearTimeout(timer); unsubscribe(['nodes_updated', 'fleet']) })

  const toneClass = { destructive: 'bg-destructive/10 text-destructive', warning: 'bg-warning/10 text-warning' }
</script>

<div class="space-y-4">
  <InfoCard icon="devices" title="All Clients"
    description="Every device in one place — WireGuard peers, Tailscale nodes, machines running the agent and devices on your private networks. Open one to manage it on its own page." />

  <div class="grid grid-cols-2 gap-3 lg:grid-cols-5">
    <StatCard icon="devices" value={rows.length} label="Clients" />
    <StatCard icon="circle-check" color="success" value={online} label="Online" />
    <StatCard icon="shield" color="info" value={counts.wireguard + counts.tailscale} label="VPN" />
    <StatCard icon="device-desktop" value={counts.machine} label="Machines" />
    <StatCard icon="router" color="warning" value={counts.lan} label="LAN devices" />
  </div>

  <Toolbar bind:search placeholder="Search by name, IP, user, OS or network...">
    <div class="flex flex-wrap items-center gap-2">
      <button type="button" onclick={() => { kindFilter = 'all'; statusFilter = 'all' }}
        class="kt-badge kt-badge-outline {kindFilter === 'all' && statusFilter === 'all' ? 'kt-badge-primary' : 'kt-badge-secondary'} cursor-pointer">
        All <span class="kt-badge kt-badge-xs kt-badge-primary">{rows.length}</span>
      </button>
      <button type="button" onclick={() => (statusFilter = statusFilter === 'online' ? 'all' : 'online')}
        class="kt-badge kt-badge-outline {statusFilter === 'online' ? 'kt-badge-success' : 'kt-badge-secondary'} cursor-pointer">Online</button>
      <button type="button" onclick={() => (statusFilter = statusFilter === 'offline' ? 'all' : 'offline')}
        class="kt-badge kt-badge-outline {statusFilter === 'offline' ? 'kt-badge-warning' : 'kt-badge-secondary'} cursor-pointer">Offline</button>
      <span class="mx-1 hidden h-4 w-px bg-border sm:block"></span>
      {#each Object.entries(KINDS) as [k, meta] (k)}
        <button type="button" onclick={() => (kindFilter = kindFilter === k ? 'all' : k)}
          class="kt-badge kt-badge-outline {kindFilter === k ? meta.badge : 'kt-badge-secondary'} cursor-pointer">
          <Icon name={meta.icon} size={14} /> {meta.label}
          <span class="kt-badge kt-badge-xs {meta.badge}">{counts[k]}</span>
        </button>
      {/each}
    </div>
  </Toolbar>

  {#if unavailable.length}
    <div class="flex items-center gap-2 text-xs text-muted-foreground">
      <Icon name="info-circle" size={14} /> Not shown (no access or service off): {unavailable.join(', ')}
    </div>
  {/if}

  {#if shown.length}
    <div class="overflow-hidden rounded-lg border border-border bg-card">
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead class="bg-muted/50 text-left text-xs uppercase tracking-wider text-muted-foreground">
            <tr>
              <th class="px-4 py-3 font-medium">Client</th>
              <th class="px-4 py-3 font-medium">Type</th>
              <th class="px-4 py-3 font-medium">IP</th>
              <th class="hidden px-4 py-3 font-medium md:table-cell">User / OS / Network</th>
              <th class="hidden px-4 py-3 font-medium sm:table-cell">Last seen</th>
              <th class="hidden px-4 py-3 text-right font-medium lg:table-cell">Traffic ↑ / ↓</th>
            </tr>
          </thead>
          <tbody>
            {#each shown as r (r.key)}
              <tr class="cursor-pointer border-t border-border hover:bg-accent/50" tabindex="0"
                onclick={() => KINDS[r.kind].open(r)} onkeydown={(e) => e.key === 'Enter' && KINDS[r.kind].open(r)}>
                <td class="px-4 py-2.5">
                  <div class="flex items-center gap-2.5">
                    <div class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg {r.online ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
                      <Icon name={KINDS[r.kind].icon} size={16} />
                    </div>
                    <div class="min-w-0">
                      <div class="flex items-center gap-1.5">
                        <span class="status-dot {r.online ? 'status-dot-success' : 'status-dot-muted'}" title={r.online ? 'Online' : 'Offline'}></span>
                        <span class="truncate font-medium text-foreground">{r.name}</span>
                      </div>
                      {#if r.flags.length}
                        <div class="mt-0.5 flex flex-wrap gap-1">
                          {#each r.flags as f (f.label)}
                            <span class="rounded px-1.5 py-0.5 text-[10px] font-medium {toneClass[f.tone]}">{f.label}</span>
                          {/each}
                        </div>
                      {/if}
                    </div>
                  </div>
                </td>
                <td class="px-4 py-2.5">
                  <div class="flex flex-wrap gap-1">
                    {#each r.kinds as k (k)}
                      <!-- Each chip opens its own page (a merged machine row has VPN + Machine). -->
                      <button type="button" title={'Open in ' + KINDS[k].label}
                        onclick={(e) => { e.stopPropagation(); KINDS[k].open(r) }}
                        class="kt-badge kt-badge-xs kt-badge-outline {KINDS[k].badge} cursor-pointer">
                        <Icon name={KINDS[k].icon} size={11} /> {KINDS[k].label}
                      </button>
                    {/each}
                  </div>
                </td>
                <td class="px-4 py-2.5"><code class="font-mono text-xs text-foreground">{r.ip || '—'}</code></td>
                <td class="hidden truncate px-4 py-2.5 text-xs text-muted-foreground md:table-cell">{r.where || '—'}</td>
                <td class="hidden px-4 py-2.5 text-xs text-muted-foreground sm:table-cell">{r.online ? 'now' : timeAgo(r.lastSeen)}</td>
                <td class="hidden px-4 py-2.5 text-right text-xs tabular-nums text-muted-foreground lg:table-cell">
                  {r.tx === null ? '—' : `${formatBytes(r.tx)} / ${formatBytes(r.rx)}`}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  {:else if !loading}
    <EmptyState icon="devices" title="No clients found"
      description={search || kindFilter !== 'all' || statusFilter !== 'all' ? 'Try a different search or filter' : 'Add WireGuard peers or Tailscale nodes, enroll machines, or create a private network'} large />
  {/if}
</div>
