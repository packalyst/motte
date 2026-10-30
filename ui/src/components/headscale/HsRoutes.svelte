<script>
  /**
   * HsRoutes — the Routes section of the Headscale page: one card per node with the subnets and exit
   * node it offers, each turned on (approved) or off. routes come from the page (each carries its
   * node); after a change onchange() reloads them. search filters by node, owner or subnet; stats
   * reports { total, shown, active, waiting } to the page.
   */
  import { toast, apiPost, apiDelete, confirm, setConfirmLoading } from '../../stores/app.js'
  import Icon from '../Icon.svelte'
  import Badge from '../Badge.svelte'
  import EmptyState from '../EmptyState.svelte'
  import GroupHeading from '../GroupHeading.svelte'
  import Segmented from '../Segmented.svelte'
  import SegmentedAction from '../SegmentedAction.svelte'
  import { timeAgo, formatDate } from '../../lib/utils/format.js'

  let { routes = [], panelRouter = null, search = '', stats = $bindable(null), onchange } = $props()

  // The panel's own Cross-Network Router (Settings → Headscale): its route links Tailscale to
  // WireGuard, so its card is marked and turning it off or deleting it warns first. panelRouter is
  // { name, route }: the router node's name and the WireGuard range it offers.
  const nodeName = (node) => node?.givenName || node?.name || ''
  const isPanelRouter = (node) => !!panelRouter?.name && nodeName(node) === panelRouter.name
  const isPanelRoute = (route) => isPanelRouter(route.node) && route.prefix === panelRouter.route

  // Check if route is exit node
  function isExitNode(prefix) {
    return prefix === '0.0.0.0/0' || prefix === '::/0'
  }

  // Process routes: combine exit node pairs (IPv4 + IPv6) into single entries
  const processedRoutes = $derived(() => {
    const result = []
    const exitNodesByNode = new Map() // Group exit nodes by node ID

    for (const route of routes) {
      if (isExitNode(route.prefix)) {
        const nodeId = route.node?.id
        if (!exitNodesByNode.has(nodeId)) {
          exitNodesByNode.set(nodeId, { ipv4: null, ipv6: null })
        }
        if (route.prefix === '0.0.0.0/0') {
          exitNodesByNode.get(nodeId).ipv4 = route
        } else {
          exitNodesByNode.get(nodeId).ipv6 = route
        }
      } else {
        // Regular subnet route
        result.push({ ...route, isExitNode: false, combined: false })
      }
    }

    // Add combined exit nodes
    for (const [nodeId, pair] of exitNodesByNode) {
      const primaryRoute = pair.ipv4 || pair.ipv6
      if (primaryRoute) {
        result.push({
          ...primaryRoute,
          prefix: 'Exit Node',
          isExitNode: true,
          combined: true,
          ipv4Route: pair.ipv4,
          ipv6Route: pair.ipv6,
          // Use IPv4 route for toggle/delete, both get affected anyway
          id: pair.ipv4?.id || pair.ipv6?.id,
          enabled: (pair.ipv4?.enabled || false) || (pair.ipv6?.enabled || false)
        })
      }
    }

    return result
  })

  // Route state, one label per route: approved and advertised → active; advertised but not
  // approved → waiting; approved or not, a route the node no longer advertises carries nothing.
  const STATE = {
    active: { label: 'Active', text: 'text-success', dot: 'status-dot-success' },
    waiting: { label: 'Waiting for approval', text: 'text-warning', dot: 'status-dot-warning' },
    off: { label: 'Not advertised', text: 'text-muted-foreground', dot: 'status-dot-muted' },
  }
  const stateOf = (r) => (!r.advertised ? 'off' : r.enabled ? 'active' : 'waiting')

  // A subnet offered by more than one node: the primary carries its traffic, the others stand by
  // and take over if it goes offline.
  const shared = $derived.by(() => {
    const n = new Map()
    for (const r of routes) if (r.advertised && r.enabled) n.set(r.prefix, (n.get(r.prefix) || 0) + 1)
    return n
  })
  function kindOf(r) {
    if (r.isExitNode) return 'all internet traffic'
    if ((shared.get(r.prefix) || 0) > 1 && r.enabled) return r.isPrimary ? 'subnet · carries traffic' : 'subnet · standby'
    return 'subnet'
  }

  // One card per node: its exit node (if any) first, then its subnets; nodes with routes waiting
  // for approval come first, then by name.
  const q = $derived(search.trim().toLowerCase())
  const groups = $derived.by(() => {
    const byNode = new Map()
    for (const r of processedRoutes()) {
      const node = r.node
      const name = nodeName(node) || '—'
      const hay = [name, node?.user?.name || '', r.isExitNode ? 'exit node' : r.prefix].join(' ').toLowerCase()
      if (q && !hay.includes(q)) continue
      const key = node?.id ?? name
      if (!byNode.has(key)) byNode.set(key, { key, name, node, routes: [] })
      byNode.get(key).routes.push(r)
    }
    const list = [...byNode.values()]
    for (const g of list) {
      g.routes.sort((a, b) => (b.isExitNode - a.isExitNode) || a.prefix.localeCompare(b.prefix, undefined, { numeric: true }))
      g.waiting = g.routes.filter((r) => stateOf(r) === 'waiting').length
    }
    return list.sort((a, b) => (b.waiting > 0) - (a.waiting > 0) || a.name.localeCompare(b.name))
  })

  $effect(() => {
    const all = processedRoutes()
    const count = (st) => all.filter((r) => stateOf(r) === st).length
    stats = { total: all.length, shown: groups.reduce((n, g) => n + g.routes.length, 0), active: count('active'), waiting: count('waiting') }
  })

  async function toggleRoute(route) {
    if (route.enabled && isPanelRoute(route)) {
      const ok = await confirm({
        title: 'Turn off the panel router route',
        message: `Turn off ${route.prefix} on the panel router?`,
        description: 'Tailscale devices lose access to WireGuard clients until it is turned on again.',
        confirmText: 'Turn off', variant: 'destructive',
      })
      if (!ok) return
    }
    try {
      const action = route.enabled ? 'disable' : 'enable'
      await apiPost(`/api/hs/routes/${route.id}/${action}`)
      toast(`Route ${route.enabled ? 'disabled' : 'enabled'}`, 'success')
      onchange?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function confirmDelete(route) {
    const isExit = route.isExitNode
    const name = nodeName(route.node)

    const confirmed = await confirm({
      title: 'Delete Route',
      message: isExit
        ? `Remove Exit Node from ${name}?`
        : `Delete route ${route.prefix}?`,
      description: isExit
        ? 'This removes both the IPv4 and IPv6 exit routes. If the node still offers them, they come back waiting for approval when it reconnects.'
        : isPanelRoute(route)
          ? 'This is the panel router route: Tailscale devices lose access to WireGuard clients. It comes back waiting for approval when the router reconnects.'
          : 'If the node still offers it, it comes back waiting for approval when it reconnects.'
    })
    if (!confirmed) return

    setConfirmLoading(true)
    try {
      // For combined exit nodes, delete both routes
      if (route.combined) {
        if (route.ipv4Route) {
          await apiDelete(`/api/hs/routes/${route.ipv4Route.id}`)
        }
        if (route.ipv6Route) {
          await apiDelete(`/api/hs/routes/${route.ipv6Route.id}`)
        }
      } else {
        await apiDelete(`/api/hs/routes/${route.id}`)
      }
      toast('Route deleted', 'success')
      onchange?.()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }
</script>

<section class="space-y-2" aria-label="Routes">
  <GroupHeading title="Routes" color="var(--color-info)"
    note={stats?.waiting ? `${stats.waiting} to approve` : `${stats?.active ?? 0} active`} />

  {#if routes.length > 0}
    {#if groups.length > 0}
      <div class="grid grid-cols-1 items-start gap-3 xl:grid-cols-2">
        {#each groups as g (g.key)}
          <section class="panel" aria-label="Routes of {g.name}">
            <div class="panel-head">
              <span class="panel-icon"><Icon name="server" size={17} /></span>
              <div class="min-w-0 flex-1">
                <div class="flex min-w-0 items-center gap-2">
                  <span class="panel-title truncate">{g.name}</span>
                  {#if isPanelRouter(g.node)}<Badge variant="primary" size="sm">Panel router</Badge>{/if}
                </div>
                <div class="flex flex-wrap items-center gap-x-1.5 text-[11px] text-muted-foreground">
                  <span class="inline-flex items-center gap-1.5 {g.node?.online ? 'text-success' : ''}">
                    <span class="status-dot {g.node?.online ? 'status-dot-success' : 'status-dot-muted'}"></span>
                    {g.node?.online ? 'Online' : g.node?.lastSeen ? `Offline · seen ${timeAgo(g.node.lastSeen)}` : 'Offline'}
                  </span>
                  {#if g.node?.ipAddresses?.[0]}<span>·</span><span class="font-mono" title={g.node.ipAddresses.join('\n')}>{g.node.ipAddresses[0]}</span>{/if}
                  {#if g.node?.user?.name}<span>·</span><span class="inline-flex items-center gap-1"><Icon name="user" size={11} />{g.node.user.name}</span>{/if}
                </div>
              </div>
              {#if g.waiting}<Badge variant="warning" size="sm">{g.waiting} waiting</Badge>{/if}
            </div>
            <ul class="-my-1 divide-y divide-dashed divide-border">
              {#each g.routes as route (route.id)}
                {@const st = STATE[stateOf(route)]}
                {@const what = route.isExitNode ? 'exit node' : route.prefix}
                <li class="flex items-center gap-3 py-2.5" title={route.createdAt ? `Offered since ${formatDate(route.createdAt)}` : undefined}>
                  <span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg {route.isExitNode ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'}">
                    <Icon name={route.isExitNode ? 'world' : 'route'} size={15} />
                  </span>
                  <div class="min-w-0 flex-1">
                    <div class="truncate text-sm font-medium text-foreground {route.isExitNode ? '' : 'font-mono'}">{route.isExitNode ? 'Exit node' : route.prefix}</div>
                    <div class="flex flex-wrap items-center gap-x-1.5 text-[11px] text-muted-foreground">
                      <span class="inline-flex items-center gap-1.5 font-medium {st.text}"><span class="status-dot {st.dot}"></span>{st.label}</span>
                      <span>·</span>
                      <span>{kindOf(route)}</span>
                    </div>
                  </div>
                  {#snippet del()}
                    <SegmentedAction icon="trash" tooltip="Delete route" label="Delete {what} on {g.name}" danger onclick={() => confirmDelete(route)} />
                  {/snippet}
                  <Segmented size="sm" class="shrink-0" label="Approval of {what} on {g.name}" trailing={del}
                    value={route.enabled ? 'on' : 'off'} onchange={(v) => (v === 'on') !== route.enabled && toggleRoute(route)}
                    options={[{ value: 'on', label: 'On', tone: 'success' }, { value: 'off', label: 'Off' }]} />
                </li>
              {/each}
            </ul>
          </section>
        {/each}
      </div>
    {/if}
  {:else}
    <EmptyState
      icon="route"
      title="No routes"
      description="Routes appear when nodes advertise subnets or exit nodes"
    />
  {/if}
</section>
