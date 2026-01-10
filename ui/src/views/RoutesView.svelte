<script>
  import { toast, apiGet, apiPost, apiDelete, confirm, setConfirmLoading } from '../stores/app.js'
  import { useDataLoader } from '$lib/composables/index.js'
  import { filterByFields } from '$lib/utils/data.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import Button from '../components/Button.svelte'
  import Modal from '../components/Modal.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import EmptyState from '../components/EmptyState.svelte'

  let { loading = $bindable(true) } = $props()

  // Multi-source data loading
  const loader = useDataLoader([
    { fn: () => apiGet('/api/hs/routes'), key: 'routes', extract: 'routes', isArray: true },
    { fn: () => apiGet('/api/hs/nodes'), key: 'nodes', extract: 'nodes', isArray: true }
  ])

  const routes = $derived(loader.data.routes || [])
  const nodes = $derived(loader.data.nodes || [])

  // Sync loading state to parent
  $effect(() => { loading = loader.loading })

  let searchQuery = $state('')

  // Get node info for a route
  function getNodeForRoute(route) {
    return nodes.find(n => n.id === route.node?.id || n.id === route.machineId)
  }

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
        const nodeId = route.node?.id || route.machineId
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

  // Filtered routes
  const filteredRoutes = $derived(
    processedRoutes().filter(r =>
      r.prefix?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.node?.givenName?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.node?.name?.toLowerCase().includes(searchQuery.toLowerCase())
    )
  )

  async function toggleRoute(route) {
    try {
      const action = route.enabled ? 'disable' : 'enable'
      await apiPost(`/api/hs/routes/${route.id}/${action}`)
      toast(`Route ${route.enabled ? 'disabled' : 'enabled'}`, 'success')
      loader.reload()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function confirmDelete(route) {
    const isExit = route.isExitNode
    const nodeName = route.node?.givenName || route.node?.name

    const confirmed = await confirm({
      title: 'Delete Route',
      message: isExit
        ? `Remove Exit Node from ${nodeName}?`
        : `Delete route ${route.prefix}?`,
      description: isExit
        ? 'This will remove both IPv4 and IPv6 exit routes.'
        : 'This action cannot be undone.'
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
      loader.reload()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      setConfirmLoading(false)
    }
  }

  // Get status label
  function getStatusInfo(route) {
    if (!route.advertised) {
      return { label: 'Not Advertised', variant: 'muted' }
    }
    if (route.enabled) {
      return { label: 'Enabled', variant: 'success' }
    }
    return { label: 'Pending', variant: 'warning' }
  }
</script>

<div class="space-y-4">
  <InfoCard
    icon="route"
    title="Network Routes"
    description="Configure subnet routes and exit nodes advertised by your network nodes. Enable routes to allow traffic to flow through specific nodes to reach internal networks or the internet."
  />

  {#if routes.length > 0}
    <!-- Toolbar -->
    <Toolbar bind:search={searchQuery} placeholder="Search routes...">
      <span class="text-sm text-muted-foreground">{filteredRoutes.length} routes</span>
    </Toolbar>

    <!-- Routes Table -->
    {#if filteredRoutes.length > 0}
      <div class="bg-card border border-border rounded-xl overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-muted/50">
            <tr>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Status</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Approval</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Route</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Type</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Node</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase">Primary</th>
              <th class="px-4 py-3 w-24"></th>
            </tr>
          </thead>
          <tbody>
            {#each filteredRoutes as route}
              {@const node = route.node || getNodeForRoute(route)}
              {@const status = getStatusInfo(route)}
              <tr class="border-t border-border hover:bg-accent/50">
                <td class="px-4 py-3">
                  <Badge variant={status.variant} size="sm">
                    {status.label}
                  </Badge>
                </td>
                <td class="px-4 py-3">
                  {#if route.enabled}
                    <Badge variant="success" size="sm">Approved</Badge>
                  {:else}
                    <Badge variant="warning" size="sm">Awaiting</Badge>
                  {/if}
                </td>
                <td class="px-4 py-3">
                  {#if route.isExitNode}
                    <div class="flex items-center gap-2">
                      <Icon name="globe" size={14} class="text-primary" />
                      <span class="font-medium text-foreground">Exit Node</span>
                    </div>
                    <div class="text-xs text-muted-foreground mt-0.5">
                      IPv4 + IPv6 (all traffic)
                    </div>
                  {:else}
                    <code class="text-sm font-mono font-medium text-foreground">{route.prefix}</code>
                  {/if}
                </td>
                <td class="px-4 py-3">
                  <Badge variant={route.isExitNode ? 'primary' : 'info'} size="sm">
                    {route.isExitNode ? 'Exit' : 'Subnet'}
                  </Badge>
                </td>
                <td class="px-4 py-3">
                  <span class="text-foreground">{node?.givenName || node?.name || '—'}</span>
                </td>
                <td class="px-4 py-3">
                  {#if route.isPrimary}
                    <Badge variant="warning" size="sm">Yes</Badge>
                  {:else}
                    <span class="text-muted-foreground">—</span>
                  {/if}
                </td>
                <td class="px-4 py-3">
                  <div class="flex items-center justify-end gap-1">
                    <button
                      onclick={() => toggleRoute(route)}
                      class="icon-btn"
                      title={route.enabled ? 'Disable route' : 'Enable route'}
                    >
                      <Icon name={route.enabled ? 'x' : 'check'} size={14} />
                    </button>
                    <button
                      onclick={() => confirmDelete(route)}
                      class="icon-btn-destructive"
                      title="Delete route"
                    >
                      <Icon name="trash" size={14} />
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <EmptyState
        icon="search"
        title="No routes found"
        description="Try a different search term"
      />
    {/if}
  {:else}
    <EmptyState
      icon="route"
      title="No routes"
      description="Routes appear when nodes advertise subnets or exit nodes"
    />
  {/if}
</div>

