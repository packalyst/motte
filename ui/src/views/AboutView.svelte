<script>
  import { onMount } from 'svelte'
  import { apiGet, getInitialTab } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import ContentBlock from '../components/ContentBlock.svelte'
  import Tabs from '../components/Tabs.svelte'

  let { loading = $bindable(true) } = $props()

  let activeTab = $state(getInitialTab('overview', ['overview', 'api']))
  let routerStatus = $state(null)
  let expandedApi = $state(null)
  let apiSchema = $state(null)

  // Service display config (icons, colors, order)
  const serviceConfig = {
    auth: { name: 'Authentication', icon: 'key', color: 'primary', order: 1 },
    headscale: { name: 'Headscale', icon: 'users', color: 'primary', order: 2 },
    firewall: { name: 'Firewall', icon: 'shield', color: 'destructive', order: 3 },
    adguard: { name: 'AdGuard', icon: 'shield-check', color: 'warning', order: 4 },
    traefik: { name: 'Traefik', icon: 'world', color: 'info', order: 5 },
    docker: { name: 'Docker', icon: 'box', color: 'info', order: 6 },
    geolocation: { name: 'Geolocation', icon: 'globe', color: 'primary', order: 7 },
    vpn: { name: 'VPN ACL', icon: 'route', color: 'success', order: 8 },
    wireguard: { name: 'WireGuard', icon: 'shield-lock', color: 'success', order: 9 },
    settings: { name: 'Settings', icon: 'settings', color: 'muted', order: 10 },
    setup: { name: 'Setup', icon: 'wand', color: 'muted', order: 11 }
  }

  // Transform API schema for display
  let apiServices = $derived(
    apiSchema?.services
      ? Object.entries(apiSchema.services)
          .map(([id, svc]) => ({
            id,
            name: serviceConfig[id]?.name || id,
            prefix: svc.prefix,
            icon: serviceConfig[id]?.icon || 'server',
            color: serviceConfig[id]?.color || 'muted',
            order: serviceConfig[id]?.order || 99,
            endpoints: svc.endpoints.map(ep => ({
              method: ep.methods[0],
              path: ep.path.replace(svc.prefix, ''),
              desc: ep.description
            }))
          }))
          .sort((a, b) => a.order - b.order)
      : []
  )

  const tabs = [
    { id: 'overview', label: 'Overview', icon: 'info-circle' },
    { id: 'api', label: 'API Reference', icon: 'code' }
  ]

  onMount(async () => {
    try {
      const [router, schema] = await Promise.all([
        apiGet('/api/vpn/router/status').catch(() => null),
        apiGet('/api/schema').catch(() => null)
      ])
      routerStatus = router
      apiSchema = schema
    } catch (e) {
      // Ignore
    }
    loading = false
  })
</script>

<div class="space-y-4">
  <InfoCard
    icon="info-circle"
    title="About"
    description="Unified admin panel for managing VPN infrastructure including WireGuard, Headscale, AdGuard DNS, and Traefik reverse proxy."
  />

  <div class="bg-card border border-border rounded-lg overflow-hidden">
    <Tabs {tabs} bind:activeTab urlKey="tab" />

    <div class="p-5">
      <!-- Overview Tab -->
      {#if activeTab === 'overview'}
        <div class="space-y-6">
          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">What is this?</h3>
            <p class="text-sm text-muted-foreground leading-relaxed">
              This admin panel provides a unified interface for managing a complete VPN infrastructure stack. It integrates multiple services to provide secure, private network access with advanced features like DNS-level ad blocking, reverse proxy routing, and cross-network communication between different VPN types.
            </p>
          </div>

          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">Key Features</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ContentBlock
                variant="box"
                border
                padding="lg"
                icon="users"
                iconColor="text-primary"
                title="Headscale Management"
                description="Manage users, nodes, pre-auth keys, API keys, and routes for your Headscale/Tailscale network."
              />
              <ContentBlock
                variant="box"
                border
                padding="lg"
                icon="shield"
                iconColor="text-success"
                title="WireGuard Peers"
                description="Create and manage WireGuard peers with QR codes for easy mobile setup."
              />
              <ContentBlock
                variant="box"
                border
                padding="lg"
                icon="shield-check"
                iconColor="text-warning"
                title="AdGuard DNS"
                description="Network-wide ad blocking, safe browsing, parental controls, and DNS query logging."
              />
              <ContentBlock
                variant="box"
                border
                padding="lg"
                icon="lock"
                iconColor="text-destructive"
                title="Firewall & Fail2Ban"
                description="Port management, IP blocking, intrusion detection with configurable jails."
              />
              <ContentBlock
                variant="box"
                border
                padding="lg"
                icon="world"
                iconColor="text-info"
                title="Traefik Proxy"
                description="View routers, services, middlewares. Configure VPN-only access mode."
              />
              <ContentBlock
                variant="box"
                border
                padding="lg"
                icon="route"
                iconColor="text-primary"
                title="Cross-Network Routing"
                description="Enable communication between WireGuard and Headscale networks with ACL rules."
              />
              <ContentBlock
                variant="box"
                border
                padding="lg"
                icon="globe"
                iconColor="text-info"
                title="Geolocation"
                description="IP lookup with MaxMind/IP2Location. Country blocking with IPDeny zone files."
              />
              <ContentBlock
                variant="box"
                border
                padding="lg"
                icon="box"
                iconColor="text-muted-foreground"
                title="Docker Management"
                description="View and manage Docker containers. Restart services, view logs and resource usage."
              />
            </div>
          </div>

          <!-- Cross-Network Routing Details -->
          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">Cross-Network Routing</h3>
            <p class="text-xs text-muted-foreground mb-3">
              VPN Router enables communication between WireGuard and Headscale networks via Tailscale container.
            </p>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
              <ContentBlock variant="box" border padding="md" title="1. Router Setup" description="Tailscale container joins Headscale and advertises WG subnet." />
              <ContentBlock variant="box" border padding="md" title="2. ACL Rules" description="Define which clients can communicate using Headscale ACL + nftables." />
              <ContentBlock variant="box" border padding="md" title="3. Traffic Flow" description="Traffic between networks flows through the router based on ACL policy." />
            </div>
          </div>

          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">Network Configuration</h3>
            <div class="grid grid-cols-2 gap-4">
              <ContentBlock variant="data" label="WireGuard Network" value={routerStatus?.wgIPRange || 'Not configured'} mono />
              <ContentBlock variant="data" label="Headscale Network" value={routerStatus?.headscaleIPRange || 'Not configured'} mono />
            </div>
          </div>

          <div>
            <h3 class="text-lg font-semibold text-foreground mb-3">System Architecture</h3>
            <div class="bg-secondary text-secondary-foreground p-4 rounded-lg font-mono text-[10px] overflow-x-auto">
              <pre class="whitespace-pre">{`┌─────────────────────────────────────────────────────────────────────┐
│                         Admin Panel (UI + API)                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │ Traefik  │  │ AdGuard  │  │Headscale │  │WireGuard │            │
│  │  Proxy   │  │   DNS    │  │   VPN    │  │   VPN    │            │
│  │ :443/80  │  │   :53    │  │  :8080   │  │ :51820   │            │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘            │
│       │             │             │             │                   │
│       └─────────────┴──────┬──────┴─────────────┘                   │
│                            │                                        │
│                     ┌──────┴──────┐                                 │
│                     │  VPN Router │ (Cross-Network)                 │
│                     │ (Tailscale) │                                 │
│                     └──────┬──────┘                                 │
│                            │                                        │
│         ┌──────────────────┴──────────────────┐                    │
│         │                                     │                    │
│   ┌─────┴─────┐                       ┌──────┴──────┐              │
│   │ Headscale │                       │  WireGuard  │              │
│   │  Network  │◄───── ACL Rules ─────►│   Network   │              │
│   │${routerStatus?.headscaleIPRange?.padStart(12) || '100.64.0.0/16'}│                       │${routerStatus?.wgIPRange?.padStart(13) || ' 100.65.0.0/16'}│              │
│   └───────────┘                       └─────────────┘              │
└─────────────────────────────────────────────────────────────────────┘`}</pre>
            </div>
          </div>
        </div>

      <!-- API Reference Tab -->
      {:else if activeTab === 'api'}
        {@const examples = [
          { title: 'Login', method: 'POST', endpoint: '/api/auth/login',
            request: `{
  "username": "admin",
  "password": "your-password"
}`,
            response: `{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": { "id": 1, "username": "admin" }
}` },
          { title: 'List Nodes', method: 'GET', endpoint: '/api/hs/nodes',
            request: null,
            response: `{
  "nodes": [
    {
      "id": "1",
      "name": "laptop",
      "ipAddresses": ["100.64.0.1"],
      "online": true,
      "user": { "name": "admin" }
    }
  ]
}` },
          { title: 'Block IP', method: 'POST', endpoint: '/api/fw/blocked',
            request: `{
  "ip": "192.168.1.100",
  "reason": "Suspicious activity",
  "source": "manual"
}`,
            response: `{
  "success": true,
  "message": "IP blocked"
}` },
          { title: 'Toggle Protection', method: 'PUT', endpoint: '/api/adguard/config',
            request: `{
  "type": "protection",
  "enabled": true
}`,
            response: `{
  "success": true
}` }
        ]}
        {@const methodColors = { GET: 'muted', POST: 'info', PUT: 'warning', DELETE: 'danger' }}

        <div class="space-y-4">
          <!-- Header -->
          <div class="flex items-center justify-between">
            <p class="text-sm text-muted-foreground">
              RESTful API with JSON. Include <code class="bg-muted px-1.5 py-0.5 rounded text-xs">Authorization: Bearer &lt;token&gt;</code> header.
            </p>
            <div class="text-xs text-muted-foreground">
              {apiServices?.reduce((acc, s) => acc + s.endpoints.length, 0) || 0} endpoints
            </div>
          </div>

          <!-- API Services Grid -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
            {#if !apiSchema}
              {#each Array(6) as _}
                <div class="bg-muted/30 rounded-lg border border-border p-3 animate-pulse">
                  <div class="flex items-center gap-2">
                    <div class="w-7 h-7 rounded bg-muted"></div>
                    <div class="flex-1">
                      <div class="h-4 w-24 bg-muted rounded mb-1"></div>
                      <div class="h-3 w-16 bg-muted rounded"></div>
                    </div>
                  </div>
                </div>
              {/each}
            {:else}
            {#each apiServices as service}
              <div class="bg-muted/30 rounded-lg border border-border overflow-hidden">
                <button
                  onclick={() => expandedApi = expandedApi === service.id ? null : service.id}
                  class="w-full flex items-center justify-between p-3 hover:bg-muted/50 transition-colors cursor-pointer"
                >
                  <div class="flex items-center gap-2">
                    <div class="w-7 h-7 rounded bg-{service.color}/10 flex items-center justify-center">
                      <Icon name={service.icon} size={14} class="text-{service.color}" />
                    </div>
                    <div class="text-left">
                      <div class="font-medium text-foreground text-sm">{service.name}</div>
                      <div class="text-[10px] text-muted-foreground font-mono">{service.prefix}</div>
                    </div>
                  </div>
                  <div class="flex items-center gap-2">
                    <span class="text-xs text-muted-foreground">{service.endpoints.length}</span>
                    <Icon name={expandedApi === service.id ? 'chevron-down' : 'chevron-right'} size={14} class="text-muted-foreground" />
                  </div>
                </button>

                {#if expandedApi === service.id}
                  <div class="border-t border-border">
                    <table class="w-full text-xs">
                      <tbody class="divide-y divide-border/50">
                        {#each service.endpoints as ep}
                          <tr class="hover:bg-muted/30">
                            <td class="px-3 py-1.5 w-16">
                              <Badge variant={methodColors[ep.method]} size="sm">{ep.method}</Badge>
                            </td>
                            <td class="px-2 py-1.5 font-mono text-foreground">{ep.path}</td>
                            <td class="px-3 py-1.5 text-muted-foreground hidden sm:table-cell">{ep.desc}</td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  </div>
                {/if}
              </div>
            {/each}
            {/if}
          </div>

          <!-- Examples -->
          <div class="pt-2">
            <h4 class="font-medium text-foreground mb-3 flex items-center gap-2">
              <Icon name="code" size={16} class="text-muted-foreground" />
              Examples
            </h4>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              {#each examples as ex}
                <div class="bg-muted/30 rounded-lg border border-border overflow-hidden">
                  <div class="flex items-center gap-2 px-3 py-2 border-b border-border bg-muted/50">
                    <Badge variant={methodColors[ex.method]} size="sm">{ex.method}</Badge>
                    <span class="font-mono text-xs text-foreground">{ex.endpoint}</span>
                  </div>
                  <div class="p-3 space-y-2">
                    {#if ex.request}
                      <div>
                        <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Request</div>
                        <pre class="bg-secondary text-secondary-foreground p-2 rounded text-[10px] font-mono overflow-x-auto">{ex.request}</pre>
                      </div>
                    {/if}
                    <div>
                      <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Response</div>
                      <pre class="bg-secondary text-secondary-foreground p-2 rounded text-[10px] font-mono overflow-x-auto">{ex.response}</pre>
                    </div>
                  </div>
                </div>
              {/each}
            </div>
          </div>
        </div>

{/if}
    </div>
  </div>
</div>
