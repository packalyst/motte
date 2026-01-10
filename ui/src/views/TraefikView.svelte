<script>
  import { apiGet } from '../stores/app.js'
  import { useDataLoader } from '$lib/composables/index.js'
  import Icon from '../components/Icon.svelte'
  import Badge from '../components/Badge.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import ContentBlock from '../components/ContentBlock.svelte'
  import EmptyState from '../components/EmptyState.svelte'

  let { loading = $bindable(true) } = $props()

  // Data loading
  const loader = useDataLoader(
    () => apiGet('/api/traefik/overview'),
    { errorMsg: 'Failed to load Traefik data' }
  )

  // Transform data - handle both array and object formats
  const routers = $derived.by(() => {
    const res = loader.data?.routers || []
    return Array.isArray(res) ? res : Object.entries(res).map(([name, r]) => ({ ...r, name }))
  })

  const services = $derived.by(() => {
    const res = loader.data?.services || []
    return Array.isArray(res) ? res : Object.entries(res).map(([name, s]) => ({ ...s, name }))
  })

  const middlewares = $derived.by(() => {
    const res = loader.data?.middlewares || []
    return Array.isArray(res) ? res : Object.entries(res).map(([name, m]) => ({ ...m, name }))
  })

  // Sync loading state to parent
  $effect(() => { loading = loader.loading })

  // Stats
  const activeRouters = $derived(routers.filter(r => r.status === 'enabled').length)

  // Get middleware type
  function getMiddlewareType(mw) {
    if (mw.rateLimit) return 'Rate Limit'
    if (mw.headers) return 'Headers'
    if (mw.ipAllowList || mw.ipWhiteList) return 'IP Allowlist'
    if (mw.basicAuth) return 'Basic Auth'
    if (mw.replacePathRegex || mw.replacePath) return 'Path Rewrite'
    if (mw.stripPrefix) return 'Strip Prefix'
    return 'Custom'
  }

  function getMiddlewareConfig(mw) {
    if (mw.rateLimit) return `${mw.rateLimit.average}/s avg, ${mw.rateLimit.burst} burst`
    if (mw.headers) {
      const parts = []
      if (mw.headers.frameDeny) parts.push('X-Frame-Options')
      if (mw.headers.contentTypeNosniff) parts.push('X-Content-Type')
      if (mw.headers.browserXssFilter) parts.push('XSS-Filter')
      return parts.join(', ') || 'Custom headers'
    }
    if (mw.ipAllowList) return `${mw.ipAllowList.sourceRange?.length || 0} ranges`
    if (mw.replacePathRegex) return mw.replacePathRegex.regex
    return '-'
  }

</script>

<div class="space-y-4">
  <InfoCard
    icon="route"
    title="Traefik Reverse Proxy"
    description="Manage your reverse proxy configuration. Monitor routers, services, and middlewares. Configure rate limiting, security headers, and IP allowlists for protection."
  />

  {#if loading}
    <LoadingSpinner centered size="lg" />
  {:else}
    <!-- Stats Grid -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-info/10 flex items-center justify-center flex-shrink-0">
          <Icon name="git-branch" size={20} class="text-info" />
        </div>
        <div>
          <div class="text-2xl font-bold text-foreground">{routers.length}</div>
          <div class="text-[11px] text-muted-foreground">Routers</div>
        </div>
      </div>
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center flex-shrink-0">
          <Icon name="server" size={20} class="text-primary" />
        </div>
        <div>
          <div class="text-2xl font-bold text-foreground">{services.length}</div>
          <div class="text-[11px] text-muted-foreground">Services</div>
        </div>
      </div>
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-warning/10 flex items-center justify-center flex-shrink-0">
          <Icon name="shield" size={20} class="text-warning" />
        </div>
        <div>
          <div class="text-2xl font-bold text-foreground">{middlewares.length}</div>
          <div class="text-[11px] text-muted-foreground">Middlewares</div>
        </div>
      </div>
      <div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
        <div class="w-10 h-10 rounded-lg bg-success/10 flex items-center justify-center flex-shrink-0">
          <Icon name="check" size={20} class="text-success" />
        </div>
        <div>
          <div class="text-2xl font-bold text-success">{activeRouters}</div>
          <div class="text-[11px] text-muted-foreground">Active</div>
        </div>
      </div>
    </div>

    <!-- Active Protections -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">
          <Icon name="shield-check" size={16} />
          Active Protections
        </h3>
      </div>
      <div class="kt-panel-body">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
          <ContentBlock variant="indicator" icon="shield-check" color="success" title="Rate Limiting" description="Enabled" />
          <ContentBlock variant="indicator" icon="file-text" color="success" title="Access Logging" description="JSON format" />
          <ContentBlock variant="indicator" icon="lock" color="success" title="Security Headers" description="XSS protection" />
          <ContentBlock variant="indicator" icon="globe" color="success" title="IP Allowlist" description="VPN only" />
        </div>
      </div>
    </div>

    <!-- Routers -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">
          <Icon name="git-branch" size={16} />
          Routers
        </h3>
      </div>
      <div class="kt-panel-body">
      {#if routers.length === 0}
        <EmptyState
          icon="git-branch"
          title="No Routers"
          description="Routers will appear when configured"
          compact
        />
      {:else}
        <div class="grid gap-3 md:grid-cols-2">
          {#each routers as router}
            <div class="p-3 bg-muted/30 border border-border rounded-lg">
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <div class="w-8 h-8 rounded-lg flex items-center justify-center bg-info/10 text-info flex-shrink-0">
                    <Icon name="git-branch" size={16} />
                  </div>
                  <span class="text-sm font-medium text-foreground truncate">{router.name}</span>
                </div>
                <Badge variant={router.status === 'enabled' ? 'success' : 'danger'} size="sm">
                  {router.status || 'unknown'}
                </Badge>
              </div>
              <div class="space-y-1.5 text-xs pl-10">
                {#if router.rule}
                  <code class="block px-2 py-1 bg-muted rounded font-mono text-[11px] break-all">{router.rule}</code>
                {/if}
                {#if router.service}
                  <div class="flex items-center gap-1.5 text-muted-foreground">
                    <Icon name="arrow-right" size={12} />
                    <span>{router.service}</span>
                  </div>
                {/if}
                {#if router.middlewares?.length}
                  <div class="flex flex-wrap gap-1">
                    {#each router.middlewares as mw}
                      <span class="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">{mw}</span>
                    {/each}
                  </div>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      {/if}
      </div>
    </div>

    <!-- Services -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">
          <Icon name="server" size={16} />
          Services
        </h3>
      </div>
      <div class="kt-panel-body">
      {#if services.length === 0}
        <EmptyState
          icon="server"
          title="No Services"
          description="Services will appear when configured"
          compact
        />
      {:else}
        <div class="grid gap-3 md:grid-cols-3">
          {#each services as service}
            <div class="p-3 bg-muted/30 border border-border rounded-lg">
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <div class="w-8 h-8 rounded-lg flex items-center justify-center bg-primary/10 text-primary flex-shrink-0">
                    <Icon name="server" size={16} />
                  </div>
                  <span class="text-sm font-medium text-foreground truncate">{service.name}</span>
                </div>
                <Badge variant={service.status === 'enabled' ? 'success' : 'warning'} size="sm">
                  {service.status || 'loadbalancer'}
                </Badge>
              </div>
              {#if service.loadBalancer?.servers?.length}
                <div class="space-y-1 pl-10">
                  {#each service.loadBalancer.servers as server}
                    <code class="block px-2 py-1 bg-muted rounded font-mono text-[11px]">{server.url || server.address}</code>
                  {/each}
                </div>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
      </div>
    </div>

    <!-- Middlewares -->
    <div class="kt-panel">
      <div class="kt-panel-header">
        <h3 class="kt-panel-title">
          <Icon name="shield" size={16} />
          Middlewares
        </h3>
      </div>
      <div class="kt-panel-body">
      {#if middlewares.length === 0}
        <EmptyState
          icon="shield"
          title="No Middlewares"
          description="Middlewares will appear when configured"
          compact
        />
      {:else}
        <div class="grid gap-3 md:grid-cols-3">
          {#each middlewares as mw}
            <div class="p-3 bg-muted/30 border border-border rounded-lg">
              <div class="flex items-center justify-between mb-1">
                <div class="flex items-center gap-2">
                  <div class="w-8 h-8 rounded-lg flex items-center justify-center bg-warning/10 text-warning flex-shrink-0">
                    <Icon name="shield" size={16} />
                  </div>
                  <span class="text-sm font-medium text-foreground truncate">{mw.name}</span>
                </div>
                <Badge variant="info" size="sm">{getMiddlewareType(mw)}</Badge>
              </div>
              <div class="text-xs text-muted-foreground pl-10">{getMiddlewareConfig(mw)}</div>
            </div>
          {/each}
        </div>
      {/if}
      </div>
    </div>
  {/if}
</div>
