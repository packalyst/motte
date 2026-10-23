<script>
  /**
   * TraefikOverview — what Traefik is doing right now (read-only, from its API): counts, which
   * protections are actually in use, and the routers, services and middlewares. Shown in Settings →
   * Web access under the Traefik settings. A protection counts as on only when a middleware of that
   * kind is attached to an enabled router — one that merely exists protects nothing.
   */
  import { apiGet } from '../stores/app.js'
  import { useDataLoader } from '$lib/composables/index.js'
  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import Tabs from './Tabs.svelte'
  import EmptyState from './EmptyState.svelte'

  const loader = useDataLoader(() => apiGet('/api/traefik/overview'), { errorMsg: 'Failed to load Traefik data' })

  // The API returns either an array or a name → object map.
  const list = (res) => (Array.isArray(res) ? res : Object.entries(res || {}).map(([name, v]) => ({ ...v, name })))
  const routers = $derived(list(loader.data?.routers))
  const services = $derived(list(loader.data?.services))
  const middlewares = $derived(list(loader.data?.middlewares))
  const activeRouters = $derived(routers.filter((r) => r.status === 'enabled'))

  const KINDS = [
    { key: 'rate', label: 'Rate limiting', icon: 'gauge', has: (m) => m.rateLimit },
    { key: 'headers', label: 'Security headers', icon: 'lock', has: (m) => m.headers },
    { key: 'allow', label: 'IP allowlist', icon: 'world', has: (m) => m.ipAllowList || m.ipWhiteList },
    { key: 'auth', label: 'Basic auth', icon: 'key', has: (m) => m.basicAuth },
  ]
  const kindLabel = (m) => KINDS.find((k) => k.has(m))?.label
    || (m.replacePathRegex || m.replacePath ? 'Path rewrite' : m.stripPrefix ? 'Strip prefix' : 'Custom')
  // Middleware names on routers may omit the provider suffix ("rate-limit" vs "rate-limit@file").
  const sameMw = (a, b) => a === b || a.split('@')[0] === b.split('@')[0]
  const protections = $derived(KINDS.map((k) => {
    const mws = middlewares.filter(k.has)
    const using = activeRouters.filter((r) => (r.middlewares || []).some((n) => mws.some((m) => sameMw(n, m.name))))
    return { ...k, routers: using.length }
  }))

  function mwConfig(mw) {
    if (mw.rateLimit) return `${mw.rateLimit.average}/s average, burst ${mw.rateLimit.burst}`
    if (mw.headers) {
      const parts = []
      if (mw.headers.frameDeny) parts.push('X-Frame-Options')
      if (mw.headers.contentTypeNosniff) parts.push('X-Content-Type-Options')
      if (mw.headers.browserXssFilter) parts.push('XSS filter')
      return parts.join(', ') || 'Custom headers'
    }
    if (mw.ipAllowList || mw.ipWhiteList) return `${(mw.ipAllowList || mw.ipWhiteList).sourceRange?.length || 0} address ranges`
    if (mw.replacePathRegex) return mw.replacePathRegex.regex
    return ''
  }

  let tab = $state('routers')
  const tabs = $derived([
    { id: 'routers', label: 'Routers', badge: routers.length },
    { id: 'services', label: 'Services', badge: services.length },
    { id: 'middlewares', label: 'Middlewares', badge: middlewares.length },
  ])
  const tint = (c) => `background: color-mix(in oklch, ${c} 14%, transparent); color: ${c}`
</script>

<div class="panel">
  <div class="panel-head">
    <span class="panel-icon text-primary"><Icon name="activity" size={17} /></span>
    <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Live routing</div>
    <span class="text-xs text-muted-foreground">read from Traefik</span>
  </div>
  {#if loader.loading}
    <div class="space-y-3 text-sm text-muted-foreground">Loading…</div>
  {:else if loader.error}
    <div class="flex items-start gap-2 text-sm text-muted-foreground">
      <Icon name="alert-triangle" size={16} class="mt-0.5 shrink-0 text-warning" />Traefik's status couldn't be loaded.
    </div>
  {:else}
    <div class="space-y-4">
      <!-- counts: one surface, hairline dividers -->
      <div class="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-4">
        {#each [
          { icon: 'git-branch', color: 'var(--info)', value: routers.length, label: 'routers' },
          { icon: 'circle-check', color: 'var(--success)', value: activeRouters.length, label: 'enabled' },
          { icon: 'server', color: 'var(--primary)', value: services.length, label: 'services' },
          { icon: 'shield', color: 'var(--warning)', value: middlewares.length, label: 'middlewares' },
        ] as s (s.label)}
          <div class="flex items-center gap-3 bg-card px-3 py-2.5">
            <span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg" style={tint(s.color)}><Icon name={s.icon} size={15} /></span>
            <div>
              <div class="text-lg font-bold leading-none tabular-nums text-foreground">{s.value}</div>
              <div class="mt-1 text-[11px] text-muted-foreground">{s.label}</div>
            </div>
          </div>
        {/each}
      </div>

      <!-- protections actually attached to enabled routers -->
      <div>
        <div class="mb-2 text-[10px] uppercase tracking-wide text-muted-foreground">Protections in use</div>
        <div class="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {#each protections as p (p.key)}
            <div class="flex items-center gap-2.5 rounded-lg border border-border px-3 py-2 {p.routers ? '' : 'opacity-60'}">
              <span class="grid h-7 w-7 shrink-0 place-items-center rounded-md {p.routers ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}"><Icon name={p.icon} size={14} /></span>
              <div class="min-w-0">
                <div class="truncate text-sm text-foreground">{p.label}</div>
                <div class="text-[11px] {p.routers ? 'text-success' : 'text-muted-foreground'}">{p.routers ? `on ${p.routers} router${p.routers === 1 ? '' : 's'}` : 'not in use'}</div>
              </div>
            </div>
          {/each}
        </div>
      </div>

      <div>
        <Tabs {tabs} bind:activeTab={tab} size="xs" />
        <div class="mt-3">
          {#if tab === 'routers'}
            {#if !routers.length}
              <EmptyState icon="git-branch" title="No routers" description="Routers appear here once Traefik has some." compact />
            {:else}
              <div class="divide-y divide-border rounded-lg border border-border">
                {#each routers as r (r.name)}
                  <div class="space-y-1.5 px-3 py-2.5">
                    <div class="flex items-center gap-2">
                      <span class="min-w-0 flex-1 truncate text-sm font-medium text-foreground">{r.name}</span>
                      {#if r.service}<span class="hidden items-center gap-1 text-[11px] text-muted-foreground sm:inline-flex"><Icon name="arrow-right" size={11} />{r.service}</span>{/if}
                      <Badge variant={r.status === 'enabled' ? 'success' : 'danger'} size="sm">{r.status || 'unknown'}</Badge>
                    </div>
                    {#if r.rule}<code class="block break-all rounded bg-muted px-2 py-1 font-mono text-[11px]">{r.rule}</code>{/if}
                    {#if r.middlewares?.length}
                      <div class="flex flex-wrap gap-1">
                        {#each r.middlewares as mw (mw)}<span class="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{mw}</span>{/each}
                      </div>
                    {/if}
                  </div>
                {/each}
              </div>
            {/if}
          {:else if tab === 'services'}
            {#if !services.length}
              <EmptyState icon="server" title="No services" description="Services appear here once Traefik has some." compact />
            {:else}
              <div class="divide-y divide-border rounded-lg border border-border">
                {#each services as s (s.name)}
                  <div class="flex flex-wrap items-center gap-2 px-3 py-2.5">
                    <span class="min-w-0 flex-1 truncate text-sm font-medium text-foreground">{s.name}</span>
                    {#each s.loadBalancer?.servers || [] as srv}
                      <code class="rounded bg-muted px-2 py-0.5 font-mono text-[11px]">{srv.url || srv.address}</code>
                    {/each}
                    <Badge variant={s.status === 'enabled' ? 'success' : 'warning'} size="sm">{s.status || 'loadbalancer'}</Badge>
                  </div>
                {/each}
              </div>
            {/if}
          {:else}
            {#if !middlewares.length}
              <EmptyState icon="shield" title="No middlewares" description="Middlewares appear here once Traefik has some." compact />
            {:else}
              <div class="divide-y divide-border rounded-lg border border-border">
                {#each middlewares as m (m.name)}
                  <div class="flex items-center gap-2 px-3 py-2.5">
                    <div class="min-w-0 flex-1">
                      <div class="truncate text-sm font-medium text-foreground">{m.name}</div>
                      {#if mwConfig(m)}<div class="truncate text-[11px] text-muted-foreground">{mwConfig(m)}</div>{/if}
                    </div>
                    <Badge variant="info" size="sm">{kindLabel(m)}</Badge>
                  </div>
                {/each}
              </div>
            {/if}
          {/if}
        </div>
      </div>
    </div>
  {/if}
</div>
