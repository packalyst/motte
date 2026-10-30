<script>
  /**
   * HeadscaleView — everything Headscale on one page, laid out like Clients: a summary, one search,
   * then the sections (Routes, Users, Auth keys, API keys) stacked under their headings. A filter
   * shows one section or all: a toggle group in the toolbar on desktop, the bottom tab bar on
   * phones. Like Clients' filters it isn't in the URL; the browser remembers the last choice.
   * The page loads its data once and hands it to the sections: /api/hs/overview (users, nodes,
   * routes; no keys) for everyone, and /api/hs/keys only for admins, as on the server. For anyone
   * else the key sections aren't mounted and have no filter or summary entry.
   */
  import { currentUser, hasRole, apiGet } from '../stores/app.js'
  import { loadState, saveState } from '../stores/helpers.js'
  import { useDataLoader } from '$lib/composables/index.js'
  import InfoCard from '../components/InfoCard.svelte'
  import StatStrip from '../components/StatStrip.svelte'
  import Toolbar from '../components/Toolbar.svelte'
  import Segmented from '../components/Segmented.svelte'
  import MobileNav from '../components/MobileNav.svelte'
  import EmptyState from '../components/EmptyState.svelte'
  import LoadingSpinner from '../components/LoadingSpinner.svelte'
  import HsRoutes from '../components/headscale/HsRoutes.svelte'
  import HsUsers from '../components/headscale/HsUsers.svelte'
  import HsAuthKeys from '../components/headscale/HsAuthKeys.svelte'
  import HsApiKeys from '../components/headscale/HsApiKeys.svelte'

  let { loading = $bindable(true) } = $props()

  const isAdmin = $derived(hasRole($currentUser, 'admin'))

  const hs = useDataLoader(() => apiGet('/api/hs/overview'), { errorMsg: 'Failed to load Headscale' })
  const keys = useDataLoader(() => (isAdmin ? apiGet('/api/hs/keys') : Promise.resolve({})), { errorMsg: 'Failed to load keys' })
  const reloadAll = () => { hs.reload(); if (isAdmin) keys.reload() } // a user's delete takes their keys too

  // Each section's data and what reloads after it changes something.
  const SECTIONS = [
    { id: 'routes', label: 'Routes', icon: 'route', view: HsRoutes, props: () => ({ routes: hs.data.routes ?? [], panelRouter: hs.data.panelRouter, onchange: hs.reload }) },
    { id: 'users', label: 'Users', icon: 'users', view: HsUsers, props: () => ({ users: hs.data.users ?? [], nodes: hs.data.nodes ?? [], panelRouter: hs.data.panelRouter, onchange: reloadAll }) },
    { id: 'authkeys', label: 'Auth keys', icon: 'key', view: HsAuthKeys, admin: true, props: () => ({ keys: keys.data.preAuthKeys ?? [], onchange: keys.reload }) },
    { id: 'apikeys', label: 'API keys', icon: 'code', view: HsApiKeys, admin: true, props: () => ({ keys: keys.data.apiKeys ?? [], onchange: keys.reload }) },
  ]
  const sections = $derived(SECTIONS.filter((x) => !x.admin || isAdmin))

  let search = $state('')
  const saved = loadState('headscale')
  let filter = $state(saved.filter || 'all')
  // a saved section this person can't see (e.g. after a role change) falls back to all
  $effect(() => { if (filter !== 'all' && !sections.some((x) => x.id === filter)) filter = 'all' })
  $effect(() => saveState('headscale', { filter }))
  const filterOptions = $derived([{ id: 'all', label: 'All', icon: 'layout-grid' }, ...sections])

  // Each section reports its numbers back (stats); bound per section, so each starts with a value.
  let stats = $state(Object.fromEntries(SECTIONS.map((x) => [x.id, null])))
  // The first load shows a spinner; a reload after a change keeps the sections on screen.
  let loaded = $state(false)
  $effect(() => { if (!hs.loading && !keys.loading) loaded = true })
  $effect(() => { loading = false }) // the page shell shows at once

  const summary = $derived([
    { icon: 'route', tone: 'success', value: stats.routes?.active ?? 0, label: 'active routes' },
    { icon: 'clock', tone: stats.routes?.waiting ? 'warning' : undefined, value: stats.routes?.waiting ?? 0, label: 'routes to approve' },
    { icon: 'users', tone: 'primary', value: stats.users?.total ?? 0, label: 'users' },
    ...(isAdmin ? [{ icon: 'key', tone: 'info', value: stats.authkeys?.active ?? 0, label: 'active auth keys', sub: `${stats.apikeys?.active ?? 0} API keys` }] : []),
  ])

  // A section is shown when the filter allows it and, while searching, it has a match.
  const visible = (id) => (filter === 'all' || filter === id) && (!search.trim() || (stats[id]?.shown ?? 0) > 0)
  const nothingFound = $derived(loaded && !!search.trim() && !sections.some((x) => visible(x.id)))
</script>

<div class="space-y-4">
  <InfoCard icon="key" title="Headscale"
    description="Your Tailscale network: the routes nodes offer, the users who own them, and the keys that let devices and tools join." />

  <StatStrip items={summary} label="Headscale summary" />

  <Toolbar bind:search size="sm" placeholder="Search nodes, subnets, users or keys…">
    <div class="hidden lg:block">
      <Segmented size="sm" label="Show" bind:value={filter} options={filterOptions.map((o) => ({ value: o.id, label: o.label }))} />
    </div>
  </Toolbar>

  {#if !loaded}<LoadingSpinner centered size="lg" />{/if}
  <div class="space-y-6" class:hidden={!loaded}>
    {#each sections as s (s.id)}
      <div class:hidden={!visible(s.id)}>
        <s.view {...s.props()} {search} bind:stats={stats[s.id]} />
      </div>
    {/each}
    {#if nothingFound}
      <EmptyState icon="search" title="Nothing found" description="Try a different search term" />
    {/if}
  </div>

  <MobileNav look="bottom" items={filterOptions} active={filter} onselect={(id) => (filter = id)} label="Show" />
</div>
