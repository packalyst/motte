<script>
  /**
   * ActivityView — the panel's activity and audit trail: every subsystem's events, newest first.
   * Search (message, user, IP), severity and source filters run on the server; "Load older" pages
   * back through everything kept. The source list comes from the events themselves.
   */
  import { onDestroy } from 'svelte'
  import { createDebouncedSearch } from '../stores/helpers.js'
  import InfoCard from '../components/InfoCard.svelte'
  import Button from '../components/Button.svelte'
  import Select from '../components/Select.svelte'
  import Input from '../components/Input.svelte'
  import Segmented from '../components/Segmented.svelte'
  import Icon from '../components/Icon.svelte'
  import ActivityFeed, { SOURCES } from '../components/ActivityFeed.svelte'

  let { loading = $bindable(true) } = $props()

  let feed = $state(null)
  let sources = $state([])
  let subsystem = $state('')
  let severity = $state('')
  let search = $state('')
  let searchInput = $state('')

  // The feed loads on mount; this page has nothing else to fetch.
  $effect(() => { loading = false })

  const { search: debounced, cleanup } = createDebouncedSearch((v) => (search = v.trim()))
  onDestroy(cleanup)

  const label = (s) => SOURCES[s]?.label || s
  const totals = $derived(sources.reduce((t, s) => ({ all: t.all + s.total, warning: t.warning + s.warning, critical: t.critical + s.critical }), { all: 0, warning: 0, critical: 0 }))
  const sourceOptions = $derived([
    { value: '', label: `All sources (${totals.all})` },
    ...sources.map((s) => ({ value: s.subsystem, label: `${label(s.subsystem)} (${s.total})` })),
  ])
  const severityOptions = $derived([
    { value: '', label: 'All' },
    { value: 'warning', label: 'Warnings', count: totals.warning },
    { value: 'critical', label: 'Critical', count: totals.critical, tone: 'destructive' },
  ])
  const filtering = $derived(!!(subsystem || severity || search))
  function clearFilters() {
    subsystem = ''
    severity = ''
    search = ''
    searchInput = ''
  }
</script>

<div class="space-y-4">
  <InfoCard
    icon="activity"
    title="Activity"
    description="Everything that happened on the panel, newest first: sign-ins, changes, blocks and alerts, with who did it and from where."
  />

  <div class="panel">
    <div class="panel-head">
      <Input type="search" value={searchInput} placeholder="Search message, user or IP…" prefixIcon="search" class="w-full sm:w-64"
        oninput={(e) => { searchInput = e.target.value; debounced(searchInput) }} />
      <Segmented options={severityOptions} bind:value={severity} label="Severity" size="sm" />
      <Select bind:value={subsystem} options={sourceOptions} class="w-48" aria-label="Source" />
      <div class="ms-auto flex items-center gap-2">
        {#if filtering}
          <Button variant="ghost" size="sm" icon="x" onclick={clearFilters}>Clear filters</Button>
        {/if}
        <Button variant="outline" size="sm" iconOnly icon="refresh" onclick={() => feed?.reload()} tooltip="Refresh" />
      </div>
    </div>
    <ActivityFeed bind:this={feed} bind:sources limit={100} {subsystem} {severity} {search} />
  </div>
</div>
