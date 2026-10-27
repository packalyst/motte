<script>
  /**
   * FilterLists — the DNS page's blocklists: the lists AdGuard downloads and blocks with. The page
   * loads `filters` (the Overview counts them too) and passes `reload`; this owns the list, the
   * add window and its catalogue. Addresses are checked by the API (public https only); the hint
   * here only explains a bad one while typing.
   */
  import { toast, apiPut, confirm } from '../stores/app.js'
  import { formatNumber, timeAgo } from '../lib/utils/format.js'
  import blocklists from '../data/blocklists.json'
  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import Button from './Button.svelte'
  import Input from './Input.svelte'
  import Checkbox from './Checkbox.svelte'
  import Tabs from './Tabs.svelte'
  import Modal from './Modal.svelte'
  import EmptyState from './EmptyState.svelte'

  let { filters = $bindable([]), reload } = $props()

  let search = $state('')
  let busyUrl = $state('')
  let updating = $state(false)

  let addOpen = $state(false)
  let addMode = $state('list') // list | manual
  let selected = $state([]) // catalogue ids
  let catalogSearch = $state('')
  let newName = $state('')
  let newUrl = $state('')
  let adding = $state(false)

  const enabledCount = $derived(filters.filter((f) => f.enabled).length)
  const totalRules = $derived(filters.reduce((sum, f) => sum + (f.enabled ? f.rules_count || 0 : 0), 0))
  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase()
    return filters.filter((f) => !q || (f.name || '').toLowerCase().includes(q) || f.url.toLowerCase().includes(q))
  })

  const catalog = $derived(blocklists.categories
    .map((c) => ({ ...c, lists: c.lists.filter((l) => !catalogSearch || l.name.toLowerCase().includes(catalogSearch.toLowerCase())) }))
    .filter((c) => c.lists.length))
  const added = (url) => filters.some((f) => f.url === url)

  // Where a list comes from: its host, or the address itself when it isn't a web address.
  function source(url) {
    try { return new URL(url).host || url } catch { return url }
  }
  // AdGuard's "never" is the zero time; a list never downloaded also has no rules.
  const neverUpdated = (f) => !f.last_updated || new Date(f.last_updated).getFullYear() < 2000
  const broken = (f) => f.enabled && !f.rules_count && neverUpdated(f)

  // What's wrong with a typed address, for the manual tab (the API decides; this only explains).
  const PRIVATE_HOST = /^(localhost|.*\.localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|169\.254\.|0\.|\[)/
  const urlProblem = $derived.by(() => {
    const u = newUrl.trim()
    if (!u) return ''
    let p
    try { p = new URL(u) } catch { return 'Enter a full web address, starting with https://' }
    if (p.protocol !== 'https:') return 'Use an https:// address'
    if (p.username || p.password) return "Don't put a login in the address"
    if (PRIVATE_HOST.test(p.hostname)) return "Addresses on this server or your own network aren't allowed"
    if (added(u)) return 'This list is already added'
    return ''
  })

  async function toggle(f, el) {
    busyUrl = f.url
    try {
      await apiPut('/api/adguard/filtering', { action: 'toggle', url: f.url, name: f.name || source(f.url), enabled: el.checked })
      filters = filters.map((x) => (x.url === f.url ? { ...x, enabled: el.checked } : x))
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
      el.checked = !el.checked // put the switch back
    } finally {
      busyUrl = ''
    }
  }

  async function remove(f) {
    const ok = await confirm({
      title: 'Remove blocklist',
      message: `Remove ${f.name || source(f.url)}?`,
      description: `Its ${formatNumber(f.rules_count)} rules stop blocking. You can add it again later.`,
      confirmText: 'Remove',
    })
    if (!ok) return
    busyUrl = f.url
    try {
      await apiPut('/api/adguard/filtering', { action: 'remove', url: f.url })
      toast('Blocklist removed', 'success')
      await reload()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      busyUrl = ''
    }
  }

  async function updateAll() {
    updating = true
    try {
      await apiPut('/api/adguard/filtering', { action: 'refresh' })
      toast('Blocklists updated', 'success')
      await reload()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      updating = false
    }
  }

  function openAdd() {
    addMode = 'list'
    selected = []
    catalogSearch = newName = newUrl = ''
    addOpen = true
  }

  async function add() {
    const lists = addMode === 'manual'
      ? [{ name: newName.trim(), url: newUrl.trim() }]
      : blocklists.categories.flatMap((c) => c.lists).filter((l) => selected.includes(l.id)).map((l) => ({ name: l.name, url: l.url }))
    if (!lists.length) return
    adding = true
    try {
      const res = await apiPut('/api/adguard/filtering', { action: 'add', filters: lists })
      const ok = res.added?.length || 0
      const failed = res.errors?.length || 0
      if (ok) toast(`Added ${ok} blocklist${ok > 1 ? 's' : ''}`, 'success')
      if (failed) toast(`AdGuard couldn't add ${failed} blocklist${failed > 1 ? 's' : ''}`, 'error')
      addOpen = false
      await reload()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      adding = false
    }
  }
</script>

<div class="data-table">
  <div class="data-table-header">
    <div class="data-table-header-start">
      <!-- the summary is desktop only: on a phone the Overview's count says it -->
      <span class="hidden self-center text-xs text-muted-foreground sm:inline">
        {#if filters.length}<span class="font-semibold text-foreground">{enabledCount}</span> of {filters.length} on · {totalRules.toLocaleString()} rules{:else}No blocklists yet{/if}
      </span>
      <!-- search and add share a line, on a phone too -->
      <div class="flex flex-1 items-center gap-2 sm:justify-end">
        {#if filters.length > 1}
          <Input type="search" bind:value={search} placeholder="Search lists..." prefixIcon="search" class="min-w-0 flex-1 sm:max-w-56 sm:flex-none" />
        {/if}
        {#if filters.length}
          <Button variant="outline" icon="refresh" loading={updating} onclick={updateAll} class="shrink-0" title="Download every list again">Update all</Button>
        {/if}
        <Button icon="plus" onclick={openAdd} class="ml-auto shrink-0 sm:ml-0">Add</Button>
      </div>
    </div>
  </div>

  {#if !filters.length}
    <div class="p-6">
      <EmptyState icon="filter" title="No blocklists" description="Add lists of ad, tracker and malware domains; AdGuard downloads them and blocks what's on them." />
    </div>
  {:else if !shown.length}
    <p class="p-6 text-center text-xs text-muted-foreground">No list matches “{search}”.</p>
  {:else}
    <div class="data-table-content">
      <!-- table-stack: each list is a compact card on a phone -->
      <table class="table-stack">
        <thead>
          <tr>
            <th>List</th>
            <th class="text-right">Rules</th>
            <th>Updated</th>
            <th>On</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {#each shown as f (f.url)}
            <tr class="{f.enabled ? '' : 'opacity-60'} {busyUrl === f.url ? 'pointer-events-none opacity-50' : ''}">
              <td class="stack-main">
                <div class="truncate text-sm font-medium text-foreground" title={f.name}>{f.name || source(f.url)}</div>
                <div class="truncate font-mono text-[11px] text-muted-foreground" title={f.url}>{source(f.url)}</div>
              </td>
              <td class="data-table-cell-nowrap text-right tabular-nums">
                {#if broken(f)}
                  <Badge variant="warning" size="sm" title="AdGuard couldn't download it — check the address"><Icon name="alert-triangle" size={10} class="mr-1" />Not downloaded</Badge>
                {:else}
                  <span class="text-xs text-foreground">{(f.rules_count || 0).toLocaleString()}</span><span class="ml-1 text-xs text-muted-foreground sm:hidden">rules</span>
                {/if}
              </td>
              <td class="data-table-cell-nowrap text-xs text-muted-foreground">{neverUpdated(f) ? '—' : timeAgo(f.last_updated)}</td>
              <td class="data-table-cell-nowrap stack-right">
                <Checkbox variant="switch" checked={f.enabled} aria-label="{f.enabled ? 'Turn off' : 'Turn on'} {f.name}" onchange={(e) => toggle(f, e.target)} />
              </td>
              <td class="data-table-cell-actions stack-end">
                <Button variant="outline" size="xs" icon="trash" class="text-destructive hover:bg-destructive/10" tooltip="Remove list" aria-label="Remove {f.name}" onclick={() => remove(f)} />
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<Modal bind:open={addOpen} title="Add blocklist" size="lg">
  <Tabs tabs={[{ id: 'list', label: 'Choose from list', icon: 'list' }, { id: 'manual', label: 'Add by address', icon: 'link' }]}
    bind:activeTab={addMode} size="sm" class="-mt-2 mb-4" />

  {#if addMode === 'list'}
    <Input bind:value={catalogSearch} placeholder="Search blocklists..." prefixIcon="search" class="mb-4" />
    <div class="max-h-[400px] space-y-4 overflow-y-auto pr-2">
      {#each catalog as category}
        <div>
          <h4 class="mb-1 text-sm font-semibold text-foreground">{category.name}</h4>
          <p class="mb-2 text-xs text-muted-foreground">{category.description}</p>
          <div class="space-y-1">
            {#each category.lists as list}
              {@const isAdded = added(list.url)}
              {@const isSelected = selected.includes(list.id)}
              <Checkbox checked={isSelected || isAdded} disabled={isAdded}
                onchange={() => (selected = isSelected ? selected.filter((id) => id !== list.id) : [...selected, list.id])}
                class="!flex !gap-3 rounded-lg border p-2 transition-colors {isAdded ? 'border-success/30 bg-success/5 opacity-60' : isSelected ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50'}">
                <div class="min-w-0 flex-1 text-sm font-medium text-foreground">{list.name}</div>
                {#if isAdded}<Badge variant="success" size="sm">Added</Badge>{/if}
              </Checkbox>
            {/each}
          </div>
        </div>
      {/each}
    </div>
  {:else}
    <div class="space-y-4">
      <Input label="Name" bind:value={newName} placeholder="My blocklist" />
      <Input label="Address" bind:value={newUrl} placeholder="https://lists.example.com/hosts.txt"
        hint="A public https:// link to a hosts file or an AdBlock-style list" />
      {#if urlProblem}
        <p class="flex items-center gap-1.5 text-xs text-destructive"><Icon name="alert-triangle" size={14} />{urlProblem}</p>
      {/if}
    </div>
  {/if}

  {#snippet footer()}
    {#if addMode === 'list'}<span class="mr-auto text-sm text-muted-foreground">{selected.length} selected</span>{/if}
    <Button variant="secondary" onclick={() => (addOpen = false)}>Cancel</Button>
    {#if addMode === 'list'}
      <Button onclick={add} loading={adding} disabled={!selected.length}>Add {selected.length || ''} blocklist{selected.length === 1 ? '' : 's'}</Button>
    {:else}
      <Button onclick={add} loading={adding} disabled={!newName.trim() || !newUrl.trim() || !!urlProblem}>Add blocklist</Button>
    {/if}
  {/snippet}
</Modal>
