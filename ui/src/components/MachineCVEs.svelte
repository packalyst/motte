<script>
  /**
   * MachineCVEs — the full vulnerability drill-down for one machine. Findings are grouped
   * by OS vs each app project/lockfile; you can filter by severity / fixable / search, and
   * select fixable OS-package CVEs to push a targeted upgrade to the agent. App/lockfile
   * CVEs are shown for context but can't be agent-fixed (the app owner bumps the dep).
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast, confirm } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Badge from './Badge.svelte'
  import Input from './Input.svelte'
  import Select from './Select.svelte'
  import EmptyState from './EmptyState.svelte'
  import { sevVariant } from '$lib/fleet.js'

  let { machine, onback } = $props()

  let groups = $state([])
  let cves = $state([])
  let total = $state(0)
  let loading = $state(true)
  let fixing = $state(false)

  // filters
  let target = $state('') // '' = all groups
  let severity = $state('')
  let fixable = $state(false)
  let q = $state('')
  let offset = $state(0)
  const PAGE = 200

  // selection: distinct package names to fix (OS-package fixable CVEs only)
  let selected = $state(new Set())

  const isOSFixable = (c) => c.class === 'os-pkgs' && !!c.fixed
  const activeGroup = $derived(groups.find((g) => g.target === target))

  async function loadGroups() {
    try { groups = (await apiGet('/api/fleet/cves/groups?machine_id=' + encodeURIComponent(machine.id))) || [] } catch { groups = [] }
  }
  async function loadList(reset = true) {
    if (reset) { offset = 0 }
    const p = new URLSearchParams({ machine_id: machine.id, limit: String(PAGE), offset: String(offset) })
    if (target) p.set('target', target)
    if (severity) p.set('severity', severity)
    if (fixable) p.set('fixable', '1')
    if (q.trim()) p.set('q', q.trim())
    try {
      const res = await apiGet('/api/fleet/cves?' + p.toString())
      cves = offset === 0 ? (res.cves || []) : [...cves, ...(res.cves || [])]
      total = res.total || 0
    } catch { if (offset === 0) { cves = []; total = 0 } }
    finally { loading = false }
  }
  onMount(async () => { await loadGroups(); await loadList() })

  function applyFilters() { selected = new Set(); loadList(true) }
  function pickGroup(t) { target = target === t ? '' : t; applyFilters() }
  function loadMore() { offset += PAGE; loadList(false) }

  function toggle(c) {
    if (!isOSFixable(c)) return
    const n = new Set(selected)
    n.has(c.pkg) ? n.delete(c.pkg) : n.add(c.pkg)
    selected = n
  }
  function selectAllFixableHere() {
    const n = new Set(selected)
    for (const c of cves) if (isOSFixable(c)) n.add(c.pkg)
    selected = n
  }

  async function fixSelected() {
    const packages = [...selected]
    if (!packages.length) return
    const ok = await confirm({
      title: `Fix ${packages.length} package${packages.length > 1 ? 's' : ''} · ${machine.name}`,
      message: `Queue a targeted upgrade of: ${packages.slice(0, 12).join(', ')}${packages.length > 12 ? '…' : ''}? The agent runs it on its next check-in (honors dry-run).`,
      confirmText: 'Queue fix', variant: 'primary',
    })
    if (!ok) return
    fixing = true
    try {
      const res = await apiPost('/api/fleet/fix', { machine_id: machine.id, packages })
      toast(`Queued upgrade of ${res.count} packages`, 'success')
      selected = new Set()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally { fixing = false }
  }

  const sevOptions = [{ value: '', label: 'All severities' }, ...['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => ({ value: s, label: s[0] + s.slice(1).toLowerCase() }))]
  const groupLabel = (g) => (g.class === 'os-pkgs' ? `OS · ${g.type || g.target}` : g.target)
</script>

<div class="space-y-4">
  <!-- header -->
  <div class="flex items-center gap-3 flex-wrap">
    <button onclick={onback} title="Back to machine"
      class="h-8 w-8 grid place-items-center rounded-lg border border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground transition cursor-pointer shrink-0">
      <Icon name="arrow-left" size={16} />
    </button>
    <div class="min-w-0 flex-1">
      <div class="text-lg font-semibold text-foreground truncate leading-tight">Vulnerabilities</div>
      <div class="text-[11px] text-muted-foreground truncate">{machine.name || machine.id} · {total.toLocaleString()} matching</div>
    </div>
    {#if selected.size > 0}
      <Button variant="primary" size="sm" icon="refresh-alert" onclick={fixSelected} loading={fixing}>Fix selected ({selected.size})</Button>
    {/if}
  </div>

  <!-- groups -->
  {#if groups.length}
    <div class="flex flex-wrap gap-2">
      <button onclick={() => pickGroup('')} class="px-3 py-1.5 rounded-lg border text-xs transition cursor-pointer {target === '' ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:bg-muted'}">
        All ({groups.reduce((a, g) => a + g.total, 0).toLocaleString()})
      </button>
      {#each groups as g}
        <button onclick={() => pickGroup(g.target)} title={g.target}
          class="px-3 py-1.5 rounded-lg border text-xs flex items-center gap-2 transition cursor-pointer {target === g.target ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:bg-muted'}">
          <Icon name={g.class === 'os-pkgs' ? 'package' : 'code'} size={13} />
          <span class="max-w-[220px] truncate">{groupLabel(g)}</span>
          {#if g.critical}<span class="text-[10px] text-destructive font-semibold">{g.critical}c</span>{/if}
          <span class="text-[10px] opacity-70">{g.total}</span>
        </button>
      {/each}
    </div>
  {/if}

  <!-- filters -->
  <div class="bg-card border border-border rounded-xl p-3 flex flex-wrap items-end gap-2">
    <div class="flex-1 min-w-[160px]"><Input bind:value={q} prefixIcon="search" placeholder="CVE id or package" onkeydown={(e) => e.key === 'Enter' && applyFilters()} /></div>
    <div class="min-w-[150px]"><Select bind:value={severity} options={sevOptions} onchange={applyFilters} /></div>
    <label class="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer px-2 py-2">
      <input type="checkbox" bind:checked={fixable} onchange={applyFilters} class="w-4 h-4 accent-primary" /> Has a fix
    </label>
    <Button size="sm" icon="filter" onclick={applyFilters}>Apply</Button>
    {#if activeGroup && activeGroup.class === 'os-pkgs'}
      <Button variant="outline" size="sm" icon="checks" onclick={selectAllFixableHere}>Select fixable on page</Button>
    {/if}
  </div>

  <!-- context note for the active group -->
  {#if activeGroup && activeGroup.class !== 'os-pkgs'}
    <div class="text-[11px] text-muted-foreground flex items-start gap-1.5 px-1">
      <Icon name="info-circle" size={13} class="mt-0.5 shrink-0" />
      This is an app dependency in <span class="font-mono">{activeGroup.target}</span> — the agent can't fix it. Bump the dependency in that project to the fixed version and redeploy.
    </div>
  {/if}

  <!-- list -->
  {#if loading && cves.length === 0}
    <div class="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">Loading…</div>
  {:else if cves.length === 0}
    <div class="bg-card border border-border rounded-xl p-8"><EmptyState icon="circle-check" title="No matching vulnerabilities" description="Nothing matches these filters." /></div>
  {:else}
    <div class="bg-card border border-border rounded-xl overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-xs">
          <thead>
            <tr class="text-[11px] text-muted-foreground text-left border-b border-border">
              <th class="py-2 px-3 w-8"></th>
              <th class="py-2 px-2 font-medium">Sev</th>
              <th class="py-2 px-2 font-medium">CVE</th>
              <th class="py-2 px-2 font-medium">Package</th>
              <th class="py-2 px-2 font-medium">Installed → Fix</th>
              <th class="py-2 px-2 font-medium">Source</th>
            </tr>
          </thead>
          <tbody>
            {#each cves as c}
              <tr class="border-b border-border/50 hover:bg-muted/40">
                <td class="py-1.5 px-3">
                  {#if isOSFixable(c)}
                    <input type="checkbox" checked={selected.has(c.pkg)} onchange={() => toggle(c)} class="w-4 h-4 accent-primary cursor-pointer" title="Select {c.pkg} for fixing" />
                  {:else}
                    <span class="inline-block w-4" title={c.class === 'os-pkgs' ? 'no fix available' : 'app dependency — fix in the project'}></span>
                  {/if}
                </td>
                <td class="py-1.5 px-2"><Badge variant={sevVariant(c.severity)} size="sm">{(c.severity || '').toLowerCase()}</Badge></td>
                <td class="py-1.5 px-2 font-mono whitespace-nowrap" title={c.title}>{c.cve_id}</td>
                <td class="py-1.5 px-2 font-mono">{c.pkg}</td>
                <td class="py-1.5 px-2 font-mono whitespace-nowrap"><span class="text-muted-foreground">{c.installed || '?'}</span>{#if c.fixed}<span class="text-success"> → {c.fixed}</span>{:else}<span class="text-muted-foreground"> → no fix</span>{/if}</td>
                <td class="py-1.5 px-2 text-muted-foreground max-w-[220px] truncate" title={c.target}>{c.class === 'os-pkgs' ? 'OS' : c.target}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if cves.length < total}
        <div class="p-2 border-t border-border text-center">
          <Button variant="ghost" size="xs" icon="chevron-down" onclick={loadMore}>Load more ({(total - cves.length).toLocaleString()} left)</Button>
        </div>
      {/if}
    </div>
    <div class="text-[11px] text-muted-foreground px-1">
      Tick fixable OS packages, then <b>Fix selected</b> — the agent runs a targeted upgrade of just those. App-dependency rows have no checkbox (fix them in the project).
    </div>
  {/if}
</div>
