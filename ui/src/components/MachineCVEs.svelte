<script>
  /**
   * MachineCVEs — the full vulnerability drill-down for one machine. Findings are grouped
   * by OS vs each app project/lockfile; you can filter by severity / fixable / search, and
   * select fixable OS-package CVEs to push a targeted upgrade to the agent. App/lockfile
   * CVEs are shown for context but can't be agent-fixed (the app owner bumps the dep).
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, apiGetBlob, toast, confirm } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Badge from './Badge.svelte'
  import Input from './Input.svelte'
  import Select from './Select.svelte'
  import Checkbox from './Checkbox.svelte'
  import EmptyState from './EmptyState.svelte'
  import { sevVariant } from '$lib/fleet.js'

  let { machine, onback } = $props()

  let groups = $state([])
  let cves = $state([])
  let total = $state(0)
  let loading = $state(true)
  let fixing = $state(false)

  // filters
  let project = $state('') // '' = all
  let severity = $state('')
  let fixable = $state(false)
  let q = $state('')
  let page = $state(0)
  const PAGE = 100

  // selection: distinct package names to fix (OS-package fixable CVEs only)
  let selected = $state(new Set())

  // Kernel packages can't be targeted-upgraded (Trivy names the installed kernel; the fix
  // is a different kernel) — they need "Update kernel & reboot", not a per-package fix.
  const isKernelPkg = (pkg) => /^linux-(image|headers|modules|tools|cloud-tools|buildinfo|generic)/.test(pkg || '')
  const isOSFixable = (c) => c.class === 'os-pkgs' && !!c.fixed && !isKernelPkg(c.pkg)
  const activeGroup = $derived(groups.find((g) => g.project === project))
  const inKernel = $derived(project === 'Kernel')
  const pageCount = $derived(Math.max(1, Math.ceil(total / PAGE)))

  function filterParams() {
    const p = new URLSearchParams({ machine_id: machine.id })
    if (project) p.set('project', project)
    if (severity) p.set('severity', severity)
    if (fixable) p.set('fixable', '1')
    if (q.trim()) p.set('q', q.trim())
    return p
  }
  async function loadGroups() {
    try { groups = (await apiGet('/api/fleet/cves/groups?machine_id=' + encodeURIComponent(machine.id))) || [] } catch { groups = [] }
  }
  async function loadList() {
    const p = filterParams()
    p.set('limit', String(PAGE)); p.set('offset', String(page * PAGE))
    try {
      const res = await apiGet('/api/fleet/cves?' + p.toString())
      cves = res.cves || []
      total = res.total || 0
    } catch { cves = []; total = 0 }
    finally { loading = false }
  }
  onMount(async () => { await loadGroups(); await loadList() })

  function applyFilters() { selected = new Set(); page = 0; loadList() }
  function goPage(n) { page = Math.min(Math.max(0, n), pageCount - 1); loadList() }

  async function updateKernel() {
    const ok = await confirm({
      title: `Update kernel · ${machine.name}`,
      message: `Run the full kernel update on ${machine.name}? This installs the newest kernel, then AUTOMATICALLY REBOOTS the host to activate it, and after it boots back up it purges the old kernels and re-scans — so the kernel CVEs clear on their own. The host will be briefly offline during the reboot. Honors dry-run (nothing changes, no reboot).`,
      confirmText: 'Update kernel & reboot', variant: 'danger',
    })
    if (!ok) return
    try {
      await apiPost('/api/fleet/command', { machine_id: machine.id, type: 'update-kernel' })
      toast('Kernel update queued — the host will reboot itself and finish cleanup automatically', 'success')
    } catch (e) { toast('Failed: ' + e.message, 'error') }
  }

  async function exportCSV() {
    try {
      const blob = await apiGetBlob('/api/fleet/cves/export?' + filterParams().toString())
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = `cves-${machine.name || machine.id}.csv`
      document.body.appendChild(a); a.click(); a.remove()
      URL.revokeObjectURL(url)
    } catch (e) { toast('Export failed: ' + e.message, 'error') }
  }

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
  const groupLabel = (g) => (g.project === 'OS' ? 'OS packages' : g.project === 'Kernel' ? 'Kernel' : g.project)
  const groupOptions = $derived([
    { value: '', label: `All projects (${groups.reduce((a, g) => a + g.total, 0).toLocaleString()})` },
    ...groups.map((g) => ({ value: g.project, label: `${groupLabel(g)} · ${g.total}${g.critical ? ` (${g.critical} crit)` : ''}` })),
  ])
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
    <Button variant="outline" size="sm" icon="download" onclick={exportCSV}>Export CSV</Button>
    {#if selected.size > 0}
      <Button variant="primary" size="sm" icon="refresh-alert" onclick={fixSelected} loading={fixing}>Fix selected ({selected.size})</Button>
    {/if}
  </div>

  <!-- filters -->
  <div class="bg-card border border-border rounded-xl p-3 flex flex-wrap items-end gap-2">
    <div class="min-w-[220px] max-w-[320px] flex-1">
      <Select bind:value={project} label="Project / OS" options={groupOptions} onchange={applyFilters} />
    </div>
    <div class="min-w-[150px]"><Select bind:value={severity} label="Severity" options={sevOptions} onchange={applyFilters} /></div>
    <div class="flex-1 min-w-[160px]"><Input bind:value={q} label="Search" prefixIcon="search" placeholder="CVE id or package" onkeydown={(e) => e.key === 'Enter' && applyFilters()} /></div>
    <Checkbox bind:checked={fixable} label="Has a fix" onchange={applyFilters} class="px-1 py-2" />
    <Button size="sm" icon="filter" onclick={applyFilters}>Apply</Button>
    {#if inKernel}
      <Button variant="primary" size="sm" icon="refresh-alert" onclick={updateKernel}>Update kernel & reboot</Button>
    {:else if activeGroup && activeGroup.class === 'os-pkgs'}
      <Button variant="outline" size="sm" icon="checks" onclick={selectAllFixableHere}>Select fixable</Button>
    {/if}
  </div>

  <!-- context note for the active group -->
  {#if inKernel}
    <div class="text-[11px] text-muted-foreground flex items-start gap-1.5 px-1">
      <Icon name="info-circle" size={13} class="mt-0.5 shrink-0" />
      Kernel CVEs can't be fixed per-package (the fix is a different kernel version). Use <b>Update kernel &amp; reboot</b> → it installs the newest kernel; then reboot the host and rescan. The old kernel's findings clear once it's autoremoved after the reboot.
    </div>
  {:else if activeGroup && activeGroup.class !== 'os-pkgs'}
    <div class="text-[11px] text-muted-foreground flex items-start gap-1.5 px-1">
      <Icon name="info-circle" size={13} class="mt-0.5 shrink-0" />
      This is an app dependency in <span class="font-mono">{activeGroup.project}</span> — the agent can't fix it. Bump the dependency in that project to the fixed version and redeploy.
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
                <td class="py-1.5 px-2 text-muted-foreground max-w-[220px] truncate" title={c.target}>{c.class === 'os-pkgs' ? 'OS' : (c.project || c.target)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if pageCount > 1}
        <div class="p-2 border-t border-border flex items-center justify-between text-xs">
          <Button variant="ghost" size="xs" icon="chevron-left" onclick={() => goPage(page - 1)} disabled={page === 0}>Prev</Button>
          <span class="text-muted-foreground">Page {page + 1} of {pageCount.toLocaleString()} · {total.toLocaleString()} findings</span>
          <Button variant="ghost" size="xs" icon="chevron-right" onclick={() => goPage(page + 1)} disabled={page >= pageCount - 1}>Next</Button>
        </div>
      {/if}
    </div>
    <div class="text-[11px] text-muted-foreground px-1">
      Tick fixable OS packages, then <b>Fix selected</b> — the agent runs a targeted upgrade of just those. App-dependency rows have no checkbox (fix them in the project).
    </div>
  {/if}
</div>
