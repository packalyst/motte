<script>
  /**
   * MachineCVEs — CVE-first vulnerability view for one machine. The list is ONE row per
   * unique CVE (worst severity, affected-package count, fixable). Click a CVE to expand and
   * load its affected packages; tick fixable OS packages to push a targeted upgrade. Kernel
   * CVEs expand to an "Update kernel & reboot" action instead (the fix is a new kernel).
   * Filters + page are persisted per machine so a refresh lands you back where you were.
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

  let summary = $state(null) // { total, unique_cves, packages, critical, high, ..., fixable }
  let hasKernel = $state(false)
  let rows = $state([]) // unique CVEs: { cve_id, severity, packages, fixable, title }
  let total = $state(0)
  let loading = $state(true)
  let fixing = $state(false)

  // filters — default to "has a fix" so the actionable set leads. Persisted per machine.
  let severity = $state('')
  let fixable = $state(true)
  let q = $state('')
  let page = $state(0)
  const PAGE = 50

  // expand state: cve_id -> { loading, items:[findings] }
  let details = $state({})
  // selection of fixable OS-package names to upgrade
  let selected = $state(new Set())

  const isKernelPkg = (pkg) => /^linux-(image|headers|modules|tools|cloud-tools|buildinfo|generic)/.test(pkg || '')
  const isOSFixable = (c) => c.class === 'os-pkgs' && !!c.fixed && !isKernelPkg(c.pkg)
  const isKernelCve = (items) => items.length > 0 && items.every((c) => isKernelPkg(c.pkg))
  const pageCount = $derived(Math.max(1, Math.ceil(total / PAGE)))

  const FKEY = 'cveflt:' + machine.id
  function saveFilters() {
    try { localStorage.setItem(FKEY, JSON.stringify({ severity, fixable, q, page })) } catch {}
  }
  function restoreFilters() {
    try {
      const s = JSON.parse(localStorage.getItem(FKEY) || 'null')
      if (s) { severity = s.severity || ''; fixable = s.fixable !== false; q = s.q || ''; page = s.page || 0 }
    } catch {}
  }

  function listParams() {
    const p = new URLSearchParams({ machine_id: machine.id })
    if (severity) p.set('severity', severity)
    if (fixable) p.set('fixable', '1')
    if (q.trim()) p.set('q', q.trim())
    return p
  }

  async function loadSummary() {
    try {
      const res = await apiGet('/api/fleet/cves/groups?machine_id=' + encodeURIComponent(machine.id))
      summary = res?.summary || null
      hasKernel = (res?.groups || []).some((g) => g.project === 'Kernel')
    } catch { summary = null }
  }
  async function loadList() {
    loading = true
    const p = listParams()
    p.set('limit', String(PAGE)); p.set('offset', String(page * PAGE))
    try {
      const res = await apiGet('/api/fleet/cves/by-cve?' + p.toString())
      rows = res.cves || []
      total = res.total || 0
    } catch { rows = []; total = 0 }
    finally { loading = false }
  }
  onMount(async () => { restoreFilters(); await loadSummary(); await loadList() })

  function applyFilters() { page = 0; details = {}; saveFilters(); loadList() }
  function goPage(n) { page = Math.min(Math.max(0, n), pageCount - 1); details = {}; saveFilters(); loadList() }

  // Expand/collapse a CVE, loading its affected packages on first open.
  async function toggleExpand(cveId) {
    if (details[cveId]) { const d = { ...details }; delete d[cveId]; details = d; return }
    details = { ...details, [cveId]: { loading: true, items: [] } }
    const p = new URLSearchParams({ machine_id: machine.id, cve_id: cveId, limit: '200' })
    try {
      const res = await apiGet('/api/fleet/cves?' + p.toString())
      details = { ...details, [cveId]: { loading: false, items: res.cves || [] } }
    } catch {
      details = { ...details, [cveId]: { loading: false, items: [] } }
    }
  }

  function toggleSel(c) {
    if (!isOSFixable(c)) return
    const n = new Set(selected)
    n.has(c.pkg) ? n.delete(c.pkg) : n.add(c.pkg)
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
    } catch (e) { toast('Failed: ' + e.message, 'error') }
    finally { fixing = false }
  }

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
      const blob = await apiGetBlob('/api/fleet/cves/export?' + listParams().toString())
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = `cves-${machine.name || machine.id}.csv`
      document.body.appendChild(a); a.click(); a.remove()
      URL.revokeObjectURL(url)
    } catch (e) { toast('Export failed: ' + e.message, 'error') }
  }

  const sevOptions = [{ value: '', label: 'All severities' }, ...['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => ({ value: s, label: s[0] + s.slice(1).toLowerCase() }))]
  const isCveId = (id) => /^CVE-/i.test(id)
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
      <div class="text-[11px] text-muted-foreground truncate">{machine.name || machine.id} · {total.toLocaleString()} CVE{total === 1 ? '' : 's'} matching</div>
    </div>
    <Button variant="outline" size="sm" icon="download" onclick={exportCSV}>Export CSV</Button>
    {#if hasKernel}
      <Button variant="primary" size="sm" icon="cpu" onclick={updateKernel}>Update kernel & reboot</Button>
    {/if}
    {#if selected.size > 0}
      <Button variant="primary" size="sm" icon="refresh-alert" onclick={fixSelected} loading={fixing}>Fix selected ({selected.size})</Button>
    {/if}
  </div>

  <!-- machine-level roll-up -->
  {#if summary}
    <div class="bg-card border border-border rounded-xl p-3 flex flex-wrap items-center gap-x-5 gap-y-2">
      <div class="flex items-center gap-1.5">
        {#if summary.critical}<Badge variant="danger" size="sm">{summary.critical.toLocaleString()} critical</Badge>{/if}
        {#if summary.high}<Badge variant="warning" size="sm">{summary.high.toLocaleString()} high</Badge>{/if}
        {#if summary.medium}<Badge variant="info" size="sm">{summary.medium.toLocaleString()} medium</Badge>{/if}
        {#if summary.low}<Badge variant="muted" size="sm">{summary.low.toLocaleString()} low</Badge>{/if}
      </div>
      <div class="flex items-center gap-1.5 text-sm">
        <Icon name="tool" size={14} class="text-success" />
        <span class="font-semibold text-foreground">{summary.fixable.toLocaleString()}</span>
        <span class="text-muted-foreground">fixable</span>
      </div>
      <div class="text-[11px] text-muted-foreground ml-auto">
        {summary.unique_cves.toLocaleString()} CVEs · {summary.packages.toLocaleString()} packages · {summary.total.toLocaleString()} findings
      </div>
    </div>
  {/if}

  <!-- filters -->
  <div class="bg-card border border-border rounded-xl p-3 flex flex-wrap items-end gap-2">
    <div class="min-w-[150px]"><Select bind:value={severity} label="Severity" options={sevOptions} onchange={applyFilters} /></div>
    <div class="flex-1 min-w-[180px]"><Input bind:value={q} label="Search" prefixIcon="search" placeholder="CVE id or package" onkeydown={(e) => e.key === 'Enter' && applyFilters()} /></div>
    <Checkbox bind:checked={fixable} label="Has a fix" onchange={applyFilters} class="px-1 py-2" />
    <Button size="sm" icon="filter" onclick={applyFilters}>Apply</Button>
  </div>

  <!-- list -->
  {#if loading && rows.length === 0}
    <div class="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">Loading…</div>
  {:else if rows.length === 0}
    <div class="bg-card border border-border rounded-xl p-8"><EmptyState icon="circle-check" title="No matching vulnerabilities" description="Nothing matches these filters." /></div>
  {:else}
    <div class="bg-card border border-border rounded-xl overflow-hidden divide-y divide-border">
      {#each rows as c (c.cve_id)}
        {@const det = details[c.cve_id]}
        <!-- CVE row header -->
        <div class="flex items-center gap-2 px-3 py-2 hover:bg-muted/40 cursor-pointer"
          role="button" tabindex="0"
          onclick={() => toggleExpand(c.cve_id)}
          onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleExpand(c.cve_id))}>
          <Icon name={det ? 'chevron-down' : 'chevron-right'} size={14} class="text-muted-foreground shrink-0" />
          <Badge variant={sevVariant(c.severity)} size="sm">{(c.severity || '').toLowerCase()}</Badge>
          <span class="font-mono text-xs text-foreground shrink-0">{c.cve_id}</span>
          {#if isCveId(c.cve_id)}
            <a href={`https://nvd.nist.gov/vuln/detail/${c.cve_id}`} target="_blank" rel="noopener noreferrer"
              onclick={(e) => e.stopPropagation()} title="View on NVD" class="text-info hover:underline shrink-0"><Icon name="external-link" size={11} /></a>
          {/if}
          {#if c.fixable}<Badge variant="success" size="sm">fixable</Badge>{/if}
          <span class="text-[11px] text-muted-foreground truncate flex-1 min-w-0" title={c.title}>{c.title || ''}</span>
          <span class="text-[11px] text-muted-foreground shrink-0 tabular-nums">{c.packages} pkg{c.packages === 1 ? '' : 's'}</span>
        </div>

        <!-- expanded: affected packages -->
        {#if det}
          <div class="bg-muted/20 px-3 py-2 border-t border-border/60">
            {#if det.loading}
              <div class="text-xs text-muted-foreground py-1.5 flex items-center gap-2"><Icon name="loader-2" size={13} class="animate-spin" />Loading affected packages…</div>
            {:else if det.items.length === 0}
              <div class="text-xs text-muted-foreground py-1.5">No package details.</div>
            {:else if isKernelCve(det.items)}
              <div class="text-[11px] text-muted-foreground flex items-start gap-1.5 py-1">
                <Icon name="info-circle" size={13} class="mt-0.5 shrink-0" />
                <div>Kernel CVE — can't be fixed per-package (the fix is a newer kernel). Affects: <span class="font-mono">{det.items.map((c) => c.pkg).join(', ')}</span>.
                  Use <button class="text-primary hover:underline font-medium" onclick={updateKernel}>Update kernel &amp; reboot</button> → it installs the newest kernel, reboots, and rescans.</div>
              </div>
            {:else}
              <table class="w-full text-xs">
                <tbody>
                  {#each det.items as c}
                    <tr class="border-b border-border/40 last:border-0">
                      <td class="py-1.5 pr-2 w-8">
                        {#if isOSFixable(c)}
                          <input type="checkbox" checked={selected.has(c.pkg)} onchange={() => toggleSel(c)} class="w-4 h-4 accent-primary cursor-pointer" title="Select {c.pkg} for fixing" />
                        {:else}
                          <span class="inline-block w-4" title={c.class === 'os-pkgs' ? 'no fix available' : 'app dependency — fix in the project'}></span>
                        {/if}
                      </td>
                      <td class="py-1.5 pr-2 font-mono">{c.pkg}</td>
                      <td class="py-1.5 pr-2 font-mono whitespace-nowrap"><span class="text-muted-foreground">{c.installed || '?'}</span>{#if c.fixed}<span class="text-success"> → {c.fixed}</span>{:else}<span class="text-muted-foreground"> → no fix</span>{/if}</td>
                      <td class="py-1.5 text-muted-foreground max-w-[200px] truncate" title={c.target}>{c.class === 'os-pkgs' ? 'OS' : (c.project || c.target)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {/if}
          </div>
        {/if}
      {/each}
    </div>

    {#if pageCount > 1}
      <div class="bg-card border border-border rounded-xl p-2 flex items-center justify-between text-xs">
        <Button variant="ghost" size="xs" icon="chevron-left" onclick={() => goPage(page - 1)} disabled={page === 0}>Prev</Button>
        <span class="text-muted-foreground">Page {page + 1} of {pageCount.toLocaleString()} · {total.toLocaleString()} CVEs</span>
        <Button variant="ghost" size="xs" icon="chevron-right" onclick={() => goPage(page + 1)} disabled={page >= pageCount - 1}>Next</Button>
      </div>
    {/if}
    <div class="text-[11px] text-muted-foreground px-1">
      Click a CVE to see its affected packages. Tick fixable OS packages, then <b>Fix selected</b> — the agent runs a targeted upgrade of just those.
    </div>
  {/if}
</div>
