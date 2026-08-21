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

  const isCveId = (id) => /^CVE-/i.test(id)
  const sevDot = { CRITICAL: 'bg-destructive', HIGH: 'bg-warning', MEDIUM: 'bg-info', LOW: 'bg-muted-foreground/60', UNKNOWN: 'bg-muted-foreground/30' }
  const sevChips = $derived(summary ? [
    { key: '', label: 'All', count: summary.unique_cves, cls: 'bg-muted-foreground/50' },
    { key: 'CRITICAL', label: 'Critical', count: summary.u_critical, cls: sevDot.CRITICAL },
    { key: 'HIGH', label: 'High', count: summary.u_high, cls: sevDot.HIGH },
    { key: 'MEDIUM', label: 'Medium', count: summary.u_medium, cls: sevDot.MEDIUM },
    { key: 'LOW', label: 'Low', count: summary.u_low, cls: sevDot.LOW },
    { key: 'UNKNOWN', label: 'Unknown', count: summary.u_unknown, cls: sevDot.UNKNOWN },
  ] : [])
  const dist = $derived(summary && summary.unique_cves ? [
    { n: summary.u_critical, cls: sevDot.CRITICAL, label: 'Critical' },
    { n: summary.u_high, cls: sevDot.HIGH, label: 'High' },
    { n: summary.u_medium, cls: sevDot.MEDIUM, label: 'Medium' },
    { n: summary.u_low, cls: sevDot.LOW, label: 'Low' },
    { n: summary.u_unknown, cls: sevDot.UNKNOWN, label: 'Unknown' },
  ].map((s) => ({ ...s, pct: Math.round((s.n / summary.unique_cves) * 1000) / 10 })) : [])
  function pickSeverity(k) { severity = k; applyFilters() }
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
  </div>

  <!-- KPI tiles -->
  {#if summary}
    <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
      <div class="bg-card border border-border rounded-xl p-3">
        <div class="text-[10px] uppercase tracking-wide text-muted-foreground font-medium">Findings</div>
        <div class="text-2xl font-bold tabular-nums text-foreground">{summary.total.toLocaleString()}</div>
        <div class="text-[11px] text-muted-foreground">CVE × package rows</div>
      </div>
      <div class="bg-card border border-border rounded-xl p-3">
        <div class="text-[10px] uppercase tracking-wide text-muted-foreground font-medium">Unique CVEs</div>
        <div class="text-2xl font-bold tabular-nums text-foreground">{summary.unique_cves.toLocaleString()}</div>
        <div class="text-[11px] text-muted-foreground">distinct advisories</div>
      </div>
      <div class="bg-card border border-border rounded-xl p-3">
        <div class="text-[10px] uppercase tracking-wide text-muted-foreground font-medium">Packages affected</div>
        <div class="text-2xl font-bold tabular-nums text-foreground">{summary.packages.toLocaleString()}</div>
        <div class="text-[11px] text-muted-foreground">across OS + app deps</div>
      </div>
      <div class="bg-card border border-border rounded-xl p-3">
        <div class="text-[10px] uppercase tracking-wide text-muted-foreground font-medium flex items-center gap-1"><Icon name="tool" size={11} class="text-success" />Fixable</div>
        <div class="text-2xl font-bold tabular-nums text-success">{summary.fixable.toLocaleString()}</div>
        <div class="text-[11px] text-muted-foreground">have an upgrade</div>
      </div>
    </div>

    <!-- Severity distribution -->
    {#if summary.unique_cves}
      <div class="bg-card border border-border rounded-xl p-4">
        <div class="flex items-center justify-between mb-2">
          <h3 class="text-sm font-semibold text-foreground">Severity distribution</h3>
          <span class="text-[11px] text-muted-foreground">share of {summary.unique_cves.toLocaleString()} unique CVEs</span>
        </div>
        <div class="flex h-2.5 rounded-full overflow-hidden bg-muted">
          {#each dist as s}
            {#if s.pct > 0}<div class={s.cls} style="width:{s.pct}%" title="{s.label}: {s.n.toLocaleString()} ({s.pct}%)"></div>{/if}
          {/each}
        </div>
        <div class="flex flex-wrap gap-x-4 gap-y-1 mt-2.5">
          {#each dist as s}
            <div class="flex items-center gap-1.5 text-[11px]">
              <span class="w-2 h-2 rounded-sm {s.cls}"></span>
              <span class="text-muted-foreground">{s.label}</span>
              <span class="tabular-nums font-medium text-foreground">{s.n.toLocaleString()}</span>
              <span class="text-muted-foreground">{s.pct}%</span>
            </div>
          {/each}
        </div>
      </div>
    {/if}
  {/if}

  <!-- filters: severity chips + fixable toggle + search -->
  <div class="bg-card border border-border rounded-xl p-3 flex flex-wrap items-center gap-x-3 gap-y-2">
    <div class="flex flex-wrap items-center gap-1.5">
      {#each sevChips as c}
        <button onclick={() => pickSeverity(c.key)}
          class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs transition cursor-pointer
                 {severity === c.key ? 'border-primary bg-primary/10 text-foreground' : 'border-border text-muted-foreground hover:text-foreground hover:border-ring'}">
          <span class="w-1.5 h-1.5 rounded-sm {c.cls}"></span>{c.label}
          <span class="text-[11px] opacity-80 tabular-nums">{c.count.toLocaleString()}</span>
        </button>
      {/each}
    </div>
    <Checkbox variant="switch" bind:checked={fixable} label="Has a fix" onchange={applyFilters} />
    <div class="flex-1 min-w-[180px] ml-auto">
      <Input bind:value={q} prefixIcon="search" placeholder="Search CVE id or package…" onkeydown={(e) => e.key === 'Enter' && applyFilters()} />
    </div>
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

  <!-- sticky selection bar -->
  {#if selected.size > 0}
    <div class="sticky bottom-4 z-10 bg-card border border-primary/40 rounded-xl shadow-lg p-3 flex items-center gap-3">
      <Icon name="checks" size={16} class="text-primary shrink-0" />
      <span class="text-sm text-foreground"><b class="tabular-nums">{selected.size}</b> package{selected.size === 1 ? '' : 's'} selected</span>
      <div class="ml-auto flex items-center gap-2">
        <Button variant="ghost" size="sm" onclick={() => (selected = new Set())}>Clear</Button>
        <Button variant="primary" size="sm" icon="refresh-alert" onclick={fixSelected} loading={fixing}>Fix selected</Button>
      </div>
    </div>
  {/if}
</div>
