<script>
  /**
   * ScanHistory — a machine's vulnerability scans: a trend (distinct CVEs per scan, split by
   * severity) and the list, newest first, each with what changed since the scan before.
   * Only summaries are stored; the findings themselves are the latest scan's (View all & fix).
   * reloadKey changes when a scan lands or fails, which refetches.
   */
  import { apiGet } from '../stores/app.js'
  import { SEV } from '$lib/fleet.js'
  import { formatBytes, formatDate, timeAgo, formatBanTime } from '$lib/utils/format.js'
  import Icon from './Icon.svelte'

  let { machineId, reloadKey = '' } = $props()

  let scans = $state([])
  let loaded = $state(false)
  let showAll = $state(false)
  let open = $state(null) // scanned_at whose changes are expanded
  let changes = $state({}) // scanned_at -> { new, fixed } | 'loading' | 'error'

  const enc = encodeURIComponent
  async function load() {
    try { scans = (await apiGet(`/api/fleet/scans?machine_id=${enc(machineId)}`))?.scans || [] } catch { /* keep last */ }
    loaded = true
  }
  $effect(() => { reloadKey; machineId; load() })

  async function toggleChanges(at) {
    open = open === at ? null : at
    if (open !== at || changes[at]) return
    changes = { ...changes, [at]: 'loading' }
    try {
      const res = await apiGet(`/api/fleet/scans/changes?machine_id=${enc(machineId)}&scanned_at=${enc(at)}`)
      changes = { ...changes, [at]: res }
    } catch { changes = { ...changes, [at]: 'error' } }
  }

  const KEY = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }
  const ok = $derived(scans.filter((s) => s.status === 'ok'))
  const chart = $derived([...scans].reverse()) // oldest → newest, left → right
  const peak = $derived(Math.max(1, ...ok.map((s) => SEV.reduce((t, v) => t + (s[KEY[v.sev]] || 0), 0))))
  const shown = $derived(showAll ? scans : scans.slice(0, 8))
  const TRIGGER = { manual: 'Manual', kernel: 'After kernel update' }
</script>

<div class="panel">
  <div class="panel-head">
    <span class="panel-icon text-info"><Icon name="history" size={17} /></span>
    <div class="min-w-0 flex-1">
      <div class="panel-title">Scan history</div>
      <div class="panel-sub">{scans.length ? `${scans.length} scan${scans.length === 1 ? '' : 's'} · newest first` : 'every scan, with what changed'}</div>
    </div>
  </div>

  {#if !loaded}
    <div class="py-1 text-sm text-muted-foreground">Loading…</div>
  {:else if !scans.length}
    <div class="py-1 text-sm text-muted-foreground">No scans yet. Each scan you run is listed here, with how long it took and what changed since the one before.</div>
  {:else}
    {#if ok.length > 1}
      <!-- trend: one bar per scan, stacked by severity; a failed scan is a short red tick -->
      <div class="mb-4 flex h-20 items-end gap-[3px]" role="img" aria-label="Distinct CVEs per scan, oldest to newest">
        {#each chart as s (s.scanned_at)}
          {#if s.status === 'ok'}
            {@const total = SEV.reduce((t, v) => t + (s[KEY[v.sev]] || 0), 0)}
            <div class="flex min-w-[3px] flex-1 flex-col-reverse overflow-hidden rounded-sm bg-muted" style="height: {Math.max(4, (total / peak) * 100)}%"
              title="{formatDate(s.scanned_at)} · {s.cves.toLocaleString()} CVEs ({SEV.map((v) => `${s[KEY[v.sev]]} ${v.label}`).join(', ')})">
              {#each SEV as v (v.sev)}
                {#if s[KEY[v.sev]]}<div class={v.bar} style="height: {(s[KEY[v.sev]] / Math.max(1, total)) * 100}%"></div>{/if}
              {/each}
            </div>
          {:else}
            <div class="h-1 min-w-[3px] flex-1 rounded-sm bg-destructive" title="{formatDate(s.scanned_at)} · failed: {s.error}"></div>
          {/if}
        {/each}
      </div>
    {/if}

    <div class="divide-y divide-dashed divide-border">
      {#each shown as s (s.scanned_at)}
        <div class="py-2 first:pt-0 last:pb-0">
          <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
            <span class="h-2 w-2 shrink-0 rounded-full {s.status === 'ok' ? 'bg-success' : 'bg-destructive'}"></span>
            <span class="font-medium text-foreground" title={formatDate(s.scanned_at)}>{timeAgo(s.scanned_at)}</span>
            <span class="rounded bg-muted px-1.5 py-px text-[10px] text-muted-foreground">{TRIGGER[s.trigger] || s.trigger}</span>
            <span class="tabular-nums text-muted-foreground">{formatBanTime(Math.round(s.seconds))}</span>
            {#if s.peak_mem}<span class="tabular-nums text-muted-foreground">peak {formatBytes(s.peak_mem)}</span>{/if}
            {#if s.status === 'ok'}
              <span class="flex flex-wrap items-center gap-x-2.5 tabular-nums sm:ml-auto">
                <span><span class="font-medium text-foreground">{s.cves.toLocaleString()}</span> <span class="text-muted-foreground">CVEs</span></span>
                {#each SEV as v (v.sev)}
                  {#if s[KEY[v.sev]]}<span class="inline-flex items-center gap-1"><span class="h-1.5 w-1.5 rounded-full {v.bar}"></span>{s[KEY[v.sev]].toLocaleString()}</span>{/if}
                {/each}
                {#if s.new == null}
                  <span class="text-muted-foreground">first scan</span>
                {:else if s.new || s.fixed}
                  <button type="button" class="inline-flex items-center gap-1 rounded-md border border-border px-1.5 py-0.5 font-medium transition-colors hover:bg-muted aria-expanded:bg-muted cursor-pointer"
                    aria-expanded={open === s.scanned_at} onclick={() => toggleChanges(s.scanned_at)}>
                    {#if s.new}<span class="text-destructive">+{s.new.toLocaleString()} new</span>{/if}{#if s.new && s.fixed}<span class="text-muted-foreground">·</span>{/if}{#if s.fixed}<span class="text-success">{s.fixed.toLocaleString()} fixed</span>{/if}
                    <Icon name={open === s.scanned_at ? 'chevron-up' : 'chevron-down'} size={12} class="text-muted-foreground" />
                  </button>
                {:else}
                  <span class="text-muted-foreground">no change</span>
                {/if}
              </span>
            {:else}
              <span class="min-w-0 break-words text-destructive sm:ml-auto">Failed: {s.error}</span>
            {/if}
          </div>
          {#if open === s.scanned_at}
            {@const c = changes[s.scanned_at]}
            <div class="mt-2 rounded-lg bg-muted/40 px-3 py-2 text-[11px]">
              {#if c === 'loading'}
                <span class="text-muted-foreground">Loading…</span>
              {:else if c === 'error' || !c}
                <span class="text-destructive">Couldn't load the changes.</span>
              {:else}
                {#each [['new', 'New since the scan before', 'text-destructive', s.new], ['fixed', 'Fixed since the scan before', 'text-success', s.fixed]] as [k, label, tone, n] (k)}
                  {#if c[k]?.length}
                    <div class="mb-1 font-medium {tone}">{label}{#if n > c[k].length} · first {c[k].length} of {n.toLocaleString()}{/if}</div>
                    <div class="mb-2 flex flex-wrap gap-1 font-mono last:mb-0">
                      {#each c[k] as id (id)}<span class="rounded bg-card px-1.5 py-px">{id}</span>{/each}
                    </div>
                  {/if}
                {/each}
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
    {#if scans.length > 8}
      <button type="button" class="mt-3 text-[11px] text-primary hover:underline" onclick={() => (showAll = !showAll)}>
        {showAll ? 'Show fewer' : `Show all ${scans.length}`}
      </button>
    {/if}
  {/if}
  <div class="panel-note">Each scan keeps a summary: when it ran, how long it took, how much memory it used and the counts per severity. Only the latest scan's findings are kept in full (View all & fix). History keeps the last 100 scans, up to 180 days.</div>
</div>
