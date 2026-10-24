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
  import UPlotChart from './UPlotChart.svelte'

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
  // uPlot columnar shape: [times (unix s), critical, high, medium, low], oldest first
  const TREND_SERIES = [
    { label: 'Critical', stroke: '--destructive' },
    { label: 'High', stroke: '--warning' },
    { label: 'Medium', stroke: '--info' },
    { label: 'Low', stroke: '--muted-foreground' },
  ]
  const trend = $derived.by(() => {
    const pts = [...ok].reverse()
    return [pts.map((s) => Math.floor(new Date(s.scanned_at).getTime() / 1000)), ...SEV.map((v) => pts.map((s) => s[KEY[v.sev]] || 0))]
  })
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
      <!-- trend: distinct CVEs per severity over time, one point per finished scan -->
      <div class="mb-4">
        <UPlotChart data={trend} series={TREND_SERIES} height={170} yFormat={(v) => Math.round(v).toLocaleString()} />
      </div>
    {/if}

    <div class="divide-y divide-dashed divide-border">
      {#each shown as s (s.scanned_at)}
        <div class="py-2.5 first:pt-0 last:pb-0">
          <!-- Same two lines on every row: when (left) / result (right), then how it ran (left) /
               the severities (right). The change button gets its own line on a phone and a third
               column on wider screens; a failure's reason gets its own line. -->
          <div class="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 text-xs sm:grid-cols-[minmax(0,1fr)_auto_auto]">
            <div class="flex min-w-0 items-center gap-2">
              <span class="h-2 w-2 shrink-0 rounded-full {s.status === 'ok' ? 'bg-success' : 'bg-destructive'}"></span>
              <span class="font-medium text-foreground" title={formatDate(s.scanned_at)}>{timeAgo(s.scanned_at)}</span>
              <span class="truncate rounded bg-muted px-1.5 py-px text-[10px] text-muted-foreground">{TRIGGER[s.trigger] || s.trigger}</span>
            </div>
            <div class="text-right tabular-nums">
              {#if s.status === 'ok'}
                <span class="font-semibold text-foreground">{s.cves.toLocaleString()}</span> <span class="text-muted-foreground">CVEs</span>
              {:else}
                <span class="font-medium text-destructive">Failed</span>
              {/if}
            </div>
            <div class="row-start-2 flex min-w-0 items-center gap-2 pl-4 text-[11px] tabular-nums text-muted-foreground">
              <span>{formatBanTime(Math.round(s.seconds))}</span>
              {#if s.peak_mem}<span class="truncate">· peak {formatBytes(s.peak_mem)}</span>{/if}
            </div>
            <div class="row-start-2 flex items-center justify-end gap-2.5 text-[11px] tabular-nums">
              {#if s.status === 'ok'}
                {#each SEV as v (v.sev)}
                  {#if s[KEY[v.sev]]}<span class="inline-flex items-center gap-1"><span class="h-1.5 w-1.5 rounded-full {v.bar}"></span>{s[KEY[v.sev]].toLocaleString()}</span>{/if}
                {/each}
              {/if}
            </div>
            <div class="col-span-2 pl-4 sm:col-span-1 sm:col-start-3 sm:row-span-2 sm:row-start-1 sm:pl-0 sm:text-right">
              {#if s.status !== 'ok'}
                <span class="break-words text-[11px] text-destructive sm:hidden">{s.error}</span>
              {:else if s.new == null}
                <span class="text-[11px] text-muted-foreground">first scan</span>
              {:else if s.new || s.fixed}
                <button type="button" class="inline-flex items-center gap-1 rounded-md border border-border px-1.5 py-0.5 font-medium tabular-nums transition-colors hover:bg-muted aria-expanded:bg-muted cursor-pointer"
                  aria-expanded={open === s.scanned_at} onclick={() => toggleChanges(s.scanned_at)}>
                  {#if s.new}<span class="text-destructive">+{s.new.toLocaleString()} new</span>{/if}{#if s.new && s.fixed}<span class="text-muted-foreground">·</span>{/if}{#if s.fixed}<span class="text-success">{s.fixed.toLocaleString()} fixed</span>{/if}
                  <Icon name={open === s.scanned_at ? 'chevron-up' : 'chevron-down'} size={12} class="text-muted-foreground" />
                </button>
              {:else}
                <span class="text-[11px] text-muted-foreground">no change</span>
              {/if}
            </div>
            {#if s.status !== 'ok'}
              <span class="col-span-3 hidden break-words pl-4 text-[11px] text-destructive sm:block">{s.error}</span>
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
