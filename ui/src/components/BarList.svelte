<script>
  // Horizontal bar list. Each row: label + bar + count.
  // Auto-computes max, supports per-row color override via `colorFor(row)` callback.
  let {
    data = [],
    labelKey = 'status',
    valueKey = 'count',
    prefixKey = null,          // optional key to render before label (e.g. flag)
    barClass = 'bg-primary',   // default bar color class
    colorFor = null,           // (row) => Tailwind class, overrides barClass
    format = (v) => v,         // format value for right-hand text
    percent = false,           // show percent of total instead of raw count
    labelWidth = 'w-24',       // Tailwind width for label column
  } = $props()

  const total = $derived(data.reduce((s, r) => s + (r[valueKey] || 0), 0))
  const max = $derived(data.length ? Math.max(...data.map(r => r[valueKey] || 0), 1) : 1)

  function rowValue(r) {
    if (percent) {
      return total ? Math.round((r[valueKey] / total) * 100) + '%' : '0%'
    }
    return format(r[valueKey])
  }
</script>

{#if data.length}
  <div class="space-y-2.5">
    {#each data as row}
      <div class="flex items-center gap-3 text-sm">
        {#if prefixKey && row[prefixKey]}
          <span class="shrink-0">{row[prefixKey]}</span>
        {/if}
        <span class="{labelWidth} shrink-0 truncate text-xs font-mono">{row[labelKey] || '—'}</span>
        <div class="flex-1 h-2 bg-muted rounded-full overflow-hidden">
          <div
            class="h-full {colorFor ? colorFor(row) : barClass}"
            style="width: {(row[valueKey] / max) * 100}%"
          ></div>
        </div>
        <span class="font-mono text-xs w-16 text-right tabular-nums">{rowValue(row)}</span>
      </div>
    {/each}
  </div>
{:else}
  <div class="text-xs text-muted-foreground py-2">No data</div>
{/if}
