<script>
  // Reusable categorical bar chart with a value axis — the same principle in
  // both orientations:
  //   horizontal → labelled rows (Core 0…N) with a 0–max x-axis
  //   vertical   → columns with a 0–max y-axis
  // Faint per-bar track, gridlines at each tick, threshold colouring. Generic:
  // any page can pass items + a colour rule. See ServerView (CPU cores).
  let {
    items = [],                 // [{ label, value }]
    orientation = 'horizontal', // 'horizontal' | 'vertical'
    max = 100,
    unit = '%',
    color = 'var(--primary)',   // fixed bar colour
    colorFn = null,             // (value) => colour; overrides `color`
    height = 150,               // plot height (vertical mode)
    barMax = 18,                // max bar thickness (px)
    ticks = [0, 25, 50, 75, 100],
    track = true,               // faint 0–max track behind each bar
    axis = true,                // scale ticks + gridlines
    valueLabels = true,         // horizontal: show the value beside each bar
    catLabels = true,           // show per-bar category labels
    labelWidth = '3.4rem',      // horizontal: width of the category-label column
    format = null,              // (value) => string
  } = $props()

  const col = (v) => (colorFn ? colorFn(v) : color)
  const pctOf = (v) => Math.max(0, Math.min(100, (v / max) * 100))
  const fmt = (v) => (format ? format(v) : `${v < 10 ? (+v).toFixed(1) : Math.round(v)}${unit}`)
  const tickLabel = (t) => (t === max ? `${t}${unit}` : `${t}`)
  // Gridline background: a 1px line at the start of each tick segment.
  const gridBg = $derived(
    track
      ? `background-image:linear-gradient(to right, var(--border) 0 1px, transparent 1px); background-size:${100 / Math.max(1, ticks.length - 1)}% 100%`
      : ''
  )
</script>

{#if orientation === 'horizontal'}
  <div class="grid gap-x-2 gap-y-1.5 items-center" style="grid-template-columns:{catLabels ? labelWidth : '0'} 1fr {valueLabels ? '2.8rem' : '0'}">
    {#each items as it}
      {@const c = col(it.value)}
      {#if catLabels}<span class="text-[11px] text-muted-foreground tabular-nums truncate">{it.label}</span>{:else}<span></span>{/if}
      <div class="relative cursor-help" data-kt-tooltip>
        <div class="relative h-4 rounded overflow-hidden bg-muted/40" style={gridBg}>
          <div class="absolute inset-y-0 left-0 rounded transition-[width] duration-300" style="width:{Math.max(2, pctOf(it.value))}%; background:{c}"></div>
        </div>
        <span data-kt-tooltip-content class="kt-tooltip hidden">{it.label}: {fmt(it.value)}</span>
      </div>
      {#if valueLabels}<span class="text-[11px] font-medium tabular-nums text-right" style="color:{c}">{fmt(it.value)}</span>{:else}<span></span>{/if}
    {/each}
    {#if axis}
      <span></span>
      <div class="flex justify-between text-[10px] text-muted-foreground pt-1 mt-0.5 border-t border-border/60">
        {#each ticks as t}<span>{tickLabel(t)}</span>{/each}
      </div>
      <span></span>
    {/if}
  </div>
{:else}
  <div>
    <div class="flex gap-2">
      {#if axis}
        <div class="flex flex-col justify-between text-right text-[10px] text-muted-foreground shrink-0" style="width:2.2rem; height:{height}px">
          {#each [...ticks].reverse() as t}<span>{tickLabel(t)}</span>{/each}
        </div>
      {/if}
      <div class="relative flex-1" style="height:{height}px">
        {#if track}
          {#each ticks as t}<div class="absolute inset-x-0 border-t border-border/40" style="bottom:{pctOf(t)}%"></div>{/each}
        {/if}
        <div class="absolute inset-0 flex items-end gap-1.5">
          {#each items as it}
            <div class="flex-1 min-w-0 flex justify-center cursor-help" data-kt-tooltip>
              <div class="w-full rounded-t transition-[height] duration-300" style="height:{pctOf(it.value)}%; max-width:{barMax}px; background:{col(it.value)}"></div>
              <span data-kt-tooltip-content class="kt-tooltip hidden">{it.label}: {fmt(it.value)}</span>
            </div>
          {/each}
        </div>
      </div>
    </div>
    {#if catLabels}
      <div class="flex gap-2">
        {#if axis}<div class="shrink-0" style="width:2.2rem"></div>{/if}
        <div class="flex-1 flex gap-1.5">
          {#each items as it}<span class="flex-1 text-center text-[9px] text-muted-foreground truncate">{it.label}</span>{/each}
        </div>
      </div>
    {/if}
  </div>
{/if}
