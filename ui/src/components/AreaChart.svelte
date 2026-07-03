<script>
  // Full-width area chart. Y-axis labels overlay inside the chart area
  // so the drawing fills 100% of the container width. HTML overlays for text
  // (pixel-perfect fonts, no SVG stretching).
  let {
    data = [],
    valueKey = 'count',
    labelKey = 'time',
    height = 200,
    strokeWidth = 2,
    yTicks = 3,
    format = (v) => v,
  } = $props()

  let containerWidth = $state(0)

  const padTop = 12
  const padBottom = 22

  const chartH = $derived(height - padTop - padBottom)

  const values = $derived(data.map(d => d?.[valueKey] ?? 0))
  const max    = $derived(values.length ? Math.max(...values, 1) : 1)

  function niceTicks(maxVal, count) {
    if (!maxVal || maxVal === 0) return [0, 1]
    const step = Math.pow(10, Math.floor(Math.log10(maxVal / count)))
    const roundedStep = Math.ceil((maxVal / count) / step) * step
    const ticks = []
    for (let i = 0; i <= count; i++) ticks.push(i * roundedStep)
    return ticks
  }
  const ticks = $derived(niceTicks(max, yTicks))
  const chartMax = $derived(ticks[ticks.length - 1] || max)

  const linePath = $derived(
    values.map((v, i) => {
      const x = values.length > 1 ? (i * containerWidth) / (values.length - 1) : 0
      const y = padTop + chartH - (v / chartMax) * chartH
      return (i === 0 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1)
    }).join(' ')
  )

  const areaPath = $derived(
    values.length
      ? linePath + ` L${containerWidth.toFixed(1)},${(padTop + chartH).toFixed(1)} L0,${(padTop + chartH).toFixed(1)} Z`
      : ''
  )

  const uid = 'ac-' + Math.random().toString(36).slice(2, 8)
</script>

<div
  bind:clientWidth={containerWidth}
  class="w-full relative"
  style="height: {height}px;"
>
  {#if data.length && containerWidth > 0}
    <svg width={containerWidth} height={height} class="block absolute inset-0">
      <defs>
        <linearGradient id={uid} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stop-color="currentColor" stop-opacity="0.25" />
          <stop offset="100%" stop-color="currentColor" stop-opacity="0" />
        </linearGradient>
      </defs>

      <!-- Gridlines (full-width) -->
      {#each ticks as t}
        {@const y = padTop + chartH - (t / chartMax) * chartH}
        <line
          x1="0" x2={containerWidth} y1={y} y2={y}
          stroke="currentColor" stroke-opacity="0.08" stroke-width="1"
          shape-rendering="crispEdges"
        />
      {/each}

      <path d={areaPath} fill="url(#{uid})" />
      <path
        d={linePath}
        fill="none" stroke="currentColor" stroke-width={strokeWidth}
        stroke-linejoin="round" stroke-linecap="round"
      />
    </svg>

    <!-- Y-axis labels overlaid inside the chart, top-left corner of each gridline -->
    <div class="absolute inset-0 pointer-events-none">
      {#each ticks as t}
        {@const y = padTop + chartH - (t / chartMax) * chartH}
        <div
          class="absolute left-1 text-[10px] text-muted-foreground/70 font-mono tabular-nums bg-card/70 px-1 rounded"
          style="top: {(y - 6).toFixed(1)}px;"
        >
          {format(t)}
        </div>
      {/each}
    </div>

    <!-- X-axis: first / middle / last, right below the chart -->
    <div
      class="absolute left-0 right-0 flex justify-between text-[10px] text-muted-foreground font-mono px-1"
      style="top: {height - padBottom + 4}px;"
    >
      <span class="truncate">{data[0]?.[labelKey] || ''}</span>
      <span class="truncate">{data[Math.floor(data.length / 2)]?.[labelKey] || ''}</span>
      <span class="truncate">{data[data.length - 1]?.[labelKey] || ''}</span>
    </div>
  {:else}
    <div class="w-full h-full flex items-center justify-center text-xs text-muted-foreground">
      No data
    </div>
  {/if}
</div>
