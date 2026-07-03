<script>
  // Clean area chart. SVG for shape (pixel-perfect, no viewBox stretching),
  // HTML overlay for axis labels (no font distortion).
  let {
    data = [],           // [{ time, count, bytes }]
    valueKey = 'count',
    labelKey = 'time',
    height = 200,
    strokeWidth = 2,
    yTicks = 3,
    format = (v) => v,
  } = $props()

  let containerWidth = $state(0)

  // Chart geometry
  const padTop = 8
  const padRight = 8
  const padBottom = 24
  const padLeft = 40

  const chartW = $derived(Math.max(containerWidth - padLeft - padRight, 0))
  const chartH = $derived(height - padTop - padBottom)

  const values = $derived(data.map(d => d?.[valueKey] ?? 0))
  const max    = $derived(values.length ? Math.max(...values, 1) : 1)

  // Nice-number ticks: round `max` up to a friendly value
  function niceTicks(maxVal, count) {
    if (!maxVal || maxVal === 0) return [0]
    const step = Math.pow(10, Math.floor(Math.log10(maxVal / count)))
    const roundedStep = Math.ceil((maxVal / count) / step) * step
    const ticks = []
    for (let i = 0; i <= count; i++) ticks.push(i * roundedStep)
    return ticks
  }
  const ticks = $derived(niceTicks(max, yTicks))
  const chartMax = $derived(ticks[ticks.length - 1] || max)

  // Path builders
  function pathAt(i, v) {
    const x = padLeft + (values.length > 1 ? (i * chartW) / (values.length - 1) : 0)
    const y = padTop + chartH - (v / chartMax) * chartH
    return [x, y]
  }

  const linePath = $derived(
    values.map((v, i) => {
      const [x, y] = pathAt(i, v)
      return (i === 0 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1)
    }).join(' ')
  )

  const areaPath = $derived(
    values.length
      ? linePath +
        ` L${(padLeft + chartW).toFixed(1)},${(padTop + chartH).toFixed(1)}` +
        ` L${padLeft},${(padTop + chartH).toFixed(1)} Z`
      : ''
  )

  // Uid for gradient (avoid collisions across multiple charts)
  const uid = 'ac-' + Math.random().toString(36).slice(2, 8)
</script>

<div
  bind:clientWidth={containerWidth}
  class="w-full relative"
  style="height: {height}px;"
>
  {#if data.length && containerWidth > 0}
    <svg
      width={containerWidth}
      height={height}
      class="block"
    >
      <defs>
        <linearGradient id={uid} x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stop-color="currentColor" stop-opacity="0.25" />
          <stop offset="100%" stop-color="currentColor" stop-opacity="0" />
        </linearGradient>
      </defs>

      <!-- Horizontal gridlines (drawn behind the area) -->
      {#each ticks as t}
        {@const y = padTop + chartH - (t / chartMax) * chartH}
        <line x1={padLeft} x2={padLeft + chartW} y1={y} y2={y}
              stroke="currentColor" stroke-opacity="0.08" stroke-width="1"
              shape-rendering="crispEdges" />
      {/each}

      <!-- Area + line -->
      <path d={areaPath} fill="url(#{uid})" />
      <path d={linePath}
            fill="none" stroke="currentColor" stroke-width={strokeWidth}
            stroke-linejoin="round" stroke-linecap="round" />
    </svg>

    <!-- Y-axis labels (HTML, precise font size) -->
    <div class="absolute inset-y-0 left-0 pointer-events-none"
         style="width: {padLeft}px;">
      {#each ticks as t}
        {@const y = padTop + chartH - (t / chartMax) * chartH}
        <div
          class="absolute right-1 -translate-y-1/2 text-[10px] text-muted-foreground font-mono tabular-nums"
          style="top: {y}px;"
        >
          {format(t)}
        </div>
      {/each}
    </div>

    <!-- X-axis labels: first / middle / last (no crowding) -->
    <div class="absolute left-0 right-0 flex justify-between text-[10px] text-muted-foreground font-mono px-0"
         style="top: {height - padBottom + 6}px; padding-left: {padLeft}px; padding-right: {padRight}px;">
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
