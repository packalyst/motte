<script>
  // Full-width area chart for time series. SVG-only, no lib.
  let {
    data = [],           // [{ time, count, bytes }]
    valueKey = 'count',
    labelKey = 'time',
    height = 180,
    stroke = 'currentColor',
    fill = 'currentColor',
    fillOpacity = 0.12,
    strokeWidth = 2,
    yTicks = 4,          // horizontal gridlines
    format = (v) => v,
  } = $props()

  const values = $derived(data.map(d => d?.[valueKey] ?? 0))
  const max    = $derived(values.length ? Math.max(...values, 1) : 1)

  // Coordinate system: 0..1000 x, 0..height y — SVG viewBox stretches
  const W = 1000
  const H = height
  const padTop = 8
  const padBottom = 24    // space for x labels
  const chartH = H - padTop - padBottom

  const stepX = $derived(values.length > 1 ? W / (values.length - 1) : W)

  const linePath = $derived(
    values.map((v, i) => {
      const x = i * stepX
      const y = padTop + chartH - (v / max) * chartH
      return (i === 0 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1)
    }).join(' ')
  )

  const areaPath = $derived(
    values.length
      ? linePath + ` L${W},${padTop + chartH} L0,${padTop + chartH} Z`
      : ''
  )

  // Gridlines
  const ticks = $derived(
    Array.from({ length: yTicks + 1 }, (_, i) => {
      const y = padTop + (chartH / yTicks) * i
      const v = max - (max / yTicks) * i
      return { y, v }
    })
  )

  // X-axis labels (first, middle, last)
  const xLabels = $derived(() => {
    if (!data.length) return []
    const first = data[0]?.[labelKey] || ''
    const mid = data[Math.floor(data.length / 2)]?.[labelKey] || ''
    const last = data[data.length - 1]?.[labelKey] || ''
    return [
      { x: 0, text: first, anchor: 'start' },
      { x: W / 2, text: mid, anchor: 'middle' },
      { x: W, text: last, anchor: 'end' },
    ]
  })
</script>

{#if data.length}
  <svg
    viewBox="0 0 {W} {H}"
    preserveAspectRatio="none"
    class="w-full block"
    style="height: {H}px;"
  >
    <!-- Gridlines -->
    {#each ticks as t}
      <line x1="0" x2={W} y1={t.y} y2={t.y}
            stroke="currentColor" stroke-opacity="0.08" stroke-width="1" />
      <text x="0" y={t.y - 3} fill="currentColor" fill-opacity="0.4"
            font-size="20" font-family="ui-monospace, monospace">{format(Math.round(t.v))}</text>
    {/each}

    <!-- Area + line -->
    <path d={areaPath} fill={fill} fill-opacity={fillOpacity} />
    <path d={linePath} fill="none" stroke={stroke}
          stroke-width={strokeWidth} stroke-linejoin="round" stroke-linecap="round" />

    <!-- X labels -->
    {#each xLabels() as x}
      <text x={x.x} y={H - 4} text-anchor={x.anchor}
            fill="currentColor" fill-opacity="0.5"
            font-size="18" font-family="ui-monospace, monospace">{x.text}</text>
    {/each}
  </svg>
{:else}
  <div style="height: {height}px;" class="flex items-center justify-center text-xs text-muted-foreground">
    No data
  </div>
{/if}
