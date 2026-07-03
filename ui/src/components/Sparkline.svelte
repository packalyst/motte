<script>
  // Compact SVG sparkline. Renders a smoothed area under a line series.
  // Zero-dependency, works with any small time-series array.
  let {
    data = [],           // [{ count, ... }] or [number]
    valueKey = 'count',  // key when data is array of objects
    width = 120,
    height = 32,
    stroke = 'currentColor',
    fill = 'currentColor',
    fillOpacity = 0.15,
    strokeWidth = 1.5,
  } = $props()

  const values = $derived(
    data.map(d => (typeof d === 'number' ? d : (d?.[valueKey] ?? 0)))
  )
  const max = $derived(values.length ? Math.max(...values, 1) : 1)
  const stepX = $derived(values.length > 1 ? width / (values.length - 1) : width)

  // Line path
  const linePath = $derived(
    values.map((v, i) => {
      const x = i * stepX
      const y = height - (v / max) * height
      return (i === 0 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1)
    }).join(' ')
  )

  // Area path (closes to baseline)
  const areaPath = $derived(
    values.length
      ? linePath + ` L${(width).toFixed(1)},${height} L0,${height} Z`
      : ''
  )
</script>

{#if values.length > 1}
  <svg
    viewBox="0 0 {width} {height}"
    width={width}
    height={height}
    preserveAspectRatio="none"
    class="overflow-visible"
  >
    <path d={areaPath} fill={fill} fill-opacity={fillOpacity} />
    <path d={linePath} fill="none" stroke={stroke} stroke-width={strokeWidth} stroke-linejoin="round" stroke-linecap="round" />
  </svg>
{:else}
  <div style="width: {width}px; height: {height}px;" class="flex items-center justify-center text-[10px] text-muted-foreground">
    —
  </div>
{/if}
