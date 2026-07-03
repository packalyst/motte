<script>
  // Compact SVG sparkline. Fills 100% of its parent's width automatically.
  // Height is fixed via prop.
  let {
    data = [],
    valueKey = 'count',
    height = 32,
    stroke = 'currentColor',
    fill = 'currentColor',
    fillOpacity = 0.15,
    strokeWidth = 1.5,
  } = $props()

  let containerWidth = $state(0)

  const values = $derived(
    data.map(d => (typeof d === 'number' ? d : (d?.[valueKey] ?? 0)))
  )
  const max = $derived(values.length ? Math.max(...values, 1) : 1)

  const linePath = $derived(
    values.map((v, i) => {
      const x = values.length > 1 ? (i * containerWidth) / (values.length - 1) : 0
      const y = height - (v / max) * height
      return (i === 0 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1)
    }).join(' ')
  )

  const areaPath = $derived(
    values.length
      ? linePath + ` L${containerWidth.toFixed(1)},${height} L0,${height} Z`
      : ''
  )
</script>

<div bind:clientWidth={containerWidth} class="w-full" style="height: {height}px;">
  {#if values.length > 1 && containerWidth > 0}
    <svg width={containerWidth} height={height} class="block">
      <path d={areaPath} fill={fill} fill-opacity={fillOpacity} />
      <path
        d={linePath}
        fill="none" stroke={stroke} stroke-width={strokeWidth}
        stroke-linejoin="round" stroke-linecap="round"
      />
    </svg>
  {:else}
    <div class="w-full h-full flex items-center justify-center text-[10px] text-muted-foreground">
      —
    </div>
  {/if}
</div>
