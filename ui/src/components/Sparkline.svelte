<script>
  // Sparkline — a tiny trend line with a soft area fill, on a fixed 0..max scale so a flat 20%
  // reads as low rather than being stretched to fill the box. Gaps (null) break the line.
  // Generic: values in order, oldest first; colour is any CSS colour or token.
  let { values = [], max = 100, color = 'var(--primary)', height = 32, label = undefined } = $props()

  const W = 100 // viewBox width; the SVG stretches to its container
  const path = $derived.by(() => {
    const n = values.length
    if (n < 2) return { line: '', area: '' }
    const x = (i) => ((i / (n - 1)) * W).toFixed(2)
    const y = (v) => (height - (Math.max(0, Math.min(max, v)) / max) * (height - 2) - 1).toFixed(2)
    let line = ''
    let area = ''
    let run = [] // the current unbroken stretch, for its area polygon
    const close = () => {
      if (run.length > 1) area += `M${run[0][0]},${height} ` + run.map(([px, py]) => `L${px},${py}`).join(' ') + ` L${run[run.length - 1][0]},${height} Z `
      run = []
    }
    values.forEach((v, i) => {
      if (v == null || isNaN(v)) { close(); return }
      const p = [x(i), y(v)]
      line += `${run.length ? 'L' : 'M'}${p[0]},${p[1]} `
      run.push(p)
    })
    close()
    return { line, area }
  })
</script>

<svg viewBox="0 0 {W} {height}" preserveAspectRatio="none" class="block w-full" style="height:{height}px"
  role={label ? 'img' : undefined} aria-label={label} aria-hidden={label ? undefined : 'true'}>
  <path d={path.area} fill={color} fill-opacity="0.12" />
  <path d={path.line} fill="none" stroke={color} stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke" />
</svg>
