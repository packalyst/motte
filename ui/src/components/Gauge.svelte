<script>
  // Reusable radial gauge — open-bottom 270° arc with scale numbers on the ring
  // and a big center value, matching the demo's CPU gauge. Generic: any page can
  // show a 0..max metric. Colour follows thresholds by default (good/warn/crit)
  // but can be pinned to a single colour.
  let {
    value = 0,            // current value
    max = 100,            // scale maximum
    label = '',           // centre sublabel, e.g. 'CPU utilization'
    unit = '%',           // suffix on the centre number
    size = 164,           // rendered px (viewBox is fixed 180)
    ticks = [0, 20, 40, 60, 80, 100],
    color = null,         // pin a colour (CSS token/value); null => thresholds
    thresholds = [
      { at: 85, color: 'var(--destructive)' },
      { at: 60, color: 'var(--warning)' },
      { at: 0, color: 'var(--success)' },
    ],
  } = $props()

  const R = 70                 // arc radius
  const TRACK = 329.87         // 270° arc length at R=70 (2πR * 270/360)

  const clamped = $derived(Math.max(0, Math.min(max, value)))
  const frac = $derived(max > 0 ? clamped / max : 0)
  const dash = $derived((frac * TRACK).toFixed(1))

  const arcColor = $derived(
    color ?? (thresholds.find((t) => (clamped / max) * 100 >= t.at)?.color || 'var(--success)')
  )

  // Position a scale label on the ring. θ measured clockwise from 12 o'clock;
  // the 270° arc runs from 225° (bottom-left) to 495°/135° (bottom-right).
  function tickPos(v) {
    const theta = ((225 + 270 * (v / max)) * Math.PI) / 180
    return {
      x: (90 + 52 * Math.sin(theta)).toFixed(1),
      y: (90 - 52 * Math.cos(theta)).toFixed(1),
      label: v,
    }
  }
  const tickPts = $derived(ticks.map(tickPos))
</script>

<svg width={size} height={size} viewBox="0 0 180 180" style="flex:none">
  <circle
    cx="90" cy="90" r="70" fill="none"
    stroke="var(--muted, oklch(90% 0 0))" stroke-opacity="0.4"
    stroke-width="9" stroke-linecap="round"
    stroke-dasharray="329.9 439.8" transform="rotate(135 90 90)"
  />
  <circle
    cx="90" cy="90" r="70" fill="none"
    stroke={arcColor} stroke-width="9" stroke-linecap="round"
    stroke-dasharray="{dash} 439.8" transform="rotate(135 90 90)"
    style="transition: stroke-dasharray .4s ease, stroke .3s ease"
  />
  <g font-size="9" fill="var(--muted-foreground)" text-anchor="middle" style="dominant-baseline:middle">
    {#each tickPts as t}
      <text x={t.x} y={t.y}>{t.label}</text>
    {/each}
  </g>
  <text x="90" y="86" text-anchor="middle" style="dominant-baseline:middle">
    <tspan font-size="34" font-weight="700" fill="var(--foreground)">{Math.round(clamped)}</tspan><tspan
      font-size="16" fill="var(--muted-foreground)">{unit}</tspan>
  </text>
  {#if label}
    <text x="90" y="118" text-anchor="middle" font-size="10" fill="var(--muted-foreground)">{label}</text>
  {/if}
</svg>
