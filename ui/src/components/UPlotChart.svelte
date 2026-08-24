<script>
  // Reusable uPlot time-series chart. Generic on purpose — any page can drop it
  // in: pass `data` in uPlot's columnar shape [xs, ...series] and a `series`
  // descriptor. Handles instance build, live setData, resize, a crosshair
  // tooltip, and theme-aware colors. See ServerView for a live example.
  import { onMount, onDestroy } from 'svelte'
  import uPlot from 'uplot'
  import 'uplot/dist/uPlot.min.css'
  import { withTz } from '$lib/utils/format.js'

  let {
    data = [],            // [xVals(unix s), series1, series2, ...]
    series = [],          // [{ label, stroke:'--cpu', width?, fill? }] one per non-x column
    height = 150,
    yRange = null,        // [min,max] fixed, or null to auto-scale
    yUnit = '',           // suffix on axis + tooltip values, e.g. '%'
    yFormat = null,       // (v) => string; overrides the default `${v}${yUnit}`
    tooltip = true,
    legend = true,        // built-in clickable legend (show/hide series + live value)
    hidden = $bindable({}), // series index -> true when hidden; bindable so a
                            // parent can drive the toggle from its own legend
  } = $props()

  let el                  // chart mount node
  let u = null            // uPlot instance
  let ro = null           // ResizeObserver
  let mo = null           // theme MutationObserver

  const css = (name) =>
    name && name.startsWith('--')
      ? getComputedStyle(document.documentElement).getPropertyValue(name).trim()
      : name
  // For the legend swatch: keep the CSS var so it re-themes for free.
  const swatch = (s) => (s && s.startsWith('--') ? `var(${s})` : s)
  // Apply alpha to a resolved colour for the gradient fill. Handles hex
  // (#rgb/#rrggbb → rgba) and functional notations (rgb/hsl/oklch → `… / a`).
  function withAlpha(col, a) {
    if (col.startsWith('#')) {
      let h = col.slice(1)
      if (h.length === 3) h = h.split('').map((c) => c + c).join('')
      const n = parseInt(h, 16)
      return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`
    }
    return /\)\s*$/.test(col) ? col.replace(/\)\s*$/, ` / ${a})`) : col
  }

  function fmtY(v) {
    if (yFormat) return yFormat(v)
    return `${v}${yUnit}`
  }

  // Latest non-null value per series, for the legend readout.
  const lastVals = $derived(
    series.map((s, i) => {
      const col = data[i + 1]
      if (!col || !col.length) return null
      for (let k = col.length - 1; k >= 0; k--) if (col[k] != null) return col[k]
      return null
    })
  )

  function toggleSeries(i) {
    hidden = { ...hidden, [i]: !hidden[i] }
  }

  function tooltipPlugin(strokes) {
    // The tooltip lives on <body> (not inside .u-over) so a card's overflow:hidden or
    // stacking context can't clip it or paint over it; it's positioned in viewport
    // coordinates (position:fixed) from the plot's bounding rect + cursor offset.
    let tip
    return {
      hooks: {
        init: () => {
          tip = document.createElement('div')
          tip.className = 'uchart-tip'
          document.body.appendChild(tip)
        },
        setCursor: (up) => {
          const i = up.cursor.idx
          if (!tip) return
          if (i == null || up.cursor.left < 0) {
            tip.style.display = 'none'
            return
          }
          const t = up.data[0][i]
          const dt = new Date(t * 1000)
          // Always label the point with date + time, so every chart (server, machines,
          // analytics) reads consistently instead of a bare intraday time.
          const label = dt.toLocaleString([], withTz({ month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }))
          let h = `<div class="uchart-tip-t">${label}</div>`
          for (let s = 1; s < up.series.length; s++) {
            const v = up.data[s][i]
            h += `<div class="uchart-tip-r"><span class="uchart-tip-sw" style="background:${strokes[s - 1]}"></span>${up.series[s].label} <b>${v == null ? '—' : fmtY(+v.toFixed(1))}</b></div>`
          }
          tip.innerHTML = h
          tip.style.display = 'block'
          // Viewport-relative placement; flip/clamp so it never spills off-screen.
          const rect = up.over.getBoundingClientRect()
          const tw = tip.offsetWidth, th = tip.offsetHeight
          let x = rect.left + up.cursor.left + 14
          let y = rect.top + up.cursor.top + 8
          if (x + tw > window.innerWidth - 8) x = rect.left + up.cursor.left - tw - 14
          if (y + th > window.innerHeight - 8) y = window.innerHeight - th - 8
          if (x < 8) x = 8
          if (y < 8) y = 8
          tip.style.left = x + 'px'
          tip.style.top = y + 'px'
        },
        destroy: () => {
          if (tip && tip.parentNode) tip.parentNode.removeChild(tip)
          tip = null
        },
      },
    }
  }

  function build() {
    if (!el) return
    if (u) { u.destroy(); u = null }
    el.innerHTML = ''

    const axisColor = css('--muted-foreground')
    const gridColor = css('--border')
    const strokes = series.map((s) => css(s.stroke))

    const ax = (size, values, extra = {}) => ({
      stroke: axisColor,
      grid: { stroke: gridColor, width: 1 },
      ticks: { stroke: gridColor, width: 1, size: 4 },
      font: '11px ui-sans-serif, system-ui, sans-serif',
      size,
      ...(values ? { values } : {}),
      ...extra,
    })
    // Axis labels: dates for a multi-day range (week/month/fleet 7d-30d), clock time
    // for an intraday range (1h/24h/live). Read live from up.data so it re-adapts when
    // the period changes without a rebuild.
    const fmtTime = (up, vals) => {
      const xs0 = up.data[0] || []
      const md = xs0.length > 1 && xs0[xs0.length - 1] - xs0[0] > 36 * 3600
      return vals.map((v) => {
        const d = new Date(v * 1000)
        return md
          ? d.toLocaleDateString([], withTz({ month: 'short', day: 'numeric' }))
          : d.toLocaleTimeString([], withTz({ hour: '2-digit', minute: '2-digit' }))
      })
    }

    const uSeries = [{}]
    series.forEach((s, idx) => {
      const col = strokes[idx]
      // points.show:false → no always-on vertex markers (sparse data); the
      // hover point still comes from cursor.points below.
      const entry = { label: s.label, stroke: col, width: s.width ?? 2, show: !hidden[idx], points: { show: false } }
      if (s.fill) {
        const a = typeof s.fill === 'number' ? s.fill : 0.2
        entry.fill = (up) => {
          const g = up.ctx.createLinearGradient(0, up.bbox.top, 0, up.bbox.top + up.bbox.height)
          g.addColorStop(0, withAlpha(col, a))
          g.addColorStop(1, withAlpha(col, 0))
          return g
        }
      }
      uSeries.push(entry)
    })

    // Explicit y auto-range that scans the LIVE data every time. uPlot caches per-series
    // min/max and doesn't always recompute them on a full data swap (e.g. switching to a
    // peer whose traffic is orders of magnitude larger) — which leaves the axis stuck at
    // a stale, too-small max and clips the tall spikes. Scanning up.data here is immune to
    // that cache. Honors hidden series; always includes the 0 baseline.
    const autoYRange = (up2) => {
      let mn = Infinity, mx = -Infinity
      for (let s = 1; s < up2.series.length; s++) {
        if (up2.series[s].show === false) continue
        const col = up2.data[s]
        if (!col) continue
        for (let i = 0; i < col.length; i++) {
          const v = col[i]
          if (v == null) continue
          if (v < mn) mn = v
          if (v > mx) mx = v
        }
      }
      if (mx === -Infinity) return [0, 100]
      return uPlot.rangeNum(Math.min(0, mn), mx, 0.1, true)
    }

    // Widen the y gutter to fit the formatted labels ("45.7 GB", "20K") so they aren't
    // clipped on the left; short labels ("45%") keep a tight gutter. `values` are the
    // formatted tick strings (null on the first sizing pass).
    const yAxisSize = (self, values) => {
      const n = (values && values.length) ? Math.max(...values.map((v) => (v == null ? 0 : String(v).length))) : 3
      return Math.min(72, Math.max(34, n * 7 + 16))
    }

    const opts = {
      width: el.clientWidth || 400,
      height,
      cursor: { y: false, points: { size: 7 } },
      legend: { show: false },
      scales: yRange ? { y: { range: () => yRange } } : { y: { range: autoYRange } },
      axes: [ax(34, fmtTime, { space: 70, gap: 6 }), ax(yAxisSize, (up, vals) => vals.map(fmtY))],
      series: uSeries,
      plugins: tooltip ? [tooltipPlugin(strokes)] : [],
    }

    u = new uPlot(opts, data.length ? data : [[]], el)
  }

  // Rebuild on theme change (canvas colors are baked at draw time).
  function watchTheme() {
    mo = new MutationObserver(build)
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'data-theme'] })
  }

  onMount(() => {
    build()
    watchTheme()
    ro = new ResizeObserver(() => {
      if (u && el) u.setSize({ width: el.clientWidth, height })
    })
    ro.observe(el)
  })

  onDestroy(() => {
    ro?.disconnect()
    mo?.disconnect()
    u?.destroy()
    u = null
  })

  // Live data push — cheap: uPlot re-renders in place, no rebuild.
  $effect(() => {
    if (u && data && data.length) u.setData(data)
  })

  // Apply show/hide when `hidden` changes (built-in legend or parent-driven).
  $effect(() => {
    const h = hidden
    if (u) for (let i = 0; i < series.length; i++) u.setSeries(i + 1, { show: !h[i] })
  })
</script>

{#if legend && series.length}
  <div class="uchart-legend">
    {#each series as s, i}
      <button type="button" class="uchart-leg" class:off={hidden[i]} onclick={() => toggleSeries(i)} title="Toggle {s.label}">
        <span class="uchart-leg-sw" style="background:{swatch(s.stroke)}"></span>
        <span>{s.label}</span>
        {#if lastVals[i] != null}<b>{fmtY(+lastVals[i].toFixed(1))}</b>{/if}
      </button>
    {/each}
  </div>
{/if}
<div bind:this={el} class="uchart" style="height:{height}px"></div>

<style>
  .uchart {
    width: 100%;
    position: relative;
  }
  .uchart-legend {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-bottom: 8px;
  }
  .uchart-leg {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 8px;
    border-radius: 999px;
    font-size: 11px;
    color: var(--muted-foreground);
    background: var(--muted);
    border: 1px solid transparent;
    cursor: pointer;
    transition: opacity 0.15s ease;
  }
  .uchart-leg b {
    color: var(--foreground);
    font-variant-numeric: tabular-nums;
  }
  .uchart-leg:hover {
    border-color: var(--border);
  }
  .uchart-leg.off {
    opacity: 0.4;
    text-decoration: line-through;
  }
  .uchart-leg-sw {
    width: 8px;
    height: 8px;
    border-radius: 2px;
    flex: none;
  }
  /* uPlot renders its own canvas; tooltip is appended into .u-over */
  :global(.uchart-tip) {
    position: fixed;
    pointer-events: none;
    z-index: 9999;
    padding: 6px 8px;
    border-radius: 7px;
    font-size: 11px;
    background: var(--card);
    color: var(--foreground);
    border: 1px solid var(--border);
    box-shadow: var(--shadow, 0 2px 8px rgba(0, 0, 0, 0.15));
    display: none;
    white-space: nowrap;
  }
  :global(.uchart-tip-t) {
    color: var(--muted-foreground);
    margin-bottom: 3px;
  }
  :global(.uchart-tip-r) {
    margin-top: 1px;
  }
  :global(.uchart-tip-sw) {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 2px;
    margin-right: 5px;
  }
</style>
