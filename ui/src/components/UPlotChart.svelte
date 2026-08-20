<script>
  // Reusable uPlot time-series chart. Generic on purpose — any page can drop it
  // in: pass `data` in uPlot's columnar shape [xs, ...series] and a `series`
  // descriptor. Handles instance build, live setData, resize, a crosshair
  // tooltip, and theme-aware colors. See ServerView for a live example.
  import { onMount, onDestroy } from 'svelte'
  import uPlot from 'uplot'
  import 'uplot/dist/uPlot.min.css'

  let {
    data = [],            // [xVals(unix s), series1, series2, ...]
    series = [],          // [{ label, stroke:'--cpu', width?, fill? }] one per non-x column
    height = 150,
    yRange = null,        // [min,max] fixed, or null to auto-scale
    yUnit = '',           // suffix on axis + tooltip values, e.g. '%'
    yFormat = null,       // (v) => string; overrides the default `${v}${yUnit}`
    tooltip = true,
  } = $props()

  let el                  // chart mount node
  let u = null            // uPlot instance
  let ro = null           // ResizeObserver
  let mo = null           // theme MutationObserver

  const css = (name) =>
    name && name.startsWith('--')
      ? getComputedStyle(document.documentElement).getPropertyValue(name).trim()
      : name
  const withAlpha = (col, a) =>
    /\)\s*$/.test(col) ? col.replace(/\)\s*$/, ` / ${a})`) : col

  function fmtY(v) {
    if (yFormat) return yFormat(v)
    return `${v}${yUnit}`
  }

  function tooltipPlugin(strokes) {
    let tip
    return {
      hooks: {
        init: (up) => {
          tip = document.createElement('div')
          tip.className = 'uchart-tip'
          up.over.appendChild(tip)
        },
        setCursor: (up) => {
          const i = up.cursor.idx
          if (i == null || up.cursor.left < 0) {
            if (tip) tip.style.display = 'none'
            return
          }
          const t = up.data[0][i]
          let h = `<div class="uchart-tip-t">${new Date(t * 1000).toLocaleTimeString()}</div>`
          for (let s = 1; s < up.series.length; s++) {
            const v = up.data[s][i]
            h += `<div class="uchart-tip-r"><span class="uchart-tip-sw" style="background:${strokes[s - 1]}"></span>${up.series[s].label} <b>${v == null ? '—' : fmtY(+v.toFixed(1))}</b></div>`
          }
          tip.innerHTML = h
          tip.style.display = 'block'
          tip.style.left = Math.min(up.cursor.left + 14, up.over.clientWidth - 130) + 'px'
          tip.style.top = up.cursor.top + 8 + 'px'
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

    const ax = (size, values) => ({
      stroke: axisColor,
      grid: { stroke: gridColor, width: 1 },
      ticks: { stroke: gridColor, width: 1, size: 4 },
      font: '11px ui-sans-serif, system-ui, sans-serif',
      size,
      ...(values ? { values } : {}),
    })

    const uSeries = [{}]
    series.forEach((s, idx) => {
      const col = strokes[idx]
      const entry = { label: s.label, stroke: col, width: s.width ?? 2 }
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

    const opts = {
      width: el.clientWidth || 400,
      height,
      cursor: { y: false, points: { size: 7 } },
      legend: { show: false },
      scales: yRange ? { y: { range: () => yRange } } : {},
      axes: [ax(28), ax(36, (up, vals) => vals.map(fmtY))],
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
</script>

<div bind:this={el} class="uchart" style="height:{height}px"></div>

<style>
  .uchart {
    width: 100%;
    position: relative;
  }
  /* uPlot renders its own canvas; tooltip is appended into .u-over */
  :global(.uchart-tip) {
    position: absolute;
    pointer-events: none;
    z-index: 10;
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
