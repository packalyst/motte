<script>
  /**
   * WorldMap — a self-contained SVG world map (real country outlines, no network,
   * no runtime projection) with one bubble per country sized by count, plus
   * scroll/drag + button zoom. Outline is a pre-projected path (lib/worldPath.js);
   * bubbles are placed from a small ISO-2 centroid table with the same projection.
   * dots: [{ country, count }] (country = 2-letter ISO); kind: 'src' | 'dest'.
   */
  import { WORLD_PATH, WORLD_VIEWBOX } from '../lib/worldPath.js'
  import CountryFlag from './CountryFlag.svelte'
  import Icon from './Icon.svelte'

  let { dots = [], kind = 'src' } = $props()

  const W = 1000, H = 500 // must match worldPath.js viewBox

  const COORDS = {
    US: [-98, 39, 'United States'], CA: [-106, 56, 'Canada'], MX: [-102, 23, 'Mexico'],
    BR: [-51, -10, 'Brazil'], AR: [-64, -34, 'Argentina'], CL: [-71, -30, 'Chile'], CO: [-74, 4, 'Colombia'],
    GB: [-2, 54, 'United Kingdom'], IE: [-8, 53, 'Ireland'], FR: [2, 47, 'France'], DE: [10, 51, 'Germany'],
    NL: [5, 52, 'Netherlands'], BE: [4, 50, 'Belgium'], ES: [-4, 40, 'Spain'], PT: [-8, 39, 'Portugal'],
    IT: [12, 42, 'Italy'], CH: [8, 47, 'Switzerland'], AT: [14, 47, 'Austria'], SE: [15, 62, 'Sweden'],
    NO: [8, 61, 'Norway'], FI: [26, 64, 'Finland'], DK: [10, 56, 'Denmark'], PL: [19, 52, 'Poland'],
    CZ: [15, 50, 'Czechia'], RO: [25, 46, 'Romania'], UA: [32, 49, 'Ukraine'], RU: [90, 62, 'Russia'],
    TR: [35, 39, 'Turkey'], GR: [22, 39, 'Greece'], BG: [25, 43, 'Bulgaria'], RS: [21, 44, 'Serbia'],
    CN: [104, 35, 'China'], JP: [138, 36, 'Japan'], KR: [127, 36, 'South Korea'], IN: [78, 21, 'India'],
    SG: [104, 1, 'Singapore'], HK: [114, 22, 'Hong Kong'], TW: [121, 24, 'Taiwan'], VN: [108, 16, 'Vietnam'],
    TH: [101, 15, 'Thailand'], ID: [113, -1, 'Indonesia'], MY: [102, 4, 'Malaysia'], PH: [122, 12, 'Philippines'],
    AU: [134, -25, 'Australia'], NZ: [172, -41, 'New Zealand'], ZA: [24, -29, 'South Africa'],
    EG: [30, 27, 'Egypt'], NG: [8, 9, 'Nigeria'], KE: [38, 0, 'Kenya'], MA: [-7, 32, 'Morocco'],
    IR: [53, 32, 'Iran'], IL: [35, 31, 'Israel'], SA: [45, 24, 'Saudi Arabia'], AE: [54, 24, 'UAE'],
    PK: [70, 30, 'Pakistan'], BD: [90, 24, 'Bangladesh'], KP: [127, 40, 'North Korea'],
  }

  const color = $derived(kind === 'src' ? 'var(--destructive)' : 'var(--info)')
  const noun = $derived(kind === 'src' ? 'blocked attempts' : 'connections')

  const plotted = $derived.by(() => {
    const max = Math.max(1, ...dots.map((d) => d.count || 0))
    return dots
      .filter((d) => COORDS[d.country])
      .map((d) => {
        const [lon, lat, name] = COORDS[d.country]
        return {
          country: d.country, count: d.count || 0, name,
          x: ((lon + 180) / 360) * W,
          y: ((90 - lat) / 180) * H,
          r: 4 + 26 * Math.sqrt((d.count || 0) / max),
        }
      })
      .sort((a, b) => b.r - a.r)
  })

  // ── zoom / pan (viewBox driven, so bubble sizes + tooltips track the zoom) ──
  let scale = $state(1)
  let ox = $state(0), oy = $state(0) // viewBox top-left in map units
  let elW = $state(1)
  const vbW = $derived(W / scale)
  const vbH = $derived(H / scale)
  const viewBox = $derived(`${ox} ${oy} ${vbW} ${vbH}`)

  function clamp() {
    ox = Math.max(0, Math.min(W - vbW, ox))
    oy = Math.max(0, Math.min(H - vbH, oy))
  }
  // Zoom keeping the point at (fracX, fracY) of the viewport fixed under the cursor.
  function zoomTo(next, fracX = 0.5, fracY = 0.5) {
    const ns = Math.max(1, Math.min(8, next))
    const px = ox + fracX * vbW, py = oy + fracY * vbH
    scale = ns
    ox = px - fracX * (W / ns)
    oy = py - fracY * (H / ns)
    clamp()
  }
  function reset() { scale = 1; ox = 0; oy = 0 }
  function onWheel(e) {
    e.preventDefault()
    const r = e.currentTarget.getBoundingClientRect()
    zoomTo(scale * (e.deltaY < 0 ? 1.2 : 1 / 1.2), (e.clientX - r.left) / r.width, (e.clientY - r.top) / r.height)
  }
  // drag to pan
  let dragging = $state(false)
  let lastX = 0, lastY = 0
  function onDown(e) { dragging = true; lastX = e.clientX; lastY = e.clientY }
  function onMove(e) {
    if (!dragging || !elW) return
    const k = vbW / elW // map units per pixel
    ox -= (e.clientX - lastX) * k
    oy -= (e.clientY - lastY) * k
    lastX = e.clientX; lastY = e.clientY
    clamp()
  }
  function onUp() { dragging = false }

  let hover = $state(null)
</script>

<div class="wrap" bind:clientWidth={elW}>
  <!-- svelte-ignore a11y_no_static_element_interactions a11y_no_noninteractive_element_interactions -->
  <svg
    viewBox={viewBox} class="map" class:grab={!dragging} class:grabbing={dragging}
    role="img" aria-label="World map of {kind === 'src' ? 'source' : 'destination'} countries"
    onwheel={onWheel} onmousedown={onDown} onmousemove={onMove} onmouseup={onUp} onmouseleave={onUp}
  >
    <path d={WORLD_PATH} class="land" />
    {#each plotted as d}
      <g role="button" tabindex="0" aria-label="{d.name}: {d.count.toLocaleString()}"
        onmouseenter={() => (hover = d)} onfocus={() => (hover = d)} onmouseleave={() => (hover = null)} onblur={() => (hover = null)}>
        <circle cx={d.x} cy={d.y} r={d.r / scale} style="fill:{color}; stroke:{color}" fill-opacity="0.28" stroke-width={1.4 / scale} />
        <circle cx={d.x} cy={d.y} r={2 / scale} style="fill:{color}" />
      </g>
    {/each}
  </svg>

  <div class="zoom">
    <button title="Zoom in" class="glyph" onclick={() => zoomTo(scale * 1.5)}>+</button>
    <button title="Zoom out" class="glyph" onclick={() => zoomTo(scale / 1.5)}>&minus;</button>
    <button title="Reset" onclick={reset}><Icon name="refresh" size={13} /></button>
  </div>

  {#if hover}
    <div class="tt" style="left:{((hover.x - ox) / vbW) * 100}%; top:{((hover.y - oy) / vbH) * 100}%">
      <div class="tt-t"><CountryFlag code={hover.country} size="sm" /> {hover.name}</div>
      <div class="tt-v">{hover.count.toLocaleString()} {noun}</div>
    </div>
  {/if}
</div>

<style>
  .wrap { position: relative; width: 100%; overflow: hidden; }
  .map {
    width: 100%; height: auto; display: block; touch-action: none;
    background: color-mix(in oklch, var(--info) 7%, var(--card));
  }
  .map.grab { cursor: grab; }
  .map.grabbing { cursor: grabbing; }
  .land { fill: color-mix(in oklch, var(--muted-foreground) 24%, var(--card)); stroke: var(--card); stroke-width: 0.4; }
  .zoom { position: absolute; top: 8px; right: 8px; display: flex; flex-direction: column; gap: 4px; }
  .zoom button {
    width: 26px; height: 26px; display: flex; align-items: center; justify-content: center;
    background: var(--card); border: 1px solid var(--border); border-radius: 6px; cursor: pointer;
    color: var(--muted-foreground); box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12);
  }
  .zoom button:hover { color: var(--foreground); }
  .zoom button.glyph { font-size: 17px; font-weight: 600; line-height: 1; }
  .tt {
    position: absolute; transform: translate(-50%, -115%); pointer-events: none;
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 6px 9px; font-size: 11.5px; white-space: nowrap; z-index: 5;
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.18);
  }
  .tt-t { display: flex; align-items: center; gap: 5px; color: var(--muted-foreground); font-size: 10.5px; margin-bottom: 2px; }
  .tt-v { font-weight: 700; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
