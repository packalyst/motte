<script>
  /**
   * WorldMap — a real, zoomable world map (Leaflet + OpenStreetMap tiles, same
   * stack the app already uses in LocationMap) with one circle per country sized
   * by count. dots: [{ country, count }] (country = 2-letter ISO); kind: 'src'|'dest'
   * only changes the marker colour + tooltip wording.
   */
  import { onMount, onDestroy } from 'svelte'

  let { dots = [], kind = 'src' } = $props()

  // Rough centroid [lon, lat, name] per country. Anything not listed is skipped on
  // the map (it still appears in the ranked list beside it).
  const COORDS = {
    US: [-98, 39, 'United States'], CA: [-106, 56, 'Canada'], MX: [-102, 23, 'Mexico'],
    BR: [-51, -10, 'Brazil'], AR: [-64, -34, 'Argentina'], CL: [-71, -30, 'Chile'], CO: [-74, 4, 'Colombia'],
    GB: [-2, 54, 'United Kingdom'], IE: [-8, 53, 'Ireland'], FR: [2, 47, 'France'], DE: [10, 51, 'Germany'],
    NL: [5, 52, 'Netherlands'], BE: [4, 50, 'Belgium'], ES: [-4, 40, 'Spain'], PT: [-8, 39, 'Portugal'],
    IT: [12, 42, 'Italy'], CH: [8, 47, 'Switzerland'], AT: [14, 47, 'Austria'], SE: [15, 62, 'Sweden'],
    NO: [8, 61, 'Norway'], FI: [26, 64, 'Finland'], DK: [10, 56, 'Denmark'], PL: [19, 52, 'Poland'],
    CZ: [15, 50, 'Czechia'], RO: [25, 46, 'Romania'], UA: [32, 49, 'Ukraine'], RU: [60, 61, 'Russia'],
    TR: [35, 39, 'Turkey'], GR: [22, 39, 'Greece'], BG: [25, 43, 'Bulgaria'], RS: [21, 44, 'Serbia'],
    CN: [104, 35, 'China'], JP: [138, 36, 'Japan'], KR: [127, 36, 'South Korea'], IN: [78, 21, 'India'],
    SG: [104, 1, 'Singapore'], HK: [114, 22, 'Hong Kong'], TW: [121, 24, 'Taiwan'], VN: [108, 16, 'Vietnam'],
    TH: [101, 15, 'Thailand'], ID: [113, -1, 'Indonesia'], MY: [102, 4, 'Malaysia'], PH: [122, 12, 'Philippines'],
    AU: [134, -25, 'Australia'], NZ: [172, -41, 'New Zealand'], ZA: [24, -29, 'South Africa'],
    EG: [30, 27, 'Egypt'], NG: [8, 9, 'Nigeria'], KE: [38, 0, 'Kenya'], MA: [-7, 32, 'Morocco'],
    IR: [53, 32, 'Iran'], IL: [35, 31, 'Israel'], SA: [45, 24, 'Saudi Arabia'], AE: [54, 24, 'UAE'],
    PK: [70, 30, 'Pakistan'], BD: [90, 24, 'Bangladesh'], KP: [127, 40, 'North Korea'],
  }

  let el = $state(null)
  let map = null
  let L = null
  let layer = null

  // Leaflet needs concrete colours (it writes SVG attributes), so these mirror the
  // app's destructive / info hues rather than reading the CSS vars.
  const markerColor = () => (kind === 'src' ? '#ef4444' : '#3b82f6')

  function draw() {
    if (!map || !L) return
    if (layer) layer.remove()
    layer = L.layerGroup().addTo(map)
    const max = Math.max(1, ...dots.map((d) => d.count || 0))
    const noun = kind === 'src' ? 'blocked attempts' : 'connections'
    for (const d of dots) {
      const c = COORDS[d.country]
      if (!c) continue
      L.circleMarker([c[1], c[0]], {
        radius: 6 + 20 * Math.sqrt((d.count || 0) / max),
        color: markerColor(), weight: 1.5, fillColor: markerColor(), fillOpacity: 0.35,
      })
        .bindTooltip(`${c[2]}: ${(d.count || 0).toLocaleString()} ${noun}`, { direction: 'top' })
        .addTo(layer)
    }
  }

  onMount(async () => {
    const leaflet = await import('leaflet')
    L = leaflet.default
    if (!document.querySelector('link[href*="leaflet.css"]')) {
      const link = document.createElement('link')
      link.rel = 'stylesheet'
      link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'
      document.head.appendChild(link)
    }
    map = L.map(el, { worldCopyJump: true, minZoom: 1, maxZoom: 6, attributionControl: false }).setView([25, 5], 1)
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 6 }).addTo(map)
    draw()
    setTimeout(() => map?.invalidateSize(), 60)
  })

  // Redraw when the data or src/dest kind changes (map itself persists).
  $effect(() => {
    dots
    kind
    draw()
  })

  onDestroy(() => {
    map?.remove()
    map = null
  })
</script>

<div bind:this={el} class="wmap"></div>

<style>
  .wmap {
    width: 100%;
    height: 340px;
    border-radius: 8px;
    overflow: hidden;
    z-index: 0; /* keep tiles under the app's sticky header/toolbars */
  }
  :global(.wmap .leaflet-container) {
    background: var(--muted);
    font: inherit;
  }
</style>
