<script>
  /**
   * WorldMap — a self-contained SVG world map (real country outlines, no network,
   * no runtime projection) with one bubble per country sized by count. The outline
   * is a pre-projected path (see lib/worldPath.js); bubbles are placed from a small
   * ISO-2 centroid table using the same equirectangular projection.
   * dots: [{ country, count }] (country = 2-letter ISO); kind: 'src' | 'dest'.
   */
  import { WORLD_PATH, WORLD_VIEWBOX } from '../lib/worldPath.js'
  import CountryFlag from './CountryFlag.svelte'

  let { dots = [], kind = 'src' } = $props()

  const W = 1000, H = 500 // must match worldPath.js viewBox

  // Rough centroid [lon, lat, name] per country. Anything not listed is skipped as a
  // bubble (it still appears in the ranked list beside the map).
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
      .sort((a, b) => b.r - a.r) // largest first so small bubbles land on top
  })

  let hover = $state(null)
</script>

<div class="wrap">
  <svg viewBox={WORLD_VIEWBOX} class="map" role="img" aria-label="World map of {kind === 'src' ? 'source' : 'destination'} countries">
    <path d={WORLD_PATH} class="land" />
    {#each plotted as d}
      <g role="button" tabindex="0" aria-label="{d.name}: {d.count.toLocaleString()}"
        onmouseenter={() => (hover = d)} onmousemove={() => (hover = d)} onmouseleave={() => (hover = null)}
        onfocus={() => (hover = d)} onblur={() => (hover = null)} style="cursor:pointer">
        <circle cx={d.x} cy={d.y} r={d.r} style="fill:{color}; stroke:{color}" fill-opacity="0.28" stroke-width="1.4" />
        <circle cx={d.x} cy={d.y} r="2" style="fill:{color}" />
      </g>
    {/each}
  </svg>

  {#if hover}
    <div class="tt" style="left:{(hover.x / W) * 100}%; top:{(hover.y / H) * 100}%">
      <div class="tt-t"><CountryFlag code={hover.country} size="sm" /> {hover.name}</div>
      <div class="tt-v">{hover.count.toLocaleString()} {noun}</div>
    </div>
  {/if}
</div>

<style>
  .wrap { position: relative; width: 100%; }
  .map {
    width: 100%; height: auto; display: block; border-radius: 8px;
    background: color-mix(in oklch, var(--info) 7%, var(--card)); /* subtle ocean */
  }
  .land {
    fill: color-mix(in oklch, var(--muted-foreground) 24%, var(--card));
    stroke: var(--card); stroke-width: 0.4;
  }
  .tt {
    position: absolute; transform: translate(-50%, -115%); pointer-events: none;
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 6px 9px; font-size: 11.5px; white-space: nowrap; z-index: 5;
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.18);
  }
  .tt-t { display: flex; align-items: center; gap: 5px; color: var(--muted-foreground); font-size: 10.5px; margin-bottom: 2px; }
  .tt-v { font-weight: 700; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
