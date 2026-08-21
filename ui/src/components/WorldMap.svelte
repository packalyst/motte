<script>
  /**
   * WorldMap — a stylized, dependency-free world map (soft continent blobs +
   * graticule) with one bubble per country sized by count. Not a real geographic
   * map; it reads at a glance for "where is traffic coming from / going to".
   * dots: [{ country, count }] (country = 2-letter ISO). kind: 'src' | 'dest'.
   */
  import CountryFlag from './CountryFlag.svelte'

  let { dots = [], kind = 'src' } = $props()

  const W = 680, H = 340

  // Rough centroid (lon, lat) + display name per country. Countries not listed are
  // skipped on the map (they still appear in the accompanying ranked list).
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

  // Soft blobs suggesting the continents (decorative, not accurate coastlines).
  const CONTINENTS = [
    [130, 112, 88, 64], [196, 232, 40, 70], [352, 90, 40, 30],
    [362, 186, 50, 80], [502, 104, 126, 74], [572, 242, 42, 26],
  ]
  const GRAT_Y = Array.from({ length: 7 }, (_, i) => (i * H) / 6)
  const GRAT_X = Array.from({ length: 13 }, (_, i) => (i * W) / 12)

  const color = $derived(kind === 'src' ? 'var(--destructive)' : 'var(--info)')

  const plotted = $derived.by(() => {
    const max = Math.max(1, ...dots.map((d) => d.count || 0))
    const ranked = [...dots].sort((a, b) => (b.count || 0) - (a.count || 0))
    const top = new Set(ranked.slice(0, 3).map((d) => d.country))
    return dots
      .filter((d) => COORDS[d.country])
      .map((d) => {
        const [lon, lat, name] = COORDS[d.country]
        return {
          country: d.country,
          count: d.count || 0,
          name,
          x: ((lon + 180) / 360) * W,
          y: ((90 - lat) / 180) * H,
          r: 5 + 17 * Math.sqrt((d.count || 0) / max),
          top: top.has(d.country),
        }
      })
  })

  let hover = $state(null) // { country, name, count, x, y }
</script>

<div class="wrap">
  <svg viewBox="0 0 {W} {H}" role="img" aria-label="World map of {kind === 'src' ? 'source' : 'destination'} countries">
    {#each CONTINENTS as [cx, cy, rx, ry]}
      <ellipse {cx} {cy} {rx} {ry} fill="var(--muted-foreground)" opacity="0.09" />
    {/each}
    {#each GRAT_Y as y}<line x1="0" y1={y} x2={W} y2={y} stroke="var(--border)" stroke-width="1" opacity="0.5" />{/each}
    {#each GRAT_X as x}<line x1={x} y1="0" x2={x} y2={H} stroke="var(--border)" stroke-width="1" opacity="0.5" />{/each}
    {#each plotted as d}
      <g style="cursor:pointer"
        role="button" tabindex="0" aria-label="{d.name}: {d.count.toLocaleString()}"
        onmouseenter={() => (hover = d)} onmousemove={() => (hover = d)} onmouseleave={() => (hover = null)}
        onfocus={() => (hover = d)} onblur={() => (hover = null)}>
        <circle cx={d.x} cy={d.y} r={d.r} fill={color} fill-opacity="0.25" stroke={color} stroke-width="1.5" />
        <circle cx={d.x} cy={d.y} r="2.4" fill={color} />
      </g>
      {#if d.top}
        <text class="lbl" x={d.x + d.r + 4} y={d.y + 3}>{d.country}</text>
      {/if}
    {/each}
  </svg>

  {#if hover}
    <div class="tt" style="left:{(hover.x / W) * 100}%; top:{(hover.y / H) * 100}%">
      <div class="tt-t"><CountryFlag code={hover.country} size="sm" /> {hover.name}</div>
      <div class="tt-v">{hover.count.toLocaleString()} {kind === 'src' ? 'blocked attempts' : 'connections'}</div>
    </div>
  {/if}
</div>

<style>
  .wrap { position: relative; }
  svg { display: block; width: 100%; height: auto; }
  .lbl { font-size: 9px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; fill: var(--muted-foreground); pointer-events: none; }
  .tt {
    position: absolute; pointer-events: none; transform: translate(-50%, -110%);
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 6px 9px; font-size: 11.5px; white-space: nowrap; z-index: 5;
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.18);
  }
  .tt-t { display: flex; align-items: center; gap: 5px; color: var(--muted-foreground); font-size: 10.5px; margin-bottom: 2px; }
  .tt-v { font-weight: 700; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
