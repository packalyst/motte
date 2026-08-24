<script>
  /**
   * Donut — a part-to-whole ring with a centered total and an inline legend.
   * Reused for the analytics status mixes (HTTP status, DNS codes, query types,
   * protocols). Segments: [{ label, count, color }] where color is any CSS colour
   * (e.g. 'var(--success)'). Thin arcs with a small gap between segments.
   */
  let { segments = [], format = (v) => String(v) } = $props()

  const total = $derived(segments.reduce((s, x) => s + (x.count || 0), 0))

  const R = 40, CX = 52, CY = 52, SW = 15
  const CIRC = 2 * Math.PI * R

  // Precompute each arc's dash length + rotation offset around the ring.
  const arcs = $derived.by(() => {
    let offset = 0
    return segments.map((s) => {
      const frac = total ? (s.count || 0) / total : 0
      const len = Math.max(0, frac * CIRC - 2) // 2px gap between segments
      const arc = { ...s, len, gap: CIRC - len, offset: -offset }
      offset += frac * CIRC
      return arc
    })
  })

  const pctOf = (n) => (total ? Math.round((n / total) * 100) : 0)

  // Styled hover tooltip (position:fixed so a card's overflow can't clip it).
  let tip = $state(null)
  function showTip(e, a) {
    tip = { label: a.label, color: a.color, count: a.count || 0, pct: pctOf(a.count), x: e.clientX, y: e.clientY }
  }
  const hideTip = () => (tip = null)
</script>

<div class="donut">
  <svg viewBox="0 0 104 104" width="112" height="112" aria-hidden="true">
    {#each arcs as a}
      <circle
        cx={CX} cy={CY} r={R} fill="none" stroke={a.color} stroke-width={SW}
        stroke-dasharray="{a.len.toFixed(1)} {a.gap.toFixed(1)}"
        stroke-dashoffset={a.offset.toFixed(1)}
        transform="rotate(-90 {CX} {CY})"
        role="presentation"
        onmouseenter={(e) => showTip(e, a)}
        onmousemove={(e) => showTip(e, a)}
        onmouseleave={hideTip}
      ></circle>
    {/each}
    <text x="52" y="49" text-anchor="middle" font-size="17" font-weight="800" fill="var(--foreground)">{format(total)}</text>
    <text x="52" y="63" text-anchor="middle" font-size="8" fill="var(--muted-foreground)">total</text>
  </svg>
  <div class="legend">
    {#each segments as s}
      <span class="item">
        <span class="sw" style="background:{s.color}"></span>
        <span class="n">{s.label}</span>
        <span class="v">{(s.count || 0).toLocaleString()}</span>
        <span class="n">· {pctOf(s.count)}%</span>
      </span>
    {/each}
  </div>
</div>

{#if tip}
  <div class="donut-tip" style="left:{Math.min(tip.x + 14, (typeof window !== 'undefined' ? window.innerWidth : 9999) - 180)}px; top:{tip.y + 14}px">
    <span class="tip-sw" style="background:{tip.color}"></span>{tip.label}
    <b>{tip.count.toLocaleString()}</b> <span class="tip-pct">({tip.pct}%)</span>
  </div>
{/if}

<style>
  .donut { display: flex; align-items: center; gap: 18px; flex-wrap: wrap; }
  .donut svg circle { transition: opacity 0.12s ease; }
  .donut svg circle:hover { opacity: 0.82; }
  .donut-tip {
    position: fixed;
    z-index: 9999;
    pointer-events: none;
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 5px 9px;
    border-radius: 7px;
    font-size: 11px;
    white-space: nowrap;
    background: var(--card);
    color: var(--foreground);
    border: 1px solid var(--border);
    box-shadow: var(--shadow, 0 2px 8px rgba(0, 0, 0, 0.15));
  }
  .donut-tip b { font-variant-numeric: tabular-nums; }
  .donut-tip .tip-pct { color: var(--muted-foreground); }
  .donut-tip .tip-sw { width: 9px; height: 9px; border-radius: 2px; flex-shrink: 0; }
  .donut svg { flex-shrink: 0; }
  .legend { display: flex; flex-wrap: wrap; gap: 9px 16px; flex: 1; min-width: 140px; }
  .item { display: flex; align-items: center; gap: 6px; font-size: 11.5px; }
  .sw { width: 9px; height: 9px; border-radius: 2px; flex-shrink: 0; }
  .n { color: var(--muted-foreground); }
  .v { font-weight: 700; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin-left: 2px; }
</style>
