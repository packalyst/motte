<script>
  // Toggable chart legend, meant to sit inline with a chart's title. Each chip
  // shows a colour swatch, the series label, and (optionally) the latest value;
  // clicking toggles the series. Pairs with UPlotChart's bindable `hidden`.
  //   series: [{ label, stroke:'--tok', val?(latest), fmt?(v) }]
  //   hidden: { [i]: true } map of hidden series
  //   latest: source object passed to val() for the live readout
  //   ontoggle(i): called on click
  let { series = [], hidden = {}, latest = null, ontoggle = () => {} } = $props()
  const swatch = (s) => (s && s.startsWith('--') ? `var(${s})` : s)
</script>

<span class="ml-auto flex items-center gap-1.5 text-[11px] font-normal text-muted-foreground">
  {#each series as s, i}
    <button
      type="button"
      class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full transition-opacity {hidden[i] ? 'opacity-40 line-through' : 'hover:bg-muted'}"
      onclick={() => ontoggle(i)}
      title="Toggle {s.label}"
    >
      <span class="w-2 h-2 rounded-sm" style="background:{swatch(s.stroke)}"></span>{s.label}{#if latest && s.val}&nbsp;<b class="text-foreground tabular-nums">{s.fmt(s.val(latest))}</b>{/if}
    </button>
  {/each}
</span>
