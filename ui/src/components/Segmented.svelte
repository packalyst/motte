<script>
  /**
   * Segmented — a compact single-choice toggle (Avg / Peak, 24h / 7d, Deny / Allow, All / Online /
   * Offline). Use bind:value, or value + onchange for a controlled toggle. options:
   * [{ value, label, count?, tone? }]; tone ('destructive' | 'success') colours
   * the option while it is selected. stretch makes the options share the full width (mobile 50/50).
   * size: 'default' matches kt-input / kt-select height (use it beside inputs); 'sm' is the
   * compact one for card headers.
   */
  let {
    options = [],
    value = $bindable(),
    onchange = undefined,
    disabled = false,
    stretch = false,
    label = undefined, // accessible group name
    size = 'default',
    class: className = '',
  } = $props()

  const SIZES = {
    default: { group: 'h-8.5 text-[0.8125rem]', option: 'h-full px-3' }, // matches kt-input / kt-select
    sm: { group: 'h-control text-xs', option: 'h-full px-2.5' }, // matches kt-input-sm / kt-select-sm
  }
  const sz = $derived(SIZES[size] || SIZES.default)

  const toneActive = {
    destructive: 'bg-destructive/15 text-destructive',
    success: 'bg-success/15 text-success',
  }

  // With onchange the parent decides (it may cancel, e.g. a declined confirmation); otherwise the
  // bound value is updated directly.
  function pick(v) {
    if (v === value) return
    if (onchange) onchange(v)
    else value = v
  }
</script>

<div role="group" aria-label={label}
  class="{stretch ? 'flex w-full sm:w-auto' : 'inline-flex'} items-center gap-0.5 rounded-lg bg-muted/60 border border-border p-0.5 shrink-0 {sz.group} {className}">
  {#each options as o (o.value)}
    <button type="button" {disabled} aria-pressed={value === o.value} onclick={() => pick(o.value)}
      class="{stretch ? 'flex-1 sm:flex-none' : ''} inline-flex items-center justify-center gap-1.5 {sz.option} rounded-md whitespace-nowrap transition cursor-pointer disabled:cursor-not-allowed disabled:opacity-60
        {value === o.value ? `${toneActive[o.tone] || 'bg-card text-foreground'} shadow-sm font-medium` : 'text-muted-foreground hover:text-foreground'}">
      {o.label}
      {#if o.count !== undefined}<span class="tabular-nums {value === o.value ? 'opacity-70' : 'opacity-60'}">{o.count}</span>{/if}
    </button>
  {/each}
</div>
