<script>
  /**
   * TileRow — one item of a dashed-box list (Allowed ports, Jails): a small tile with a value and
   * a unit, a title with a short line under it (icon + text), and the item's control at the end
   * (children). tone colours the tile: warning | success | destructive | muted; dim fades the row.
   */
  import Icon from './Icon.svelte'

  let { value, unit = '', tone = 'muted', title, subIcon = undefined, sub = '', dim = false, children } = $props()

  const TONE = {
    warning: 'border-warning/30 bg-warning/10 text-warning',
    success: 'border-success/30 bg-success/10 text-success',
    destructive: 'border-destructive/30 bg-destructive/10 text-destructive',
    muted: 'border-border bg-muted text-muted-foreground',
  }
</script>

<li class="flex min-w-0 items-center gap-3 rounded-lg border border-dashed border-border bg-muted/50 p-2 transition {dim ? 'opacity-60' : ''}">
  <div class="flex w-14 shrink-0 flex-col items-center justify-center rounded-md border py-1 {TONE[tone] || TONE.muted}">
    <span class="font-mono text-sm font-semibold leading-tight tabular-nums text-foreground">{value}</span>
    {#if unit}<span class="text-[9px] font-medium uppercase leading-tight tracking-wider">{unit}</span>{/if}
  </div>
  <div class="min-w-0 flex-1">
    <div class="truncate text-sm font-medium text-foreground">{title}</div>
    {#if sub}
      <div class="flex items-center gap-1 text-[11px] text-muted-foreground">
        {#if subIcon}<Icon name={subIcon} size={12} class="shrink-0" />{/if}<span class="truncate">{sub}</span>
      </div>
    {/if}
  </div>
  {@render children?.()}
</li>
