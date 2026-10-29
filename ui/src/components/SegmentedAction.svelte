<script>
  /**
   * SegmentedAction — an icon in a Segmented's trailing slot: a row action (remove, edit) when it has
   * onclick, otherwise a static icon whose tooltip says why there's no action (a lock).
   */
  import Icon from './Icon.svelte'

  let { icon, tooltip, onclick = undefined, danger = false, label = undefined } = $props()
</script>

{#if onclick}
  <button type="button" aria-label={label || tooltip} data-kt-tooltip {onclick}
    class="grid h-full w-7 cursor-pointer place-items-center rounded-md text-muted-foreground transition
      {danger ? 'hover:bg-destructive/15 hover:text-destructive' : 'hover:bg-card hover:text-foreground'}">
    <Icon name={icon} size={14} />
    <span data-kt-tooltip-content class="kt-tooltip hidden">{tooltip}</span>
  </button>
{:else}
  <span class="grid h-full w-7 cursor-help place-items-center text-muted-foreground/50" data-kt-tooltip>
    <Icon name={icon} size={14} />
    <span data-kt-tooltip-content class="kt-tooltip hidden">{tooltip}</span>
  </span>
{/if}
