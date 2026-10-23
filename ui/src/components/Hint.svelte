<script>
  /**
   * Hint — a label with its explanation on hover instead of a line of text under the field:
   * renders the children (the label text) plus a small info icon; hovering either shows the
   * KTUI tooltip. Screen readers get the text inline (sr-only). Without text it's just the label.
   */
  import Icon from './Icon.svelte'

  let { text = undefined, children } = $props()
</script>

{#if text}
  <span class="inline-flex cursor-help items-center gap-1" data-kt-tooltip>
    {@render children()}
    <Icon name="info-circle" size={12} class="shrink-0 text-muted-foreground" />
    <span data-kt-tooltip-content class="kt-tooltip hidden max-w-xs">{text}</span>
    <span class="sr-only">: {text}</span>
  </span>
{:else}
  {@render children()}
{/if}
