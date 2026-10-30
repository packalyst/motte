<script>
  /**
   * GroupHeading — the heading over a group of cards on a page that stacks several groups (the
   * Headscale page): a coloured mark, an uppercase title running into a hairline, a short note
   * (a count) and an optional "+ …" action at the end. action: { label, onclick } — leave it out
   * for people who may not add.
   */
  import Icon from './Icon.svelte'

  let { title, color = 'var(--color-primary)', note = '', action = undefined } = $props()
</script>

<div class="flex items-center gap-3">
  <h2 class="flex min-w-0 flex-1 items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground after:h-px after:flex-1 after:bg-border">
    <span class="h-2 w-2 shrink-0 rounded-sm" style="background: {color}"></span>
    {title}
    {#if note}<span class="font-normal normal-case tracking-normal">{note}</span>{/if}
  </h2>
  {#if action}
    <button type="button" class="link-action" onclick={action.onclick}><Icon name="plus" size={12} />{action.label}</button>
  {/if}
</div>
