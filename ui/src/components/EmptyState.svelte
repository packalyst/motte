<script>
  import Icon from './Icon.svelte'

  let {
    icon = 'inbox',
    title = 'No items',
    description = '',
    compact = false,
    large = false,
    inline = false, // one row inside a page section: tinted icon beside the text
    color = '', // inline only: the section's colour for the icon tile
    children
  } = $props()
</script>

{#if inline}
  <div class="flex items-center gap-4 rounded-xl border border-dashed border-border bg-card/40 px-4 py-4 sm:px-5">
    <span class="grid h-10 w-10 shrink-0 place-items-center rounded-xl {color ? '' : 'bg-muted text-muted-foreground'}"
      style={color ? `background: color-mix(in oklch, ${color} 14%, transparent); color: ${color}` : undefined}>
      <Icon name={icon} size={20} />
    </span>
    <div class="min-w-0 flex-1">
      <h4 class="text-sm font-medium text-foreground">{title}</h4>
      {#if description}<p class="mt-0.5 text-xs text-pretty text-muted-foreground">{description}</p>{/if}
    </div>
  </div>
{:else}
  <div class="empty-state {compact ? 'empty-state-compact' : ''} {large ? 'empty-state-lg' : ''}">
    <div class="empty-state-icon {large ? 'empty-state-icon-lg' : ''}">
      <Icon name={icon} size={20} />
    </div>
    <h4 class="mt-3 text-sm font-medium text-foreground">{title}</h4>
    {#if description}
      <p class="mt-1 text-xs text-muted-foreground">{description}</p>
    {/if}
    {#if children}
      <div class="mt-4">
        {@render children()}
      </div>
    {/if}
  </div>
{/if}
