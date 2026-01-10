<script>
  import Icon from './Icon.svelte'

  let {
    icon = 'inbox',
    title = 'No items',
    description = '',
    compact = false,
    large = false,
    children
  } = $props()
</script>

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
