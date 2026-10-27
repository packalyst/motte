<script>
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'

  let {
    label = '',
    icon = undefined,
    variant = 'default',
    size = 'sm',
    disabled = false,
    items = [],
    ariaLabel = '', // names the button when there's no label (icon-only, e.g. a row's ⋯ menu)
    class: className = ''
  } = $props()

  let open = $state(false)

  function handleItemClick(item) {
    if (item.onclick && !item.disabled) {
      item.onclick()
    }
    open = false
  }
</script>

<div class="relative {className}">
  <Button
    onclick={() => open = !open}
    {variant}
    {size}
    icon={label ? icon : icon || 'dots'}
    iconOnly={!label}
    {disabled}
    aria-label={label ? undefined : ariaLabel}
    aria-haspopup="menu"
    aria-expanded={open}
  >
    {label}
    <Icon name="chevron-down" size={12} class="ml-1 {open ? 'rotate-180' : ''}" />
  </Button>

  {#if open}
    <div class="kt-dropdown" role="menu">
      {#each items as item}
        {#if item.divider}
          <div class="kt-dropdown-divider"></div>
        {:else}
          <button
            onclick={() => handleItemClick(item)}
            disabled={item.disabled}
            class="kt-dropdown-item cursor-pointer {item.variant === 'destructive' ? 'text-destructive' : ''}"
          >
            {#if item.icon}
              <Icon name={item.icon} size={14} class="kt-dropdown-item-icon {item.iconClass || ''}" />
            {/if}
            {item.label}
            {#if item.badge}
              <span class="ml-auto text-xs text-muted">({item.badge})</span>
            {/if}
          </button>
        {/if}
      {/each}
    </div>
    <button class="kt-dropdown-backdrop" onclick={() => open = false} aria-label="Close menu"></button>
  {/if}
</div>
