<script>
  import Icon from './Icon.svelte';

  let {
    variant = 'primary',
    size = 'default',
    icon = undefined,
    iconOnly = false,
    disabled = false,
    loading = false,
    type = 'button',
    class: className = '',
    onclick = undefined,
    label = undefined,
    tooltip = undefined,
    children,
    ...restProps
  } = $props();

  const variantClasses = {
    primary: '',
    secondary: 'kt-btn-secondary',
    destructive: 'kt-btn-destructive',
    success: 'kt-btn-success',
    outline: 'kt-btn-outline',
    ghost: 'kt-btn-ghost',
    mono: 'kt-btn-mono'
  };

  const sizeClasses = {
    default: 'kt-btn-sm',
    sm: 'kt-btn-sm',
    xs: 'kt-btn-xs'
  };

  const spinnerSizes = {
    default: 'w-4 h-4',
    sm: 'w-3 h-3',
    xs: 'w-3 h-3'
  };

  const classes = $derived([
    'kt-btn',
    variantClasses[variant],
    sizeClasses[size],
    iconOnly && 'kt-btn-icon',
    className
  ].filter(Boolean).join(' '));
</script>

<button
  {type}
  disabled={disabled || loading}
  {onclick}
  class={classes}
  data-kt-tooltip={tooltip ? '' : undefined}
  {...restProps}
>
  {#if loading}
    <span class="{spinnerSizes[size]} border-2 border-current border-t-transparent rounded-full animate-spin"></span>
  {:else if icon}
    <Icon name={icon} size={size === 'xs' ? 12 : 14} />
  {/if}
  {#if !iconOnly}
    {#if label}
      {label}
    {:else}
      {@render children?.()}
    {/if}
  {/if}
  {#if tooltip}
    <span data-kt-tooltip-content class="kt-tooltip hidden">{tooltip}</span>
  {/if}
</button>
