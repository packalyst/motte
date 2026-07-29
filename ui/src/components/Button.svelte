<script>
  import Icon from './Icon.svelte';
  import { copyWithToast } from '../stores/helpers.js';
  import { toast } from '../stores/app.js';

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
    copyText = undefined, // when set, clicking copies it (icon → check + toast)
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

  // Copy feedback: when copyText is set, copy it and briefly swap the icon to a
  // checkmark so every copy button gets consistent visual confirmation.
  let copied = $state(false);
  let copyTimer;
  async function handleClick(e) {
    if (copyText !== undefined && copyText !== null && copyText !== '') {
      if (await copyWithToast(String(copyText), toast)) {
        copied = true;
        clearTimeout(copyTimer);
        copyTimer = setTimeout(() => (copied = false), 1500);
      }
    }
    onclick?.(e);
  }
</script>

<button
  {type}
  disabled={disabled || loading}
  onclick={handleClick}
  class={classes}
  data-kt-tooltip={tooltip ? '' : undefined}
  {...restProps}
>
  {#if loading}
    <span class="{spinnerSizes[size]} border-2 border-current border-t-transparent rounded-full animate-spin"></span>
  {:else if copied}
    <Icon name="check" size={size === 'xs' ? 12 : 14} />
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
