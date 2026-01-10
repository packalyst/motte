<script>
  import Icon from './Icon.svelte';

  let {
    checked = $bindable(false),
    variant = 'default', // 'default' | 'switch' | 'chip'
    color = 'primary',   // 'primary' | 'warning' | 'success' | 'destructive' - for chip variant
    borderless = false,  // for chip variant: removes border (used in input groups)
    labelPosition = undefined, // 'left' | 'right' - where label appears relative to checkbox (default: 'left' for switch, 'right' for others)
    label = undefined,
    helperText = undefined,
    icon = undefined,
    disabled = false,
    indeterminate = false,
    class: className = '',
    children,
    onchange = undefined,
    ...restProps
  } = $props();

  // Color classes for chip variant (with border)
  const chipColors = {
    primary: 'bg-primary/10 border-primary text-primary',
    warning: 'bg-warning/10 border-warning text-warning',
    success: 'bg-success/10 border-success text-success',
    destructive: 'bg-destructive/10 border-destructive text-destructive',
  };

  // Color classes for borderless chip variant
  const chipColorsBorderless = {
    primary: 'bg-primary/10 text-primary',
    warning: 'bg-warning/10 text-warning',
    success: 'bg-success/10 text-success',
    destructive: 'bg-destructive/10 text-destructive',
  };

  // Get the appropriate color classes based on borderless prop
  const getChipColorClass = (c) => borderless
    ? (chipColorsBorderless[c] || chipColorsBorderless.primary)
    : (chipColors[c] || chipColors.primary);

  // Effective label position (switch defaults to left, others default to right)
  const effectivePosition = $derived(labelPosition ?? (variant === 'switch' ? 'left' : 'right'));

  function handleChange(e) {
    checked = e.target.checked;
    onchange?.(e);
  }
</script>

{#if variant === 'switch'}
  <!-- Switch toggle variant (kt-switch) -->
  <label class="flex items-center gap-3 {disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'} {className}">
    {#if effectivePosition === 'left' && (label || helperText)}
      <div class="flex-1">
        {#if label}
          <span class="text-sm font-medium text-foreground">{label}</span>
        {/if}
        {#if helperText}
          <p class="text-xs text-muted-foreground">{helperText}</p>
        {/if}
      </div>
    {/if}
    <input
      type="checkbox"
      class="kt-switch kt-switch-sm"
      {checked}
      {disabled}
      onchange={handleChange}
      {...restProps}
    />
    {#if effectivePosition === 'right' && (label || helperText)}
      <div>
        {#if label}
          <span class="text-sm font-medium text-foreground">{label}</span>
        {/if}
        {#if helperText}
          <p class="text-xs text-muted-foreground">{helperText}</p>
        {/if}
      </div>
    {/if}
  </label>

{:else if variant === 'chip'}
  <!-- Chip toggle variant (button-like, no hidden input to avoid focus/scroll issues) -->
  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
  <button
    type="button"
    class="inline-flex items-center gap-1.5 px-2 py-1 rounded cursor-pointer transition-colors text-xs select-none
    {!borderless ? 'border' : ''}
    {checked
      ? getChipColorClass(color)
      : borderless ? 'text-muted-foreground hover:bg-accent hover:text-foreground' : 'border-border text-muted-foreground hover:bg-accent hover:text-foreground'}
    {disabled ? 'opacity-50 cursor-not-allowed' : ''}
    {className}"
    {disabled}
    onclick={(e) => { e.preventDefault(); if (!disabled) { checked = !checked; onchange?.({ target: { checked } }); } }}
    onkeydown={(e) => { if (e.key === ' ') e.preventDefault(); }}
    {...restProps}
  >
    {#if icon}
      <Icon name={icon} size={12} />
    {/if}
    {#if children}
      {@render children()}
    {:else if label}
      <span>{label}</span>
    {/if}
  </button>

{:else}
  <!-- Default checkbox variant -->
  <label class="inline-flex items-center gap-2 {disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'} {className}">
    {#if effectivePosition === 'left'}
      {#if children}
        {@render children()}
      {:else if label}
        <span class="text-sm text-foreground">{label}</span>
      {/if}
    {/if}
    <input
      type="checkbox"
      class="kt-checkbox"
      {checked}
      {disabled}
      {indeterminate}
      onchange={handleChange}
      {...restProps}
    />
    {#if effectivePosition === 'right'}
      {#if children}
        {@render children()}
      {:else if label}
        <span class="text-sm text-foreground">{label}</span>
      {/if}
    {/if}
    {#if helperText}
      <span class="text-xs text-muted-foreground">{helperText}</span>
    {/if}
  </label>
{/if}
