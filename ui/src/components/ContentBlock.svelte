<script>
  import Icon from './Icon.svelte'
  import { toast } from '../stores/app.js'
  import { copyWithToast } from '../stores/helpers.js'

  /**
   * ContentBlock - Unified component for content display patterns
   *
   * Variants:
   * - row: Horizontal layout with title/desc on left, action on right (default)
   * - box: Vertical content box with optional icon header
   * - header: Section header with dashed bottom border
   * - status: Smaller status info box
   * - indicator: Status indicator with colored bg/border (e.g., success, warning)
   * - data: Label + value display with optional copy button
   *
   * Props:
   * - icon: Optional icon name
   * - iconSize: Icon size (default 20 for row with icon, 18 for box, 16 otherwise)
   * - iconColor: Icon color class (e.g., "text-primary", "text-success")
   * - color: Color for indicator variant (success, warning, info, destructive)
   * - active: When true, applies success styling (green border/bg) - for row with icon
   * - inactive: When true, applies destructive styling (red border/bg) - for row with icon
   * - activeBorder: When true, applies only green border (no bg change)
   * - inactiveBorder: When true, applies only red border (no bg change)
   * - label: Label text for data variant
   * - value: Value text for data variant (or use children)
   * - copyable: Enable copy button for data variant
   * - mono: Use monospace font for value in data variant
   */
  let {
    variant = 'row',
    title = '',
    description = '',
    icon = '',
    iconSize = 0,
    iconColor = '',
    color = 'success',
    active = false,
    inactive = false,
    activeBorder = false,
    inactiveBorder = false,
    border = false,
    padding = 'md',
    label = '',
    value = '',
    copyable = false,
    mono = false,
    class: className = '',
    children,
    descriptionSlot
  } = $props()

  const paddings = {
    sm: 'p-2',
    md: 'p-3',
    lg: 'p-4'
  }

  // Determine icon size based on variant and explicit prop
  const computedIconSize = $derived(iconSize || (variant === 'row' && icon ? 20 : variant === 'box' && icon ? 18 : 16))
</script>

{#if variant === 'header'}
  <h4 class="text-xs font-medium text-foreground mb-2 pb-2 border-b border-dashed border-border {className}">
    {title}
  </h4>
{:else if variant === 'status'}
  <div class="{paddings[padding]} bg-muted/50 rounded text-[10px] border border-dashed border-border {className}">
    {#if title}
      <div class="font-medium text-foreground">{title}</div>
    {/if}
    {#if description}
      <div class="text-muted-foreground">{description}</div>
    {/if}
    {#if children}
      {@render children()}
    {/if}
  </div>
{:else if variant === 'indicator'}
  <div class="flex items-center gap-3 {paddings[padding]} bg-{color}/10 border border-{color}/20 rounded-lg {className}">
    {#if icon}
      <Icon name={icon} size={iconSize || 18} class="text-{color}" />
    {/if}
    <div>
      {#if title}
        <div class="text-xs font-medium text-foreground">{title}</div>
      {/if}
      {#if description}
        <div class="text-[10px] text-muted-foreground">{description}</div>
      {/if}
    </div>
    {#if children}
      {@render children()}
    {/if}
  </div>
{:else if variant === 'data'}
  <div class="{paddings[padding]} bg-muted/50 rounded-lg border border-dashed border-border {className}">
    {#if label}
      <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">{label}</div>
    {/if}
    <div class="flex items-center gap-1">
      {#if children}
        {@render children()}
      {:else if value}
        {#if mono}
          <code class="text-sm font-mono text-foreground truncate">{value}</code>
        {:else}
          <span class="text-sm text-foreground">{value}</span>
        {/if}
      {/if}
      {#if copyable && value}
        <button onclick={() => copyWithToast(value, toast)} class="p-0.5 text-muted-foreground hover:text-foreground shrink-0 cursor-pointer">
          <Icon name="copy" size={12} />
        </button>
      {/if}
    </div>
  </div>
{:else if variant === 'box'}
  <div class="{paddings[padding]} bg-muted/30 rounded-lg {border ? 'border border-border' : ''} {className}">
    {#if icon && title}
      <div class="flex items-center gap-2 mb-2">
        <Icon name={icon} size={computedIconSize} class={iconColor || 'text-primary'} />
        <span class="font-medium text-foreground">{title}</span>
      </div>
    {:else if title}
      <div class="text-xs font-medium text-foreground">{title}</div>
    {/if}
    {#if description}
      <p class="text-xs text-muted-foreground">{description}</p>
    {/if}
    {#if children}
      {@render children()}
    {/if}
  </div>
{:else}
  <!-- row variant (default) -->
  {#if icon}
    <!-- Row with icon -->
    <div class="{paddings.lg} rounded-lg border bg-muted/30 {active ? 'border-success/30 !bg-success/5' : inactive ? 'border-destructive/30 !bg-destructive/5' : activeBorder ? 'border-success/50' : inactiveBorder ? 'border-destructive/50' : 'border-border'} {className}">
      <div class="flex items-start justify-between">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-lg flex items-center justify-center {active || activeBorder ? 'bg-success/10 text-success' : inactive || inactiveBorder ? 'bg-destructive/10 text-destructive' : 'bg-muted text-muted-foreground'}">
            <Icon name={icon} size={computedIconSize} />
          </div>
          <div>
            {#if title}
              <div class="font-medium text-foreground">{title}</div>
            {/if}
            {#if descriptionSlot}
              {@render descriptionSlot()}
            {:else if description}
              <div class="text-xs text-muted-foreground">{description}</div>
            {/if}
          </div>
        </div>
        {#if children}
          {@render children()}
        {/if}
      </div>
    </div>
  {:else}
    <!-- Simple row without icon -->
    <div class="flex items-center justify-between {paddings[padding]} bg-muted/30 rounded-lg border border-dashed {activeBorder ? 'border-success/50' : inactiveBorder ? 'border-destructive/50' : 'border-border'} {className}">
      <div>
        {#if title}
          <div class="text-xs font-medium text-foreground">{title}</div>
        {/if}
        {#if description}
          <div class="text-[10px] text-muted-foreground">{description}</div>
        {/if}
      </div>
      {#if children}
        {@render children()}
      {/if}
    </div>
  {/if}
{/if}
