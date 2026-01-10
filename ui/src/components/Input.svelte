<script>
  import Icon from './Icon.svelte';
  import Checkbox from './Checkbox.svelte';
  import Button from './Button.svelte';

  let {
    type = 'text',
    value = $bindable(''),
    placeholder = '',
    disabled = false,
    readonly = false,
    required = false,
    autocomplete = undefined,
    class: className = '',
    size = 'sm',

    // Label support
    label = undefined,
    labelClass = 'block text-xs font-medium text-foreground mb-1',
    helperText = undefined,
    helperClass = 'text-[10px] text-muted-foreground mt-1',

    // Icon support
    prefixIcon = undefined,
    suffixIcon = undefined,

    // Icon button support - renders Button INSIDE input, pass object with Button props
    prefixIconBtn = undefined,
    suffixIconBtn = undefined,

    // Addon support
    prefixAddon = undefined,
    suffixAddon = undefined,
    prefixAddonIcon = undefined,
    suffixAddonIcon = undefined,
    // Addon button support - pass object with Button props: { icon, label, variant, onclick, ... }
    prefixAddonBtn = undefined,
    suffixAddonBtn = undefined,

    // Checkbox addon support
    prefixCheckbox = undefined,  // { icon, label, color, variant } or true
    suffixCheckbox = undefined,  // { icon, label, color, variant } or true
    prefixCheckboxChecked = $bindable(false),
    suffixCheckboxChecked = $bindable(false),
    onPrefixCheckboxChange = undefined,
    onSuffixCheckboxChange = undefined,

    // Password toggle - auto-enabled for type="password", set false to disable
    showPasswordToggle = undefined,

    onkeydown = undefined,
    onclick = undefined,
    oninput = undefined,
    onchange = undefined,
    tooltip = undefined,
    ...restProps
  } = $props();

  // Password visibility state
  let passwordVisible = $state(false);

  // Auto-detect password toggle: enabled by default for password fields unless explicitly disabled
  const isPasswordField = $derived(type === 'password');
  const hasPasswordToggle = $derived(showPasswordToggle ?? isPasswordField);

  // Compute actual input type (toggle between password and text)
  const actualType = $derived(isPasswordField && passwordVisible ? 'text' : type);

  // Toggle password visibility
  function togglePassword() {
    passwordVisible = !passwordVisible;
  }

  // Size classes mapping (sm is default)
  const sizeClasses = {
    sm: { input: 'kt-input-sm', addon: 'kt-input-addon-sm', btn: 'sm' },
    lg: { input: 'kt-input-lg', addon: 'kt-input-addon-lg', btn: 'lg' },
    default: { input: '', addon: '', btn: 'sm' }
  };
  const sizeConfig = $derived(sizeClasses[size] || sizeClasses.sm);
  const sizeClass = $derived(sizeConfig.input);
  const addonSizeClass = $derived(sizeConfig.addon);
  const btnSize = $derived(sizeConfig.btn);

  // Normalize checkbox props
  const prefixCheckboxProps = $derived(prefixCheckbox === true ? {} : prefixCheckbox);
  const suffixCheckboxProps = $derived(suffixCheckbox === true ? {} : suffixCheckbox);

  // Normalize addon icon props (can be string or { icon, tooltip })
  const suffixAddonIconProps = $derived(typeof suffixAddonIcon === 'string' ? { icon: suffixAddonIcon } : suffixAddonIcon);
  const prefixAddonIconProps = $derived(typeof prefixAddonIcon === 'string' ? { icon: prefixAddonIcon } : prefixAddonIcon);

  // Determine wrapper type - any prefix/suffix uses input-group
  const hasInputGroup = $derived(prefixAddon || suffixAddon || prefixAddonIcon || suffixAddonIcon || prefixAddonBtn || suffixAddonBtn || prefixCheckbox || suffixCheckbox || prefixIconBtn || suffixIconBtn || prefixIcon || suffixIcon || hasPasswordToggle);

  // Whether input needs inner wrapper (has icons or icon buttons inside)
  const hasInnerWrapper = $derived(prefixIcon || suffixIcon || suffixIconBtn || prefixIconBtn || hasPasswordToggle);
</script>

<!-- Reusable snippet for the input element -->
{#snippet inputElement(inputClass, showTooltip = false)}
  <input
    bind:value
    type={actualType}
    {placeholder}
    {disabled}
    {readonly}
    {required}
    {autocomplete}
    class={inputClass}
    data-kt-tooltip={showTooltip ? tooltip : undefined}
    {onkeydown}
    {onclick}
    {oninput}
    {onchange}
    {...restProps}
  />
{/snippet}

<!-- Reusable snippet for prefix addons (outside input) -->
{#snippet prefixAddons()}
  {#if prefixAddon}
    <span class="kt-input-addon {addonSizeClass}">{prefixAddon}</span>
  {/if}
  {#if prefixAddonIcon}
    <span class="kt-input-addon kt-input-addon-icon {addonSizeClass}">
      <Icon name={prefixAddonIcon} size={14} />
    </span>
  {/if}
  {#if prefixAddonBtn}
    <Button {...prefixAddonBtn} size={btnSize} class="kt-input-addon {addonSizeClass} kt-btn-outline" />
  {/if}
  {#if prefixCheckbox}
    <Checkbox
      variant={prefixCheckboxProps?.variant || 'chip'}
      color={prefixCheckboxProps?.color || 'primary'}
      borderless={true}
      icon={prefixCheckboxProps?.icon}
      label={prefixCheckboxProps?.label}
      bind:checked={prefixCheckboxChecked}
      onchange={onPrefixCheckboxChange}
      class="kt-input-addon {addonSizeClass}"
    />
  {/if}
{/snippet}

<!-- Reusable snippet for suffix addons (outside input) -->
{#snippet suffixAddons()}
  {#if suffixCheckbox}
    <Checkbox
      variant={suffixCheckboxProps?.variant || 'chip'}
      color={suffixCheckboxProps?.color || 'primary'}
      borderless={true}
      icon={suffixCheckboxProps?.icon}
      label={suffixCheckboxProps?.label}
      bind:checked={suffixCheckboxChecked}
      onchange={onSuffixCheckboxChange}
      class="kt-input-addon {addonSizeClass}"
    />
  {/if}
  {#if suffixAddonBtn}
    <Button {...suffixAddonBtn} size={btnSize} class="kt-input-addon {addonSizeClass} kt-btn-outline" />
  {/if}
  {#if suffixAddonIcon}
    <span class="kt-input-addon kt-input-addon-icon {addonSizeClass}" data-kt-tooltip={suffixAddonIconProps?.tooltip ? '' : undefined}>
      <Icon name={suffixAddonIconProps?.icon} size={14} />
      {#if suffixAddonIconProps?.tooltip}
        <span data-kt-tooltip-content class="kt-tooltip hidden">{suffixAddonIconProps.tooltip}</span>
      {/if}
    </span>
  {/if}
  {#if suffixAddon}
    <span class="kt-input-addon {addonSizeClass}">{suffixAddon}</span>
  {/if}
{/snippet}

<!-- Reusable snippet for input with inner icons/buttons -->
{#snippet inputWithInner()}
  <div class="kt-input {sizeClass} flex-1">
    {#if prefixIconBtn}
      <Button {...prefixIconBtn} size="xs" variant="ghost" iconOnly class="-ms-1" />
    {/if}
    {#if prefixIcon}
      <Icon name={prefixIcon} size={14} />
    {/if}
    {@render inputElement("w-full")}
    {#if suffixIcon}
      <Icon name={suffixIcon} size={14} />
    {/if}
    {#if hasPasswordToggle}
      <Button
        icon={passwordVisible ? 'eye-off' : 'eye'}
        size="xs"
        variant="ghost"
        iconOnly
        class="-me-1"
        onclick={togglePassword}
        tabindex={-1}
      />
    {/if}
    {#if suffixIconBtn}
      <Button {...suffixIconBtn} size="xs" variant="ghost" iconOnly class="-me-1" />
    {/if}
  </div>
{/snippet}

<!-- Reusable snippet for the full input group -->
{#snippet inputGroup()}
  <div class="kt-input-group {className}">
    {@render prefixAddons()}
    {#if hasInnerWrapper}
      {@render inputWithInner()}
    {:else}
      {@render inputElement(`kt-input ${sizeClass} w-full`)}
    {/if}
    {@render suffixAddons()}
  </div>
{/snippet}

<!-- Reusable snippet for the main input content -->
{#snippet inputContent()}
  {#if hasInputGroup}
    {@render inputGroup()}
  {:else}
    {@render inputElement(`kt-input ${sizeClass} ${className}`, true)}
  {/if}
{/snippet}

<!-- Main template -->
{#if label || helperText}
  <div>
    {#if label}
      <label for={restProps.id} class={labelClass}>{label}</label>
    {/if}
    {@render inputContent()}
    {#if helperText}
      <p class={helperClass}>{helperText}</p>
    {/if}
  </div>
{:else}
  {@render inputContent()}
{/if}
