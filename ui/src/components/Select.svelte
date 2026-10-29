<script>
  import Hint from './Hint.svelte';
  import Icon from './Icon.svelte';

  let {
    value = $bindable(''),
    disabled = false,
    required = false,
    class: className = '',
    size = 'sm',

    // Label support
    label = undefined,
    labelClass = 'block text-xs font-medium text-foreground mb-1',
    helperText = undefined,
    helperClass = 'field-hint',
    hint = undefined, // shown as a tooltip on the label instead of text under the field
    prefixIcon = undefined, // an icon inside the field, before the value (like Input's)

    // Options - can pass as prop or use slot
    options = [],

    onchange = undefined,
    children,
    ...restProps
  } = $props();

  // Size classes mapping (sm is default)
  const sizeClasses = {
    sm: 'kt-select-sm',
    lg: ''
  };
  // `in`, not ||: lg maps to '' (plain kt-select), which || would turn back into sm
  const sizeClass = $derived(size in sizeClasses ? sizeClasses[size] : sizeClasses.sm);
</script>

{#snippet field()}
  {#if prefixIcon}
    <div class="relative">
      <Icon name={prefixIcon} size={14} class="pointer-events-none absolute start-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
      {@render selectEl('ps-8')}
    </div>
  {:else}
    {@render selectEl('')}
  {/if}
{/snippet}

{#snippet selectEl(extra)}
  <select
    bind:value
    {disabled}
    {required}
    class="kt-select {sizeClass} {extra} {className}"
    {onchange}
    {...restProps}
  >
    {#if options.length > 0}
      {#each options as opt}
        <option value={opt.value}>{opt.label}</option>
      {/each}
    {:else}
      {@render children?.()}
    {/if}
  </select>
{/snippet}

{#if label || helperText}
  <div>
    {#if label}
      <label for={restProps.id} class={labelClass}><Hint text={hint}>{label}</Hint></label>
    {/if}
    {@render field()}
    {#if helperText}
      <p class={helperClass}>{helperText}</p>
    {/if}
  </div>
{:else}
  {@render field()}
{/if}
