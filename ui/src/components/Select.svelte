<script>
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
    helperClass = 'text-[10px] text-muted-foreground mt-1',

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
  const sizeClass = $derived(sizeClasses[size] || sizeClasses.sm);
</script>

{#if label || helperText}
  <div>
    {#if label}
      <label for={restProps.id} class={labelClass}>{label}</label>
    {/if}

    <select
      bind:value
      {disabled}
      {required}
      class="kt-select {sizeClass} {className}"
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

    {#if helperText}
      <p class={helperClass}>{helperText}</p>
    {/if}
  </div>
{:else}
  <select
    bind:value
    {disabled}
    {required}
    class="kt-select {sizeClass} {className}"
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
{/if}
