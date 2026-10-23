<script>
  let { variant = 'default', size = 'md', children } = $props()

  const sizes = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-xs'
  }
</script>

<span class="kt-badge kt-badge-sm kt-badge-outline kt-badge-{variant} {sizes[size]}">
  {@render children()}
</span>
