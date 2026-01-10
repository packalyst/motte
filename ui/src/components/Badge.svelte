<script>
  let { variant = 'default', size = 'md', children } = $props()

  const variants = {
    default: 'bg-muted text-muted-foreground',
    success: 'bg-success/15 text-success',
    danger: 'bg-destructive/15 text-destructive',
    warning: 'bg-warning/15 text-warning',
    info: 'bg-info/15 text-info',
    muted: 'bg-muted text-muted-foreground',
    primary: 'bg-primary/15 text-primary'
  }

  const sizes = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-2.5 py-1 text-xs'
  }
</script>

<span class="kt-badge kt-badge-sm kt-badge-outline kt-badge-{variant} {sizes[size]}">
  {@render children()}
</span>
