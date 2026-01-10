<script>
  import Icon from './Icon.svelte'

  let {
    icon,
    color = 'primary',
    value,
    label
  } = $props()

  const colorClasses = {
    primary: 'bg-primary/10 text-primary',
    info: 'bg-info/10 text-info',
    success: 'bg-success/10 text-success',
    warning: 'bg-warning/10 text-warning',
    destructive: 'bg-destructive/10 text-destructive'
  }
</script>

<div class="bg-card border border-border rounded-lg p-4 flex items-center gap-3">
  <div class="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 {colorClasses[color] || colorClasses.primary}">
    <Icon name={icon} size={20} />
  </div>
  <div>
    <div class="text-2xl font-bold text-foreground">{value}</div>
    <div class="text-[11px] text-muted-foreground">{label}</div>
  </div>
</div>
