<script>
  import Icon from './Icon.svelte'

  let {
    icon = null,
    title,
    description = '',
    active = false,
    color = 'primary', // primary, success, warning, destructive, info
    size = 'md', // sm, md, lg
    iconBox = false, // Show icon in a colored box (action card style)
    disabled = false,
    class: className = '',
    onclick
  } = $props()

  const sizes = {
    sm: { padding: 'p-2.5', gap: 'gap-2', title: 'text-xs', desc: 'text-[9px]', icon: 16, iconBox: 'w-8 h-8' },
    md: { padding: 'p-3', gap: 'gap-2', title: 'text-sm', desc: 'text-[10px]', icon: 18, iconBox: 'w-9 h-9' },
    lg: { padding: 'p-4', gap: 'gap-3', title: 'text-sm', desc: 'text-xs', icon: 20, iconBox: 'w-10 h-10' }
  }

  const colors = {
    primary: { border: 'border-primary', bg: 'bg-primary/10', hover: 'hover:border-primary/50', text: 'text-primary' },
    success: { border: 'border-success', bg: 'bg-success/10', hover: 'hover:border-success/50', text: 'text-success' },
    warning: { border: 'border-warning', bg: 'bg-warning/10', hover: 'hover:border-warning/50', text: 'text-warning' },
    destructive: { border: 'border-destructive', bg: 'bg-destructive/10', hover: 'hover:border-destructive/50', text: 'text-destructive' },
    info: { border: 'border-info', bg: 'bg-info/10', hover: 'hover:border-info/50', text: 'text-info' }
  }

  const s = $derived(sizes[size])
  const c = $derived(colors[color])
</script>

<button
  type="button"
  {onclick}
  {disabled}
  class="flex items-center {s.gap} {s.padding} border rounded-lg text-left transition-all
    {active ? `${c.border} ${c.bg}` : `border-border ${c.hover}`}
    {disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
    {className}"
>
  {#if icon}
    {#if iconBox}
      <div class="{s.iconBox} rounded-lg flex items-center justify-center shrink-0 {active ? `${c.bg} ${c.text}` : 'bg-muted/50 text-muted-foreground'}">
        <Icon name={icon} size={s.icon} />
      </div>
    {:else}
      <Icon name={icon} size={s.icon} class="shrink-0 {active ? c.text : 'text-muted-foreground'}" />
    {/if}
  {/if}
  <div class="text-left min-w-0">
    <div class="{s.title} font-medium text-foreground">{title}</div>
    {#if description}
      <div class="{s.desc} text-muted-foreground">{description}</div>
    {/if}
  </div>
</button>
