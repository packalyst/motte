<script>
  /**
   * GroupButton — an icon button for a `.btn-group` (joined buttons with dividers), with a KTUI
   * tooltip that also names it for screen readers. tone colours the icon: default, primary, destructive.
   */
  import Icon from './Icon.svelte'

  let { icon, tooltip, tone = 'default', disabled = false, onclick } = $props()

  const TONES = {
    default: '',
    primary: 'text-primary! hover:bg-primary/10!',
    destructive: 'text-destructive! hover:bg-destructive/10!',
  }
</script>

<button type="button" class="custom_btns {TONES[tone] || ''}" {disabled} {onclick} aria-label={tooltip} data-kt-tooltip>
  <Icon name={icon} size={14} />
  <span data-kt-tooltip-content class="kt-tooltip hidden">{tooltip}</span>
</button>
