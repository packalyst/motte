<script>
  /**
   * AccessRow — one VPN client in an access list (the VPN client window and the LAN device window):
   * a checkbox (access on/off), the client's name, IP and type, and — when onboth is given, for a
   * checked row — the "Bi" button that makes the access two-way. A disabled row can't be changed;
   * note is a snippet shown after the type (e.g. why it's disabled).
   */
  import Icon from './Icon.svelte'

  let { name, ip, type, checked = false, both = false, disabled = false, bothTitle = '', ontoggle, onboth = undefined, note = undefined } = $props()

  const toggle = () => !disabled && ontoggle()
</script>

<div class="flex items-center gap-2 p-2.5 border-b border-border last:border-b-0 {disabled ? 'opacity-60' : 'hover:bg-accent/30'} transition-colors">
  <button
    onclick={toggle}
    {disabled}
    aria-label="Allow {name}"
    aria-pressed={checked}
    class="w-5 h-5 rounded border flex items-center justify-center shrink-0
      {disabled ? 'border-border bg-muted cursor-not-allowed' : checked ? 'bg-primary border-primary text-white cursor-pointer' : 'border-border cursor-pointer'}"
  >
    {#if checked && !disabled}
      <Icon name="check" size={12} />
    {/if}
  </button>
  <div class="flex-1 min-w-0" onclick={toggle} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && toggle()} role="button" tabindex="0" class:cursor-pointer={!disabled}>
    <div class="text-sm font-medium text-foreground truncate">{name}</div>
    <div class="text-[10px] text-muted-foreground">
      {ip} • {type === 'wireguard' ? 'WG' : 'TS'}
      {@render note?.()}
    </div>
  </div>
  {#if checked && onboth}
    <button
      onclick={onboth}
      {disabled}
      aria-pressed={both}
      class="flex items-center gap-1.5 px-2 py-1 rounded text-[10px] transition-colors shrink-0
        {both ? 'bg-info/15 text-info border border-info/30' : 'bg-muted/50 text-muted-foreground border border-border hover:border-info/30'}"
      title={bothTitle}
    >
      <Icon name="arrows-right-left" size={12} />
      Bi
    </button>
  {/if}
</div>
