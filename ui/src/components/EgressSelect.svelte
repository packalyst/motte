<script>
  /**
   * EgressSelect — picks the internet address LAN devices leave from: the server's main address or
   * one of its extra public addresses, shared by networks or dedicated to one device. Used by the
   * network form (its default; self = its interface) and the device window (inherit = the
   * network's default, adds "Network default"; self = the device's id).
   */
  import Select from './Select.svelte'
  import Icon from './Icon.svelte'
  import { egressOptions, egressMissing, egressConflict } from '$lib/lan.js'

  let { value = $bindable(''), addrs = null, inherit = undefined, self = undefined, disabled = false, onchange = undefined } = $props()

  const options = $derived(egressOptions(addrs, value, inherit, self))
  const noExtras = $derived(!(addrs?.extras || []).length)
</script>

<div class="space-y-1.5">
  <Select label="Internet address" prefixIcon="world" bind:value {options} {disabled} {onchange}
          hint="Where this traffic appears to come from online. An extra address is either shared (a network's default, for all its devices) or dedicated to one device. Neither accepts an incoming connection: it only carries the devices' own traffic and its replies." />
  {#if egressMissing(addrs, value)}
    <p class="flex items-start gap-1.5 text-[11px] text-warning">
      <Icon name="alert-triangle" size={13} class="mt-px shrink-0" />{value} is no longer on this server, so devices using it have no internet. Pick another address.
    </p>
  {:else if egressConflict(addrs, value)}
    <p class="flex items-start gap-1.5 text-[11px] text-warning">
      <Icon name="alert-triangle" size={13} class="mt-px shrink-0" />{value} is held by more than one network or device, so none of them has internet through it. Pick another address.
    </p>
  {:else if noExtras}
    <p class="text-[11px] text-muted-foreground">To give devices their own address, add another public IP to the server's internet interface; it shows up here.</p>
  {/if}
</div>
