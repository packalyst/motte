<script>
  /**
   * EgressSelect — picks the internet address LAN devices leave from: the server's main address or
   * one of its extra public addresses. Used by the network form (its default) and the device
   * window (inherit = the network's default, adds "Network default").
   */
  import Select from './Select.svelte'
  import Icon from './Icon.svelte'
  import { egressOptions, egressMissing } from '$lib/lan.js'

  let { value = $bindable(''), addrs = null, inherit = undefined, disabled = false, onchange = undefined } = $props()

  const options = $derived(egressOptions(addrs, value, inherit))
  const noExtras = $derived(!(addrs?.extras || []).length)
</script>

<div class="space-y-1.5">
  <Select label="Internet address" prefixIcon="world" bind:value {options} {disabled} {onchange}
          hint="Where this traffic appears to come from online. A dedicated address accepts no incoming connection at all: it only carries these devices' own traffic and its replies." />
  {#if egressMissing(addrs, value)}
    <p class="flex items-start gap-1.5 text-[11px] text-warning">
      <Icon name="alert-triangle" size={13} class="mt-px shrink-0" />{value} is no longer on this server, so devices using it have no internet. Pick another address.
    </p>
  {:else if noExtras}
    <p class="text-[11px] text-muted-foreground">To give devices their own address, add another public IP to the server's internet interface; it shows up here.</p>
  {/if}
</div>
