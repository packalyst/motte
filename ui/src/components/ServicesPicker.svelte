<script>
  /**
   * ServicesPicker — what LAN devices may reach on the internet: services from the server's catalog
   * plus custom ports. value is the list ("web,time,tcp:8883"); '' means "inherit". For a network
   * that is the panel's default; for a device (inherit = its network's list) it is the network's.
   * Nothing outside the list goes out.
   */
  import Checkbox from './Checkbox.svelte'
  import Select from './Select.svelte'
  import Input from './Input.svelte'
  import Button from './Button.svelte'
  import Icon from './Icon.svelte'
  import { splitServices, servicesLabel } from '$lib/lan.js'

  let { value = $bindable(''), info = null, inherit = undefined, disabled = false } = $props()

  const catalog = $derived(info?.catalog || [])
  const forDevice = $derived(inherit !== undefined)
  // The list the boxes show: the own one, else what it inherits.
  const inherited = $derived((forDevice && inherit) || info?.default || '')
  const shown = $derived(splitServices(value || inherited))
  const custom = $derived(shown.filter((t) => t.includes(':')))

  // An empty list would read as "inherit", so the last one can't be taken away here: to give a
  // device nothing, switch its internet off.
  const set = (list) => { if (list.length) value = list.join(',') }
  const toggle = (id, on) => set(on ? [...shown, id] : shown.filter((t) => t !== id))
  const removePort = (t) => set(shown.filter((x) => x !== t))

  let proto = $state('tcp')
  let port = $state('')
  const portOk = $derived(/^\d+$/.test(port) && +port >= 1 && +port <= 65535 && !(proto === 'tcp' && +port === 25))
  function addPort() {
    const t = `${proto}:${+port}`
    if (!portOk || shown.includes(t)) return
    set([...shown, t])
    port = ''
  }
  const ports = (s) => [s.tcp?.length && `TCP ${s.tcp.join(', ')}`, s.udp?.length && `UDP ${s.udp.join(', ')}`].filter(Boolean).join(' · ')
</script>

<div class="space-y-2">
  <div class="text-[10px] uppercase tracking-wide text-muted-foreground">Allowed on the internet</div>
  {#if forDevice}
    <Checkbox variant="switch" checked={!value} {disabled}
              label="Use the network's default"
              helperText={servicesLabel(inherited, catalog)}
              onchange={(e) => { value = e.target.checked ? '' : inherited }} />
  {/if}
  {#if !forDevice || value}
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
      {#each catalog as s (s.id)}
        <Checkbox controlled checked={shown.includes(s.id)} disabled={disabled || (shown.length === 1 && shown[0] === s.id)} label={s.name}
                  helperText={[ports(s), s.note].filter(Boolean).join(' — ')}
                  onchange={() => toggle(s.id, !shown.includes(s.id))} />
      {/each}
    </div>
    <div class="grid grid-cols-[6rem_1fr_auto] gap-2 items-end">
      <Select label="Custom port" bind:value={proto} {disabled} options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]} />
      <Input bind:value={port} placeholder="e.g. 8883" inputmode="numeric" class="font-mono" {disabled} />
      <Button variant="secondary" icon="plus" disabled={disabled || !portOk} onclick={addPort}>Add</Button>
    </div>
    {#if custom.length}
      <div class="flex flex-wrap gap-1.5">
        {#each custom as t (t)}
          <span class="inline-flex items-center gap-1 rounded-md border border-border px-2 py-0.5 font-mono text-[11px]">
            {t.replace(':', ' ').toUpperCase()}
            <button type="button" class="text-muted-foreground hover:text-destructive disabled:opacity-40" aria-label="Remove {t}" disabled={disabled || shown.length === 1} onclick={() => removePort(t)}><Icon name="x" size={12} /></button>
          </span>
        {/each}
      </div>
    {/if}
  {/if}
</div>
