<script>
  /**
   * ServicesPicker — what LAN devices may reach on the internet: the ticked services, plus either
   * custom ports or, with "All other ports" ticked, every port except the services left unticked.
   * value is the list ("web,time,tcp:8883", "web,all"); '' means "inherit": for a network the
   * panel's default, for a device (inherit = its network's list) the network's. The catalog comes
   * from the server.
   */
  import Checkbox from './Checkbox.svelte'
  import Select from './Select.svelte'
  import Input from './Input.svelte'
  import Button from './Button.svelte'
  import Icon from './Icon.svelte'
  import { splitServices, servicesLabel } from '$lib/lan.js'

  let { value = $bindable(''), info = null, inherit = undefined, disabled = false } = $props()

  const ALL = 'all'
  const services = $derived((info?.catalog || []).filter((s) => s.id !== ALL))
  const forDevice = $derived(inherit !== undefined)
  // The list the controls show: the own one, else what it inherits.
  const inherited = $derived((forDevice && inherit) || info?.default || '')
  const shown = $derived(splitServices(value || inherited))
  const allOn = $derived(shown.includes(ALL))
  const custom = $derived(shown.filter((t) => t.includes(':')))
  const picked = $derived(shown.filter((t) => t !== ALL))

  // A list never goes empty (it would read as "inherit"): to give a device nothing, switch its
  // internet off. Without All other ports one thing must stay ticked; with it, any may be unticked.
  const set = (list) => { if (list.length) value = list.join(',') }
  const lastOne = (t) => !allOn && picked.length === 1 && picked[0] === t
  const toggle = (t) => set(shown.includes(t) ? shown.filter((x) => x !== t) : [...shown, t])

  // Ticking All other ports drops the custom ports (they are open anyway); unticking it keeps the
  // services, or starts from the default when none is ticked.
  function toggleAll() {
    if (!allOn) return set([...shown.filter((t) => !t.includes(':')), ALL])
    set(picked.length ? picked : splitServices(info?.default))
  }

  let proto = $state('tcp')
  let port = $state('')
  const portOk = $derived(/^\d+$/.test(port) && +port >= 1 && +port <= 65535 && !(proto === 'tcp' && +port === 25))
  function addPort() {
    const t = `${proto}:${+port}`
    if (!portOk || shown.includes(t)) return
    set([...shown, t])
    port = ''
  }
  const ports = (s) => [s.tcp?.length && `TCP ${s.tcp.join(', ')}`, s.udp?.length && `UDP ${s.udp.join(', ')}`].filter(Boolean)
</script>

<div class="space-y-2">
  <div class="flex items-center justify-between gap-2">
    <span class="text-xs font-medium text-foreground">Allowed on the internet</span>
    {#if forDevice}
      <Checkbox variant="switch" checked={!value} {disabled} label="Network default"
                onchange={(e) => { value = e.target.checked ? '' : inherited }} />
    {/if}
  </div>

  {#if forDevice && !value}
    <p class="text-[11px] text-muted-foreground">Uses the network's setting: <span class="text-foreground">{servicesLabel(inherited, info?.catalog)}</span>. Switch it off to choose for this device.</p>
  {:else}
    <div class="divide-y divide-border overflow-hidden rounded-lg border border-border">
      {#each services as s (s.id)}
        {@const on = shown.includes(s.id)}
        <div class="flex items-center gap-3 px-3 py-2 {on ? 'bg-primary/5' : ''}">
          <Checkbox controlled checked={on} disabled={disabled || lastOne(s.id)} label={s.name}
                    helperText={s.note} class="flex-1 min-w-0" onchange={() => toggle(s.id)} />
          <div class="flex shrink-0 flex-wrap justify-end gap-1">
            {#each ports(s) as p (p)}
              <span class="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">{p}</span>
            {/each}
          </div>
        </div>
      {/each}

      <div class="px-3 py-2 {allOn ? 'bg-warning/10' : 'bg-muted/40'}">
        <Checkbox controlled checked={allOn} {disabled} label="All other ports" onchange={toggleAll}
                  helperText={allOn
                    ? 'Every port is open except the services left unticked above.'
                    : 'Off: only the services above and the ports added below go out.'} />
      </div>

      {#if !allOn}
        <div class="space-y-2 px-3 py-2.5">
          <div class="flex items-center gap-2">
            <div class="w-20 shrink-0">
              <Select bind:value={proto} {disabled} options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]} />
            </div>
            <div class="min-w-0 flex-1">
              <Input bind:value={port} placeholder="Add a port, e.g. 8883" inputmode="numeric" class="font-mono" {disabled}
                     onkeydown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addPort() } }} />
            </div>
            <Button variant="secondary" icon="plus" disabled={disabled || !portOk} onclick={addPort}>Add</Button>
          </div>
          {#if custom.length}
            <div class="flex flex-wrap gap-1.5">
              {#each custom as t (t)}
                <span class="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-0.5 font-mono text-[11px]">
                  {t.replace(':', ' ').toUpperCase()}
                  <button type="button" class="text-muted-foreground hover:text-destructive disabled:opacity-40" aria-label="Remove {t}"
                          disabled={disabled || lastOne(t)} onclick={() => toggle(t)}><Icon name="x" size={12} /></button>
                </span>
              {/each}
            </div>
          {/if}
        </div>
      {/if}
    </div>
    {#if !allOn && picked.length === 1}
      <p class="flex items-start gap-1.5 rounded-md border border-warning/30 bg-warning/10 px-2.5 py-1.5 text-[11px] text-warning">
        <Icon name="alert-triangle" size={13} class="mt-px shrink-0" />At least one must stay ticked. To block all internet, switch Internet off.
      </p>
    {/if}
  {/if}
</div>
