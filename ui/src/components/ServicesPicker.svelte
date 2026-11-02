<script>
  /**
   * ServicesPicker — what LAN devices may reach on the internet (out) and, for one device, what the
   * internet may open to it (in).
   * Out: the ticked services, plus either custom ports or, with "All other ports" ticked, every port
   * except the services left unticked. value is the list ("web,time,tcp:8883", "web,all"); '' means
   * "inherit": for a network the panel's default, for a device (inherit = its network's list) the
   * network's.
   * In (device only, inbound = [{ entry, sources }]): per service or custom port, from the sources
   * listed or from anyone. Only on the device's own dedicated address (inboundAllowed), never "all
   * other ports". The server checks all of it again. The catalog comes from the server.
   */
  import Checkbox from './Checkbox.svelte'
  import Select from './Select.svelte'
  import Input from './Input.svelte'
  import Button from './Button.svelte'
  import Icon from './Icon.svelte'
  import { splitServices, servicesLabel } from '$lib/lan.js'

  let {
    value = $bindable(''), info = null, inherit = undefined, disabled = false,
    inbound = $bindable(undefined), inboundAllowed = false,
  } = $props()

  const ALL = 'all'
  const ANY = 'any'
  const services = $derived((info?.catalog || []).filter((s) => s.id !== ALL))
  const forDevice = $derived(inherit !== undefined)
  const withIn = $derived(forDevice && inbound !== undefined)
  // The out list the controls show: the own one, else what it inherits.
  const inherited = $derived((forDevice && inherit) || info?.default || '')
  const shown = $derived(splitServices(value || inherited))
  const outEditable = $derived(!forDevice || !!value)
  const allOn = $derived(shown.includes(ALL))
  const picked = $derived(shown.filter((t) => t !== ALL))
  const inList = $derived(inbound || [])
  const inOf = (t) => inList.find((e) => e.entry === t)
  // Custom ports in either direction, each once.
  const custom = $derived([...new Set([...shown.filter((t) => t.includes(':')), ...inList.map((e) => e.entry).filter((t) => t.includes(':'))])])

  // An out list never goes empty (it would read as "inherit"): to give a device nothing, switch its
  // internet off. Without All other ports one thing must stay ticked; with it, any may be unticked.
  const set = (list) => { if (list.length) value = list.join(',') }
  const lastOne = (t) => !allOn && picked.length === 1 && picked[0] === t
  const toggleOut = (t) => set(shown.includes(t) ? shown.filter((x) => x !== t) : [...shown, t])
  const toggleIn = (t) => { inbound = inOf(t) ? inList.filter((e) => e.entry !== t) : [...inList, { entry: t, sources: [] }] }
  const setSources = (t, sources) => { inbound = inList.map((e) => (e.entry === t ? { ...e, sources } : e)) }
  const parseSources = (text) => text.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)
  const removeCustom = (t) => {
    if (shown.includes(t) && !lastOne(t)) toggleOut(t)
    if (inOf(t)) toggleIn(t)
  }

  // Ticking All other ports drops the custom out ports (they are open anyway); unticking it keeps
  // the services, or starts from the default when none is ticked.
  function toggleAll() {
    if (!allOn) return set([...shown.filter((t) => !t.includes(':')), ALL])
    set(picked.length ? picked : splitServices(info?.default))
  }

  let proto = $state('tcp')
  let port = $state('')
  const portOk = $derived(/^\d+$/.test(port) && +port >= 1 && +port <= 65535 && !(proto === 'tcp' && +port === 25))
  // A new port goes out (when the device has its own list and not every port is open already),
  // else in.
  const addOut = $derived(outEditable && !allOn)
  const canAdd = $derived(!disabled && portOk && (addOut || (withIn && inboundAllowed)))
  function addPort() {
    const t = `${proto}:${+port}`
    if (!canAdd || custom.includes(t)) return
    if (addOut) set([...shown, t])
    else toggleIn(t)
    port = ''
  }
  const ports = (s) => [s.tcp?.length && `TCP ${s.tcp.join(', ')}`, s.udp?.length && `UDP ${s.udp.join(', ')}`, s.icmp && 'ICMP echo'].filter(Boolean)
  // A service with no ports (Ping) only goes out: there is no way in for it.
  const outOnly = (t) => { const s = services.find((x) => x.id === t); return !!s && !s.tcp?.length && !s.udp?.length }
</script>

{#snippet directions(t)}
  {@const outOn = shown.includes(t)}
  {@const inOn = !!inOf(t)}
  <div class="flex shrink-0 gap-1">
    <Checkbox variant="chip" label="Out" checked={outOn} color="primary"
              disabled={disabled || !outEditable || (outOn && lastOne(t)) || (allOn && t.includes(':'))}
              onchange={() => toggleOut(t)} />
    {#if !outOnly(t)}
      <Checkbox variant="chip" label="In" checked={inOn} color="warning"
                disabled={disabled || (!inOn && !inboundAllowed)} onchange={() => toggleIn(t)} />
    {/if}
  </div>
{/snippet}

{#snippet sourcesEditor(t)}
  {@const e = inOf(t)}
  {#if e}
    {@const anyone = e.sources.length === 1 && e.sources[0] === ANY}
    <div class="mt-2 space-y-1.5 border-t border-dashed border-border pt-2">
      <div class="flex items-center gap-2">
        <span class="shrink-0 text-[11px] text-muted-foreground">In from</span>
        <div class="min-w-0 flex-1">
          <Input value={anyone ? '' : e.sources.join(', ')} placeholder="IP addresses or ranges, e.g. 198.51.100.7, 203.0.113.0/24"
                 class="font-mono" disabled={disabled || anyone}
                 onchange={(ev) => setSources(t, parseSources(ev.target.value))} />
        </div>
        <Checkbox variant="chip" label="Anyone" checked={anyone} color="destructive" {disabled}
                  onchange={() => setSources(t, anyone ? [] : [ANY])} />
      </div>
      {#if anyone}
        <p class="flex items-start gap-1.5 text-[11px] text-warning">
          <Icon name="alert-triangle" size={13} class="mt-px shrink-0" />Anyone on the internet can connect to this port on the device.
        </p>
      {:else if !e.sources.length}
        <p class="text-[11px] text-warning">Say who may connect in, or choose Anyone.</p>
      {/if}
    </div>
  {/if}
{/snippet}

<div class="space-y-2">
  <div class="flex items-center justify-between gap-2">
    <span class="text-xs font-medium text-foreground">{withIn ? 'Allowed in and out' : 'Allowed on the internet'}</span>
    {#if forDevice}
      <Checkbox variant="switch" checked={!value} {disabled} label="Out: network default"
                onchange={(e) => { value = e.target.checked ? '' : inherited }} />
    {/if}
  </div>

  {#if forDevice && !value}
    <p class="text-[11px] text-muted-foreground">Out uses the network's setting: <span class="text-foreground">{servicesLabel(inherited, info?.catalog)}</span>. Switch it off to choose for this device.</p>
  {/if}
  {#if withIn && !inboundAllowed}
    <p class="text-[11px] text-muted-foreground">In needs an address dedicated to this device: pick one above. Until then nothing can connect in.</p>
  {/if}

  {#if !forDevice || withIn || value}
    <div class="divide-y divide-border overflow-hidden rounded-lg border border-border">
      {#each services as s (s.id)}
        {@const on = shown.includes(s.id)}
        <div class="px-3 py-2 {on || inOf(s.id) ? 'bg-primary/5' : ''}">
          <div class="flex items-center gap-3">
            {#if withIn}
              <div class="min-w-0 flex-1">
                <div class="text-sm text-foreground">{s.name}</div>
                {#if s.note}<p class="text-xs text-muted-foreground">{s.note}</p>{/if}
              </div>
            {:else}
              <Checkbox controlled checked={on} disabled={disabled || lastOne(s.id)} label={s.name}
                        helperText={s.note} class="flex-1 min-w-0" onchange={() => toggleOut(s.id)} />
            {/if}
            <div class="flex shrink-0 flex-wrap justify-end gap-1">
              {#each ports(s) as p (p)}
                <span class="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">{p}</span>
              {/each}
            </div>
            {#if withIn}{@render directions(s.id)}{/if}
          </div>
          {#if withIn}{@render sourcesEditor(s.id)}{/if}
        </div>
      {/each}

      {#if withIn}
        {#each custom as t (t)}
          <div class="px-3 py-2 {shown.includes(t) || inOf(t) ? 'bg-primary/5' : ''}">
            <div class="flex items-center gap-3">
              <span class="min-w-0 flex-1 font-mono text-sm">{t.replace(':', ' ').toUpperCase()}</span>
              {@render directions(t)}
              <button type="button" class="text-muted-foreground hover:text-destructive disabled:opacity-40" aria-label="Remove {t}"
                      disabled={disabled || (shown.includes(t) && lastOne(t))} onclick={() => removeCustom(t)}><Icon name="x" size={14} /></button>
            </div>
            {@render sourcesEditor(t)}
          </div>
        {/each}
      {/if}

      <div class="px-3 py-2 {allOn ? 'bg-warning/10' : 'bg-muted/40'}">
        <Checkbox controlled checked={allOn} disabled={disabled || !outEditable} label="All other ports (out only)" onchange={toggleAll}
                  helperText={allOn
                    ? 'Every port is open out except the services left unticked above.'
                    : 'Off: only the services ticked out, plus the ports added below, go out.'} />
      </div>

      {#if !allOn || withIn}
        <div class="space-y-2 px-3 py-2.5">
          <div class="flex items-center gap-2">
            <div class="w-20 shrink-0">
              <Select bind:value={proto} {disabled} options={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]} />
            </div>
            <div class="min-w-0 flex-1">
              <Input bind:value={port} placeholder="Add a port, e.g. 8883" inputmode="numeric" class="font-mono" {disabled}
                     onkeydown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addPort() } }} />
            </div>
            <Button variant="secondary" icon="plus" disabled={!canAdd} onclick={addPort}>Add</Button>
          </div>
          {#if !withIn && custom.length}
            <div class="flex flex-wrap gap-1.5">
              {#each custom as t (t)}
                <span class="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-0.5 font-mono text-[11px]">
                  {t.replace(':', ' ').toUpperCase()}
                  <button type="button" class="text-muted-foreground hover:text-destructive disabled:opacity-40" aria-label="Remove {t}"
                          disabled={disabled || lastOne(t)} onclick={() => toggleOut(t)}><Icon name="x" size={12} /></button>
                </span>
              {/each}
            </div>
          {/if}
        </div>
      {/if}
    </div>
    {#if outEditable && !allOn && picked.length === 1}
      <p class="flex items-start gap-1.5 rounded-md border border-warning/30 bg-warning/10 px-2.5 py-1.5 text-[11px] text-warning">
        <Icon name="alert-triangle" size={13} class="mt-px shrink-0" />At least one must stay ticked out. To block all internet, switch Internet off.
      </p>
    {/if}
  {/if}
</div>
