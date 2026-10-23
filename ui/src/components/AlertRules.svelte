<script>
  // Resource alerts — PER USER, rules only. Delivery channels (push/webhook/email) live in the
  // Notifications card above; these rules just decide WHAT fires. A rule watches the panel host
  // and/or specific fleet machines and/or "all machines".
  import { onMount } from 'svelte'
  import { apiGet, apiPut, apiPost, apiDelete, toast } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Input from './Input.svelte'
  import Select from './Select.svelte'
  import Checkbox from './Checkbox.svelte'
  import GroupButton from './GroupButton.svelte'

  let rules = $state([])
  let machines = $state([])
  let loading = $state(true)

  const metricOptions = [
    { value: 'cpu', label: 'CPU %' },
    { value: 'mem', label: 'Memory %' },
    { value: 'disk', label: 'Disk %' },
  ]

  onMount(load)

  async function load() {
    loading = true
    try {
      const [r, m] = await Promise.allSettled([apiGet('/api/alerts/rules'), apiGet('/api/fleet/machines')])
      rules = r.status === 'fulfilled' ? (r.value || []).map(normalize) : []
      machines = m.status === 'fulfilled' ? (m.value || []).filter((x) => !x.revoked) : [] // a revoked machine reports nothing
    } catch (e) {
      toast(e.message || 'Could not load alert rules', 'error')
    } finally {
      loading = false
    }
  }

  function normalize(r) {
    return { ...r, targets: { host: false, allMachines: false, machineIds: [], ...(r.targets || {}) } }
  }

  function addRule() {
    rules = [...rules, { id: null, name: 'High CPU', metric: 'cpu', targets: { host: true, allMachines: false, machineIds: [] }, threshold: 90, forMin: 5, enabled: true }]
  }

  function toggleMachine(r, id) {
    const set = new Set(r.targets.machineIds)
    set.has(id) ? set.delete(id) : set.add(id)
    r.targets.machineIds = [...set]
  }

  function validTargets(r) {
    return r.targets.host || r.targets.allMachines || r.targets.machineIds.length > 0
  }

  async function saveRule(r) {
    if (!validTargets(r)) return toast('Pick at least one target (host, a machine, or all)', 'error')
    const body = {
      name: r.name, metric: r.metric,
      targets: { host: !!r.targets.host, allMachines: !!r.targets.allMachines, machineIds: r.targets.allMachines ? [] : r.targets.machineIds },
      threshold: Number(r.threshold), forMin: Number(r.forMin), enabled: !!r.enabled,
    }
    try {
      if (r.id) {
        await apiPut(`/api/alerts/rules/${r.id}`, body)
      } else {
        const created = await apiPost('/api/alerts/rules', body)
        r.id = created.id
      }
      toast('Rule saved', 'success')
    } catch (e) {
      toast(e.message || 'Save failed', 'error')
    }
  }

  async function removeRule(r) {
    if (!r.id) {
      rules = rules.filter((x) => x !== r)
      return
    }
    try {
      await apiDelete(`/api/alerts/rules/${r.id}`)
      rules = rules.filter((x) => x !== r)
    } catch (e) {
      toast(e.message || 'Delete failed', 'error')
    }
  }

  function nameFor(id) {
    return machines.find((m) => m.id === id)?.name || id
  }
</script>

{#snippet chip(on, label, onclick, icon)}
  <button type="button" aria-pressed={on} {onclick}
    class="inline-flex cursor-pointer items-center gap-1.5 rounded-md border px-2 py-1 text-xs transition-colors
      {on ? 'border-primary/40 bg-primary/10 text-primary' : 'border-border text-muted-foreground hover:bg-muted/50 hover:text-foreground'}">
    <Icon name={on ? 'check' : icon} size={12} />{label}
  </button>
{/snippet}

<div class="space-y-3">
  <div class="flex items-center gap-3">
    <h4 class="flex min-w-0 flex-1 items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground after:h-px after:flex-1 after:bg-border">
      <Icon name="bell-ringing" size={13} />Resource alert rules
    </h4>
    <button type="button" class="link-action" onclick={addRule}><Icon name="plus" size={12} />Add rule</button>
  </div>
  <p class="text-[11px] text-muted-foreground">
    Fire when CPU, memory or disk stays over a threshold — on this panel and/or fleet machines. Uses the channels above.
  </p>

  {#if loading}
    <div class="text-sm text-muted-foreground">Loading…</div>
  {:else if rules.length === 0}
    <div class="flex items-center gap-3 rounded-lg border border-dashed border-border px-4 py-4 text-xs text-muted-foreground">
      <Icon name="bell" size={16} class="shrink-0" />No rules yet — add one to start alerting.
    </div>
  {:else}
    {#each rules as r (r.id ?? r)}
      <div class="rounded-lg border border-border {r.enabled ? '' : 'opacity-70'}">
        <!-- header: on/off, name, actions -->
        <div class="flex items-center gap-2.5 border-b border-border px-3 py-2">
          <Checkbox variant="switch" checked={r.enabled} onchange={(e) => (r.enabled = e.target.checked)} aria-label="Rule enabled" />
          <div class="min-w-0 flex-1"><Input bind:value={r.name} placeholder="Rule name" aria-label="Rule name" /></div>
          <div class="btn-group shrink-0">
            <GroupButton icon="device-floppy" tone="primary" tooltip="Save rule" onclick={() => saveRule(r)} />
            <GroupButton icon="trash" tone="destructive" tooltip="Delete rule" onclick={() => removeRule(r)} />
          </div>
        </div>
        <div class="space-y-3 p-3">
          <!-- condition -->
          <div class="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <Select label="When" bind:value={r.metric} options={metricOptions} />
            <Input label="Is over" type="number" bind:value={r.threshold} suffixAddon="%" min="1" max="100" />
            <Input label="For at least" type="number" bind:value={r.forMin} suffixAddon="min" min="1" />
          </div>
          <!-- targets -->
          <div class="space-y-1.5">
            <div class="text-[10px] uppercase tracking-wide text-muted-foreground">Watch</div>
            <div class="flex flex-wrap gap-1.5">
              {@render chip(r.targets.host, 'This panel', () => (r.targets.host = !r.targets.host), 'server')}
              {@render chip(r.targets.allMachines, 'All machines', () => (r.targets.allMachines = !r.targets.allMachines), 'devices')}
              {#if !r.targets.allMachines}
                {#each machines as m (m.id)}
                  {@render chip(r.targets.machineIds.includes(m.id), m.name || m.id, () => toggleMachine(r, m.id), 'device-desktop')}
                {/each}
              {/if}
            </div>
            {#if !r.targets.allMachines && machines.length === 0}
              <p class="text-[11px] text-muted-foreground">No machines enrolled yet.</p>
            {/if}
          </div>
        </div>
      </div>
    {/each}
  {/if}
</div>
