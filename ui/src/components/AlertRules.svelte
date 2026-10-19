<script>
  // Resource alerts — PER USER, rules only. Delivery channels (push/webhook/email) live in the
  // Notifications card above; these rules just decide WHAT fires. A rule watches the panel host
  // and/or specific fleet machines and/or "all machines".
  import { onMount } from 'svelte'
  import { apiGet, apiPut, apiPost, apiDelete, toast } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Input from './Input.svelte'
  import Select from './Select.svelte'
  import Checkbox from './Checkbox.svelte'

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
      machines = m.status === 'fulfilled' ? m.value || [] : []
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

<div class="kt-panel">
  <div class="kt-panel-header">
    <h3 class="kt-panel-title"><Icon name="bell-ringing" size={16} /> Resource alerts</h3>
  </div>
  <div class="kt-panel-body space-y-3">
    <div class="flex items-center justify-between">
      <p class="text-xs text-muted-foreground">
        Fire when CPU, memory or disk stays over a threshold — on this panel and/or fleet machines. Delivered via your channels above.
      </p>
      <Button variant="outline" size="xs" icon="plus" onclick={addRule}>Add rule</Button>
    </div>

    {#if loading}
      <div class="text-sm text-muted-foreground">Loading…</div>
    {:else if rules.length === 0}
      <p class="text-xs text-muted-foreground">No rules yet — add one to start alerting.</p>
    {:else}
      {#each rules as r (r.id ?? r)}
        <div class="space-y-2 rounded-md border border-border p-3">
          <div class="flex flex-wrap items-center gap-2">
            <Checkbox checked={r.enabled} onchange={(e) => (r.enabled = e.target.checked)} />
            <Input bind:value={r.name} placeholder="Name" class="w-32" />
            <Select bind:value={r.metric} options={metricOptions} />
            <span class="text-xs text-muted-foreground">over</span>
            <Input type="number" bind:value={r.threshold} class="w-16" /><span class="text-xs">%</span>
            <span class="text-xs text-muted-foreground">for</span>
            <Input type="number" bind:value={r.forMin} class="w-16" /><span class="text-xs">min</span>
            <div class="ml-auto flex items-center gap-1">
              <Button variant="outline" size="xs" icon="device-floppy" onclick={() => saveRule(r)}>Save</Button>
              <Button variant="ghost" size="xs" icon="trash" iconOnly onclick={() => removeRule(r)} />
            </div>
          </div>
          <!-- Targets -->
          <div class="flex flex-wrap items-center gap-x-4 gap-y-1 pl-1 text-sm">
            <span class="text-xs font-medium text-muted-foreground">Watch:</span>
            <label class="flex items-center gap-1.5"><Checkbox checked={r.targets.host} onchange={(e) => (r.targets.host = e.target.checked)} /> This panel</label>
            <label class="flex items-center gap-1.5"><Checkbox checked={r.targets.allMachines} onchange={(e) => (r.targets.allMachines = e.target.checked)} /> All machines</label>
            {#if !r.targets.allMachines && machines.length > 0}
              <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
                {#each machines as m (m.id)}
                  <label class="flex items-center gap-1.5 text-xs">
                    <Checkbox checked={r.targets.machineIds.includes(m.id)} onchange={() => toggleMachine(r, m.id)} /> {m.name || m.id}
                  </label>
                {/each}
              </div>
            {/if}
          </div>
        </div>
      {/each}
    {/if}
  </div>
</div>
