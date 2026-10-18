<script>
  // Run one allowlisted command across several machines at once. Step-up (password + 2FA when
  // enabled) is collected once and verified once server-side. Per-host results are shown after.
  import { apiPost, toast, stepUpConfirm } from '../stores/app.js'
  import Modal from './Modal.svelte'
  import Button from './Button.svelte'
  import Select from './Select.svelte'
  import Checkbox from './Checkbox.svelte'
  import Icon from './Icon.svelte'

  let { open = $bindable(false), machines = [] } = $props()

  // Curated allowlisted commands worth running fleet-wide (payload-free).
  const commandOptions = [
    { value: 'apply-updates', label: 'Apply OS updates' },
    { value: 'update-kernel', label: 'Update kernel' },
    { value: 'restart', label: 'Reboot host' },
    { value: 'update-agent', label: 'Update agent' },
    { value: 'sync-blocks', label: 'Push panel blocklist' },
  ]

  let command = $state('apply-updates')
  let selected = $state(new Set())
  let running = $state(false)
  let results = $state(null)

  function toggle(id) {
    const s = new Set(selected)
    s.has(id) ? s.delete(id) : s.add(id)
    selected = s
  }
  function selectAll() { selected = new Set(machines.map((m) => m.id)) }
  function selectNone() { selected = new Set() }

  const label = $derived(commandOptions.find((c) => c.value === command)?.label || command)

  async function run() {
    const ids = [...selected]
    if (ids.length === 0) return toast('Select at least one machine', 'error')
    const su = await stepUpConfirm({
      title: `Run "${label}" on ${ids.length} host${ids.length > 1 ? 's' : ''}`,
      message: `This queues "${label}" on ${ids.length} selected machine${ids.length > 1 ? 's' : ''}. Re-enter your credentials to authorize it.`,
      confirmText: 'Run',
      variant: 'destructive',
    })
    if (!su?.confirmed || !su?.password) return
    running = true
    results = null
    try {
      const res = await apiPost('/api/fleet/bulk-command', {
        machine_ids: ids, type: command, currentPassword: su.password, totpCode: su.totp || '',
      })
      results = res.results || []
      toast(`Queued on ${res.queued}/${res.total} host${res.total > 1 ? 's' : ''}`, res.queued === res.total ? 'success' : 'warning')
    } catch (e) {
      toast(e.message || 'Bulk run failed', 'error')
    } finally {
      running = false
    }
  }

  function nameFor(id) {
    return machines.find((m) => m.id === id)?.name || id
  }
</script>

<Modal bind:open title="Run on multiple hosts" size="md">
  <div class="space-y-4">
    <div class="flex items-center gap-2">
      <span class="text-sm font-medium">Command</span>
      <Select bind:value={command} options={commandOptions} />
    </div>

    <div class="space-y-1.5">
      <div class="flex items-center justify-between">
        <span class="text-sm font-medium">Machines ({selected.size}/{machines.length})</span>
        <div class="flex gap-2">
          <Button variant="ghost" size="xs" onclick={selectAll}>All</Button>
          <Button variant="ghost" size="xs" onclick={selectNone}>None</Button>
        </div>
      </div>
      <div class="max-h-56 overflow-y-auto divide-y divide-border rounded-md border border-border">
        {#each machines as m (m.id)}
          <label class="flex items-center gap-2 px-3 py-1.5 text-sm cursor-pointer hover:bg-muted/40">
            <Checkbox checked={selected.has(m.id)} onchange={() => toggle(m.id)} />
            <span class="font-medium">{m.name || m.id}</span>
            {#if m.tags?.length}<span class="text-[10px] text-muted-foreground">{m.tags.join(', ')}</span>{/if}
          </label>
        {/each}
        {#if machines.length === 0}
          <p class="px-3 py-2 text-xs text-muted-foreground">No machines.</p>
        {/if}
      </div>
    </div>

    {#if results}
      <div class="space-y-1 rounded-md border border-border p-2 text-xs max-h-40 overflow-y-auto">
        {#each results as r}
          <div class="flex items-center justify-between gap-2">
            <span class="font-medium">{nameFor(r.machine_id)}</span>
            {#if r.ok}
              <span class="text-success flex items-center gap-1"><Icon name="check" size={12} /> queued</span>
            {:else}
              <span class="text-destructive truncate">{r.error}</span>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>

  {#snippet footer()}
    <Button variant="secondary" onclick={() => (open = false)}>Close</Button>
    <Button variant="primary" icon="player-play" loading={running} disabled={selected.size === 0} onclick={run}>
      Run on {selected.size} host{selected.size === 1 ? '' : 's'}
    </Button>
  {/snippet}
</Modal>
