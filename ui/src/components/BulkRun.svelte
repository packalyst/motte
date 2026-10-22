<script>
  // Run one allowlisted command across several machines at once. Step-up (password + 2FA when
  // enabled) is collected once and verified once server-side. Each host's result shows on its row.
  import { apiPost, toast, stepUpConfirm } from '../stores/app.js'
  import { statusInfo } from '$lib/fleet.js'
  import Modal from './Modal.svelte'
  import Button from './Button.svelte'
  import Checkbox from './Checkbox.svelte'
  import Segmented from './Segmented.svelte'
  import Icon from './Icon.svelte'

  let { open = $bindable(false), machines = [] } = $props()

  // Curated allowlisted commands worth running fleet-wide (payload-free).
  const commandOptions = [
    { value: 'apply-updates', label: 'Apply OS updates', icon: 'package', hint: 'Install pending package updates' },
    { value: 'update-kernel', label: 'Update kernel', icon: 'cpu', hint: 'Install the latest kernel; applies after a reboot' },
    { value: 'restart', label: 'Reboot host', icon: 'power', hint: 'Restarts the machine — sessions on it drop', danger: true },
    { value: 'update-agent', label: 'Update agent', icon: 'refresh', hint: 'Move the agent to the latest release' },
    { value: 'sync-blocks', label: 'Push panel blocklist', icon: 'shield', hint: "Send the panel's blocked IPs to the machine" },
  ]

  let command = $state('apply-updates')
  let selected = $state(new Set())
  let running = $state(false)
  let results = $state({}) // machine_id → { ok, error }

  // Each opening starts clean.
  $effect(() => {
    if (open) { selected = new Set(); results = {} }
  })

  function toggle(id) {
    const s = new Set(selected)
    s.has(id) ? s.delete(id) : s.add(id)
    selected = s
  }
  // Only online machines can be picked: a command for an offline one would wait in the queue and
  // run whenever it reconnects — a reboot days later, by surprise.
  const online = $derived(machines.filter((m) => statusInfo(m).reachable).map((m) => m.id))
  // Quick picks: the toggle shows which one the current selection matches (none after hand-picking).
  const preset = $derived(selected.size === 0 ? 'none' : selected.size === online.length && online.every((id) => selected.has(id)) ? 'all' : undefined)
  const presetOptions = $derived([
    { value: 'all', label: 'All online', count: online.length },
    { value: 'none', label: 'None' },
  ])

  const cmd = $derived(commandOptions.find((c) => c.value === command))
  const plural = (n) => `${n} machine${n === 1 ? '' : 's'}`

  async function run() {
    const ids = [...selected]
    if (ids.length === 0) return toast('Select at least one machine', 'error')
    const su = await stepUpConfirm({
      title: `${cmd.label} on ${plural(ids.length)}`,
      message: `This queues "${cmd.label}" on ${plural(ids.length)}. Re-enter your credentials to authorize it.`,
      confirmText: 'Run',
      variant: 'destructive',
    })
    if (!su?.confirmed || !su?.password) return
    running = true
    results = {}
    try {
      const res = await apiPost('/api/fleet/bulk-command', {
        machine_ids: ids, type: command, currentPassword: su.password, totpCode: su.totp || '',
      })
      results = Object.fromEntries((res.results || []).map((r) => [r.machine_id, r]))
      toast(`Queued on ${res.queued}/${plural(res.total)}`, res.queued === res.total ? 'success' : 'warning')
    } catch (e) {
      toast(e.message || 'Bulk run failed', 'error')
    } finally {
      running = false
    }
  }
</script>

<Modal bind:open title="Run on multiple machines" size="lg">
  <div class="space-y-4">
    <div>
      <div class="mb-2 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Command</div>
      <div role="radiogroup" aria-label="Command" class="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {#each commandOptions as c (c.value)}
          {@const on = command === c.value}
          <button type="button" role="radio" aria-checked={on} onclick={() => (command = c.value)}
            class="flex cursor-pointer items-start gap-2.5 rounded-lg border p-2.5 text-left transition-colors
              {on ? (c.danger ? 'border-destructive/50 bg-destructive/10' : 'border-primary/50 bg-primary/10') : 'border-border hover:bg-muted/50'}">
            <span class="grid h-7 w-7 shrink-0 place-items-center rounded-md {c.danger ? 'bg-destructive/10 text-destructive' : 'bg-primary/10 text-primary'}">
              <Icon name={c.icon} size={14} />
            </span>
            <span class="min-w-0">
              <span class="block text-sm font-medium text-foreground">{c.label}</span>
              <span class="block text-[11px] leading-snug text-muted-foreground">{c.hint}</span>
            </span>
          </button>
        {/each}
      </div>
    </div>

    <div>
      <div class="mb-2 flex items-center gap-2">
        <span class="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Machines</span>
        <span class="text-[11px] text-muted-foreground tabular-nums">{selected.size} of {online.length} online selected</span>
        <Segmented size="sm" label="Select machines" class="ml-auto" value={preset} options={presetOptions}
          onchange={(k) => (selected = new Set(k === 'all' ? online : []))} />
      </div>
      <div class="max-h-64 divide-y divide-border overflow-y-auto rounded-lg border border-border">
        {#each machines as m (m.id)}
          {@const st = statusInfo(m)}
          {@const r = results[m.id]}
          <label class="flex items-center gap-3 px-3 py-2 text-sm transition-colors {st.reachable ? 'cursor-pointer hover:bg-muted/40' : 'cursor-not-allowed opacity-50'} {selected.has(m.id) ? 'bg-primary/5' : ''}"
            title={st.reachable ? undefined : 'Not online — commands can only be sent to machines that are online'}>
            <Checkbox checked={selected.has(m.id)} disabled={!st.reachable} onchange={() => toggle(m.id)} />
            <span class="min-w-0 flex-1">
              <span class="block truncate font-medium text-foreground">{m.name || m.id}</span>
              <span class="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                <span class="h-1.5 w-1.5 rounded-full {st.dot}"></span>{st.label}
                {#each m.tags || [] as t (t)}<span class="inline-flex items-center gap-0.5 rounded bg-muted px-1 text-[10px]"><Icon name="tag" size={9} />{t}</span>{/each}
              </span>
            </span>
            {#if r}
              {#if r.ok}
                <span class="inline-flex shrink-0 items-center gap-1 text-[11px] text-success"><Icon name="circle-check" size={13} />queued</span>
              {:else}
                <span class="max-w-[45%] truncate text-[11px] text-destructive" title={r.error}><Icon name="alert-circle" size={13} class="mr-1 inline" />{r.error}</span>
              {/if}
            {/if}
          </label>
        {/each}
        {#if machines.length === 0}
          <p class="px-3 py-4 text-center text-xs text-muted-foreground">No machines.</p>
        {/if}
      </div>
    </div>
  </div>

  {#snippet footer()}
    <span class="mr-auto text-[11px] text-muted-foreground">You'll confirm with your password.</span>
    <Button variant="secondary" onclick={() => (open = false)}>Close</Button>
    <Button variant={cmd?.danger ? 'destructive' : 'primary'} icon={cmd?.icon || 'player-play'} loading={running} disabled={selected.size === 0} onclick={run}>
      {cmd?.label} on {plural(selected.size)}
    </Button>
  {/snippet}
</Modal>
