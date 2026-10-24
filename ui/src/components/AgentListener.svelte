<script>
  /**
   * AgentListener — the fleet agent listener control (Settings → Agents): on/off and port. A port
   * change keeps the old port open for a few minutes while agents move over; the config is locked
   * until then. Saving is admin-only on the server.
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Input from './Input.svelte'
  import Checkbox from './Checkbox.svelte'

  let ep = $state(null) // { enabled, port, listening, migrating, migrate_ends_at, … }
  let cfgEnabled = $state(false)
  let cfgPort = $state(9443)
  let savingCfg = $state(false)

  async function load() {
    try {
      ep = await apiGet('/api/fleet/endpoints')
      if (!savingCfg) { cfgEnabled = ep.enabled; cfgPort = ep.port }
    } catch (e) {
      toast('Failed to load the agent listener: ' + e.message, 'error')
    }
  }
  onMount(load)

  // Port migration: while both ports are open the config is locked (a second change would strand
  // agents). The old port closes once every machine has reconnected on the new one (normally
  // seconds; machines that can't, at the latest by migrate_ends_at). Re-poll so it unlocks.
  const migrating = $derived(!!ep?.migrating)
  const migrateBy = $derived(migrating && ep?.migrate_ends_at ? new Date(ep.migrate_ends_at).toLocaleString() : '')
  $effect(() => {
    if (!migrating) return
    const t = setInterval(async () => {
      try {
        const fresh = await apiGet('/api/fleet/endpoints')
        if (!savingCfg) {
          ep = { ...ep, ...fresh }
          if (!fresh.migrating) { cfgPort = fresh.port; cfgEnabled = fresh.enabled }
        }
      } catch { /* keep last state */ }
    }, 5000)
    return () => clearInterval(t)
  })

  async function saveConfig() {
    savingCfg = true
    try {
      const res = await apiPost('/api/fleet/config', { enabled: cfgEnabled, port: Number(cfgPort) })
      ep = { ...ep, ...res }
      if (res.migrating) {
        toast('New port sent to the agents — the old port stays open until they have all reconnected', 'success')
      } else {
        toast(cfgEnabled ? `Fleet listener on :${ep.port}` : 'Fleet listener off', 'success')
      }
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      savingCfg = false
    }
  }
</script>

<div class="panel">
  <div class="panel-head">
    <span class="panel-icon text-primary"><Icon name="plug-connected" size={17} /></span>
    <div class="min-w-0 flex-1 panel-title flex items-center gap-2">Agent listener</div>
    <span class="inline-flex items-center gap-1.5 text-xs {ep?.listening ? 'text-success' : 'text-muted-foreground'}">
      <span class="h-1.5 w-1.5 rounded-full {ep?.listening ? 'bg-success' : 'bg-muted-foreground'}"></span>
      {ep?.listening ? `Accepting agents on :${ep.port}` : 'Closed'}
    </span>
  </div>
  <div class="space-y-4">
    <div class="flex items-start justify-between gap-3 rounded-lg border border-border p-3">
      <div class="flex min-w-0 items-start gap-2.5">
        <span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg {ep?.listening ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
          <Icon name={ep?.listening ? 'lock-open' : 'lock'} size={16} />
        </span>
        <div class="min-w-0">
          <div class="text-sm font-medium text-foreground">Accept agent connections</div>
          <div class="text-[11px] text-muted-foreground">Opens the port through the firewall and starts the mutual-TLS listener. Nothing to edit in env or compose.</div>
        </div>
      </div>
      <Checkbox variant="switch" bind:checked={cfgEnabled} onchange={saveConfig} disabled={migrating || !ep} aria-label="Accept agent connections" />
    </div>
    <div class="max-w-xs">
      <Input type="number" bind:value={cfgPort} min="1" max="65535" prefixIcon="plug" label="Port" disabled={migrating || !ep}
        suffixAddonBtn={{ icon: 'device-floppy', label: 'Save', variant: 'primary', onclick: saveConfig, disabled: savingCfg || migrating || !ep }} />
    </div>
    {#if migrating}
      <p class="flex items-start gap-1.5 text-[11px] text-warning">
        <Icon name="refresh" size={13} class="mt-0.5 shrink-0 animate-spin" />
        Changing port — agents are being told the new port ({ep.port}). The old port stays open until every machine has reconnected on the new one (usually under a minute; at the latest {migrateBy} for machines that are offline); settings are locked until then.
      </p>
    {/if}
  </div>
  <div class="panel-foot">
    <p class="flex items-start gap-1.5 text-[11px] text-muted-foreground">
      <Icon name="info-circle" size={13} class="mt-0.5 shrink-0" />Machines are added from Clients → Add client → Machine.
    </p>
  </div>
</div>
