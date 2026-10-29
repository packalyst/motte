<script>
  /**
   * CertLifetime — how long machines' client certificates last (Settings → Agents). Machines renew
   * theirs in its last third while online; a change applies from each machine's next certificate.
   * Saving asks for the password again (admin-only on the server).
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast, withStepUp, STEPUP_CANCELLED } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import Select from './Select.svelte'
  import Button from './Button.svelte'

  let cur = $state(null) // { days, choices }
  let days = $state('90')
  let saving = $state(false)

  onMount(async () => {
    try {
      cur = await apiGet('/api/fleet/cert-lifetime')
      days = String(cur.days)
    } catch (e) {
      toast('Failed to load the certificate lifetime: ' + e.message, 'error')
    }
  })

  async function save() {
    saving = true
    try {
      const res = await withStepUp((extra) => apiPost('/api/fleet/cert-lifetime', { days: Number(days), ...extra }),
        { title: 'Change certificate lifetime', message: 'Confirm your password to change how long machine certificates last.', confirmText: 'Save' })
      if (res === STEPUP_CANCELLED) return
      cur = res
      toast(`Machine certificates now last ${res.days} days`, 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      saving = false
    }
  }
</script>

<div class="panel">
  <div class="panel-head">
    <span class="panel-icon text-primary"><Icon name="certificate" size={17} /></span>
    <div class="min-w-0 flex-1">
      <div class="panel-title">Machine certificates</div>
      <div class="panel-sub">how long each machine's identity lasts before it renews</div>
    </div>
  </div>
  <div class="max-w-xs">
    <Select bind:value={days} size="lg" label="Lifetime" disabled={!cur || saving}
      options={(cur?.choices || [30, 60, 90, 180, 365]).map((d) => ({ value: String(d), label: `${d} days` }))} />
  </div>
  <div class="mt-3">
    <Button size="sm" icon="device-floppy" loading={saving} disabled={!cur || saving || Number(days) === cur.days} onclick={save}>Save</Button>
  </div>
  <div class="panel-foot">
    <p class="flex items-start gap-1.5 text-[11px] text-muted-foreground">
      <Icon name="info-circle" size={13} class="mt-0.5 shrink-0" />A machine renews its certificate by itself in the last third of its life, while online, and the panel accepts renewal only then. Shorter means a stolen certificate works for less time; a machine offline for longer than this must be re-enrolled. A change applies from each machine's next certificate.
    </p>
  </div>
</div>
