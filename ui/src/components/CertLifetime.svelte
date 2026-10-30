<script>
  /**
   * CertLifetime — how long machines' client certificates last (Settings → Agents, inside the agent
   * listener card). Machines renew theirs in its last third while online; a change applies from each
   * machine's next certificate. Saving asks for the password again (admin-only on the server).
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast, withStepUp, STEPUP_CANCELLED } from '../stores/app.js'
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

<div class="min-w-0">
  <div class="flex items-end gap-2">
    <div class="min-w-0 flex-1">
      <Select bind:value={days} label="Certificate lifetime" prefixIcon="certificate" disabled={!cur || saving}
        options={(cur?.choices || [30, 60, 90, 180, 365]).map((d) => ({ value: String(d), label: `${d} days` }))} />
    </div>
    <Button size="sm" variant="primary" icon="device-floppy" iconOnly tooltip="Save" aria-label="Save certificate lifetime" loading={saving} disabled={!cur || saving || Number(days) === cur.days} onclick={save} />
  </div>
  <p class="field-hint">Renews by itself in its last third while online. Shorter is safer; a machine offline longer must be re-enrolled.</p>
</div>
