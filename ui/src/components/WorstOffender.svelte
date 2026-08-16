<script>
  /**
   * WorstOffender — the single IP generating the most hostile traffic this hour,
   * with a one-click ban. Data from /api/fw/overview.top_attacker.
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast } from '../stores/app.js'
  import Icon from './Icon.svelte'
  import CountryFlag from './CountryFlag.svelte'

  let a = $state(null)
  let banning = $state(false)

  async function load() {
    try { const d = await apiGet('/api/fw/overview'); a = d?.top_attacker || null } catch {}
  }
  onMount(() => { load(); const t = setInterval(load, 30000); return () => clearInterval(t) })

  async function ban() {
    if (!a?.ip) return
    banning = true
    try {
      await apiPost('/api/fw/entries', { type: 'ip', value: a.ip, action: 'block', direction: 'inbound', reason: 'Worst offender (manual)' })
      toast(`Blocked ${a.ip}`, 'success')
      a = null
    } catch (e) {
      toast('Failed to block: ' + e.message, 'error')
    } finally {
      banning = false
    }
  }
</script>

<div class="bg-card border border-border rounded-xl p-4">
  <h3 class="text-sm font-semibold text-foreground mb-0.5 flex items-center gap-2"><Icon name="skull" size={16} class="text-destructive" />Worst offender right now</h3>
  <p class="text-[11px] text-muted-foreground mb-3">The single IP generating the most hostile traffic this hour.</p>
  {#if !a}
    <div class="text-sm text-muted-foreground py-3 text-center">No notable attacker this hour.</div>
  {:else}
    <div class="flex items-center gap-3">
      <div class="w-8 h-8 rounded-lg bg-destructive/10 text-destructive grid place-items-center shrink-0"><Icon name="skull" size={16} /></div>
      <div class="min-w-0 flex-1">
        <div class="text-sm font-medium text-foreground flex items-center gap-2">
          {#if a.country}<CountryFlag code={a.country} size="sm" />{/if}
          <span class="font-mono truncate">{a.ip}</span>
          {#if a.reputation?.level}<span class="text-[10px] px-1.5 py-0.5 rounded-full bg-destructive/15 text-destructive">rep {a.reputation.score ?? a.reputation.level}</span>{/if}
        </div>
        <div class="text-[11px] text-muted-foreground font-mono truncate">{a.owner || 'unknown owner'} · ×{a.count} hits</div>
      </div>
      <button onclick={ban} disabled={banning} class="shrink-0 text-xs px-3 py-1.5 rounded-lg bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-50">
        {banning ? 'Banning…' : 'Ban'}
      </button>
    </div>
  {/if}
</div>
