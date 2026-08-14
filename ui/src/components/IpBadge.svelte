<script>
  /**
   * IpBadge - compact reputation/enrichment badge for an IP.
   *
   * Presentational only: the parent is responsible for having batch-loaded the
   * geo data (stores/geo.js lookupIPs) and passing the result in as `geo`. This
   * keeps lookups batched at the list level instead of one request per badge.
   *
   * Props:
   * - geo: the geo result object for the IP (or null/undefined if not loaded)
   * - compact: dot only (score in tooltip), no owner/chips
   * - showOwner: show the ASN owner name (default true)
   */
  import { reputationMeta, proxyTypeLabel } from '../lib/reputation.js'

  let { geo = null, compact = false, showOwner = true } = $props()

  const rep = $derived(geo?.reputation || null)
  const meta = $derived(reputationMeta(rep?.level))
  const proxyLabel = $derived(geo?.is_proxy ? (proxyTypeLabel(geo.proxy_type) || 'Proxy') : '')
  const tooltip = $derived(
    rep
      ? `${meta.label}${rep.score ? ` (${rep.score}/100)` : ''}${rep.reasons?.length ? ' — ' + rep.reasons.join(', ') : ''}`
      : ''
  )
</script>

{#if geo}
  <span class="inline-flex items-center gap-1.5 min-w-0" title={tooltip}>
    {#if rep}
      <span class="w-2 h-2 rounded-full shrink-0 {meta.dot}"></span>
    {/if}
    {#if !compact}
      {#if rep}
        <span class="text-[11px] font-medium {meta.text} shrink-0">{rep.score}</span>
      {/if}
      {#if showOwner && geo.as_name}
        <span class="text-[11px] text-muted-foreground truncate">{geo.as_name}</span>
      {/if}
      {#if proxyLabel}
        <span class="text-[10px] px-1 py-px rounded bg-warning/10 text-warning border border-warning/20 shrink-0">{proxyLabel}</span>
      {/if}
    {/if}
  </span>
{/if}
