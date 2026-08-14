<script>
  /**
   * IpLookup - self-contained "who is this IP?" tool.
   * Type an IP, get country + owner (ASN) + proxy/VPN flags + a blended
   * reputation verdict. Reusable across Analytics / Firewall / Overview.
   */
  import Input from './Input.svelte'
  import Button from './Button.svelte'
  import Icon from './Icon.svelte'
  import CountryFlag from './CountryFlag.svelte'
  import { lookupIPs, getGeoData, checkGeoEnabled } from '../stores/geo.js'
  import { reputationMeta, proxyTypeLabel, usageTypeLabel } from '../lib/reputation.js'

  let { ip: initialIp = '' } = $props()

  let query = $state(initialIp)
  let result = $state(null)
  let error = $state('')
  let loading = $state(false)

  const meta = $derived(reputationMeta(result?.reputation?.level))

  // Accept an IPv4 or IPv6 literal; keep it lenient and let the backend judge.
  function looksLikeIP(s) {
    return /^[0-9a-fA-F:.]+$/.test(s) && (s.includes('.') || s.includes(':'))
  }

  async function lookup() {
    const ip = query.trim()
    error = ''
    result = null
    if (!ip) return
    if (!looksLikeIP(ip)) { error = 'Enter a valid IPv4 or IPv6 address.'; return }
    loading = true
    try {
      if (!(await checkGeoEnabled())) {
        error = 'IP lookup is disabled — enable a provider in Settings → Geolocation.'
        return
      }
      await lookupIPs([ip])
      const g = getGeoData(ip)
      if (!g) { error = 'No data for this IP.'; return }
      result = g
    } catch (e) {
      error = e?.message || 'Lookup failed.'
    } finally {
      loading = false
    }
  }

  function onKey(e) { if (e.key === 'Enter') lookup() }
</script>

<div class="bg-card border border-border rounded-lg p-4 shadow-sm">
  <div class="flex items-center gap-2 mb-3">
    <Icon name="search" size={16} class="text-muted-foreground" />
    <span class="text-sm font-semibold">IP lookup</span>
  </div>

  <div class="flex items-end gap-2">
    <div class="flex-1">
      <Input bind:value={query} placeholder="1.2.3.4" prefixIcon="world" onkeydown={onKey} />
    </div>
    <Button onclick={lookup} {loading} disabled={loading} variant="secondary" size="sm" icon="search">Look up</Button>
  </div>

  {#if error}
    <div class="mt-3 text-xs text-warning flex items-center gap-1.5">
      <Icon name="alert-triangle" size={13} />{error}
    </div>
  {/if}

  {#if result}
    <div class="mt-3 rounded-lg border {meta.ring} p-3 space-y-2">
      <!-- Verdict -->
      <div class="flex items-center justify-between gap-2">
        <div class="flex items-center gap-2 min-w-0">
          <span class="w-2.5 h-2.5 rounded-full shrink-0 {meta.dot}"></span>
          <span class="text-sm font-semibold {meta.text}">{meta.label}</span>
        </div>
        {#if result.reputation}
          <span class="text-xs font-mono {meta.text} tabular-nums">{result.reputation.score}/100</span>
        {/if}
      </div>

      <!-- Facts -->
      <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <div class="flex items-center gap-1.5 min-w-0">
          <span class="text-muted-foreground">Location</span>
          <span class="flex items-center gap-1 truncate">
            {#if result.country_code}<CountryFlag code={result.country_code} size="sm" />{/if}
            <span class="truncate">{result.country_name || result.country_code || '—'}</span>
          </span>
        </div>
        <div class="flex items-center gap-1.5 min-w-0">
          <span class="text-muted-foreground">Owner</span>
          <span class="truncate">{result.as_name || '—'}{#if result.asn} <span class="text-muted-foreground">AS{result.asn}</span>{/if}</span>
        </div>
        {#if usageTypeLabel(result.usage_type)}
          <div class="flex items-center gap-1.5"><span class="text-muted-foreground">Network</span><span>{usageTypeLabel(result.usage_type)}</span></div>
        {/if}
        {#if result.is_proxy}
          <div class="flex items-center gap-1.5"><span class="text-muted-foreground">Proxy</span><span class="text-warning">{proxyTypeLabel(result.proxy_type) || 'Yes'}</span></div>
        {/if}
        {#if result.threat && result.threat !== '-'}
          <div class="flex items-center gap-1.5"><span class="text-muted-foreground">Threat</span><span class="text-destructive">{result.threat}</span></div>
        {/if}
      </div>

      <!-- Why -->
      {#if result.reputation?.reasons?.length}
        <div class="text-[11px] text-muted-foreground pt-1.5 border-t border-border/50">
          {result.reputation.reasons.join(' · ')}
        </div>
      {/if}
    </div>
  {/if}
</div>
