<script>
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import CountryFlag from '../components/CountryFlag.svelte'
  import { lookupIPs, getGeoData, checkGeoEnabled } from '../stores/geo.js'
  import { reputationMeta, proxyTypeLabel, usageTypeLabel } from '../lib/reputation.js'

  // The Dashboard shell binds `loading`.
  let { loading = $bindable(true), onLogout } = $props()

  function isPrivate(ip) {
    return !ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')
  }

  // Default to the admin's own IP (from the current session) and look it up.
  onMount(async () => {
    loading = false
    try {
      const res = await apiGet('/api/auth/sessions')
      const list = Array.isArray(res) ? res : (res?.sessions || [])
      const ip = (list.find(s => s.current) || list[0])?.ipAddress
      if (ip && looksLikeIP(ip) && !isPrivate(ip)) lookup(ip)
    } catch {}
  })

  let query = $state('')
  let result = $state(null)
  let hits = $state(null)     // times this IP hit us (from logs)
  let error = $state('')
  let busy = $state(false)
  let recent = $state([])     // [{ip, country_code, as_name, level, score}]

  const meta = $derived(reputationMeta(result?.reputation?.level))

  function looksLikeIP(s) {
    return /^[0-9a-fA-F:.]+$/.test(s) && (s.includes('.') || s.includes(':'))
  }

  async function lookup(ip = query.trim()) {
    query = ip
    error = ''; result = null; hits = null
    if (!ip) return
    if (!looksLikeIP(ip)) { error = 'Enter a valid IPv4 or IPv6 address.'; return }
    busy = true
    try {
      if (!(await checkGeoEnabled())) { error = 'IP lookup is disabled — enable a provider in Settings → Geolocation.'; return }
      await lookupIPs([ip])
      const g = getGeoData(ip)
      if (!g) { error = 'No data for this IP.'; return }
      result = g
      recent = [{ ip, country_code: g.country_code, as_name: g.as_name, level: g.reputation?.level, score: g.reputation?.score }, ...recent.filter(r => r.ip !== ip)].slice(0, 6)
      // Cross-reference: how many times this IP has hit us (best-effort).
      try { const l = await apiGet(`/api/logs?search=${encodeURIComponent(ip)}&limit=1`); hits = l?.total ?? null } catch { hits = null }
    } catch (e) {
      error = e?.message || 'Lookup failed.'
    } finally {
      busy = false
    }
  }

  async function act(entry, label) {
    try {
      await apiPost('/api/fw/entries', { direction: 'inbound', ...entry })
      toast(label, 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // Classification chips from the enrichment data.
  const chips = $derived.by(() => {
    if (!result) return []
    const out = []
    if (result.is_proxy) out.push({ on: true, text: proxyTypeLabel(result.proxy_type) || 'Proxy / VPN' })
    const u = usageTypeLabel(result.usage_type)
    if (u) out.push({ on: /hosting|data|dch/i.test(u), text: u })
    if (result.threat && result.threat !== '-') out.push({ on: true, text: result.threat })
    if (out.length === 0) out.push({ on: false, text: 'No proxy / threat flags' })
    return out
  })
</script>

<div class="space-y-4">
  <InfoCard icon="map-search" title="IP Lookup" description="Look up any IP: owner (ASN), country, VPN / proxy / hosting flags, reputation, and how often it has hit you — then block it in one click." />

  <!-- Big search -->
  <div class="flex items-center gap-2 bg-card border border-border rounded-xl p-2 pl-4 shadow-sm">
    <Icon name="search" size={18} class="text-muted-foreground shrink-0" />
    <input
      bind:value={query}
      onkeydown={(e) => e.key === 'Enter' && lookup()}
      placeholder="Paste an IP address — e.g. 45.155.205.18"
      class="flex-1 bg-transparent outline-none text-sm py-2"
    />
    <div class="shrink-0"><Button variant="primary" icon="search" loading={busy} onclick={() => lookup()}>Look up</Button></div>
  </div>

  {#if error}
    <div class="bg-warning/10 border border-warning/30 rounded-xl p-3 text-sm text-warning flex items-center gap-2"><Icon name="alert-triangle" size={15} />{error}</div>
  {/if}

  {#if result}
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <!-- Facts -->
      <div class="bg-card border border-border rounded-xl p-4 lg:col-span-2">
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-base font-semibold font-mono flex items-center gap-2">
            {#if result.country_code}<CountryFlag code={result.country_code} size="sm" />{/if}{query}
          </h3>
          {#if result.reputation}
            <span class="text-xs font-mono px-2 py-1 rounded-lg {meta.text}" style="background:color-mix(in srgb, currentColor 12%, transparent)">reputation {result.reputation.score}/100</span>
          {/if}
        </div>
        <div class="space-y-0">
          <div class="flex justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Verdict</span><span class="font-medium {meta.text}">{meta.label}</span></div>
          <div class="flex justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Owner (ASN)</span><span class="font-medium text-right">{result.as_name || '—'}{#if result.asn} · AS{result.asn}{/if}</span></div>
          <div class="flex justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Country</span><span class="font-medium">{result.country_name || result.country_code || '—'}</span></div>
          {#if result.extra?.city || result.extra?.region}<div class="flex justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">City / region</span><span class="font-medium text-right">{[result.extra.city, result.extra.region].filter(Boolean).join(', ')}</span></div>{/if}
          {#if result.extra?.isp}<div class="flex justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">ISP</span><span class="font-medium text-right truncate max-w-[60%]">{result.extra.isp}</span></div>{/if}
          {#if result.extra?.domain}<div class="flex justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Domain</span><span class="font-medium font-mono text-xs">{result.extra.domain}</span></div>{/if}
          {#if result.extra?.timezone}<div class="flex justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Timezone</span><span class="font-medium">{result.extra.timezone}</span></div>{/if}
          {#if usageTypeLabel(result.usage_type)}<div class="flex justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Network</span><span class="font-medium">{usageTypeLabel(result.usage_type)}</span></div>{/if}
          {#if result.fraud_score != null}<div class="flex justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Fraud score</span><span class="font-medium tabular-nums {result.fraud_score >= 75 ? 'text-destructive' : result.fraud_score >= 40 ? 'text-warning' : 'text-foreground'}">{result.fraud_score}/100</span></div>{/if}
          {#if result.threat && result.threat !== '-'}<div class="flex justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Threat</span><span class="font-medium text-destructive">{result.threat}</span></div>{/if}
          <div class="flex justify-between text-sm py-1.5 border-b border-border"><span class="text-muted-foreground">Hits here</span><span class="font-medium tabular-nums">{hits == null ? '—' : hits.toLocaleString()}</span></div>
          {#if result.provider}<div class="flex justify-between text-sm py-1.5"><span class="text-muted-foreground">Source</span><span class="font-medium text-xs">{result.provider}</span></div>{/if}
        </div>
        {#if result.reputation?.reasons?.length}
          <div class="text-[11px] text-muted-foreground mt-3 pt-2 border-t border-dashed border-border">{result.reputation.reasons.join(' · ')}</div>
        {/if}
      </div>

      <!-- Classification -->
      <div class="bg-card border border-border rounded-xl p-4">
        <h3 class="text-sm font-semibold mb-1">Classification</h3>
        <p class="text-[11px] text-muted-foreground mb-3">What kind of address this is.</p>
        <div class="flex flex-wrap gap-2">
          {#each chips as c}
            <span class="text-xs px-2.5 py-1 rounded-full font-medium {c.on ? 'bg-destructive/10 text-destructive' : 'bg-success/10 text-success'}">
              {c.on ? '⚠' : '✓'} {c.text}
            </span>
          {/each}
        </div>
      </div>
    </div>

    <!-- Actions -->
    <div class="bg-card border border-border rounded-xl p-3 flex flex-wrap items-center gap-3">
      <span class="text-xs text-muted-foreground">Actions:</span>
      <div class="kt-btn-group">
        <Button variant="destructive" size="sm" icon="ban" onclick={() => act({ type: 'ip', value: query, action: 'block' }, `Blocked ${query}`)}>Ban IP</Button>
        {#if result.asn}<Button variant="destructive" size="sm" onclick={() => act({ type: 'asn', value: String(result.asn), action: 'block', name: result.as_name }, `Blocking AS${result.asn}`)}>Ban range (AS{result.asn})</Button>{/if}
        {#if result.country_code}<Button variant="outline" size="sm" icon="world" onclick={() => act({ type: 'country', value: result.country_code, action: 'block', name: result.country_name }, `Blocking ${result.country_name || result.country_code}`)}>Block {result.country_name || result.country_code}</Button>{/if}
      </div>
      <Button variant="success" size="sm" icon="check" class="ml-auto" onclick={() => act({ type: 'ip', value: query, action: 'allow' }, `Allow-listed ${query}`)}>Allow-list</Button>
    </div>
  {/if}

  {#if recent.length}
    <div>
      <h2 class="text-xs uppercase tracking-wide text-muted-foreground font-semibold mb-2">Recent lookups</h2>
      <div class="bg-card border border-border rounded-xl divide-y divide-border">
        {#each recent as r}
          <button onclick={() => lookup(r.ip)} class="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-muted/40 text-sm">
            {#if r.country_code}<CountryFlag code={r.country_code} size="sm" />{/if}
            <span class="font-mono">{r.ip}</span>
            <span class="text-muted-foreground text-xs truncate">{r.as_name || ''}</span>
            {#if r.score != null}<span class="ml-auto text-xs font-mono {reputationMeta(r.level).text}">rep {r.score}</span>{/if}
          </button>
        {/each}
      </div>
    </div>
  {/if}
</div>
