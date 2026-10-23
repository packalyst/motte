<script>
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast, confirm, openView } from '../stores/app.js'
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import StatStrip from '../components/StatStrip.svelte'
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
  let shown = $state('')      // the IP the result belongs to (query can be edited after)
  let hits = $state(null)     // times this IP hit us (from logs)
  let error = $state('')
  let disabled = $state(false) // no lookup provider configured
  let busy = $state(false)
  let recent = $state([])     // [{ip, country_code, level}]

  const meta = $derived(reputationMeta(result?.reputation?.level))
  const LEVEL_TONE = { high: 'destructive', medium: 'warning', low: 'success' }

  function looksLikeIP(s) {
    return /^[0-9a-fA-F:.]+$/.test(s) && (s.includes('.') || s.includes(':'))
  }

  async function lookup(ip = query.trim()) {
    query = ip
    error = ''; disabled = false; result = null; hits = null
    if (!ip) return
    if (!looksLikeIP(ip)) { error = 'Enter a valid IPv4 or IPv6 address.'; return }
    busy = true
    try {
      if (!(await checkGeoEnabled())) { disabled = true; return }
      await lookupIPs([ip])
      const g = getGeoData(ip)
      if (!g) { error = 'No data for this IP.'; return }
      result = g; shown = ip
      recent = [{ ip, country_code: g.country_code, level: g.reputation?.level }, ...recent.filter(r => r.ip !== ip)].slice(0, 6)
      // Cross-reference: how many times this IP has hit us (best-effort).
      try { const l = await apiGet(`/api/logs?search=${encodeURIComponent(ip)}&limit=1`); hits = l?.total ?? null } catch { hits = null }
    } catch (e) {
      error = e?.message || 'Lookup failed.'
    } finally {
      busy = false
    }
  }

  async function act(entry, label) {
    const isBlock = entry.action === 'block'
    const target = entry.type === 'country' ? (entry.name || entry.value) : entry.type === 'asn' ? `AS${entry.value}` : entry.value
    const ok = await confirm({
      title: `${isBlock ? 'Block' : 'Allow'} ${target}`,
      message: `Add a firewall ${isBlock ? 'block' : 'allow'} rule for ${target}?`,
      confirmText: isBlock ? 'Block' : 'Allow',
      variant: isBlock ? 'destructive' : 'success',
    })
    if (!ok) return
    try {
      await apiPost('/api/fw/entries', { direction: 'inbound', ...entry })
      toast(label, 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // What kind of address this is; `on` = a flag worth a second look.
  const chips = $derived.by(() => {
    if (!result) return []
    const out = []
    if (result.is_proxy) out.push({ on: true, text: proxyTypeLabel(result.proxy_type) || 'Proxy / VPN' })
    const u = usageTypeLabel(result.usage_type)
    if (u) out.push({ on: /hosting|data|dch/i.test(u), text: u })
    if (result.threat && result.threat !== '-') out.push({ on: true, text: result.threat })
    if (out.length === 0) out.push({ on: false, text: 'No proxy or threat flags' })
    return out
  })

  const stats = $derived(result ? [
    { icon: 'shield-check', value: result.reputation ? result.reputation.score : '—', of: result.reputation ? 100 : undefined, label: 'Risk score', tone: LEVEL_TONE[result.reputation?.level] },
    { icon: 'activity', value: hits == null ? '—' : hits.toLocaleString(), label: 'Hits on this server', tone: hits ? 'info' : undefined },
    { icon: 'server', value: usageTypeLabel(result.usage_type) || '—', label: 'Network type' },
    { icon: 'alert-triangle', value: result.fraud_score ?? '—', of: result.fraud_score != null ? 100 : undefined, label: 'Fraud score',
      tone: result.fraud_score >= 75 ? 'destructive' : result.fraud_score >= 40 ? 'warning' : undefined },
  ] : [])

  // label · value rows for the two detail panels; empty values are left out
  const network = $derived(result ? [
    ['Owner', result.as_name],
    ['ASN', result.asn ? `AS${result.asn}` : ''],
    ['ISP', result.extra?.isp],
    ['Domain', result.extra?.domain],
    ['Data source', result.provider],
  ].filter(([, v]) => v) : [])
  const location = $derived(result ? [
    ['Country', result.country_name || result.country_code],
    ['City', result.extra?.city],
    ['Region', result.extra?.region],
    ['Timezone', result.extra?.timezone],
    ['Coordinates', result.extra?.latitude != null && result.extra?.longitude != null ? `${(+result.extra.latitude).toFixed(2)}, ${(+result.extra.longitude).toFixed(2)}` : ''],
  ].filter(([, v]) => v) : [])
</script>

{#snippet details(icon, title, sub, rows)}
  <div class="panel">
    <div class="panel-head">
      <span class="panel-icon"><Icon name={icon} size={17} /></span>
      <div class="min-w-0 flex-1">
        <div class="panel-title">{title}</div>
        <div class="panel-sub">{sub}</div>
      </div>
    </div>
    {#if rows.length}
      <dl class="divide-y divide-dashed divide-border text-sm">
        {#each rows as [k, v]}
          <div class="flex items-baseline justify-between gap-4 py-2 first:pt-0 last:pb-0">
            <dt class="shrink-0 text-xs text-muted-foreground">{k}</dt>
            <dd class="min-w-0 truncate text-right font-medium" title={v}>{v}</dd>
          </div>
        {/each}
      </dl>
    {:else}
      <div class="text-sm text-muted-foreground">Not reported by this data source.</div>
    {/if}
  </div>
{/snippet}

<div class="space-y-4">
  <!-- Search -->
  <div class="panel">
    <div class="panel-head">
      <span class="panel-icon text-primary"><Icon name="world-search" size={17} /></span>
      <div class="min-w-0 flex-1">
        <div class="panel-title">IP Lookup</div>
        <div class="panel-sub">owner · location · VPN and proxy flags · risk · hits on this server</div>
      </div>
    </div>
    <form class="flex gap-2" onsubmit={(e) => { e.preventDefault(); lookup() }}>
      <div class="flex min-w-0 flex-1 items-center gap-2 rounded-lg border border-input bg-background px-3 focus-within:border-ring focus-within:ring-2 focus-within:ring-ring/20">
        <Icon name="search" size={16} class="shrink-0 text-muted-foreground" />
        <input bind:value={query} aria-label="IP address" placeholder="IPv4 or IPv6, e.g. 203.0.113.7" autocomplete="off" spellcheck="false"
          class="h-10 min-w-0 flex-1 bg-transparent font-mono text-sm outline-none placeholder:font-sans" />
      </div>
      <Button type="submit" variant="primary" icon="search" loading={busy} class="h-10">Look up</Button>
    </form>
    {#if recent.length}
      <div class="mt-3 flex flex-wrap items-center gap-1.5">
        <span class="mr-1 text-[11px] text-muted-foreground">Recent</span>
        {#each recent as r (r.ip)}
          <button type="button" onclick={() => lookup(r.ip)}
            class="inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-1 font-mono text-[11px] transition-colors hover:bg-muted cursor-pointer {r.ip === shown && result ? 'bg-muted' : ''}">
            <span class="h-1.5 w-1.5 rounded-full {reputationMeta(r.level).dot}"></span>
            {#if r.country_code}<CountryFlag code={r.country_code} size="sm" />{/if}{r.ip}
          </button>
        {/each}
      </div>
    {/if}
  </div>

  {#if disabled}
    <div class="panel flex flex-wrap items-center gap-3">
      <span class="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-warning/10 text-warning"><Icon name="world-off" size={17} /></span>
      <div class="min-w-0 flex-1">
        <div class="text-sm font-medium">IP lookup is off</div>
        <div class="text-xs text-muted-foreground">Choose a lookup provider (IP2Location or MaxMind) in Settings → Web → Geolocation.</div>
      </div>
      <button type="button" class="link-action" onclick={() => openView('settings', 's=web')}>Open settings<Icon name="arrow-right" size={12} /></button>
    </div>
  {:else if error}
    <div class="flex items-center gap-2 rounded-xl border border-warning/30 bg-warning/10 p-3 text-sm text-warning"><Icon name="alert-triangle" size={15} />{error}</div>
  {/if}

  {#if result}
    <!-- Verdict: the address, what it is, and what you can do about it -->
    <div class="panel">
      <div class="flex flex-wrap items-start gap-4">
        <span class="grid h-12 w-12 shrink-0 place-items-center rounded-xl border {meta.ring} {meta.text}">
          <Icon name={result.reputation?.level === 'low' ? 'shield-check' : result.reputation?.level ? 'alert-triangle' : 'help-circle'} size={22} />
        </span>
        <div class="min-w-0 flex-1">
          <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
            <h2 class="truncate font-mono text-lg font-semibold">{shown}</h2>
            <span class="text-sm font-semibold {meta.text}">{meta.label}</span>
          </div>
          <div class="mt-0.5 flex flex-wrap items-center gap-x-1.5 text-xs text-muted-foreground">
            {#if result.country_code}<CountryFlag code={result.country_code} size="sm" />{/if}
            <span>{[result.extra?.city, result.country_name || result.country_code].filter(Boolean).join(', ') || 'Unknown location'}</span>
            {#if result.as_name}<span>· {result.as_name}</span>{/if}
          </div>
          <div class="mt-3 flex flex-wrap gap-1.5">
            {#each chips as c}
              <span class="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium {c.on ? 'bg-destructive/10 text-destructive' : 'bg-success/10 text-success'}">
                <Icon name={c.on ? 'alert-triangle' : 'check'} size={12} />{c.text}
              </span>
            {/each}
          </div>
        </div>
      </div>
      {#if result.reputation?.reasons?.length}
        <div class="panel-note">Why: {result.reputation.reasons.join(' · ')}</div>
      {/if}
      <div class="panel-foot">
        <span class="mr-1 text-[11px] text-muted-foreground">Firewall</span>
        <Button variant="destructive" size="sm" icon="ban" onclick={() => act({ type: 'ip', value: shown, action: 'block' }, `Blocked ${shown}`)}>Block IP</Button>
        {#if result.asn}<Button variant="outline" size="sm" icon="network" onclick={() => act({ type: 'asn', value: String(result.asn), action: 'block', name: result.as_name }, `Blocking AS${result.asn}`)}>Block AS{result.asn}</Button>{/if}
        {#if result.country_code}<Button variant="outline" size="sm" icon="world" onclick={() => act({ type: 'country', value: result.country_code, action: 'block', name: result.country_name }, `Blocking ${result.country_name || result.country_code}`)}>Block {result.country_name || result.country_code}</Button>{/if}
        <Button variant="success" size="sm" icon="check" class="ml-auto" onclick={() => act({ type: 'ip', value: shown, action: 'allow' }, `Allow-listed ${shown}`)}>Always allow</Button>
      </div>
    </div>

    <StatStrip label="Lookup summary" items={stats} />

    <div class="grid gap-4 lg:grid-cols-2 lg:items-start">
      {@render details('network', 'Network', 'who owns and runs this address', network)}
      {@render details('map-pin', 'Location', 'where the address is registered', location)}
    </div>
  {:else if !busy && !error && !disabled}
    <div class="panel grid place-items-center py-10 text-center">
      <span class="mb-3 grid h-11 w-11 place-items-center rounded-xl bg-muted text-muted-foreground"><Icon name="world-search" size={20} /></span>
      <div class="text-sm font-medium">Paste an address from your logs</div>
      <div class="mt-1 max-w-sm text-xs text-muted-foreground">See who owns it, where it is, whether it's a VPN, proxy or data center, how risky it looks and how often it has hit this server. Then block or allow it in one click.</div>
    </div>
  {/if}
</div>
