<script>
  /**
   * Certificates — every certificate the panel depends on (Settings → Certificates): the websites'
   * Let's Encrypt certificates, the fleet CA, the agent listener's certificate and the machines'
   * client certificates, with what needs attention. The server decides each one's warning state
   * (due: key → days step, 0 = expired); admin-only there. onload(overview) lets the page show the
   * attention count in its menu.
   */
  import { onMount } from 'svelte'
  import { apiGet, apiPost, toast, openView } from '../stores/app.js'
  import { formatDate, formatExpiryDate, timeAgo } from '../lib/utils/format.js'
  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import Button from './Button.svelte'

  let { onload = undefined } = $props()

  let o = $state(null)
  let renewing = $state(false)

  function show(next) {
    o = next
    onload?.(next)
  }

  async function load() {
    try {
      show(await apiGet('/api/certs'))
    } catch (e) {
      toast('Failed to load certificates: ' + e.message, 'error')
    }
  }
  onMount(load)

  async function renewListener() {
    renewing = true
    try {
      show(await apiPost('/api/certs/listener/renew', {}))
      toast('Agent listener certificate renewed', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      renewing = false
    }
  }

  function dueState(key) {
    const step = o?.due?.[key]
    if (step === 0) return { label: 'Expired', variant: 'destructive' }
    if (step !== undefined) return { label: 'Expires soon', variant: 'warning' }
    return { label: 'OK', variant: 'success' }
  }
  function websiteState(w) {
    if (w.status === 'missing') return { label: 'No certificate', variant: 'warning' }
    const s = dueState('web:' + w.domain)
    return w.problem && s.variant === 'success' ? { label: "Can't renew", variant: 'destructive' } : s
  }
  const expiry = (t) => `${formatExpiryDate(t)} · ${formatDate(t)}`
  const shortFp = (fp) => (fp || '').replace('sha256:', '').slice(0, 16)

  const fleet = $derived(o?.fleet)
  const agentsDue = $derived((fleet?.agents || []).filter((a) => o.due['agent:' + a.machineId] !== undefined))
</script>

{#snippet row(icon, title, sub, state)}
  <div class="flex min-w-0 items-start gap-2.5">
    <span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-muted text-muted-foreground"><Icon name={icon} size={16} /></span>
    <div class="min-w-0">
      <div class="text-sm font-medium text-foreground break-all">{title}</div>
      <div class="text-[11px] text-muted-foreground">{sub}</div>
    </div>
  </div>
  {#if state}<Badge variant={state.variant} size="sm">{state.label}</Badge>{/if}
{/snippet}

<div class="panel">
  <div class="panel-head">
    <span class="panel-icon text-primary"><Icon name="world-www" size={17} /></span>
    <div class="min-w-0 flex-1">
      <div class="panel-title">Websites</div>
      <div class="panel-sub">Let's Encrypt certificates Traefik serves</div>
    </div>
  </div>
  {#if !o}
    <p class="text-xs text-muted-foreground">Loading…</p>
  {:else if o.websites.length === 0}
    <p class="text-xs text-muted-foreground">No website certificates yet.</p>
  {:else}
    <ul class="divide-y divide-border">
      {#each o.websites as w (w.domain)}
        <li class="py-2.5">
          <div class="flex items-start justify-between gap-3">
            {@render row('certificate', w.domain + (w.role === 'panel' ? ' (panel)' : w.role === 'proxy' ? ' (proxy)' : ''),
              (w.notAfter ? expiry(w.notAfter) : 'Not issued') + (w.resolver ? ' · ' + (w.resolver.includes('dns') ? 'DNS check' : 'HTTP check') : ''),
              websiteState(w))}
          </div>
          {#if w.problem}
            <p class="mt-1.5 flex items-start gap-1.5 pl-10 text-[11px] text-warning">
              <Icon name="alert-triangle" size={13} class="mt-0.5 shrink-0" /><span>{w.problem}</span>
            </p>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
  <div class="panel-foot">
    <p class="flex items-start gap-1.5 text-[11px] text-muted-foreground">
      <Icon name="info-circle" size={13} class="mt-0.5 shrink-0" />Traefik renews these by itself about 30 days before they expire. Admins are notified if one gets close to expiry without renewing.
    </p>
  </div>
</div>

{#if fleet}
  <div class="panel">
    <div class="panel-head">
      <span class="panel-icon text-primary"><Icon name="shield-lock" size={17} /></span>
      <div class="min-w-0 flex-1">
        <div class="panel-title">Agents</div>
        <div class="panel-sub">the panel's own certificates for the connection with machine agents</div>
      </div>
    </div>
    <ul class="divide-y divide-border">
      <li class="flex items-start justify-between gap-3 py-2.5">
        {@render row('key', 'Fleet CA', `${expiry(fleet.ca.notAfter)} · ${shortFp(fleet.ca.fingerprint)}`, dueState('fleet-ca'))}
      </li>
      <li class="py-2.5">
        <div class="flex items-start justify-between gap-3">
          {#if fleet.listener}
            {@render row('plug-connected', 'Agent listener', `${expiry(fleet.listener.notAfter)} · renews by itself`, dueState('fleet-listener'))}
          {:else}
            {@render row('plug-connected', 'Agent listener', 'Off: no certificate in use', null)}
          {/if}
        </div>
        {#if fleet.listener}
          <div class="mt-1.5 flex flex-wrap items-center justify-between gap-2 pl-10">
            <span class="text-[11px] text-muted-foreground break-all">Valid for {fleet.listener.hosts?.join(', ')}</span>
            <Button variant="outline" size="sm" icon="refresh" loading={renewing} onclick={renewListener}>Renew now</Button>
          </div>
        {/if}
      </li>
      <li class="py-2.5">
        <div class="flex items-start justify-between gap-3">
          {@render row('device-desktop', 'Machine certificates',
            `${fleet.agents.length} enrolled · each lasts ${fleet.agentLifetimeDays} days and renews itself`,
            agentsDue.length ? { label: `${agentsDue.length} need attention`, variant: 'warning' } : { label: 'OK', variant: 'success' })}
        </div>
        {#if agentsDue.length}
          <ul class="mt-1.5 space-y-1 pl-10">
            {#each agentsDue as a (a.machineId)}
              {@const s = dueState('agent:' + a.machineId)}
              <li class="flex flex-wrap items-center gap-x-2 text-[11px]">
                <button type="button" class="link-action" onclick={() => openView('clients', 'm=' + encodeURIComponent(a.machineId))}>{a.name}</button>
                <span class={s.variant === 'destructive' ? 'text-destructive' : 'text-warning'}>{formatExpiryDate(a.notAfter)}</span>
                <span class="text-muted-foreground">· last seen {timeAgo(a.lastSeen)}</span>
              </li>
            {/each}
          </ul>
        {/if}
      </li>
    </ul>
    <div class="panel-foot">
      <p class="flex items-start gap-1.5 text-[11px] text-muted-foreground">
        <Icon name="info-circle" size={13} class="mt-0.5 shrink-0" />Agents trust only the fleet CA. A machine renews its certificate while it's online; one offline until its certificate expires must be re-enrolled.
      </p>
    </div>
  </div>
{/if}
