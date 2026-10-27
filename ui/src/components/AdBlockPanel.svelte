<script>
  /**
   * AdBlockPanel — one client's AdGuard ad & tracker blocking: the switch, domains allowed just for
   * this client, and its recently blocked lookups with an Allow button. Admin only (the blocked list
   * is browsing history); the server enforces it, resolves the client's address itself and audits
   * every change. Shared by the VPN client modal and the LAN device modal.
   */
  import { apiGet, apiPut, apiPost, apiDelete, toast } from '../stores/app.js'
  import { timeAgo } from '$lib/utils/format.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Input from './Input.svelte'
  import Checkbox from './Checkbox.svelte'
  import Skeleton from './Skeleton.svelte'

  let { clientKey } = $props()

  let data = $state(null) // { state, blocked, allowed, ip }
  let error = $state('')
  let busy = $state(false)
  let domain = $state('')

  const base = () => `/api/clients/${encodeURIComponent(clientKey)}/adblock`
  async function load() {
    error = ''
    try {
      data = await apiGet(base())
    } catch (e) {
      data = null
      error = e.message
    }
  }
  $effect(() => {
    clientKey
    load()
  })

  async function act(fn, done) {
    busy = true
    try {
      await fn()
      if (done) toast(done, 'success')
      await load()
    } catch (e) {
      toast(e.message, 'error')
    } finally {
      busy = false
    }
  }
  const setBlocking = (on) => act(() => apiPut(base(), { blocking: on }), on ? 'Ad blocking on' : 'Ad blocking off')
  const allow = (d) => act(() => apiPost(base() + '/allow', { domain: d }), `${d} allowed`)
  const disallow = (d) => act(() => apiDelete(base() + '/allow?domain=' + encodeURIComponent(d)), `${d} is blocked again`)
  function allowTyped() {
    const d = domain.trim()
    if (d) allow(d).then(() => (domain = ''))
  }

  const REASONS = {
    FilteredBlackList: 'Blocklist',
    FilteredBlockedService: 'Blocked service',
    FilteredSafeBrowsing: 'Safe browsing',
    FilteredParental: 'Parental control',
    FilteredSafeSearch: 'Safe search',
  }
  const st = $derived(data?.state)
</script>

{#if error}
  <div class="flex items-start gap-2.5 rounded-lg border border-border p-3 text-sm text-muted-foreground">
    <Icon name="alert-triangle" size={16} class="mt-0.5 shrink-0 text-warning" />{error}
  </div>
{:else if !data}
  <!-- the panel's shape while it loads, so it doesn't jump when the data lands -->
  <div class="space-y-4" aria-busy="true" aria-label="Loading ad blocking">
    <div class="flex items-start justify-between gap-3 rounded-lg border border-border p-3">
      <div class="flex-1 space-y-2"><Skeleton class="h-4 w-48" /><Skeleton class="h-3 w-full" /><Skeleton class="h-3 w-24" /></div>
      <Skeleton class="h-5 w-9 rounded-full" />
    </div>
    <div class="space-y-2"><Skeleton class="h-2.5 w-40" /><Skeleton class="h-3 w-12" /><Skeleton class="h-control w-full" /></div>
    <div class="space-y-2">
      <Skeleton class="h-2.5 w-28" />
      <div class="divide-y divide-border rounded-lg border border-border">
        {#each [0, 1, 2, 3] as _}
          <div class="space-y-1.5 px-3 py-2.5"><Skeleton class="h-3 w-1/2" /><Skeleton class="h-2.5 w-1/4" /></div>
        {/each}
      </div>
      <Skeleton class="h-3 w-64" />
    </div>
  </div>
{:else}
  <div class="space-y-4">
    <div class="flex items-start justify-between gap-3 rounded-lg border border-border p-3">
      <div class="min-w-0">
        <div class="flex items-center gap-1.5 text-sm font-medium text-foreground">
          <Icon name={st.blocking ? 'shield-check' : 'shield-off'} size={15} class={st.blocking ? 'text-success' : 'text-warning'} />Ad & tracker blocking
        </div>
        <p class="mt-0.5 text-[11px] text-muted-foreground">
          {#if st.managed_elsewhere}
            AdGuard has its own client entry “{st.managed_elsewhere}” for {data.ip}. Change it in AdGuard.
          {:else if st.global_off}
            Filtering is turned off in AdGuard for everyone, so nothing is blocked right now.
          {:else}
            Blocks ads and trackers for this client using your AdGuard blocklists. Safe browsing and other protections stay as set in AdGuard.
          {/if}
        </p>
      </div>
      <Checkbox variant="switch" checked={st.blocking} disabled={busy || !!st.managed_elsewhere || st.global_off}
        onchange={() => setBlocking(!st.blocking)} aria-label="Ad and tracker blocking" />
    </div>

    <div>
      <div class="mb-2 text-[10px] uppercase tracking-wide text-muted-foreground">Always allowed for this client</div>
      <div class="flex flex-wrap items-center gap-1.5">
        {#each data.allowed as d (d)}
          <span class="inline-flex items-center gap-1 rounded-md bg-success/10 py-0.5 pl-2 pr-1 font-mono text-[11px] text-success">
            {d}
            <button type="button" onclick={() => disallow(d)} disabled={busy} aria-label="Block {d} again"
              class="grid h-4 w-4 cursor-pointer place-items-center rounded hover:bg-success/20"><Icon name="x" size={11} /></button>
          </span>
        {:else}
          <span class="text-[11px] text-muted-foreground">None.</span>
        {/each}
      </div>
      <form class="mt-2 flex gap-2" onsubmit={(e) => { e.preventDefault(); allowTyped() }}>
        <div class="min-w-0 flex-1"><Input bind:value={domain} placeholder="e.g. ads.example.com" prefixIcon="world" class="font-mono" /></div>
        <Button type="submit" variant="outline" icon="check" disabled={busy || !domain.trim()}>Allow</Button>
      </form>
    </div>

    <div>
      <div class="mb-2 flex items-center justify-between">
        <span class="text-[10px] uppercase tracking-wide text-muted-foreground">Recently blocked</span>
        <Button variant="ghost" size="xs" iconOnly icon="refresh" onclick={load} tooltip="Refresh" />
      </div>
      {#if data.blocked.length}
        <div class="max-h-64 divide-y divide-border overflow-y-auto rounded-lg border border-border">
          {#each data.blocked as b (b.domain)}
            {@const allowed = data.allowed.includes(b.domain)}
            <div class="flex items-center gap-3 px-3 py-2">
              <div class="min-w-0 flex-1">
                <div class="truncate font-mono text-xs text-foreground">{b.domain}</div>
                <div class="truncate text-[11px] text-muted-foreground">{timeAgo(b.time)} · {REASONS[b.reason] || b.reason}</div>
              </div>
              {#if allowed}
                <span class="inline-flex items-center gap-1 text-[11px] text-success"><Icon name="check" size={12} />allowed</span>
              {:else}
                <Button variant="ghost" size="xs" icon="check" disabled={busy} onclick={() => allow(b.domain)}>Allow</Button>
              {/if}
            </div>
          {/each}
        </div>
      {:else}
        <p class="text-[11px] text-muted-foreground">Nothing blocked for this client recently.</p>
      {/if}
      <p class="mt-2 text-[11px] text-muted-foreground">Allowing a domain affects only this client. Every change is logged.</p>
    </div>
  </div>
{/if}
