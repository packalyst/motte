<script>
  /**
   * BlockRules — the DNS page's custom rules: block or allow a domain for every device using this
   * DNS. AdGuard keeps them in one list together with the panel's per-client exceptions (set on a
   * client's page) and any rule written by hand in AdGuard; those are shown, locked, and never
   * changed here. Rules are added and removed one at a time, so nothing else in the list is lost.
   */
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPut, confirm } from '../stores/app.js'
  import { clientsList, watchClients, openClient } from '../lib/clients.js'
  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import Button from './Button.svelte'
  import Input from './Input.svelte'
  import Segmented from './Segmented.svelte'
  import Select from './Select.svelte'
  import Modal from './Modal.svelte'
  import EmptyState from './EmptyState.svelte'
  import LoadingSpinner from './LoadingSpinner.svelte'

  // The panel's client exceptions: a marker line naming the client, then its rule (see the API's
  // adguard allowMarker / allowRule).
  const PANEL_MARKER = '! motte-managed allow '
  const PANEL_RULE = /^@@\|\|([^^]+)\^\$client='([^']+)'$/
  // A rule this page manages: a plain hostname, blocked (||d^) or allowed (@@||d^) for everyone.
  const PLAIN = /^(@@)?\|\|((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\^$/

  const VIEWS = [
    { value: 'all', label: 'All' },
    { value: 'block', label: 'Blocked', tone: 'destructive' },
    { value: 'allow', label: 'Allowed', tone: 'success' },
  ]
  const EXAMPLES = [
    ['Block', 'ads.example.com', 'that name and every name under it'],
    ['Allow', 'cdn.example.com', 'let it through even when a blocklist has it'],
  ]

  let userRules = $state([])
  let loaded = $state(false)
  let view = $state('all')
  let search = $state('')
  let busyKey = $state('')

  let formOpen = $state(false)
  let formDomain = $state('')
  let formKind = $state('block') // block | allow
  const formAllow = $derived(formKind === 'allow')
  let saving = $state(false)

  const clientByKey = $derived(new Map($clientsList.clients.map((c) => [c.key, c])))

  // One row per rule: block / allow (ours), client (the panel's exception), advanced (by hand).
  const rows = $derived.by(() => {
    const out = []
    for (let i = 0; i < userRules.length; i++) {
      const line = userRules[i].trim()
      if (line.startsWith(PANEL_MARKER)) {
        const m = (userRules[i + 1] || '').match(PANEL_RULE)
        if (m) {
          out.push({ kind: 'client', domain: m[1], ip: m[2], clientKey: line.slice(PANEL_MARKER.length) })
          i++
        }
        continue
      }
      if (!line || line.startsWith('!') || line.startsWith('#')) continue // comments
      const m = line.match(PLAIN)
      if (m) out.push({ kind: m[1] ? 'allow' : 'block', domain: m[2] })
      else out.push({ kind: 'advanced', domain: line })
    }
    return out
  })

  const counts = $derived({
    block: rows.filter((r) => r.kind === 'block').length,
    allow: rows.filter((r) => r.kind === 'allow' || r.kind === 'client').length,
  })

  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase()
    return rows
      .filter((r) => view === 'all' || (view === 'block' ? r.kind === 'block' : r.kind === 'allow' || r.kind === 'client'))
      .filter((r) => !q || r.domain.toLowerCase().includes(q) || (r.kind === 'client' && clientName(r).toLowerCase().includes(q)))
      .sort((a, b) => a.domain.localeCompare(b.domain))
  })

  const formClean = $derived(formDomain.trim().toLowerCase().replace(/\.$/, ''))
  const duplicate = $derived(rows.some((r) => r.kind === (formAllow ? 'allow' : 'block') && r.domain === formClean))
  const opposite = $derived(!duplicate && rows.some((r) => r.kind === (formAllow ? 'block' : 'allow') && r.domain === formClean))

  const keyOf = (r) => r.kind + ' ' + r.domain + ' ' + (r.clientKey || '')
  function clientName(r) {
    return clientByKey.get(r.clientKey)?.name || r.ip
  }

  async function load() {
    try {
      const res = await apiGet('/api/adguard/filtering')
      userRules = res?.user_rules || []
    } catch (e) {
      toast('Failed to load rules: ' + e.message, 'error')
    } finally {
      loaded = true
    }
  }

  function openForm() {
    formDomain = ''
    formKind = view === 'allow' ? 'allow' : 'block'
    formOpen = true
  }

  async function save() {
    if (duplicate) return toast('That rule already exists', 'error')
    saving = true
    try {
      await apiPut('/api/adguard/filtering', { action: 'addRule', domain: formDomain, allow: formAllow })
      toast(formAllow ? 'Domain allowed' : 'Domain blocked', 'success')
      formOpen = false
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      saving = false
    }
  }

  async function remove(r) {
    const allow = r.kind === 'allow'
    const ok = await confirm({
      title: allow ? 'Remove allow rule' : 'Unblock domain',
      message: `${allow ? 'Stop allowing' : 'Unblock'} ${r.domain}?`,
      description: allow ? 'Blocklists apply to it again.' : 'Devices can reach it again, unless a blocklist has it.',
      confirmText: allow ? 'Remove' : 'Unblock',
    })
    if (!ok) return
    busyKey = keyOf(r)
    try {
      await apiPut('/api/adguard/filtering', { action: 'removeRule', domain: r.domain, allow })
      toast(allow ? 'Allow rule removed' : 'Domain unblocked', 'success')
      await load()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      busyKey = ''
    }
  }

  onMount(() => {
    load()
    return watchClients() // client names for the panel's exceptions
  })
</script>

{#if !loaded}
  <LoadingSpinner size="lg" centered />
{:else}
  <div class="data-table">
    <div class="data-table-header">
      <div class="data-table-header-start">
        <Segmented size="sm" label="Rule type" stretch bind:value={view}
          options={VIEWS.map((v) => ({ ...v, label: v.value === 'all' ? v.label : `${v.label} ${counts[v.value]}` }))} />
        <!-- search and add share a line, on a phone too -->
        <div class="flex flex-1 items-center gap-2">
          <Input type="search" bind:value={search} placeholder="Search domain or client..." prefixIcon="search" class="min-w-0 flex-1 sm:max-w-64 sm:flex-none" />
          <Button icon="plus" class="ml-auto shrink-0" onclick={openForm}>Add rule</Button>
        </div>
      </div>
    </div>

    {#if rows.length === 0}
      <div class="p-6">
        <EmptyState icon="ban" title="No custom rules" description="Block a domain for every device on this DNS, or allow one that a blocklist catches." />
      </div>
    {:else if shown.length === 0}
      <p class="p-6 text-center text-xs text-muted-foreground">No rule matches.</p>
    {:else}
      <div class="data-table-content">
        <!-- table-stack: each rule is a compact card on a phone -->
        <table class="table-stack">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Rule</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each shown as r (keyOf(r))}
              {@const busy = busyKey === keyOf(r)}
              <tr class={busy ? 'pointer-events-none opacity-50' : ''}>
                <td class="stack-main">
                  <div class="flex min-w-0 items-center gap-2">
                    {#if r.kind === 'block'}
                      <Icon name="ban" size={14} class="shrink-0 text-destructive" />
                    {:else if r.kind === 'advanced'}
                      <Icon name="code" size={14} class="shrink-0 text-muted-foreground" />
                    {:else}
                      <Icon name="check" size={14} class="shrink-0 text-success" />
                    {/if}
                    <span class="truncate font-mono text-xs text-foreground" title={r.domain}>{r.domain}</span>
                  </div>
                </td>
                <td class="data-table-cell-nowrap">
                  {#if r.kind === 'block'}
                    <Badge variant="destructive" size="sm">Blocked</Badge>
                  {:else if r.kind === 'allow'}
                    <Badge variant="success" size="sm">Allowed</Badge>
                  {:else if r.kind === 'client'}
                    <Badge variant="success" size="sm" title={r.ip}><Icon name="user" size={10} class="mr-1" />Allowed for {clientName(r)}</Badge>
                  {:else}
                    <Badge variant="muted" size="sm" title="Written in AdGuard — change it there">Advanced rule</Badge>
                  {/if}
                </td>
                <td class="data-table-cell-actions stack-end">
                  {#if r.kind === 'client'}
                    {@const c = clientByKey.get(r.clientKey)}
                    {#if c}<Button variant="ghost" size="xs" icon="external-link" onclick={() => openClient(c)} title="Set on the client's page">Client</Button>{/if}
                  {:else if r.kind === 'advanced'}
                    <span class="inline-flex p-1.5 text-muted-foreground" title="Written in AdGuard — change it there"><Icon name="lock" size={14} /></span>
                  {:else}
                    <Button variant="outline" size="xs" icon="trash" class="text-destructive hover:bg-destructive/10" tooltip={r.kind === 'allow' ? 'Remove allow rule' : 'Unblock'} aria-label="Remove rule for {r.domain}" onclick={() => remove(r)} />
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
{/if}

<Modal bind:open={formOpen} title="Add rule" size="md">
  <div class="space-y-4">
    <!-- the rule: a Block / Allow switch on a phone, a select beside the domain from sm up -->
    <Segmented label="Rule" stretch bind:value={formKind} class="sm:hidden"
      options={[{ value: 'block', label: 'Block', tone: 'destructive' }, { value: 'allow', label: 'Allow', tone: 'success' }]} />
    <div class="grid gap-4 sm:grid-cols-[8rem_1fr] sm:gap-2">
    <div class="hidden sm:block">
      <Select label="Rule" bind:value={formKind} options={[{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }]} />
    </div>
    <Input label="Domain" bind:value={formDomain} placeholder="ads.example.com" prefixIcon="world"
      hint="A plain domain name: the rule covers it and every name under it"
      onkeydown={(e) => e.key === 'Enter' && save()} />
    </div>
    {#if duplicate}
      <p class="flex items-center gap-1.5 text-xs text-destructive"><Icon name="alert-triangle" size={14} />This rule already exists.</p>
    {:else if opposite}
      <p class="flex items-center gap-1.5 text-xs text-warning"><Icon name="info-circle" size={14} />{formClean} is already {formAllow ? 'blocked' : 'allowed'} — an allow rule wins over a block.</p>
    {/if}
    <div class="rounded-lg border border-dashed border-border p-3 text-xs text-muted-foreground">
      <div class="mb-1.5 font-medium text-foreground">Examples</div>
      <ul class="space-y-1.5">
        {#each EXAMPLES as [kind, domain, what]}
          <li class="flex flex-wrap items-baseline justify-between gap-x-3">
            <span><span class={kind === 'Block' ? 'text-destructive' : 'text-success'}>{kind}</span> <span class="font-mono text-foreground">{domain}</span></span>
            <span>{what}</span>
          </li>
        {/each}
      </ul>
    </div>
  </div>
  {#snippet footer()}
    <Button variant="secondary" onclick={() => (formOpen = false)}>Cancel</Button>
    <Button onclick={save} loading={saving} disabled={!formDomain.trim() || duplicate}>{formAllow ? 'Allow domain' : 'Block domain'}</Button>
  {/snippet}
</Modal>
