<script>
  /**
   * DnsRewrites — the DNS page's rewrites tab: answer a name with an address (or another name)
   * for every device using this DNS. Rewrites that Domain Routes keeps for its VPN-only domains
   * are shown but locked here: they're managed (and re-synced) from Domain Routes.
   */
  import { onMount } from 'svelte'
  import { toast, apiGet, apiPut, confirm, currentView } from '../stores/app.js'
  import { isValidHost, rewriteKind } from '../lib/utils/net.js'
  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import Button from './Button.svelte'
  import DropdownButton from './DropdownButton.svelte'
  import Input from './Input.svelte'
  import Checkbox from './Checkbox.svelte'
  import Modal from './Modal.svelte'
  import EmptyState from './EmptyState.svelte'
  import LoadingSpinner from './LoadingSpinner.svelte'

  let rewrites = $state([])
  let routeDomains = $state(new Set()) // VPN-only Domain Routes: their rewrites are managed there
  let loaded = $state(false)
  let search = $state('')
  let busyKey = $state('')

  // add / edit window: `editing` is the rewrite being changed (null when adding)
  let formOpen = $state(false)
  let editing = $state(null)
  let formDomain = $state('')
  let formAnswer = $state('')
  let saving = $state(false)

  const EXAMPLES = [
    ['nas.home', '10.8.0.50', 'a device on the VPN by name'],
    ['*.lab.home', '10.8.0.60', 'every name under lab.home'],
    ['tv.home', 'nas.home', 'an alias of another name'],
  ]

  const keyOf = (r) => r.domain + '\u0000' + r.answer
  const managed = (r) => routeDomains.has(r.domain)

  const shown = $derived.by(() => {
    const q = search.trim().toLowerCase()
    return rewrites
      .filter((r) => !q || r.domain.toLowerCase().includes(q) || r.answer.toLowerCase().includes(q))
      .sort((a, b) => a.domain.localeCompare(b.domain))
  })

  // Same name and answer already there (ignoring the one being edited): AdGuard would refuse it.
  const duplicate = $derived(rewrites.some((r) => r !== editing && r.domain === formDomain.trim() && r.answer === formAnswer.trim()))
  // Same name, another answer: allowed — AdGuard answers with all of them.
  const sibling = $derived(!duplicate && rewrites.some((r) => r !== editing && r.domain === formDomain.trim()))

  async function load() {
    try {
      const [list, domains] = await Promise.all([
        apiGet('/api/adguard/rewrites'),
        apiGet('/api/domains').catch(() => ({ routes: [] })),
      ])
      rewrites = (list || []).map((r) => ({ ...r, enabled: r.enabled !== false }))
      routeDomains = new Set((domains?.routes || []).filter((d) => d.accessMode !== 'public').map((d) => d.domain))
    } catch (e) {
      toast('Failed to load rewrites: ' + e.message, 'error')
    } finally {
      loaded = true
    }
  }

  function openForm(r = null) {
    editing = r
    formDomain = r?.domain || ''
    formAnswer = r?.answer || ''
    formOpen = true
  }

  async function save() {
    const domain = formDomain.trim()
    const answer = formAnswer.trim()
    if (!isValidHost(domain)) return toast('Enter a domain, e.g. nas.home or *.lab.home', 'error')
    if (!isValidHost(answer)) return toast('Answer with an IP address or another domain', 'error')
    if (duplicate) return toast('That rewrite already exists', 'error')
    saving = true
    try {
      if (editing) {
        await apiPut('/api/adguard/rewrites', { action: 'update', target: { domain: editing.domain, answer: editing.answer }, domain, answer, enabled: editing.enabled })
        rewrites = rewrites.map((r) => (r === editing ? { ...r, domain, answer } : r))
        toast('Rewrite updated', 'success')
      } else {
        await apiPut('/api/adguard/rewrites', { action: 'add', domain, answer })
        rewrites = [...rewrites, { domain, answer, enabled: true }]
        toast('Rewrite added', 'success')
      }
      formOpen = false
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      saving = false
    }
  }

  // el: the switch's input — put back by hand if AdGuard refuses (the prop alone wouldn't change)
  async function setEnabled(r, el) {
    const enabled = el.checked
    busyKey = keyOf(r)
    try {
      await apiPut('/api/adguard/rewrites', { action: 'update', target: { domain: r.domain, answer: r.answer }, domain: r.domain, answer: r.answer, enabled })
      rewrites = rewrites.map((x) => (x === r ? { ...x, enabled } : x))
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
      el.checked = !enabled
    } finally {
      busyKey = ''
    }
  }

  async function remove(r) {
    const ok = await confirm({
      title: 'Delete rewrite',
      message: `Delete ${r.domain} → ${r.answer}?`,
      description: 'Devices get the normal DNS answer for this name again.',
      confirmText: 'Delete',
    })
    if (!ok) return
    busyKey = keyOf(r)
    try {
      await apiPut('/api/adguard/rewrites', { action: 'delete', domain: r.domain, answer: r.answer })
      rewrites = rewrites.filter((x) => x !== r)
      toast('Rewrite deleted', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    } finally {
      busyKey = ''
    }
  }

  onMount(load)
</script>

{#if !loaded}
  <LoadingSpinner size="lg" centered />
{:else}
  <div class="data-table">
    <div class="data-table-header">
      <div class="data-table-header-start">
        <Input type="search" bind:value={search} placeholder="Search domain or answer..." prefixIcon="search" class="sm:w-72" />
      </div>
      <div class="flex items-center justify-between gap-2 sm:justify-end">
        <span class="text-xs text-muted-foreground">{rewrites.length} rewrite{rewrites.length === 1 ? '' : 's'}</span>
        <Button icon="plus" onclick={() => openForm()}>Add rewrite</Button>
      </div>
    </div>

    {#if rewrites.length === 0}
      <div class="p-6">
        <EmptyState icon="link" title="No DNS rewrites" description="Give a device a name: answer nas.home with 10.8.0.50 for everyone on this DNS." />
      </div>
    {:else if shown.length === 0}
      <p class="p-6 text-center text-xs text-muted-foreground">No rewrite matches “{search}”.</p>
    {:else}
      <div class="data-table-content">
        <!-- table-stack: each rewrite is a compact card on a phone -->
        <table class="table-stack">
          <thead>
            <tr>
              <th>Rewrite</th>
              <th>Answers with</th>
              <th>On</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each shown as r (keyOf(r))}
              {@const kind = rewriteKind(r.answer)}
              {@const locked = managed(r)}
              {@const busy = busyKey === keyOf(r)}
              <tr class="{r.enabled ? '' : 'opacity-60'} {busy ? 'pointer-events-none opacity-50' : ''}">
                <td class="stack-main">
                  <div class="flex min-w-0 items-center gap-1.5">
                    <Icon name="world" size={14} class="shrink-0 text-muted-foreground" />
                    <span class="truncate font-mono text-xs font-medium text-foreground">{r.domain}</span>
                    {#if r.domain.startsWith('*.')}<Badge variant="warning" size="sm">Wildcard</Badge>{/if}
                  </div>
                  <div class="mt-0.5 flex min-w-0 items-center gap-1.5 pl-5">
                    <Icon name="corner-down-right" size={12} class="shrink-0 text-muted-foreground" />
                    <span class="truncate font-mono text-xs text-primary">{r.answer}</span>
                  </div>
                </td>
                <td class="data-table-cell-nowrap">
                  <div class="flex items-center gap-1">
                    <Badge variant={kind.variant} size="sm">{kind.label}</Badge>
                    {#if locked}<Badge variant="primary" size="sm"><Icon name="route" size={10} class="mr-1" />Domain route</Badge>{/if}
                  </div>
                </td>
                <td class="data-table-cell-nowrap stack-right">
                  <Checkbox variant="switch" checked={r.enabled} disabled={locked || busy}
                    aria-label="{r.enabled ? 'Turn off' : 'Turn on'} {r.domain}"
                    onchange={(e) => setEnabled(r, e.target)} />
                </td>
                <td class="data-table-cell-actions stack-end">
                  {#if locked}
                    <Button variant="ghost" size="xs" icon="external-link" onclick={() => currentView.set('domains')} title="Managed in Domain Routes">Manage</Button>
                  {:else}
                    <div class="kt-btn-group hidden sm:inline-flex">
                      <Button variant="outline" size="xs" icon="pencil" tooltip="Edit rewrite" aria-label="Edit rewrite" onclick={() => openForm(r)} />
                      <Button variant="outline" size="xs" icon="trash" class="text-destructive hover:bg-destructive/10" tooltip="Delete rewrite" aria-label="Delete rewrite" onclick={() => remove(r)} />
                    </div>
                    <!-- phone: the ⋯ in a kt-btn-group, like the desktop pair (it doesn't clip the menu) -->
                    <div class="kt-btn-group sm:hidden">
                      <DropdownButton variant="outline" size="xs" ariaLabel="Rewrite actions" items={[
                        { label: 'Edit', icon: 'pencil', onclick: () => openForm(r) },
                        { label: 'Delete', icon: 'trash', variant: 'destructive', onclick: () => remove(r) },
                      ]} />
                    </div>
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

<Modal bind:open={formOpen} title={editing ? 'Edit rewrite' : 'Add rewrite'} size="md">
  <div class="space-y-4">
    <!-- domain → answer: one line from sm up -->
    <div class="grid gap-4 sm:grid-cols-[1fr_auto_1fr] sm:items-end sm:gap-2">
    <Input label="Domain" bind:value={formDomain} placeholder="nas.home" prefixIcon="world"
      hint="The name devices ask for. Start with *. to cover every subdomain, e.g. *.lab.home"
      onkeydown={(e) => e.key === 'Enter' && save()} />
    <Icon name="arrow-right" size={16} class="mb-2.5 hidden text-muted-foreground sm:block" />
    <Input label="Answer" bind:value={formAnswer} placeholder="10.8.0.50" prefixIcon="corner-down-right"
      hint="An IPv4 or IPv6 address, or another domain to answer as (an alias)"
      onkeydown={(e) => e.key === 'Enter' && save()} />
    </div>
    {#if duplicate}
      <p class="flex items-center gap-1.5 text-xs text-destructive"><Icon name="alert-triangle" size={14} />This rewrite already exists.</p>
    {:else if sibling}
      <p class="flex items-center gap-1.5 text-xs text-warning"><Icon name="info-circle" size={14} />{formDomain.trim()} already has a rewrite — devices will get both answers.</p>
    {/if}
    <div class="rounded-lg border border-dashed border-border p-3 text-xs text-muted-foreground">
      <div class="mb-1.5 font-medium text-foreground">Examples</div>
      <!-- the rewrite on the left, what it does on the right -->
      <ul class="space-y-1.5">
        {#each EXAMPLES as [domain, answer, what]}
          <li class="flex flex-wrap items-baseline justify-between gap-x-3">
            <span class="font-mono"><span class="text-foreground">{domain}</span> → <span class="text-primary">{answer}</span></span>
            <span>{what}</span>
          </li>
        {/each}
      </ul>
    </div>
  </div>
  {#snippet footer()}
    <Button variant="secondary" onclick={() => (formOpen = false)}>Cancel</Button>
    <Button onclick={save} loading={saving} disabled={!formDomain.trim() || !formAnswer.trim() || duplicate}>{editing ? 'Save' : 'Add rewrite'}</Button>
  {/snippet}
</Modal>
