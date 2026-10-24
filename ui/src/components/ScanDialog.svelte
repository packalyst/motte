<script>
  /**
   * ScanDialog — opened by Scan: choose folders the vulnerability scan leaves out, then scan.
   * Three ways to pick: the current list, the folders the last scan's findings came from, and
   * a folder browser that asks the agent for one folder's sub-folders at a time (names only).
   * The chosen list is saved on the machine and also applies to later scans.
   */
  import { untrack } from 'svelte'
  import { apiGet, apiPost } from '../stores/app.js'
  import Modal from './Modal.svelte'
  import Button from './Button.svelte'
  import Icon from './Icon.svelte'
  import Checkbox from './Checkbox.svelte'

  let { open = $bindable(false), machine, excluded = [], onscan } = $props()

  let chosen = $state([])
  let sources = $state([]) // [{ project, total }] from the last scan, app folders only
  let nodes = $state({}) // path -> { open, loading, error, dirs: [{ name, skipped }], truncated }
  let busy = $state(false)
  let typed = $state('')
  // the rules the panel and the agent enforce: a clean absolute folder, not "/", no glob
  // characters, and not one holding the system's package records (a scan would look clean)
  const PROTECTED = ['/etc', '/var/lib/dpkg', '/var/lib/rpm', '/usr/lib/sysimage/rpm', '/lib/apk']
  const typedOk = $derived(/^\/[^\0-\x1f\x7f]*[^/]$/.test(typed) && !/[*?[\]{}\\]/.test(typed) && !/(^|\/)\.\.?(\/|$)/.test(typed) && !typed.includes('//')
    && typed.length <= 512 && !PROTECTED.some((p) => p === typed || p.startsWith(typed + '/')))
  function addTyped() {
    if (!typedOk) return
    toggle(typed, true)
    typed = ''
  }

  // Fresh state each time it opens: start from the machine's saved list. Only `open` is a
  // dependency; the rest reads and resets state this effect must not re-run on.
  $effect(() => {
    if (!open) return
    untrack(() => {
      chosen = [...(excluded || [])]
      nodes = {}
      loadSources()
      expand('/')
    })
  })

  async function loadSources() {
    try {
      const res = await apiGet('/api/fleet/cves/groups?machine_id=' + encodeURIComponent(machine.id))
      sources = (res?.groups || []).filter((g) => g.project?.startsWith('/')).sort((a, b) => b.total - a.total).slice(0, 8)
    } catch { sources = [] }
  }

  async function expand(path) {
    const n = nodes[path]
    if (n?.dirs) { nodes = { ...nodes, [path]: { ...n, open: !n.open } }; return }
    nodes = { ...nodes, [path]: { open: true, loading: true } }
    try {
      const res = await apiPost('/api/fleet/dirs', { machine_id: machine.id, path })
      nodes = { ...nodes, [path]: { open: true, dirs: res?.dirs || [], truncated: !!res?.truncated } }
    } catch (e) {
      nodes = { ...nodes, [path]: { open: true, error: e?.message || 'Could not list this folder' } }
    }
  }

  const join = (dir, name) => (dir === '/' ? '/' + name : dir + '/' + name)
  // A folder under a left-out one is left out with it.
  const coveredBy = (path) => chosen.find((c) => path !== c && path.startsWith(c + '/'))
  function toggle(path, on) {
    chosen = on ? [...chosen.filter((c) => !c.startsWith(path + '/')), path].sort() : chosen.filter((c) => c !== path)
  }

  async function scan() {
    busy = true
    try { await onscan?.([...chosen].sort()); open = false } finally { busy = false }
  }
</script>

{#snippet tree(path, depth)}
  {@const n = nodes[path]}
  {#if n?.loading}
    <div class="py-1 text-[11px] text-muted-foreground" style="padding-left: {depth * 16 + 22}px">Asking the machine…</div>
  {:else if n?.error}
    <div class="py-1 text-[11px] text-destructive" style="padding-left: {depth * 16 + 22}px">{n.error}</div>
  {:else if n?.dirs}
    {#each n.dirs as d (d.name)}
      {@const full = join(path, d.name)}
      {@const parent = coveredBy(full)}
      <div class="flex items-center gap-1.5 rounded py-0.5 pr-1 hover:bg-muted/50" style="padding-left: {depth * 16}px">
        <button type="button" class="grid h-5 w-5 shrink-0 place-items-center rounded text-muted-foreground hover:text-foreground cursor-pointer disabled:opacity-30"
          disabled={d.skipped} aria-label="{nodes[full]?.open ? 'Collapse' : 'Expand'} {full}" onclick={() => expand(full)}>
          <Icon name={nodes[full]?.open ? 'chevron-down' : 'chevron-right'} size={13} />
        </button>
        {#if d.skipped}
          <Icon name="folder" size={14} class="shrink-0 text-muted-foreground/60" />
          <span class="truncate font-mono text-xs text-muted-foreground/70">{d.name}</span>
          <span class="ml-auto shrink-0 text-[10px] text-muted-foreground">always skipped</span>
        {:else}
          <Checkbox checked={!!parent || chosen.includes(full)} disabled={!!parent} onchange={(e) => toggle(full, e.target.checked)} aria-label="Leave out {full}">
            <span class="flex min-w-0 items-center gap-1.5">
              <Icon name="folder" size={14} class="shrink-0 text-muted-foreground" />
              <span class="truncate font-mono text-xs">{d.name}</span>
            </span>
          </Checkbox>
        {/if}
      </div>
      {#if nodes[full]?.open}{@render tree(full, depth + 1)}{/if}
    {:else}
      <div class="py-1 text-[11px] text-muted-foreground" style="padding-left: {depth * 16 + 22}px">No sub-folders.</div>
    {/each}
    {#if n.truncated}<div class="py-1 text-[11px] text-muted-foreground" style="padding-left: {depth * 16 + 22}px">Too many to list; type the path above instead.</div>{/if}
  {/if}
{/snippet}

<Modal bind:open title="Scan for vulnerabilities" size="lg">
  <div class="space-y-5">
    <p class="text-sm text-muted-foreground">
      The scan reads every installed package and app lockfile on {machine.name}. Leave out folders you don't run in production, such as copies, backups or old projects. System folders, Docker storage and caches are always skipped.
    </p>

    <section>
      <div class="mb-2 text-xs font-medium">Left out <span class="text-muted-foreground">· {chosen.length}</span></div>
      {#if chosen.length}
        <div class="flex flex-wrap gap-1.5">
          {#each chosen as c (c)}
            <span class="inline-flex max-w-full items-center gap-1 rounded-md bg-muted px-2 py-1 font-mono text-[11px]">
              <span class="truncate">{c}</span>
              <button type="button" class="shrink-0 text-muted-foreground hover:text-foreground cursor-pointer" aria-label="Scan {c} again" onclick={() => toggle(c, false)}><Icon name="x" size={12} /></button>
            </span>
          {/each}
        </div>
      {:else}
        <div class="text-xs text-muted-foreground">Nothing. The whole machine is scanned.</div>
      {/if}
      <form class="mt-2 flex gap-2" onsubmit={(e) => { e.preventDefault(); addTyped() }}>
        <input bind:value={typed} aria-label="Folder path to leave out" placeholder="/path/to/folder" spellcheck="false" autocomplete="off"
          class="kt-input kt-input-sm min-w-0 flex-1 font-mono" />
        <Button type="submit" variant="outline" size="sm" icon="plus" disabled={!typedOk}>Leave out</Button>
      </form>
    </section>

    {#if sources.length}
      <section>
        <div class="mb-2 text-xs font-medium">Where the last scan's findings came from</div>
        <div class="divide-y divide-dashed divide-border rounded-lg border border-border">
          {#each sources as g (g.project)}
            {@const parent = coveredBy(g.project)}
            <div class="flex items-center gap-3 px-3 py-2">
              <Checkbox checked={!!parent || chosen.includes(g.project)} disabled={!!parent} onchange={(e) => toggle(g.project, e.target.checked)} aria-label="Leave out {g.project}">
                <span class="truncate font-mono text-xs">{g.project}</span>
              </Checkbox>
              <span class="ml-auto shrink-0 text-[11px] tabular-nums text-muted-foreground">{g.total.toLocaleString()} findings</span>
            </div>
          {/each}
        </div>
      </section>
    {/if}

    <section>
      <div class="mb-2 text-xs font-medium">Browse folders</div>
      <div class="max-h-72 overflow-y-auto rounded-lg border border-border p-2">
        {@render tree('/', 0)}
      </div>
    </section>
  </div>

  {#snippet footer()}
    <Button variant="secondary" onclick={() => (open = false)}>Cancel</Button>
    <Button variant="primary" icon="scan" loading={busy} onclick={scan}>{chosen.length ? `Scan, leaving out ${chosen.length}` : 'Scan the whole machine'}</Button>
  {/snippet}
</Modal>
