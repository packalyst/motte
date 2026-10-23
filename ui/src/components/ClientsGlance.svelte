<script>
  /**
   * ClientsGlance — the Overview's client section: each kind online out of total (opens Clients
   * narrowed to it) and what needs someone to act (flags, approvals, uninstalled machines), plus
   * live console sessions for operators. Reads the shared live client list (lib/clients.js).
   */
  import { onMount, onDestroy } from 'svelte'
  import { currentUser, hasRole, openView } from '../stores/app.js'
  import { KINDS, clientsList, watchClients, summarize, openClients, openClient } from '$lib/clients.js'
  import { consoleSessions, openConsoleEvents } from '$lib/consoleEvents.js'
  import Icon from './Icon.svelte'

  const SHOWN = 6 // attention rows before "+N more"
  const TONE = { destructive: 'bg-destructive/10 text-destructive', warning: 'bg-warning/10 text-warning' }

  const summary = $derived(summarize($clientsList.clients))
  const canConsole = $derived(hasRole($currentUser, 'operator'))
  const tint = (color) => `background: color-mix(in oklch, ${color} 14%, transparent); color: ${color}`

  let releases = []
  onMount(() => {
    releases.push(watchClients())
    if (canConsole) releases.push(openConsoleEvents())
  })
  onDestroy(() => releases.forEach((r) => r()))
</script>

<div class="space-y-4">
  <!-- Each kind: online / total -->
  <div class="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-border bg-border lg:grid-cols-4">
    {#each Object.entries(KINDS) as [k, meta] (k)}
      {@const n = summary.kinds[k]}
      <button type="button" onclick={() => openClients(k)} title="Open {meta.group}"
        class="flex items-center gap-3 bg-card px-4 py-3.5 text-left cursor-pointer transition-colors hover:bg-muted/40">
        <span class="grid h-9 w-9 shrink-0 place-items-center rounded-lg" style={tint(meta.color)}><Icon name={meta.icon} size={18} /></span>
        <span class="min-w-0 flex-1">
          <span class="block text-xl font-bold leading-none tabular-nums text-foreground">{n.online}<span class="text-sm font-medium text-muted-foreground"> / {n.total}</span></span>
          <span class="mt-1 block truncate text-[11px] text-muted-foreground">{meta.group}<span class="hidden sm:inline">{' online'}</span></span>
          <span class="mt-2 block h-1 overflow-hidden rounded-full bg-muted">
            <span class="block h-full rounded-full" style="width: {n.total ? (n.online / n.total) * 100 : 0}%; background: {meta.color}"></span>
          </span>
        </span>
      </button>
    {/each}
  </div>

  <!-- What needs someone to act: one card per client, its issues as tags, worst first -->
  <div class="panel">
    <div class="panel-head">
      <span class="panel-icon {summary.issues.destructive ? '!bg-destructive/10 !text-destructive' : summary.attention.length ? '!bg-warning/10 !text-warning' : '!bg-success/10 !text-success'}">
        <Icon name={summary.attention.length ? 'alert-triangle' : 'circle-check'} size={18} />
      </span>
      <div class="min-w-0 flex-1">
        <div class="panel-title">Needs attention</div>
        <div class="panel-sub">
          {#if !$clientsList.loaded}Loading…
          {:else if summary.attention.length}{summary.attention.length} {summary.attention.length === 1 ? 'client' : 'clients'} to look at
          {:else}Nothing to do: no vulnerabilities, expiring keys or waiting devices{/if}
        </div>
      </div>
      {#if summary.issues.destructive}<span class="inline-flex items-center gap-1 rounded-md bg-destructive/10 px-2 py-1 text-[11px] font-semibold tabular-nums text-destructive">{summary.issues.destructive} critical</span>{/if}
      {#if summary.issues.warning}<span class="inline-flex items-center gap-1 rounded-md bg-warning/10 px-2 py-1 text-[11px] font-semibold tabular-nums text-warning">{summary.issues.warning} {summary.issues.warning === 1 ? 'warning' : 'warnings'}</span>{/if}
    </div>

    {#if summary.attention.length}
      <ul class="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {#each summary.attention.slice(0, SHOWN) as a (a.c.key)}
          {@const meta = KINDS[a.c.kind]}
          <li>
            <button type="button" onclick={() => openClient(a.c)} title="Open {a.c.name}"
              class="group flex h-full w-full items-start gap-3 rounded-lg border border-border bg-muted/20 p-3 text-left cursor-pointer transition-colors hover:border-muted-foreground/40 hover:bg-muted/40">
              <span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg" style={tint(meta.color)}><Icon name={meta.icon} size={16} /></span>
              <span class="min-w-0 flex-1">
                <span class="flex items-baseline gap-2">
                  <span class="truncate text-[13px] font-semibold text-foreground">{a.c.name}</span>
                  <span class="shrink-0 text-[10px] text-muted-foreground">{meta.label}{a.c.machine ? ' · Machine' : ''}</span>
                </span>
                <span class="mt-1.5 flex flex-wrap gap-1">
                  {#each a.items as it, i (i)}
                    <span class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium {TONE[it.tone] || 'bg-muted text-muted-foreground'}"><Icon name={it.icon || 'alert-triangle'} size={11} />{it.label}</span>
                  {/each}
                </span>
              </span>
              <Icon name="chevron-right" size={14} class="mt-2 text-muted-foreground opacity-40 transition-opacity group-hover:opacity-100" />
            </button>
          </li>
        {/each}
      </ul>
      {#if summary.attention.length > SHOWN}
        <button type="button" onclick={() => openClients()} class="mt-3 text-xs font-medium text-primary cursor-pointer hover:underline">
          +{summary.attention.length - SHOWN} more on Clients →
        </button>
      {/if}
    {/if}

    {#if canConsole}
      <button type="button" onclick={() => openView('sessions')}
        class="panel-note flex w-[calc(100%+2rem)] items-center gap-2 cursor-pointer hover:text-foreground">
        <Icon name="terminal-2" size={13} class={$consoleSessions.length ? 'text-success' : ''} />
        <span class="flex-1 text-left"><b class="font-semibold tabular-nums text-foreground">{$consoleSessions.length}</b> live console {$consoleSessions.length === 1 ? 'session' : 'sessions'}</span>
        <Icon name="chevron-right" size={13} />
      </button>
    {/if}
  </div>
</div>
