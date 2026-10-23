<script>
  /**
   * ClientCard — the card for one client (WireGuard peer, Tailscale node, machine, LAN device),
   * shared by the Nodes and All clients pages. Header: device icon in the client-type colour with
   * an online dot; name + status pill on the first line, subtitle + state labels on the second. Body: a two-column info grid.
   * Footer (optional): tags, chips or an action. The name is the card's link and its ::after covers
   * the whole card, so a click anywhere opens it; interactive footer content must be
   * `relative z-10` to stay clickable on top.
   *
   * flags: [{ label, tone: 'destructive' | 'warning', icon, count? }] — shown as an icon (+ count),
   *        label in a tooltip
   * info:  [{ icon, text, mono?, tone? }]
   */
  import Icon from './Icon.svelte'

  let {
    name,
    icon,
    color,
    online = false,
    subtitle = '',
    subtitleIcon = 'user',
    flags = [],
    info = [],
    tags = null, // string[] for a tags footer; null = no tags footer
    emptyTags = '',
    highlight = false, // e.g. waiting for approval
    gone = false, // a machine whose agent was uninstalled
    onopen,
    openTitle = undefined,
    footer = undefined, // snippet
    stats = undefined, // snippet: a full-width line under the info grid (traffic, usage meters…)
  } = $props()

  const TONE_PILL = { destructive: 'bg-destructive/10 text-destructive', warning: 'bg-warning/10 text-warning' }
  const TONE_TEXT = { destructive: 'text-destructive', warning: 'text-warning', success: 'text-success' }

  // A tag can arrive twice (set by an admin and advertised by the device, or a Tailscale tag that
  // matches a machine tag once its prefix is stripped).
  const shownTags = $derived(tags && [...new Set(tags)])

  // Long names are cut to a fixed length (the full name is in a tooltip), so every card's title
  // reads the same width.
  const NAME_MAX = 16
  const shortName = $derived(name.length > NAME_MAX ? name.slice(0, NAME_MAX - 1).trimEnd() + '…' : name)
</script>

<article class="relative flex flex-col rounded-lg border shadow-sm transition hover:shadow-md
  has-[.card-open:focus-visible]:ring-2 has-[.card-open:focus-visible]:ring-primary/40
  {highlight ? 'border-warning/50' : online ? 'border-success/30' : gone ? 'border-dashed border-destructive/40' : 'border-border'}
  {gone ? 'bg-destructive/5' : 'bg-card'}">
  <div class="flex items-start gap-2.5 p-3">
    {#if gone}
      <!-- same mark as the machine's uninstalled page -->
      <span class="relative grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-border bg-card text-muted-foreground">
        <Icon name="plug-connected-x" size={18} />
        <span class="absolute -right-1 -top-1 grid h-4 w-4 place-items-center rounded-full border-2 border-card bg-destructive text-white"><Icon name="x" size={9} /></span>
      </span>
    {:else}
      <span class="relative grid h-9 w-9 shrink-0 place-items-center rounded-lg {online ? '' : 'opacity-60 grayscale'}"
        style="background: color-mix(in oklch, {color} 14%, transparent); color: {color}">
        <Icon name={icon} size={18} />
        <span class="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full border-2 border-card {online ? 'bg-success' : 'bg-muted-foreground/50'}"></span>
      </span>
    {/if}
    <div class="min-w-0 flex-1">
      <div class="flex items-center gap-2">
        <button type="button" onclick={onopen} title={openTitle} aria-label={name}
          class="card-open min-w-0 flex-1 truncate text-left text-sm font-semibold text-foreground cursor-pointer outline-none after:absolute after:inset-0 after:rounded-lg">
          {#if shortName !== name}
            <!-- relative z-10 lifts it above the card link so the tooltip gets the hover -->
            <span data-kt-tooltip class="relative z-10">{shortName}<span data-kt-tooltip-content class="kt-tooltip hidden">{name}</span></span>
          {:else}{name}{/if}
        </button>
        <span class="inline-flex shrink-0 items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium {online ? 'bg-success/10 text-success' : gone ? 'bg-destructive/10 text-destructive' : 'bg-muted text-muted-foreground'}">
          {#if gone}
            <Icon name="plug-connected-x" size={11} />Uninstalled
          {:else}
            <span class="status-dot {online ? 'status-dot-success' : 'status-dot-muted'}"></span>
            {online ? 'Online' : 'Offline'}
          {/if}
        </span>
      </div>
      <!-- always present (even empty) so headers are the same height across a row -->
      <div class="mt-0.5 flex min-h-5 items-center gap-2">
        <div class="flex min-w-0 flex-1 items-center gap-1 text-[11px] text-muted-foreground">
          {#if subtitle}
            <Icon name={subtitleIcon} size={11} class="shrink-0" />
            <span class="truncate">{subtitle}</span>
          {/if}
        </div>
        {#each flags as f, i (i)}
          <!-- relative z-10 lifts it above the card link so the tooltip gets the hover -->
          <span data-kt-tooltip role="img" aria-label={f.label}
            class="relative z-10 inline-flex h-5 min-w-5 shrink-0 cursor-help items-center justify-center gap-0.5 rounded px-1 text-[10px] font-semibold tabular-nums {TONE_PILL[f.tone] || TONE_PILL.warning}">
            <Icon name={f.icon || 'alert-triangle'} size={13} />{#if f.count}{f.count}{/if}
            <span data-kt-tooltip-content class="kt-tooltip hidden">{f.label}</span>
          </span>
        {/each}
      </div>
    </div>
  </div>

  {#if info.length || stats}
    <div class="space-y-2.5 border-t border-border/50 px-3 py-2.5">
      {#if info.length}
        <div class="grid grid-cols-2 gap-x-3 gap-y-1.5 text-[11px]">
          {#each info as it, i (i)}
            <!-- right column aligns right, so each row reads edge to edge -->
            <div class="flex min-w-0 items-center gap-1.5 {i % 2 ? 'justify-end' : ''}">
              <Icon name={it.icon} size={12} class="shrink-0 {TONE_TEXT[it.tone] || 'text-dim'}" />
              {#if it.mono}
                <code class="truncate font-mono text-foreground">{it.text}</code>
              {:else}
                <span class="truncate {TONE_TEXT[it.tone] || 'text-muted-foreground'}">{it.text}</span>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
      {#if stats}{@render stats()}{/if}
    </div>
  {/if}

  {#if tags !== null || footer}
    <div class="mt-auto flex min-h-[32px] flex-wrap items-center gap-1 border-t border-border/50 px-3 py-2">
      {#if shownTags?.length}
        {#each shownTags.slice(0, 3) as tag (tag)}
          <span class="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground"><Icon name="tag" size={10} class="shrink-0 text-dim" />{tag}</span>
        {/each}
        {#if shownTags.length > 3}
          <span class="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">+{shownTags.length - 3}</span>
        {/if}
      {:else if tags !== null && emptyTags}
        <span class="inline-flex items-center gap-1 text-[10px] text-muted-foreground"><Icon name="tag" size={12} class="shrink-0 text-dim" />{emptyTags}</span>
      {/if}
      {#if footer}{@render footer()}{/if}
    </div>
  {/if}
</article>
