<script>
  /**
   * ClientCard — the card for one client (WireGuard peer, Tailscale node, machine, LAN device),
   * shared by the Nodes and All clients pages. Header: device icon in the client-type colour with
   * an online dot, name + subtitle, status pill and state labels. Body: a two-column info grid.
   * Footer (optional): tags, chips or an action. The name is the card's link and its ::after covers
   * the whole card, so a click anywhere opens it; interactive footer content must be
   * `relative z-10` to stay clickable on top.
   *
   * flags: [{ label, tone: 'destructive' | 'warning', icon? }]
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
    onopen,
    openTitle = undefined,
    footer = undefined, // snippet
  } = $props()

  const TONE_PILL = { destructive: 'bg-destructive/10 text-destructive', warning: 'bg-warning/10 text-warning' }
  const TONE_TEXT = { destructive: 'text-destructive', warning: 'text-warning', success: 'text-success' }
</script>

<article class="relative flex flex-col rounded-lg border bg-card shadow-sm transition hover:shadow-md
  has-[.card-open:focus-visible]:ring-2 has-[.card-open:focus-visible]:ring-primary/40
  {highlight ? 'border-warning/50' : online ? 'border-success/30' : 'border-border'}">
  <div class="flex items-center gap-2.5 p-3">
    <span class="relative grid h-9 w-9 shrink-0 place-items-center rounded-lg {online ? '' : 'opacity-60 grayscale'}"
      style="background: color-mix(in oklch, {color} 14%, transparent); color: {color}">
      <Icon name={icon} size={18} />
      <span class="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full border-2 border-card {online ? 'bg-success' : 'bg-muted-foreground/50'}"></span>
    </span>
    <div class="min-w-0 flex-1">
      <button type="button" onclick={onopen} title={openTitle}
        class="card-open block w-full truncate text-left text-sm font-semibold text-foreground cursor-pointer outline-none after:absolute after:inset-0 after:rounded-lg">{name}</button>
      {#if subtitle}
        <div class="mt-0.5 flex items-center gap-1 text-[11px] text-muted-foreground">
          <Icon name={subtitleIcon} size={11} class="shrink-0" />
          <span class="truncate">{subtitle}</span>
        </div>
      {/if}
    </div>
    <div class="flex shrink-0 flex-col items-end gap-1">
      <span class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium {online ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}">
        <span class="status-dot {online ? 'status-dot-success' : 'status-dot-muted'}"></span>
        {online ? 'Online' : 'Offline'}
      </span>
      {#each flags as f (f.label)}
        <span class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium {TONE_PILL[f.tone] || TONE_PILL.warning}">
          {#if f.icon}<Icon name={f.icon} size={10} />{/if}{f.label}
        </span>
      {/each}
    </div>
  </div>

  {#if info.length}
    <div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t border-border/50 px-3 py-2.5 text-[11px]">
      {#each info as it, i (i)}
        <div class="flex min-w-0 items-center gap-1.5">
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

  {#if tags !== null || footer}
    <div class="flex min-h-[32px] flex-wrap items-center gap-1 border-t border-border/50 px-3 py-2">
      {#if tags?.length}
        {#each tags.slice(0, 3) as tag (tag)}
          <span class="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">{tag}</span>
        {/each}
        {#if tags.length > 3}
          <span class="rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">+{tags.length - 3}</span>
        {/if}
      {:else if tags !== null && emptyTags}
        <span class="text-[10px] text-muted-foreground">{emptyTags}</span>
      {/if}
      {#if footer}{@render footer()}{/if}
    </div>
  {/if}
</article>
