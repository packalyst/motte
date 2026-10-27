<script>
  /**
   * StatStrip — a row of headline numbers on one surface with hairline dividers (Sessions,
   * Tunnels, DNS). items: [{ icon, value, label, tone? | color?, of?, sub?, mono? }]
   * - tone: success | destructive | warning | info | primary (tile colour), or color: any CSS
   *   colour/token for the tile tint
   * - of: shown as "value / of"; sub: extra detail after the label (hidden on phones)
   * - mono: monospace value (hostnames, domains)
   */
  import Icon from './Icon.svelte'

  let { items = [], label = undefined } = $props()

  const TONE = {
    success: 'bg-success/10 text-success',
    destructive: 'bg-destructive/10 text-destructive',
    warning: 'bg-warning/10 text-warning',
    info: 'bg-info/10 text-info',
    primary: 'bg-primary/10 text-primary',
  }
  const tint = (c) => `background: color-mix(in oklch, ${c} 14%, transparent); color: ${c}`
  // literal classes for Tailwind; phones always two across
  // (three on a two-across phone: the first one spans the row instead of leaving an empty cell)
  const COLS = { 2: 'grid-cols-2', 3: 'grid-cols-2 lg:grid-cols-3 [&>:first-child]:col-span-2 lg:[&>:first-child]:col-span-1', 4: 'grid-cols-2 lg:grid-cols-4' }
</script>

<section aria-label={label} class="grid gap-px overflow-hidden rounded-xl border border-border bg-border {COLS[items.length] || COLS[4]}">
  {#each items as s (s.label)}
    <div class="flex min-w-0 items-center gap-3 bg-card px-4 py-3">
      <span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg {s.color ? '' : TONE[s.tone] || 'bg-muted text-muted-foreground'}" style={s.color ? tint(s.color) : undefined}>
        <Icon name={s.icon} size={16} />
      </span>
      <div class="min-w-0">
        <div class="truncate font-bold leading-none tabular-nums text-foreground {s.mono ? 'font-mono text-sm' : 'text-xl'}" title={String(s.value)}>
          {s.value}{#if s.of !== undefined}<span class="text-sm font-medium text-muted-foreground">{` / ${s.of}`}</span>{/if}
        </div>
        <div class="mt-1 truncate text-[11px] text-muted-foreground">{s.label}{#if s.sub}<span class="hidden text-muted-foreground/70 sm:inline">{` · ${s.sub}`}</span>{/if}</div>
      </div>
    </div>
  {/each}
</section>
