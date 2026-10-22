<script>
  /**
   * SectionNav — the left menu for pages split into sections (a machine, Settings…): a dropdown on
   * mobile, a vertical rail on desktop whose divider runs the full height of the page. items:
   * [{ id, label, icon, badge?, soon? }]; the page owns the active id and decides what selecting
   * does (e.g. also update the URL).
   */
  import Icon from './Icon.svelte'
  import Badge from './Badge.svelte'
  import Select from './Select.svelte'

  let { items = [], active, onselect, label = 'Sections' } = $props()
</script>

<div class="lg:hidden">
  <Select value={active} size="lg" aria-label={label} onchange={(e) => onselect(e.target.value)}
    options={items.map((i) => ({ value: i.id, label: i.label + (i.badge !== undefined ? ` (${i.badge})` : '') + (i.soon ? ' — soon' : '') }))} />
</div>

<nav aria-label={label}
  class="hidden shrink-0 flex-col gap-1 border-r border-border pr-3 lg:flex lg:w-52 lg:self-stretch">
  <div class="sticky top-4 flex flex-col gap-1">
    {#each items as item (item.id)}
      <button type="button" onclick={() => onselect(item.id)} aria-current={active === item.id ? 'page' : undefined}
        class="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm whitespace-nowrap shrink-0 transition cursor-pointer {active === item.id ? 'bg-primary/10 text-primary font-medium' : 'text-muted-foreground hover:bg-muted hover:text-foreground'}">
        <Icon name={item.icon} size={16} class="shrink-0" />
        <span>{item.label}</span>
        {#if item.badge !== undefined}<span class="ml-auto"><Badge variant="destructive" size="sm">{item.badge}</Badge></span>{/if}
        {#if item.soon}<span class="ml-auto text-[9px] uppercase tracking-wide text-muted-foreground/70 border border-border rounded px-1 py-0.5">soon</span>{/if}
      </button>
    {/each}
  </div>
</nav>
