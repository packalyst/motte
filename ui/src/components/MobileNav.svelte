<script>
  /**
   * MobileNav — the phone version of a page's section menu or tabs, in one of two looks:
   *   look="select" (default): a select in a card that stays under the top bar (.sticky-bar).
   *     Place it directly in the page column (not inside a small wrapper), or it can only stick
   *     within that wrapper.
   *   look="bottom": an app tab bar fixed at the bottom of the screen, icons over labels
   *     (.bottom-nav), below lg only. For a handful of sections (up to five fit a phone).
   * The select is hidden from `from` up, where the page shows its rail or tab bar instead.
   * items: [{ id, label, icon?, badge?, soon? }]
   */
  import Select from './Select.svelte'
  import Icon from './Icon.svelte'
  import { selectSection } from '../stores/app.js'

  let { items = [], active, onselect, label = 'Sections', from = 'lg', look = 'select' } = $props()

  // whole class names, so Tailwind sees them
  const HIDE = { sm: 'sm:hidden', md: 'md:hidden', lg: 'lg:hidden' }
</script>

{#if look === 'bottom'}
  <!-- !m-0: a parent's space-y margin must not lift a fixed bar off the screen edge -->
  <nav class="bottom-nav !m-0 lg:hidden" aria-label={label}
    style="--n: {items.length}; --a: {Math.max(0, items.findIndex((i) => i.id === active))}">
    <span class="bottom-nav-indicator" aria-hidden="true"></span>
    {#each items as i (i.id)}
      <button type="button" class="bottom-nav-item" aria-current={active === i.id ? 'page' : undefined}
        disabled={i.soon} title={i.soon ? `${i.label} (soon)` : undefined} onclick={() => selectSection(onselect, i.id)}>
        <span class="bottom-nav-icon">
          <Icon name={i.icon} size={20} />
          {#if i.badge}<span class="bottom-nav-badge">{i.badge}</span>{/if}
        </span>
        <span class="max-w-full truncate">{i.label}</span>
      </button>
    {/each}
  </nav>
{:else}
  <div class="sticky-bar {HIDE[from] || HIDE.lg}">
    <div class="sticky-bar-card">
      <Select value={active} size="lg" aria-label={label} onchange={(e) => selectSection(onselect, e.target.value)}
        options={items.map((i) => ({ value: i.id, label: i.label + (i.badge !== undefined ? ` (${i.badge})` : '') + (i.soon ? ' — soon' : '') }))} />
    </div>
  </div>
{/if}
