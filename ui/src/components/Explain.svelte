<script>
  /**
   * Explain - inline jargon with a hoverable plain-English tooltip.
   *
   * Usage:
   *   <Explain term="AAAA" />                     → shows "AAAA" + info tip from glossary
   *   <Explain term="policy drop" label="drop" /> → custom visible label
   *   <Explain label="foo" tip="custom text" />   → ad-hoc tip, no glossary
   *
   * The visible term stays inline; an info dot reveals the definition on hover
   * or keyboard focus (accessible).
   */
  import Icon from './Icon.svelte'
  import { explain } from '$lib/glossary.js'

  let { term = '', label = '', tip = '' } = $props()

  const text = $derived(label || term)
  const definition = $derived(tip || explain(term))
</script>

{#if definition}
  <span class="relative inline-flex items-center gap-0.5 group align-baseline">
    {#if text}<span>{text}</span>{/if}
    <button
      type="button"
      class="inline-flex text-muted-foreground/70 hover:text-foreground focus:text-foreground focus:outline-none cursor-help"
      aria-label={`What is ${text || 'this'}? ${definition}`}
    >
      <Icon name="info-circle" size={13} />
    </button>
    <span
      role="tooltip"
      class="pointer-events-none absolute bottom-full left-1/2 z-50 mb-1.5 w-56 -translate-x-1/2 rounded-lg border border-border bg-popover px-2.5 py-1.5 text-[11px] font-normal leading-snug text-popover-foreground shadow-md opacity-0 transition-opacity duration-100 group-hover:opacity-100 group-focus-within:opacity-100"
    >
      {definition}
    </span>
  </span>
{:else if text}
  <span>{text}</span>
{/if}
