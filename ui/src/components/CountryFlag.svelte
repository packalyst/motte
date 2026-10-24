<script>
  /**
   * CountryFlag - Display country flag with optional details
   *
   * Props:
   * - code: 2-letter country code (required)
   * - name: Country name (optional, shown if showName is true)
   * - showName: Show country name next to flag
   * - size: 'sm' | 'md' | 'lg' (default: 'md')
   */
  import { flagUrl } from '../lib/utils/flags.js'

  let {
    code = '',
    name = '',
    showName = false,
    size = 'md'
  } = $props()

  const sizes = {
    sm: 'w-4 h-3',
    md: 'w-5 h-4',
    lg: 'w-6 h-[18px]'
  }

  const src = $derived(flagUrl(code))
</script>

{#if src}
  <span class="inline-flex items-center gap-1.5">
    <img
      {src}
      alt={code}
      class="{sizes[size]} rounded-sm shadow-sm object-cover"
      loading="lazy"
    />
    {#if showName && name}
      <span class="text-xs text-muted-foreground">{name}</span>
    {/if}
  </span>
{/if}
