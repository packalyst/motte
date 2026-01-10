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
  let {
    code = '',
    name = '',
    showName = false,
    size = 'md'
  } = $props()

  const sizes = {
    sm: { width: 16, height: 12, class: 'w-4 h-3' },
    md: { width: 20, height: 15, class: 'w-5 h-4' },
    lg: { width: 24, height: 18, class: 'w-6 h-[18px]' }
  }

  const validCode = $derived(code && /^[a-zA-Z]{2}$/.test(code) ? code.toLowerCase() : null)
</script>

{#if validCode}
  <span class="inline-flex items-center gap-1.5">
    <img
      src="https://flagcdn.com/{sizes[size].width}x{sizes[size].height}/{validCode}.png"
      alt={code}
      class="{sizes[size].class} rounded-sm shadow-sm object-cover"
      loading="lazy"
    />
    {#if showName && name}
      <span class="text-xs text-muted-foreground">{name}</span>
    {/if}
  </span>
{/if}
