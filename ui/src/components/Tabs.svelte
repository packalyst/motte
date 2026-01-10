<script>
  import Icon from './Icon.svelte'

  /**
   * Tabs - Tab navigation component
   *
   * Props:
   * - tabs: Array of {id, label, icon?, badge?}
   * - activeTab: Currently active tab id (bindable)
   * - urlKey: If set, persists tab to URL hash
   * - onchange: Callback when tab changes
   * - size: 'default' | 'sm' | 'xs' - Tab size variant
   * - background: Show background color on tab bar
   */
  let {
    tabs = [],
    activeTab = $bindable(''),
    urlKey = '',
    onchange = null,
    size = 'default',
    background = false,
    class: className = ''
  } = $props()

  const sizes = {
    default: 'px-4 py-3 text-sm',
    sm: 'px-4 py-2 text-sm',
    xs: 'px-3 py-2.5 text-xs'
  }

  // Set initial active tab if not set (parent should use getInitialTab() from app.js)
  $effect(() => {
    if (!activeTab && tabs.length > 0) {
      activeTab = tabs[0].id
    }
  })

  function selectTab(tabId) {
    if (activeTab === tabId) return  // Already on this tab
    activeTab = tabId

    // Update URL hash if urlKey is set
    if (urlKey && typeof window !== 'undefined') {
      const hash = window.location.hash.slice(1)
      const params = new URLSearchParams(hash)
      params.set(urlKey, tabId)
      window.history.replaceState(null, '', '#' + params.toString())
    }

    // Call onchange callback
    if (onchange) onchange(tabId)
  }
</script>

<div class="flex border-b border-border {background ? 'bg-muted/30' : ''} {className}">
  {#each tabs as tab}
    <button
      onclick={() => selectTab(tab.id)}
      class="flex items-center gap-1.5 {sizes[size]} font-medium whitespace-nowrap transition-colors border-b-2 -mb-px cursor-pointer
        {activeTab === tab.id ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground'}"
    >
      {#if tab.icon}
        <Icon name={tab.icon} size={size === 'xs' ? 14 : 16} />
      {/if}
      {tab.label}
      {#if tab.badge !== undefined}
        <span class="px-1.5 py-0.5 text-[10px] font-medium rounded-full bg-muted text-muted-foreground">
          {tab.badge}
        </span>
      {/if}
    </button>
  {/each}
</div>
