<script>
  // Combobox: a Select with a filter box, for long option lists (e.g. timezones).
  // Mirrors Select's API (value/options/onchange/label/helperText) so it drops in.
  import Icon from './Icon.svelte'

  let {
    value = $bindable(''),
    options = [], // [{ value, label }]
    onchange = undefined,
    disabled = false,
    label = undefined,
    labelClass = 'block text-xs font-medium text-foreground mb-1',
    helperText = undefined,
    helperClass = 'text-[10px] text-muted-foreground mt-1',
    placeholder = 'Select…',
    class: className = '',
    id = undefined,
  } = $props()

  let open = $state(false)
  let query = $state('')
  let highlighted = $state(0)
  let rootEl
  let btnEl
  let inputEl
  let itemEls = $state([])
  // The menu is position:fixed (positioned from the button's viewport rect) so a card's
  // overflow:hidden or a sibling card's stacking context can't clip or cover it.
  let menuStyle = $state('')

  function positionMenu() {
    if (!btnEl) return
    const r = btnEl.getBoundingClientRect()
    const spaceBelow = window.innerHeight - r.bottom
    const menuMax = 300
    const flipUp = spaceBelow < menuMax && r.top > spaceBelow
    const vert = flipUp ? `bottom:${window.innerHeight - r.top + 4}px` : `top:${r.bottom + 4}px`
    menuStyle = `position:fixed; left:${r.left}px; width:${r.width}px; ${vert}; z-index:9999;`
  }

  const selectedLabel = $derived(options.find((o) => o.value === value)?.label ?? '')
  const filtered = $derived(
    query.trim()
      ? options.filter((o) => o.label.toLowerCase().includes(query.trim().toLowerCase()))
      : options
  )

  function openList() {
    if (disabled) return
    open = true
    query = ''
    highlighted = Math.max(0, options.findIndex((o) => o.value === value))
    positionMenu()
    queueMicrotask(() => { positionMenu(); inputEl?.focus() })
  }
  function close() { open = false; query = '' }
  function choose(opt) {
    value = opt.value
    close()
    onchange?.({ target: { value: opt.value } })
  }
  function onKey(e) {
    if (!open) {
      if (e.key === 'Enter' || e.key === 'ArrowDown' || e.key === ' ') { e.preventDefault(); openList() }
      return
    }
    if (e.key === 'ArrowDown') { e.preventDefault(); highlighted = Math.min(highlighted + 1, filtered.length - 1) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); highlighted = Math.max(highlighted - 1, 0) }
    else if (e.key === 'Enter') { e.preventDefault(); if (filtered[highlighted]) choose(filtered[highlighted]) }
    else if (e.key === 'Escape') { e.preventDefault(); close() }
  }

  // Reset the highlight when the filter changes; keep the highlighted row in view.
  $effect(() => { query; highlighted = 0 })
  $effect(() => { if (open) itemEls[highlighted]?.scrollIntoView({ block: 'nearest' }) })

  function onDocClick(e) { if (rootEl && !rootEl.contains(e.target)) close() }
</script>

<svelte:document onclick={onDocClick} />
<svelte:window onscroll={() => open && positionMenu()} onresize={() => open && positionMenu()} />

<div>
  {#if label}<label for={id} class={labelClass}>{label}</label>{/if}
  <div class="relative {className}" bind:this={rootEl}>
    <button
      type="button"
      {id}
      {disabled}
      bind:this={btnEl}
      class="kt-select kt-select-sm w-full text-left flex items-center justify-between gap-2 disabled:opacity-50"
      onclick={() => (open ? close() : openList())}
      onkeydown={onKey}
      aria-haspopup="listbox"
      aria-expanded={open}
    >
      <span class="truncate {selectedLabel ? '' : 'text-muted-foreground'}">{selectedLabel || placeholder}</span>
      <Icon name="chevron-down" size={14} class="text-muted-foreground shrink-0" />
    </button>

    {#if open}
      <div style={menuStyle} class="rounded-md border border-border bg-card shadow-lg" role="listbox">
        <div class="p-1.5 border-b border-border">
          <!-- svelte-ignore a11y_autofocus -->
          <input
            bind:this={inputEl}
            bind:value={query}
            onkeydown={onKey}
            placeholder="Search…"
            class="w-full bg-muted rounded px-2 py-1 text-xs text-foreground outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
        <div class="max-h-56 overflow-y-auto py-1">
          {#if filtered.length === 0}
            <div class="px-3 py-2 text-xs text-muted-foreground">No matches</div>
          {:else}
            {#each filtered as opt, i (opt.value)}
              <button
                type="button"
                role="option"
                aria-selected={opt.value === value}
                bind:this={itemEls[i]}
                class="w-full text-left px-3 py-1.5 text-xs truncate {i === highlighted ? 'bg-muted' : ''} {opt.value === value ? 'text-primary font-medium' : 'text-foreground'}"
                onmouseenter={() => (highlighted = i)}
                onclick={() => choose(opt)}
              >
                {opt.label}
              </button>
            {/each}
          {/if}
        </div>
      </div>
    {/if}
  </div>
  {#if helperText}<p class={helperClass}>{helperText}</p>{/if}
</div>
