/**
 * Composable for localStorage-backed persistent state.
 * Automatically saves state changes to localStorage.
 *
 * Usage:
 *   const filter = usePersistentState('nodes_filter', { status: 'all', type: 'all' })
 *
 *   // Access/modify like normal state:
 *   filter.value.status = 'online'
 *
 *   // Or replace entirely:
 *   filter.value = { status: 'offline', type: 'server' }
 *
 *   // Reset to default:
 *   filter.reset()
 *
 * @param {string} key - localStorage key
 * @param {*} defaultValue - Default value if not in storage
 * @returns {Object} { value, reset }
 */
export function usePersistentState(key, defaultValue) {
  const storageKey = `vpn_panel_${key}`

  // Load initial value from storage
  function loadFromStorage() {
    try {
      const stored = localStorage.getItem(storageKey)
      if (stored) {
        const parsed = JSON.parse(stored)
        // Merge with defaults to handle new fields
        if (typeof defaultValue === 'object' && defaultValue !== null && !Array.isArray(defaultValue)) {
          return { ...defaultValue, ...parsed }
        }
        return parsed
      }
    } catch {
      // Ignore storage errors
    }
    return typeof defaultValue === 'object' ? { ...defaultValue } : defaultValue
  }

  let value = $state(loadFromStorage())

  // Save to storage on changes
  $effect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(value))
    } catch {
      // Ignore storage errors
    }
  })

  function reset() {
    value = typeof defaultValue === 'object' ? { ...defaultValue } : defaultValue
  }

  function clear() {
    localStorage.removeItem(storageKey)
    reset()
  }

  return {
    get value() { return value },
    set value(v) { value = v },
    reset,
    clear
  }
}

/**
 * Simple persistent boolean toggle.
 *
 * Usage:
 *   const collapsed = usePersistentToggle('sidebar_collapsed', false)
 *
 *   <button onclick={collapsed.toggle}>Toggle</button>
 *   {#if !collapsed.value}
 *     <Sidebar />
 *   {/if}
 *
 * @param {string} key - localStorage key
 * @param {boolean} defaultValue - Default value
 * @returns {Object} { value, toggle, set }
 */
export function usePersistentToggle(key, defaultValue = false) {
  const storageKey = `vpn_panel_${key}`

  function loadFromStorage() {
    try {
      const stored = localStorage.getItem(storageKey)
      if (stored !== null) {
        return stored === 'true'
      }
    } catch {
      // Ignore storage errors
    }
    return defaultValue
  }

  let value = $state(loadFromStorage())

  $effect(() => {
    try {
      localStorage.setItem(storageKey, String(value))
    } catch {
      // Ignore storage errors
    }
  })

  function toggle() {
    value = !value
  }

  function set(v) {
    value = v
  }

  return {
    get value() { return value },
    set value(v) { value = v },
    toggle,
    set
  }
}

/**
 * Persistent sort state for tables.
 *
 * Usage:
 *   const sort = usePersistentSort('users_sort', { field: 'name', dir: 'asc' })
 *
 *   <th onclick={() => sort.toggle('name')}>
 *     Name {sort.indicator('name')}
 *   </th>
 *
 *   const sorted = $derived(sortByMultiple(items, [{ field: sort.field, dir: sort.dir }]))
 *
 * @param {string} key - localStorage key
 * @param {Object} defaultValue - Default { field, dir }
 * @returns {Object} Sort state and methods
 */
export function usePersistentSort(key, defaultValue = { field: '', dir: 'asc' }) {
  const state = usePersistentState(key, defaultValue)

  function toggle(field) {
    if (state.value.field === field) {
      state.value = {
        field,
        dir: state.value.dir === 'asc' ? 'desc' : 'asc'
      }
    } else {
      state.value = { field, dir: 'asc' }
    }
  }

  function indicator(field) {
    if (state.value.field !== field) return ''
    return state.value.dir === 'asc' ? ' ↑' : ' ↓'
  }

  return {
    get field() { return state.value.field },
    get dir() { return state.value.dir },
    get value() { return state.value },
    toggle,
    indicator,
    reset: state.reset
  }
}

/**
 * Persistent pagination state with search and filters.
 * Automatically saves to localStorage and provides computed offset.
 *
 * Usage:
 *   const pagination = usePaginatedState('logs', { type: '', status: '' })
 *
 *   // Access state:
 *   pagination.page, pagination.perPage, pagination.search, pagination.offset
 *   pagination.filters.type, pagination.filters.status
 *
 *   // Update state:
 *   pagination.setPage(2)
 *   pagination.setSearch('error')
 *   pagination.setFilter('type', 'dns')
 *   pagination.resetPage() // Reset to page 1
 *
 * @param {string} key - localStorage key
 * @param {Object} defaultFilters - Default filter values (optional)
 * @param {number} defaultPerPage - Default items per page (uses settings if not provided)
 * @returns {Object} Pagination state and methods
 */
export function usePaginatedState(key, defaultFilters = {}, defaultPerPage = null) {
  const storageKey = `vpn_panel_${key}`

  // Get default per page from settings
  function getDefaultPerPage() {
    if (defaultPerPage !== null) return defaultPerPage
    try {
      return parseInt(localStorage.getItem('settings_items_per_page') || '25')
    } catch {
      return 25
    }
  }

  // Load initial value from storage
  function loadFromStorage() {
    try {
      const stored = localStorage.getItem(storageKey)
      if (stored) {
        const parsed = JSON.parse(stored)
        return {
          page: parsed.page || 1,
          perPage: parsed.perPage || getDefaultPerPage(),
          search: parsed.search || '',
          filters: { ...defaultFilters, ...parsed.filters }
        }
      }
    } catch {
      // Ignore storage errors
    }
    return {
      page: 1,
      perPage: getDefaultPerPage(),
      search: '',
      filters: { ...defaultFilters }
    }
  }

  let state = $state(loadFromStorage())

  // Computed offset
  const offset = $derived((state.page - 1) * state.perPage)

  // Save to storage on changes
  $effect(() => {
    try {
      localStorage.setItem(storageKey, JSON.stringify(state))
    } catch {
      // Ignore storage errors
    }
  })

  function setPage(page) {
    state.page = page
  }

  function setPerPage(perPage) {
    state.perPage = perPage
    state.page = 1 // Reset to first page when changing page size
  }

  function setSearch(search) {
    state.search = search
    state.page = 1 // Reset to first page on search
  }

  function setFilter(filterKey, value) {
    state.filters[filterKey] = value
    state.page = 1 // Reset to first page on filter change
  }

  function resetPage() {
    state.page = 1
  }

  function reset() {
    state = {
      page: 1,
      perPage: getDefaultPerPage(),
      search: '',
      filters: { ...defaultFilters }
    }
  }

  return {
    get page() { return state.page },
    set page(v) { state.page = v },
    get perPage() { return state.perPage },
    set perPage(v) { setPerPage(v) },
    get search() { return state.search },
    set search(v) { setSearch(v) },
    get filters() { return state.filters },
    get offset() { return offset },
    setPage,
    setPerPage,
    setSearch,
    setFilter,
    resetPage,
    reset
  }
}
