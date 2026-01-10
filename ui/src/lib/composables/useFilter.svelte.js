import { debounce, filterByFields } from '../utils/data.js'

/**
 * Composable for filtering/searching items with debounce support.
 *
 * Usage:
 *   const { filtered, search, setSearch } = useFilter(items, {
 *     fields: ['name', 'domain', 'description'],
 *     debounce: 300
 *   })
 *
 * With getter (for reactive sources):
 *   const { filtered } = useFilter(() => data.routes, { fields: ['domain'] })
 *
 * @param {Array|Function} items - Array or getter function returning array
 * @param {Object} options - Filter options
 * @param {Array<string>} options.fields - Fields to search (supports dot notation)
 * @param {number} options.debounce - Debounce delay in ms (default: 0)
 * @returns {Object} { filtered, search, setSearch }
 */
export function useFilter(items, options = {}) {
  const { fields = [], debounce: debounceMs = 0 } = options

  let search = $state('')
  let debouncedSearch = $state('')

  // Create debounced setter if delay specified
  const updateDebouncedSearch = debounceMs > 0
    ? debounce((val) => { debouncedSearch = val }, debounceMs)
    : (val) => { debouncedSearch = val }

  function setSearch(value) {
    search = value
    updateDebouncedSearch(value)
  }

  // Get items - support both array and getter function
  const getItems = () => {
    const source = typeof items === 'function' ? items() : items
    return Array.isArray(source) ? source : []
  }

  // Computed filtered items
  const filtered = $derived.by(() => {
    const source = getItems()
    const query = debounceMs > 0 ? debouncedSearch : search

    if (!query || !query.trim() || fields.length === 0) {
      return source
    }

    return filterByFields(source, fields, query)
  })

  return {
    get filtered() { return filtered },
    get search() { return search },
    setSearch
  }
}

/**
 * Simple filter for select/dropdown options.
 *
 * Usage:
 *   const activeFilter = useSelectFilter('all')
 *
 *   // In template:
 *   <select bind:value={activeFilter.value}>
 *
 *   // Filter usage:
 *   const visible = $derived(
 *     items.filter(item => activeFilter.matches(item, 'status'))
 *   )
 *
 * @param {string} initial - Initial filter value
 * @param {string} allValue - Value that means "show all" (default: 'all')
 * @returns {Object} { value, set, matches, isAll }
 */
export function useSelectFilter(initial = 'all', allValue = 'all') {
  let value = $state(initial)

  function set(newValue) {
    value = newValue
  }

  function matches(item, field) {
    if (value === allValue) return true
    const itemValue = item[field]
    return itemValue === value
  }

  return {
    get value() { return value },
    set value(v) { value = v },
    set,
    matches,
    get isAll() { return value === allValue }
  }
}

/**
 * Multi-filter composable for complex filtering scenarios.
 *
 * Usage:
 *   const filters = useMultiFilter({
 *     status: { initial: 'all', field: 'status' },
 *     type: { initial: 'all', field: 'nodeType' },
 *     search: { initial: '', fields: ['name', 'hostname'] }
 *   })
 *
 *   // Access individual filter values
 *   filters.values.status
 *   filters.setFilter('status', 'online')
 *
 *   // Apply all filters at once
 *   const visible = $derived(filters.apply(items))
 *
 * @param {Object} config - Filter configurations
 * @returns {Object} { values, setFilter, apply, reset }
 */
export function useMultiFilter(config) {
  const initialValues = {}
  for (const [key, opts] of Object.entries(config)) {
    initialValues[key] = opts.initial ?? 'all'
  }

  let values = $state({ ...initialValues })

  function setFilter(key, value) {
    values[key] = value
  }

  function reset() {
    values = { ...initialValues }
  }

  function apply(items) {
    if (!Array.isArray(items)) return []

    return items.filter(item => {
      for (const [key, opts] of Object.entries(config)) {
        const filterValue = values[key]

        // Skip if "all" value
        if (filterValue === 'all' || filterValue === '') continue

        if (opts.fields) {
          // Text search across multiple fields
          const query = filterValue.toLowerCase().trim()
          if (!query) continue

          const matches = opts.fields.some(field => {
            const val = item[field]
            return val && String(val).toLowerCase().includes(query)
          })
          if (!matches) return false
        } else if (opts.field) {
          // Exact match on single field
          if (item[opts.field] !== filterValue) return false
        } else if (opts.fn) {
          // Custom filter function
          if (!opts.fn(item, filterValue)) return false
        }
      }
      return true
    })
  }

  return {
    get values() { return values },
    setFilter,
    apply,
    reset
  }
}
