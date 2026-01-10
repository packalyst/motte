import { onMount } from 'svelte'
import { toast } from '../../stores/app.js'

/**
 * Composable for loading data with automatic error handling and loading state.
 *
 * Single source usage:
 *   const { data, loading, error, reload } = useDataLoader(
 *     () => apiGet('/api/domains'),
 *     { extract: 'routes', errorMsg: 'Failed to load routes' }
 *   )
 *
 * Multi-source usage:
 *   const { data, loading, error, reload } = useDataLoader([
 *     { fn: () => apiGet('/api/domains'), key: 'routes', extract: 'routes' },
 *     { fn: () => apiGet('/api/vpn/clients'), key: 'clients', isArray: true }
 *   ])
 *
 * @param {Function|Array} sources - Single loader function or array of source configs
 * @param {Object} options - Options for single source mode
 * @returns {Object} { data, loading, error, reload }
 */
export function useDataLoader(sources, options = {}) {
  let data = $state({})
  let loading = $state(true)
  let error = $state(null)

  const isSingle = typeof sources === 'function'
  const errorMsg = options.errorMsg || 'Failed to load data'

  async function load() {
    loading = true
    error = null

    try {
      if (isSingle) {
        // Single source mode
        const result = await sources()
        if (options.extract) {
          data = result[options.extract] || (options.isArray ? [] : {})
        } else if (options.isArray) {
          data = Array.isArray(result) ? result : []
        } else {
          data = result
        }
      } else {
        // Multi-source mode
        const promises = sources.map(src =>
          src.fn().catch(() => null)
        )
        const results = await Promise.all(promises)

        const newData = {}
        sources.forEach((src, i) => {
          const result = results[i]
          if (result === null) {
            newData[src.key] = src.isArray ? [] : (src.default ?? {})
          } else if (src.extract) {
            newData[src.key] = result[src.extract] || (src.isArray ? [] : {})
          } else if (src.isArray) {
            newData[src.key] = Array.isArray(result) ? result : []
          } else {
            newData[src.key] = result
          }
        })
        data = newData
      }
    } catch (e) {
      error = e
      toast(errorMsg + ': ' + e.message, 'error')
    } finally {
      loading = false
    }
  }

  onMount(() => {
    load()
  })

  return {
    get data() { return data },
    get loading() { return loading },
    get error() { return error },
    reload: load
  }
}

/**
 * Simpler version that just manages loading state for an async operation.
 *
 * Usage:
 *   const { execute, loading } = useAsync()
 *   await execute(async () => { await apiPost(...) }, 'Operation failed')
 */
export function useAsync() {
  let loading = $state(false)
  let error = $state(null)

  async function execute(fn, errorMsg = 'Operation failed') {
    loading = true
    error = null
    try {
      const result = await fn()
      return result
    } catch (e) {
      error = e
      toast(errorMsg + ': ' + e.message, 'error')
      throw e
    } finally {
      loading = false
    }
  }

  return {
    get loading() { return loading },
    get error() { return error },
    execute
  }
}
