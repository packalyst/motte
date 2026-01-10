<script>
  import Icon from './Icon.svelte'
  import Select from './Select.svelte'

  let {
    page = $bindable(1),
    perPage = $bindable(25),
    total = 0,
    onPageChange = () => {},
    onPerPageChange = () => {}
  } = $props()

  const totalPages = $derived(Math.ceil(total / perPage) || 1)
  const offset = $derived((page - 1) * perPage)

  const perPageOptions = [
    { value: 10, label: '10' },
    { value: 25, label: '25' },
    { value: 50, label: '50' },
    { value: 100, label: '100' }
  ]

  function goToPage(p) {
    if (p < 1 || p > totalPages) return
    page = p
    onPageChange(p)
  }

  function changePerPage(newPerPage) {
    perPage = newPerPage
    page = 1
    onPerPageChange(newPerPage)
    onPageChange(1)
  }

  // Memoized page numbers
  const pageNumbers = $derived.by(() => {
    const pages = []
    const maxVisible = 5

    if (totalPages <= maxVisible + 2) {
      for (let i = 1; i <= totalPages; i++) pages.push(i)
    } else {
      pages.push(1)

      let start = Math.max(2, page - 1)
      let end = Math.min(totalPages - 1, page + 1)

      if (page <= 3) {
        end = Math.min(totalPages - 1, maxVisible)
      } else if (page >= totalPages - 2) {
        start = Math.max(2, totalPages - maxVisible + 1)
      }

      if (start > 2) pages.push('...')
      for (let i = start; i <= end; i++) pages.push(i)
      if (end < totalPages - 1) pages.push('...')

      if (totalPages > 1) pages.push(totalPages)
    }

    return pages
  })
</script>

<div class="pagination">
  <!-- Info: per page + showing text -->
  <div class="pagination-info">
    <span class="pagination-select">Show</span>
    <Select
      bind:value={perPage}
      options={perPageOptions}
      onchange={(e) => changePerPage(parseInt(e.target.value))}
      class="w-14 pagination-select"
    />
    <span class="pagination-info-text">
      {offset + 1}–{Math.min(offset + perPage, total)} of {total.toLocaleString()}
    </span>
  </div>

  <!-- Navigation -->
  <div class="pagination-nav">
    <!-- First -->
    <button
      onclick={() => goToPage(1)}
      disabled={page === 1}
      class="pagination-btn"
      title="First page"
    >
      <Icon name="chevrons-left" size={14} />
    </button>

    <!-- Prev -->
    <button
      onclick={() => goToPage(page - 1)}
      disabled={page === 1}
      class="pagination-btn"
      title="Previous page"
    >
      <Icon name="chevron-left" size={14} />
    </button>

    <!-- Mobile: current page indicator -->
    <span class="pagination-mobile-info">
      {page} / {totalPages}
    </span>

    <!-- Desktop: page numbers -->
    <div class="pagination-pages">
      {#each pageNumbers as p}
        {#if p === '...'}
          <span class="pagination-btn pagination-btn-ellipsis">
            <Icon name="dots" size={14} />
          </span>
        {:else}
          <button
            onclick={() => goToPage(p)}
            class="pagination-btn {p === page ? 'pagination-btn-active' : ''}"
          >
            {p}
          </button>
        {/if}
      {/each}
    </div>

    <!-- Next -->
    <button
      onclick={() => goToPage(page + 1)}
      disabled={page === totalPages}
      class="pagination-btn"
      title="Next page"
    >
      <Icon name="chevron-right" size={14} />
    </button>

    <!-- Last -->
    <button
      onclick={() => goToPage(totalPages)}
      disabled={page === totalPages}
      class="pagination-btn"
      title="Last page"
    >
      <Icon name="chevrons-right" size={14} />
    </button>
  </div>
</div>
