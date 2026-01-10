<script>
  let { columns = [], data = [], onRowClick = null } = $props()
</script>

<div class="overflow-x-auto">
  <table class="w-full text-sm">
    <thead class="bg-muted/50">
      <tr>
        {#each columns as col}
          <th class="px-4 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider {col.class || ''}">
            {col.label}
          </th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#each data as row, i}
        <tr
          class="hover:bg-accent/50 {onRowClick ? 'cursor-pointer' : ''}"
          onclick={() => onRowClick?.(row)}
        >
          {#each columns as col}
            <td class="px-4 py-3 border-b border-border {col.cellClass || ''}">
              {#if col.render}
                {@html col.render(row)}
              {:else}
                {row[col.key] ?? '-'}
              {/if}
            </td>
          {/each}
        </tr>
      {/each}
    </tbody>
  </table>
</div>

{#if data.length === 0}
  <div class="flex flex-col items-center justify-center py-8 text-center">
    <p class="text-sm text-muted-foreground">No data</p>
  </div>
{/if}
