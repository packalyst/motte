<script>
  let { name, size = 24, class: className = '' } = $props()
</script>

<span
  class="icon-[tabler--{name}] shrink-0 {className}"
  style="width: {size}px; height: {size}px;"
></span>
