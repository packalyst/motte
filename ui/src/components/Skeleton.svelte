<script>
  // A grey placeholder in the shape of content that's still loading; size it with classes.
  let { class: className = '', ...rest } = $props()
</script>

<div class="rounded bg-foreground/10 motion-safe:animate-pulse {className}" aria-hidden="true" {...rest}></div>
