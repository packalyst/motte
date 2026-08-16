<script>
  import { statsStore } from '../stores/websocket.js'
  import Icon from './Icon.svelte'

  // From the WS stats stream (no polling).
  const d = $derived($statsStore?.security?.visitors)
</script>

<div class="bg-card border border-border rounded-xl p-4">
  <h3 class="text-sm font-semibold text-foreground mb-0.5 flex items-center gap-2"><Icon name="world" size={16} class="text-info" />Public visitors now</h3>
  <p class="text-[11px] text-muted-foreground mb-3">Browsing your public domains this hour (real client IP).</p>
  <div class="grid grid-cols-2 gap-3">
    <div>
      <div class="text-2xl font-bold tabular-nums text-foreground">{(d?.unique_visitors ?? 0).toLocaleString()}</div>
      <div class="text-xs text-muted-foreground mt-0.5">unique visitors</div>
    </div>
    <div>
      <div class="text-2xl font-bold tabular-nums text-foreground">{d?.countries ?? 0}</div>
      <div class="text-xs text-muted-foreground mt-0.5">countries</div>
    </div>
  </div>
</div>
