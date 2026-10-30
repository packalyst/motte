<script>
  /**
   * HsKeyRow — one key card in a key grid of the Headscale page (auth keys, API keys): its prefix with
   * what goes beside it (meta, a snippet), its state and expiry followed by extra facts (facts, a
   * snippet of "· …" items) and, while the key still works, an expire button.
   * A key that no longer works is faded.
   */
  import { formatExpiryDate } from '$lib/utils/format.js'
  import { keyState, KEY_STATE } from '$lib/hskeys.js'
  import Icon from '../Icon.svelte'
  import Button from '../Button.svelte'

  let { key, prefix, label, onexpire, meta = undefined, facts = undefined } = $props()
  const kind = $derived(keyState(key))
  const st = $derived(KEY_STATE[kind])
</script>

<li class="panel flex items-center gap-3 p-3 {st.works ? '' : 'opacity-60'}">
  <span class="grid h-9 w-9 shrink-0 place-items-center rounded-lg {st.tint}"><Icon name="key" size={16} /></span>
  <div class="min-w-0 flex-1">
    <div class="flex min-w-0 items-center gap-2">
      <code class="truncate font-mono text-sm font-medium text-foreground">{prefix}…</code>
      {@render meta?.()}
    </div>
    <div class="flex flex-wrap items-center gap-x-1.5 text-[11px] text-muted-foreground">
      <!-- an expired key's state is its expiry ("Expired 2 days ago"); a used one's is just "Used" -->
      <span class="inline-flex items-center gap-1.5 font-medium {st.text}"><span class="status-dot {st.dot}"></span>{kind === 'expired' ? formatExpiryDate(key.expiration) : st.label}</span>
      {#if st.works}<span>·</span><span class={kind === 'soon' ? 'text-warning' : ''}>{formatExpiryDate(key.expiration)}</span>{/if}
      {@render facts?.()}
    </div>
  </div>
  {#if st.works}
    <div class="kt-btn-group shrink-0">
      <Button variant="outline" size="xs" icon="ban" class="text-destructive hover:bg-destructive/10" tooltip="Expire key" aria-label="Expire {label}" onclick={onexpire} />
    </div>
  {/if}
</li>
