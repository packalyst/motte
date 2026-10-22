<script>
  /**
   * TagEditor — tag chips plus, for editors, an add field and remove buttons. Used for machine
   * scoping tags and Headscale ACL tags. prefix ('tag:' for Headscale) is stored on every tag but
   * hidden on the chips and added to what the user types. onsave(nextTags) persists the full list
   * and throws on failure; the server applies the same name rule (helper.NormalizeTags).
   */
  import Icon from './Icon.svelte'
  import Input from './Input.svelte'

  let {
    tags = [],
    prefix = '',
    canEdit = false,
    onsave,
    emptyText = 'No tags',
  } = $props()

  const MAX_TAGS = 16 // helper.MaxTags
  const NAME = /^[a-zA-Z][a-zA-Z0-9-]{0,62}$/
  const show = (t) => t.slice(prefix.length)

  let draft = $state('')
  let error = $state('')
  let saving = $state(false)

  async function save(next) {
    saving = true
    try {
      await onsave(next)
      error = ''
      return true
    } catch (e) {
      error = e.message
      return false
    } finally {
      saving = false
    }
  }

  async function add() {
    const name = draft.trim().replace(/^tag:/, '')
    if (!name) return
    if (!NAME.test(name)) { error = 'Start with a letter; use only letters, digits and dashes.'; return }
    if (tags.includes(prefix + name)) { draft = ''; return }
    if (tags.length >= MAX_TAGS) { error = `At most ${MAX_TAGS} tags.`; return }
    if (await save([...tags, prefix + name])) draft = ''
  }
</script>

<div class="space-y-2">
  <div class="flex flex-wrap items-center gap-1.5">
    {#each tags as t (t)}
      <span class="inline-flex items-center gap-1 rounded bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
        {show(t)}
        {#if canEdit}
          <button type="button" disabled={saving} onclick={() => save(tags.filter((x) => x !== t))}
            class="cursor-pointer hover:text-destructive disabled:cursor-not-allowed" title="Remove tag" aria-label="Remove tag {show(t)}"><Icon name="x" size={11} /></button>
        {/if}
      </span>
    {:else}
      <span class="text-xs text-muted-foreground">{emptyText}</span>
    {/each}
  </div>
  {#if canEdit}
    <form onsubmit={(e) => { e.preventDefault(); add() }}>
      <Input bind:value={draft} placeholder="Add a tag, e.g. prod" prefixIcon="tag" disabled={saving}
        suffixAddonBtn={{ label: 'Add', icon: 'plus', type: 'submit', loading: saving, disabled: !draft.trim() }} />
    </form>
    {#if error}<p role="alert" class="text-[11px] text-destructive">{error}</p>{/if}
  {/if}
</div>
