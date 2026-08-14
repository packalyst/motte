<script>
  import Icon from '../components/Icon.svelte'
  import Button from '../components/Button.svelte'
  import ActivityFeed from '../components/ActivityFeed.svelte'

  let { loading = $bindable(true) } = $props()

  let feed = $state(null)

  // The feed loads on mount; this page has nothing else to fetch.
  $effect(() => { loading = false })

  async function refresh() {
    await feed?.reload()
  }
</script>

<div class="space-y-4">
  <div class="flex items-center justify-between gap-3">
    <div class="flex items-center gap-2">
      <Icon name="activity" size={20} class="text-primary" />
      <div>
        <h1 class="text-lg font-semibold">Activity</h1>
        <p class="text-xs text-muted-foreground">One feed across the firewall, peers, and settings — newest first.</p>
      </div>
    </div>
    <Button onclick={refresh} variant="secondary" size="sm" icon="refresh">Refresh</Button>
  </div>

  <div class="bg-card border border-border rounded-lg p-4 shadow-sm">
    <ActivityFeed bind:this={feed} limit={200} />
  </div>
</div>
