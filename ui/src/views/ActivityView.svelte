<script>
  import InfoCard from '../components/InfoCard.svelte'
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
  <InfoCard
    icon="activity"
    title="Activity"
    description="One chronological feed across the firewall, peers, AdGuard and settings — newest first."
  >
    <Button onclick={refresh} variant="secondary" size="sm" icon="refresh">Refresh</Button>
  </InfoCard>

  <div class="kt-panel">
    <div class="kt-panel-body">
      <ActivityFeed bind:this={feed} limit={200} />
    </div>
  </div>
</div>
