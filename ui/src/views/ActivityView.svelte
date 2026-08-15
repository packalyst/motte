<script>
  import InfoCard from '../components/InfoCard.svelte'
  import Button from '../components/Button.svelte'
  import Select from '../components/Select.svelte'
  import Icon from '../components/Icon.svelte'
  import ActivityFeed from '../components/ActivityFeed.svelte'

  let { loading = $bindable(true) } = $props()

  let feed = $state(null)
  let subsystem = $state('')

  // The feed loads on mount; this page has nothing else to fetch.
  $effect(() => { loading = false })

  const sourceOptions = [
    { value: '', label: 'All sources' },
    { value: 'firewall', label: 'Firewall' },
    { value: 'wireguard', label: 'Peers' },
    { value: 'adguard', label: 'AdGuard' },
    { value: 'docker', label: 'Docker' },
    { value: 'settings', label: 'Settings' },
    { value: 'geolocation', label: 'Geolocation' },
  ]

  async function refresh() {
    await feed?.reload()
  }
</script>

<div class="space-y-4">
  <InfoCard
    icon="activity"
    title="Activity"
    description="One chronological feed across the firewall, peers, AdGuard and settings — newest first."
  />

  <div class="kt-panel">
    <div class="kt-panel-header">
      <h3 class="kt-panel-title">
        <Icon name="clock" size={16} class="text-muted-foreground" />
        Recent events
      </h3>
      <div class="flex items-center gap-2">
        <Select bind:value={subsystem} options={sourceOptions} class="w-40" />
        <Button onclick={refresh} variant="secondary" size="sm" icon="refresh">Refresh</Button>
      </div>
    </div>
    <div class="kt-panel-body">
      <ActivityFeed bind:this={feed} limit={200} {subsystem} />
    </div>
  </div>
</div>
