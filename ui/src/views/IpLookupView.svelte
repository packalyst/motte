<script>
  import { onMount } from 'svelte'
  import InfoCard from '../components/InfoCard.svelte'
  import IpLookup from '../components/IpLookup.svelte'

  // The Dashboard shell binds `loading`; there's nothing to fetch, so clear it immediately.
  let { loading = $bindable(true), onLogout } = $props()
  onMount(() => { loading = false })
</script>

<div class="space-y-4">
  <InfoCard
    icon="search"
    title="IP Lookup"
    description="Look up any IP address: owner (ASN), country, VPN / proxy / hosting flags, and a blended reputation verdict. Uses your geolocation databases — no external calls."
  />
  <div class="max-w-3xl">
    <IpLookup />
  </div>
</div>
