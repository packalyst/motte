<script>
  import InfoCard from '../components/InfoCard.svelte'
  import IpLookup from '../components/IpLookup.svelte'
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
