<script>
  import { onMount, onDestroy } from 'svelte'
  import Modal from './Modal.svelte'
  import Button from './Button.svelte'
  import Icon from './Icon.svelte'
  import { formatDate } from '../lib/utils/format.js'

  let {
    open = $bindable(false),
    location = null,
    onUpdate = null
  } = $props()

  let mapContainer = $state(null)
  let map = $state(null)
  let marker = $state(null)
  let L = $state(null)

  // Initialize map when modal opens
  $effect(() => {
    if (open && mapContainer && location && !map) {
      initMap()
    }
  })

  // Cleanup when modal closes
  $effect(() => {
    if (!open && map) {
      map.remove()
      map = null
      marker = null
    }
  })

  async function initMap() {
    if (!mapContainer || !location) return

    // Dynamic import of Leaflet
    const leaflet = await import('leaflet')
    L = leaflet.default

    // Import Leaflet CSS
    if (!document.querySelector('link[href*="leaflet.css"]')) {
      const link = document.createElement('link')
      link.rel = 'stylesheet'
      link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css'
      document.head.appendChild(link)
    }

    const lat = location.latitude
    const lng = location.longitude

    // Create map
    map = L.map(mapContainer).setView([lat, lng], 14)

    // Add OpenStreetMap tiles
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '© OpenStreetMap contributors',
      maxZoom: 19
    }).addTo(map)

    // Custom marker icon
    const markerIcon = L.divIcon({
      className: 'custom-marker',
      html: `<div class="marker-pin"></div>`,
      iconSize: [30, 42],
      iconAnchor: [15, 42]
    })

    // Add marker
    marker = L.marker([lat, lng], { icon: markerIcon }).addTo(map)

    // Add accuracy circle if available
    if (location.accuracy) {
      L.circle([lat, lng], {
        radius: location.accuracy,
        color: '#3b82f6',
        fillColor: '#3b82f6',
        fillOpacity: 0.1,
        weight: 2
      }).addTo(map)
    }

    // Fix map size after modal animation
    setTimeout(() => {
      map?.invalidateSize()
    }, 100)
  }

  function formatAccuracy(meters) {
    if (!meters) return 'Unknown'
    if (meters < 100) return `~${Math.round(meters)}m`
    if (meters < 1000) return `~${Math.round(meters / 10) * 10}m`
    return `~${(meters / 1000).toFixed(1)}km`
  }

  onDestroy(() => {
    if (map) {
      map.remove()
      map = null
    }
  })
</script>

<style>
  :global(.custom-marker) {
    background: transparent;
  }
  :global(.marker-pin) {
    width: 30px;
    height: 30px;
    border-radius: 50% 50% 50% 0;
    background: #3b82f6;
    position: absolute;
    transform: rotate(-45deg);
    left: 50%;
    top: 50%;
    margin: -20px 0 0 -15px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
  }
  :global(.marker-pin::after) {
    content: '';
    width: 14px;
    height: 14px;
    margin: 8px 0 0 8px;
    background: #fff;
    position: absolute;
    border-radius: 50%;
  }
</style>

<Modal bind:open title="Device Location" size="lg">
  {#if location}
    <div class="space-y-4">
      <!-- Map container -->
      <div
        bind:this={mapContainer}
        class="w-full h-[300px] rounded-lg overflow-hidden border border-border bg-muted"
      ></div>

      <!-- Location details -->
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div class="p-3 bg-muted/50 rounded-lg border border-dashed border-border">
          <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Device</div>
          <div class="text-sm font-medium text-foreground truncate">{location.device_name || 'Unknown'}</div>
        </div>
        <div class="p-3 bg-muted/50 rounded-lg border border-dashed border-border">
          <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Accuracy</div>
          <div class="text-sm font-medium text-foreground">{formatAccuracy(location.accuracy)}</div>
        </div>
        <div class="p-3 bg-muted/50 rounded-lg border border-dashed border-border">
          <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Latitude</div>
          <div class="text-sm font-mono text-foreground">{location.latitude?.toFixed(6)}</div>
        </div>
        <div class="p-3 bg-muted/50 rounded-lg border border-dashed border-border">
          <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Longitude</div>
          <div class="text-sm font-mono text-foreground">{location.longitude?.toFixed(6)}</div>
        </div>
      </div>

      <!-- Last updated -->
      <div class="flex items-center justify-between text-sm text-muted-foreground">
        <span class="flex items-center gap-2">
          <Icon name="clock" size={14} />
          Last updated: {formatDate(location.recorded_at)}
        </span>
      </div>
    </div>
  {:else}
    <div class="text-center py-8 text-muted-foreground">
      <Icon name="map-pin-off" size={32} class="mx-auto mb-2 opacity-50" />
      <p>No location data available</p>
    </div>
  {/if}

  {#snippet footer()}
    <Button variant="secondary" onclick={() => open = false}>Close</Button>
    {#if onUpdate}
      <Button icon="refresh" onclick={onUpdate}>Update Location</Button>
    {/if}
  {/snippet}
</Modal>
