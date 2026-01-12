<script>
  import { isOnline } from '../stores/network.js'
  import Icon from './Icon.svelte'
</script>

{#if !$isOnline}
  <div class="offline-overlay">
    <div class="offline-content">
      <div class="offline-icon">
        <Icon name="wifi-off" size={48} />
      </div>
      <h2>No Internet Connection</h2>
      <p>Please check your network and try again</p>
      <div class="offline-spinner">
        <Icon name="loader-2" size={20} class="animate-spin" />
        <span>Waiting for connection...</span>
      </div>
    </div>
  </div>
{/if}

<style>
  .offline-overlay {
    position: fixed;
    inset: 0;
    z-index: 9999;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0, 0, 0, 0.4);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    animation: fadeIn 0.3s ease-out;
  }

  .offline-content {
    text-align: center;
    color: white;
    padding: 2rem;
    max-width: 300px;
  }

  .offline-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 80px;
    height: 80px;
    border-radius: 50%;
    background: rgba(255, 255, 255, 0.1);
    margin-bottom: 1.5rem;
  }

  .offline-content h2 {
    font-size: 1.25rem;
    font-weight: 600;
    margin: 0 0 0.5rem 0;
  }

  .offline-content p {
    font-size: 0.875rem;
    opacity: 0.8;
    margin: 0 0 1.5rem 0;
  }

  .offline-spinner {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    font-size: 0.75rem;
    opacity: 0.7;
  }

  @keyframes fadeIn {
    from {
      opacity: 0;
    }
    to {
      opacity: 1;
    }
  }
</style>
