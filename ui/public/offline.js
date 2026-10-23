// Offline page (served by sw.js when a page load fails): reload once the panel answers again.
// It probes with a plain fetch, which the service worker passes straight to the network.
const status = document.getElementById('status')

async function reachable() {
  try {
    const res = await fetch('/', { cache: 'no-store' })
    return res.ok
  } catch {
    return false
  }
}

async function retry() {
  status.textContent = 'Checking…'
  if (await reachable()) return location.reload()
  status.textContent = 'Still offline · retrying automatically'
}

document.getElementById('retry').addEventListener('click', retry)
window.addEventListener('online', retry)
setTimeout(retry, 1500) // a brief blip (VPN or IP switch) recovers on its own
setInterval(retry, 10000)
