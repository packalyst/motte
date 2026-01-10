import { mount } from 'svelte'
import './app.css'
import App from './App.svelte'
// Import directly from component path to avoid loading all KTUI components
import { KTModal } from '@keenthemes/ktui/lib/esm/components/modal'
import { KTToast } from '@keenthemes/ktui/lib/esm/components/toast'
import { KTTooltip } from '@keenthemes/ktui/lib/esm/components/tooltip'

// Make KTUI components globally available
window.KTModal = KTModal
window.KTToast = KTToast
window.KTTooltip = KTTooltip
KTModal.init()

// Auto-initialize KTTooltip when new elements are added to the DOM
const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    if (mutation.type === 'childList' && mutation.addedNodes.length) {
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const tooltips = node.matches?.('[data-kt-tooltip]')
            ? [node]
            : node.querySelectorAll?.('[data-kt-tooltip]') || []
          tooltips.forEach(el => {
            if (!el._ktTooltipInit) {
              el._ktTooltipInit = true
              new KTTooltip(el)
            }
          })
        }
      })
    }
  }
})
observer.observe(document.body, { childList: true, subtree: true })

const app = mount(App, {
  target: document.getElementById('app'),
})

export default app
