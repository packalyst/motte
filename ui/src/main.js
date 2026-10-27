import { mount } from 'svelte'
import './app.css'
import App from './App.svelte'
// Import directly from component path to avoid loading all KTUI components
import { KTModal } from '@keenthemes/ktui/components/modal'
import { KTTooltip } from '@keenthemes/ktui/components/tooltip'

// Make KTUI components globally available
window.KTModal = KTModal
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

// Touch has no hover: a tap fakes a mouseenter (iOS sends no mouseleave until the next tap
// elsewhere), so a hover tooltip would stay up, over a modal the tap opened. So hover tooltips
// don't show on a touch-only screen, nor right after a touch on one that also has a mouse or
// trackpad (tablets, many Android phones, touch laptops), whose media query says it can hover.
const touchOnly = window.matchMedia?.('(hover: none)').matches
let lastTouch = 0
document.addEventListener('pointerdown', (e) => { if (e.pointerType === 'touch') lastTouch = Date.now() }, { capture: true, passive: true })
document.addEventListener('show', (e) => {
  const el = e.target
  if (!(el instanceof Element) || !el.hasAttribute('data-kt-tooltip-initialized')) return
  if (!touchOnly && Date.now() - lastTouch > 1000) return
  if (KTTooltip.getInstance(el)?.getTriggerOption() === 'hover' && e.detail?.payload) e.detail.payload.cancel = true
})

const app = mount(App, {
  target: document.getElementById('app'),
})

// Register the service worker here (moved out of an inline <script> in index.html) so the
// page carries NO inline scripts and the CSP can use a strict script-src 'self'.
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {})
}

export default app
