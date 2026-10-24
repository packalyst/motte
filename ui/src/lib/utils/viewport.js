/**
 * Svelte action for a full-screen `fixed` layer that has a text input (the console): keeps it
 * inside the part of the screen the on-screen keyboard leaves visible. iOS doesn't shrink the page
 * when the keyboard opens, it covers it (and scrolls the page to show the caret), so a fixed
 * inset-0 layer would sit half under the keyboard. While the visible area is shorter than the
 * window, the layer takes its height and top and is marked data-keyboard (the keyboard then covers
 * the home-indicator area, so no bottom safe-area padding is needed); otherwise its own classes
 * apply unchanged.
 * `enabled` false leaves the node alone (a layer that isn't the fixed one).
 */
export function keyboardAware(node, enabled = true) {
  const vv = typeof window !== 'undefined' ? window.visualViewport : null
  if (!vv) return {}
  const update = () => {
    const covered = vv.height < window.innerHeight - 1
    node.style.height = covered ? `${vv.height}px` : ''
    node.style.top = covered ? `${vv.offsetTop}px` : ''
    node.style.bottom = covered ? 'auto' : ''
    node.toggleAttribute('data-keyboard', covered)
  }
  // Listening only while enabled; turned off, the node is left as its own classes make it.
  const listen = (on) => {
    const method = on ? 'addEventListener' : 'removeEventListener'
    vv[method]('resize', update)
    vv[method]('scroll', update)
    if (on) {
      update()
      return
    }
    node.style.height = node.style.top = node.style.bottom = ''
    node.removeAttribute('data-keyboard')
  }
  if (enabled) listen(true)
  return {
    update(next = true) {
      if (next !== enabled) listen((enabled = next))
    },
    destroy() {
      if (enabled) listen(false)
    },
  }
}
