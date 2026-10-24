/**
 * Svelte action for a full-screen `fixed` layer that has a text input (the console): keeps it
 * inside the part of the screen the on-screen keyboard leaves visible. iOS doesn't shrink the page
 * when the keyboard opens, it covers it (and scrolls the page to show the caret), so a fixed
 * inset-0 layer would sit half under the keyboard. While the visible area is shorter than the
 * window, the layer takes its height and top; otherwise its own classes apply unchanged.
 * `enabled` false leaves the node alone (a layer that isn't the fixed one).
 */
export function keyboardAware(node, enabled = true) {
  const vv = typeof window !== 'undefined' ? window.visualViewport : null
  if (!vv || !enabled) return {}
  const update = () => {
    const covered = vv.height < window.innerHeight - 1
    node.style.height = covered ? `${vv.height}px` : ''
    node.style.top = covered ? `${vv.offsetTop}px` : ''
    node.style.bottom = covered ? 'auto' : ''
  }
  vv.addEventListener('resize', update)
  vv.addEventListener('scroll', update)
  update()
  return {
    destroy() {
      vv.removeEventListener('resize', update)
      vv.removeEventListener('scroll', update)
    },
  }
}
