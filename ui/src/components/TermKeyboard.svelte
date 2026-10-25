<script>
  // On-screen keyboard for the console on phones, laid out like the iPhone's (letters / 123 / #+=,
  // shift and caps lock). Shown instead of the system keyboard, so iOS adds no "^ v ✓" bar.
  // Key labels come only from the layouts below: the library renders them as HTML, so never put
  // text from anywhere else into `layout` or `display`.
  import { onMount, onDestroy } from 'svelte'
  import Keyboard from 'simple-keyboard'
  import 'simple-keyboard/build/css/index.css'

  let { onkey } = $props()

  const layout = {
    default: ['q w e r t y u i o p', 'a s d f g h j k l', '{shift} z x c v b n m {bksp}', '{num} {space} {enter}'],
    shift: ['Q W E R T Y U I O P', 'A S D F G H J K L', '{shift} Z X C V B N M {bksp}', '{num} {space} {enter}'],
    num: ['1 2 3 4 5 6 7 8 9 0', '- / : ; ( ) $ & @ "', '{sym} . , ? ! \' {bksp}', '{abc} {space} {enter}'],
    sym: ['[ ] { } # % ^ * + =', '_ \\ | ~ < > ` € £ •', '{num2} . , ? ! \' {bksp}', '{abc} {space} {enter}'],
  }
  const display = {
    '{shift}': '⇧', '{bksp}': '⌫', '{enter}': 'return', '{space}': 'space',
    '{num}': '123', '{num2}': '123', '{sym}': '#+=', '{abc}': 'ABC',
  }
  const SEND = { '{bksp}': '\x7f', '{enter}': '\r', '{space}': ' ' }

  let el
  let kb
  let caps = false // shift locked (double tap)
  let lastShift = 0

  function setLayout(name) {
    kb.setOptions({ layoutName: name })
    el.classList.toggle('caps', caps)
  }
  function press(b) {
    if (b === '{shift}') {
      const now = Date.now()
      const cur = kb.options.layoutName
      if (cur === 'shift' && now - lastShift < 350) caps = true // double tap: caps lock
      else if (cur === 'shift') caps = false
      lastShift = now
      return setLayout(cur === 'shift' && !caps ? 'default' : 'shift')
    }
    if (b === '{num}' || b === '{num2}') return setLayout('num')
    if (b === '{sym}') return setLayout('sym')
    if (b === '{abc}') return setLayout('default')
    onkey?.(SEND[b] ?? b)
    if (kb.options.layoutName === 'shift' && !caps) setLayout('default') // shift is one letter, like iOS
    if (b === '{space}' && kb.options.layoutName !== 'default' && kb.options.layoutName !== 'shift') setLayout('default')
  }

  onMount(() => {
    kb = new Keyboard(el, {
      layout, display, layoutName: 'default', mergeDisplay: false,
      onKeyPress: press,
      useTouchEvents: true, preventMouseDownDefault: true, stopMouseDownPropagation: true,
      physicalKeyboardHighlight: false, theme: 'hg-theme-default ios-kb',
    })
  })
  onDestroy(() => kb?.destroy())
</script>

<div bind:this={el} class="select-none"></div>

<style>
  /* iPhone dark keyboard */
  :global(.ios-kb.hg-theme-default) {
    background: #1c1c1e; padding: 5px 3px 3px; border-radius: 0; font-family: -apple-system, system-ui, sans-serif;
  }
  :global(.ios-kb .hg-row) { gap: 6px; margin-bottom: 8px !important; padding: 0 3px; }
  :global(.ios-kb .hg-row:last-child) { margin-bottom: 2px !important; }
  :global(.ios-kb .hg-row .hg-button:not(:last-child)) { margin-right: 0 !important; }
  :global(.ios-kb .hg-button) {
    height: 36px; border-radius: 5px; border: 0; box-shadow: 0 1px 0 rgba(0,0,0,.45);
    background: #6b6b6e; color: #fff; font-size: 19px; font-weight: 400; position: relative;
    -webkit-tap-highlight-color: transparent; padding: 0;
  }
  :global(.ios-kb .hg-functionBtn) { background: #464649; font-size: 15px; }
  :global(.ios-kb .hg-button.hg-activeButton) { background: #8e8e93; }
  :global(.ios-kb .hg-functionBtn.hg-activeButton) { background: #8e8e93; }
  /* row 2 (letters) is inset like iOS; the bottom row's keys have fixed widths */
  :global(.ios-kb .hg-row:nth-child(2)) { padding: 0 20px; }
  :global(.ios-kb.hg-layout-num .hg-row:nth-child(2)), :global(.ios-kb.hg-layout-sym .hg-row:nth-child(2)) { padding: 0 3px; }
  :global(.ios-kb [data-skbtn="{shift}"]), :global(.ios-kb [data-skbtn="{bksp}"]) { max-width: 44px; margin-right: 8px !important; }
  :global(.ios-kb [data-skbtn="{bksp}"]) { margin: 0 0 0 8px !important; font-size: 20px; }
  :global(.ios-kb [data-skbtn="{sym}"]), :global(.ios-kb [data-skbtn="{num2}"]) { max-width: 44px; margin-right: 8px !important; }
  :global(.ios-kb.hg-layout-num .hg-row:nth-child(3) .hg-standardBtn), :global(.ios-kb.hg-layout-sym .hg-row:nth-child(3) .hg-standardBtn) { max-width: 52px; }
  :global(.ios-kb [data-skbtn="{num}"]), :global(.ios-kb [data-skbtn="{abc}"]) { max-width: 46px; }
  :global(.ios-kb [data-skbtn="{enter}"]) { max-width: 92px; }
  :global(.ios-kb [data-skbtn="{space}"]) { background: #6b6b6e; }
  :global(.ios-kb.hg-layout-shift [data-skbtn="{shift}"]) { background: #fff; color: #000; }
  :global(.caps.ios-kb [data-skbtn="{shift}"]) { box-shadow: inset 0 -3px 0 #000; }
</style>
