<script>
  /**
   * OtpInput - 6-digit OTP code input with auto-focus and auto-submit
   *
   * Props:
   * - value: bindable string value
   * - onComplete: callback when all 6 digits entered
   * - size: 'sm' | 'md' | 'lg' (default: 'md')
   * - disabled: disable all inputs
   */
  let {
    value = $bindable(''),
    onComplete,
    size = 'md',
    disabled = false
  } = $props()

  const sizes = {
    md: 'w-9 h-11 text-base',
    lg: 'w-10 h-12 text-lg',
  }

  function handleInput(e, i) {
    const val = e.target.value.replace(/\D/g, '')
    const arr = value.split('')
    arr[i] = val
    value = arr.join('').slice(0, 6)

    if (val && i < 5) {
      e.target.nextElementSibling?.focus()
    }

    if (value.length === 6 && onComplete) {
      onComplete(value)
    }
  }

  function handleKeydown(e, i) {
    if (e.key === 'Backspace' && !value[i] && i > 0) {
      e.target.previousElementSibling?.focus()
    }
  }

  function handlePaste(e) {
    e.preventDefault()
    const paste = (e.clipboardData?.getData('text') || '').replace(/\D/g, '').slice(0, 6)
    value = paste

    if (paste.length === 6 && onComplete) {
      onComplete(paste)
    }
  }
</script>

<div class="flex  gap-2">
  {#each Array(6) as _, i}
    <input
      type="text"
      maxlength="1"
      inputmode="numeric"
      pattern="[0-9]"
      class="otp-input {sizes[size]}"
      value={value[i] || ''}
      {disabled}
      oninput={(e) => handleInput(e, i)}
      onkeydown={(e) => handleKeydown(e, i)}
      onpaste={handlePaste}
    />
  {/each}
</div>
