<script>
  /**
   * AddMachineModal — enrolls a machine: pick the address the agent dials (a direct IP — mTLS can't
   * go through Cloudflare), mint a one-time token and show the one-command install. Only offered
   * while the agent listener is on (Settings → Agents); the token endpoint is admin-only. Once the
   * command is shown, the modal can only be closed after copying it, so it isn't lost.
   * With `machine`, it re-enrolls that machine instead: a one-time command (after a password
   * confirm) that gives it a new certificate as the same machine, history kept.
   */
  import { apiGet, apiPost, toast, openView, withStepUp, STEPUP_CANCELLED } from '../stores/app.js'
  import { copyToClipboard } from '$lib/utils/clipboard.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Modal from './Modal.svelte'
  import Select from './Select.svelte'

  let { open = $bindable(false), oncreated = undefined, machine = null } = $props()

  let ep = $state(null) // listener state: { enabled, hosts:[], domain, … }
  let selectedHost = $state('')
  let creating = $state(false)
  let token = $state(null) // { install_command, expires_at }
  let copied = $state(false)

  // Each opening re-reads the listener state and starts over.
  $effect(() => {
    if (!open) return
    token = null
    copied = false
    apiGet('/api/fleet/endpoints')
      .then((e) => { ep = e; selectedHost = e.hosts?.[0] || '' })
      .catch((e) => toast('Failed to load the agent listener: ' + e.message, 'error'))
  })

  async function generate() {
    creating = true
    try {
      if (machine) {
        const res = await withStepUp((extra) => apiPost('/api/fleet/machine/reenroll', { machine_id: machine.id, panel_host: selectedHost, ...extra }),
          { title: `Re-enroll ${machine.name}`, message: 'Confirm your password to issue a one-time re-enroll command.', confirmText: 'Issue command' })
        if (res === STEPUP_CANCELLED) return
        token = res
        return
      }
      // The machine's real name comes from its hostname at enroll; this label only names the token.
      const label = 'machine-' + Math.random().toString(36).slice(2, 8)
      const res = await withStepUp((extra) => apiPost('/api/fleet/token', { label, ttl_seconds: 3600, panel_host: selectedHost, ...extra }),
        { title: 'Add a machine', message: 'Confirm your password to create a one-time install command.', confirmText: 'Create command' })
      if (res === STEPUP_CANCELLED) return
      token = res
      oncreated?.()
    } catch (e) {
      toast('Failed to create token: ' + e.message, 'error')
    } finally {
      creating = false
    }
  }

  async function copy() {
    const ok = await copyToClipboard(token.install_command)
    toast(ok ? 'Install command copied' : 'Copy failed — select the command and copy it manually', ok ? 'success' : 'error')
    copied = true // unlocks closing either way: the command is on screen
  }

  function toSettings() {
    open = false
    openView('settings', 's=agents')
  }
</script>

<Modal bind:open title={token ? 'Install command' : machine ? `Re-enroll ${machine.name}` : 'Enroll a machine'} size="lg" dismissible={!token || copied} showClose={!token || copied}>
  {#if !ep}
    <div class="py-6 text-center text-sm text-muted-foreground">Loading…</div>
  {:else if !ep.enabled}
    <div class="flex items-start gap-3">
      <Icon name="lock" size={18} class="text-muted-foreground shrink-0 mt-0.5" />
      <div class="space-y-3 text-sm">
        <p><span class="font-medium text-foreground">The agent listener is off.</span>
          <span class="text-muted-foreground">Machines can't enroll or report until it's on.</span></p>
        <Button variant="outline" icon="settings" onclick={toSettings}>Settings → Agents</Button>
      </div>
    </div>
  {:else if token}
    <div class="space-y-3">
      <p class="text-sm text-muted-foreground">{#if machine}Run this on {machine.name}. It removes the agent's old identity and enrolls it again as this machine; the current certificate stops working. It works once and expires in an hour.{:else}Run this on the new machine. It works once and expires in an hour.{/if}</p>
      {#if token.install_command}
        <pre class="bg-muted rounded-lg p-3 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all border border-border">{token.install_command}</pre>
      {:else}
        <div class="text-sm text-warning">Pick an address the agent can reach, so the install command can be built.</div>
      {/if}
    </div>
  {:else}
    <div class="space-y-3">
      {#if machine}
        <p class="text-sm text-muted-foreground">Gives {machine.name} a new certificate as the same machine, keeping its history: for a machine whose certificate expired while it was offline, or one being reinstalled.</p>
      {/if}
      {#if ep.hosts?.length}
        <Select bind:value={selectedHost} size="lg" label="Agent connects to" options={ep.hosts.map((h) => ({ value: h, label: h }))} />
      {/if}
      <p class="text-[11px] text-muted-foreground">Pick a directly-reachable IP — the mTLS channel can't go through Cloudflare.</p>
      {#if !ep.domain}
        <p class="text-[11px] text-warning flex items-center gap-1.5"><Icon name="alert-triangle" size={13} />Set a panel domain (SSL_DOMAIN) — the install downloads over the domain's HTTPS.</p>
      {/if}
    </div>
  {/if}

  {#snippet footer()}
    {#if token}
      {#if !copied}<span class="mr-auto text-[11px] text-muted-foreground">Copy the command to continue.</span>{/if}
      <Button icon={copied ? 'check' : 'copy'} onclick={copied ? () => (open = false) : copy} disabled={!token.install_command}>{copied ? 'Close' : 'Copy command'}</Button>
    {:else}
      <Button variant="secondary" onclick={() => (open = false)}>Cancel</Button>
      {#if ep?.enabled}
        <Button icon="key" loading={creating} disabled={creating || !ep.domain} onclick={generate}>{machine ? 'Issue re-enroll command' : 'Generate install command'}</Button>
      {/if}
    {/if}
  {/snippet}
</Modal>
