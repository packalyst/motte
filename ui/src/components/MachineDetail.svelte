<script>
  /**
   * MachineDetail — the per-machine hub, laid out WebTerm-style: a header (status, live
   * CPU/MEM/load, primary actions) beside a left sub-nav rail of capabilities (Overview /
   * Sessions / Files / Docker / Diagnostics / Forwards / Services / Network / Security /
   * Maintenance / Host / AI). The open sub-page is kept in the URL hash (#m=<id>&s=<sub>) so a
   * refresh returns to it. All state, handlers and the live WS subscription live once in this
   * container; panels only re-home the existing cards — no gate, handler or data path changes.
   */
  import { onMount } from 'svelte'
  import { get } from 'svelte/store'
  import { apiGet, apiPost, toast, confirm, stepUpConfirm, currentUser, currentView, consoleTarget, consoleReturn } from '../stores/app.js'
  import { consoleSessions, openConsoleEvents, refreshSessions } from '../lib/consoleEvents.js'
  import { subscribe, unsubscribe, fleetStore, wsConnected } from '../stores/websocket.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import Badge from './Badge.svelte'
  import Input from './Input.svelte'
  import EmptyState from './EmptyState.svelte'
  import Modal from './Modal.svelte'
  import Gauge from './Gauge.svelte'
  import SessionCard from './SessionCard.svelte'
  import RecordingPlayer from './RecordingPlayer.svelte'
  import UPlotChart from './UPlotChart.svelte'
  import { timeAgo, formatBytes } from '$lib/utils/format.js'
  import { usageColor, sevVariant, statusInfo, round, fmtUptime } from '$lib/fleet.js'

  let { machine, latestAgent = null, onback, ondeleted, onviewcves } = $props()

  // --- Browser console (point 7) ---
  const ROLE_RANK = { viewer: 1, operator: 2, admin: 3, owner: 4 }
  const canOpenConsole = $derived((ROLE_RANK[$currentUser?.role] || 0) >= ROLE_RANK.operator)
  const canManageConsole = $derived((ROLE_RANK[$currentUser?.role] || 0) >= ROLE_RANK.admin)
  // Local mirrors (toggled optimistically from the API response), re-synced when the parent hands
  // in a fresher machine.
  let consoleEnabled = $state(false)
  let consoleRecord = $state(false)
  $effect.pre(() => {
    consoleEnabled = machine.console_enabled
    consoleRecord = machine.console_record
  })
  let consoleBusy = $state(false)
  // openConsole navigates to the standalone console page (not an overlay), opening the given session
  // as a tab there — or a fresh session when none is passed. The target is a one-shot the console
  // page consumes on arrival.
  // `panel` (files | docker | diag | forwards) opens that console panel on arrival.
  function openConsole(session = null, panel = null) {
    if (!consoleEnabled) {
      toast('Console is disabled for this machine', 'error')
      return
    }
    consoleTarget.set({
      machine_id: machine.id,
      machine_name: machine.name,
      session,
      label: session ? liveSessions.find((s) => s.id === session)?.label : null,
      fresh: !session,
      panel,
    })
    consoleReturn.set({ view: 'fleet', hash: 'm=' + encodeURIComponent(machine.id) }) // close → back to this machine
    currentView.set('console')
  }

  // Resumable sessions (tmux) the caller owns on this host — drives the Sessions tab's reattach
  // list. A session survives a browser drop, so this lets you climb back into it after a reload.
  // This machine's live sessions come from the shared console-events WS (pushed, no polling).
  const liveSessions = $derived($consoleSessions.filter((s) => s.machine_id === machine.id))
  async function killSession(s) {
    const ok = await confirm({
      title: 'Close session',
      message: `Close Session ${s.label || ''} on ${machine.name}? Anything running in it is terminated.`,
      variant: 'destructive', confirmText: 'Close',
    })
    if (!ok) return
    try {
      await apiPost('/api/fleet/console/kill', { machine_id: machine.id, session: s.id })
      toast('Session closed', 'success') // the WS pushes the updated list
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function setConsole(enabled) {
    let password = '', totp = ''
    if (enabled) {
      const r = await stepUpConfirm({
        title: 'Enable console',
        description: `A remote interactive shell on ${machine.name} is powerful. Re-authenticate to enable it.`,
      })
      if (!r?.confirmed) return
      password = r.password
      totp = r.totp
    } else if (!(await confirm({ title: 'Disable console', message: `Disable the console on ${machine.name}? Any live sessions are closed.`, variant: 'primary', confirmText: 'Disable' }))) {
      return
    }
    await applyConsole(enabled, consoleRecord, password, totp, enabled ? 'Console enabled' : 'Console disabled')
  }

  // Recording policy (WebTerm model): Off, or Always — every session on this machine recorded, with
  // no per-session switch. Changing it while the console is on re-authenticates (turning it OFF
  // weakens the audit trail); it applies to sessions opened from now on.
  async function setRecording(next) {
    if (next === consoleRecord) return
    let password = ''
    let totp = ''
    if (consoleEnabled) {
      const r = await stepUpConfirm({
        title: next ? 'Record all sessions' : 'Stop recording sessions',
        description: next
          ? `Every console session on ${machine.name} will be recorded from now on. Re-authenticate to confirm.`
          : `New console sessions on ${machine.name} will no longer be recorded. Re-authenticate to confirm.`,
      })
      if (!r?.confirmed) return
      password = r.password
      totp = r.totp
    }
    await applyConsole(consoleEnabled, next, password, totp, next ? 'Recording all sessions' : 'Recording off')
  }

  async function applyConsole(enabled, record, password, totp, okMsg) {
    consoleBusy = true
    try {
      const res = await apiPost('/api/fleet/console/toggle', {
        machine_id: machine.id, enabled, record, currentPassword: password, totpCode: totp,
      })
      consoleEnabled = res.enabled
      consoleRecord = res.record
      toast(okMsg, 'success')
    } catch (e) {
      toast(e.message || 'Could not update console', 'error')
    } finally {
      consoleBusy = false
    }
  }

  // Session recordings on this machine (own; admins see everyone's). Reloaded when the Sessions tab
  // opens and whenever the live-session set changes (a session ending finalizes its recording).
  let recordings = $state([])
  let retentionDays = $state(30)
  let playingRec = $state(null)
  async function loadRecordings() {
    try {
      const res = await apiGet('/api/fleet/console/recordings?machine_id=' + encodeURIComponent(machine.id))
      recordings = res.recordings || []
      retentionDays = res.retentionDays || retentionDays
    } catch {
      recordings = []
    }
  }
  // Admin only. One prompt is both the confirmation and the re-authentication (the server asks for it
  // every time — no grace window for erasing a recording); the deletion itself is audited.
  async function deleteRecording(rec) {
    const r = await stepUpConfirm({
      title: 'Delete recording',
      message: `Delete ${rec.title} by ${rec.user} on ${machine.name}?`,
      description: 'It is gone for good — copies of the file left anywhere become unreadable. The deletion is kept in the audit log. Re-authenticate to confirm.',
      confirmText: 'Delete', variant: 'destructive',
    })
    if (!r?.confirmed) return
    try {
      await apiPost('/api/fleet/console/recording/delete', {
        machine_id: machine.id, name: rec.name, currentPassword: r.password, totpCode: r.totp || '',
      })
      recordings = recordings.filter((x) => x.name !== rec.name)
      toast('Recording deleted', 'success')
    } catch (e) {
      toast(e.message || 'Could not delete the recording', 'error')
    }
  }

  function downloadRecording(rec) {
    const a = document.createElement('a') // same-origin GET: the session cookie authenticates it
    a.href = `/api/fleet/console/recording?machine_id=${encodeURIComponent(machine.id)}&name=${encodeURIComponent(rec.name)}`
    a.download = rec.name
    a.click()
  }

  // Machine tags — drive operator/viewer scoping. Editing is admin+ (backend-enforced).
  let tags = $state([])
  $effect.pre(() => { tags = [...(machine.tags || [])] })
  let newTag = $state('')
  async function saveTags(next) {
    try {
      await apiPost('/api/fleet/machine/tags', { machine_id: machine.id, tags: next })
      tags = next
      toast('Tags updated', 'success')
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }
  function addTag() {
    const t = newTag.trim()
    newTag = ''
    if (!t || tags.includes(t)) return
    saveTags([...tags, t])
  }
  const removeTag = (t) => saveTags(tags.filter((x) => x !== t))

  // Self-update landed in agent 0.1.20; older agents can't be updated from the panel.
  const MIN_SELFUPDATE = '0.1.20'
  // Compare dotted numeric versions ("0.1.20"): -1 a<b, 0 equal, 1 a>b.
  function cmpVer(a, b) {
    const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number)
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pa[i] || 0) - (pb[i] || 0)
      if (d) return d < 0 ? -1 : 1
    }
    return 0
  }
  // Agent-version state for the Agent card: current vs latest published.
  const agentUpdate = $derived.by(() => {
    const cur = report?.agent
    if (!cur || !latestAgent) return { state: 'unknown', cur }        // no data / GitHub unreachable
    if (cmpVer(cur, latestAgent) >= 0) return { state: 'current', cur }
    if (cmpVer(cur, MIN_SELFUPDATE) < 0) return { state: 'reinstall', cur, latest: latestAgent }
    return { state: 'updatable', cur, latest: latestAgent }          // self-update will work
  })

  let report = $state(null)
  let loading = $state(true)
  let blockIP = $state('')

  const st = $derived(statusInfo(machine))
  const dryRun = $derived(report?.dry_run ?? true)
  const m = $derived(report?.metrics || {})
  const cves = $derived(report?.cves || null)
  const intr = $derived(report?.intrusion || null)
  const facts = $derived(report?.facts || null)

  // --- Sub-nav (WebTerm-style left rail; horizontal scroller on mobile) ---
  // Badge the Security item with the count that actually needs action now (critical+high CVEs).
  const secBadge = $derived(((cves?.counts?.CRITICAL || 0) + (cves?.counts?.HIGH || 0)) || undefined)
  // `soon` items are capabilities not built yet (AI), shown with an honest placeholder — no fake
  // data, no backend call. Files / Docker / Diagnostics / Forwards are live console panels.
  const navList = $derived([
    { id: 'overview', label: 'Overview', icon: 'dashboard' },
    { id: 'sessions', label: 'Sessions', icon: 'terminal-2' },
    { id: 'files', label: 'Files', icon: 'folder' },
    { id: 'docker', label: 'Docker', icon: 'brand-docker' },
    { id: 'diagnostics', label: 'Diagnostics', icon: 'stethoscope' },
    { id: 'forwards', label: 'Forwards', icon: 'arrows-exchange' },
    { id: 'services', label: 'Services', icon: 'stack-2' },
    { id: 'network', label: 'Network', icon: 'network' },
    { id: 'security', label: 'Security', icon: 'shield-lock', badge: secBadge },
    { id: 'maintenance', label: 'Maintenance', icon: 'tool' },
    { id: 'host', label: 'Host', icon: 'server' },
    { id: 'ai', label: 'AI tools', icon: 'sparkles', soon: true },
  ])
  const navIds = ['overview', 'sessions', 'files', 'docker', 'diagnostics', 'forwards', 'services', 'network', 'security', 'maintenance', 'host', 'ai']

  // Remember the open sub-page in the URL hash (#m=<id>&s=<sub>) so a refresh lands back on it.
  // We only touch the `s` param (MachinesView owns `m`) and use replaceState so switching
  // sub-pages doesn't fire hashchange — that would re-run the parent's hash reconciler.
  function readSub() {
    if (typeof window === 'undefined') return 'overview'
    const s = new URLSearchParams(window.location.hash.slice(1)).get('s')
    return s && navIds.includes(s) ? s : 'overview'
  }
  let activeTab = $state(readSub())
  function go(id) {
    activeTab = id
    if (typeof window === 'undefined') return
    const p = new URLSearchParams(window.location.hash.slice(1))
    if (id && id !== 'overview') p.set('s', id)
    else p.delete('s')
    const q = p.toString()
    history.replaceState(history.state, '', window.location.pathname + (q ? '#' + q : ''))
  }

  // Keep the resumable-session list fresh while the Sessions tab is open by subscribing to the shared
  // console-events WS (it pushes updates on open/close; no polling). A refresh asks for a live list.
  $effect(() => {
    if (activeTab !== 'sessions' || !consoleEnabled || !canOpenConsole) return
    const release = openConsoleEvents()
    refreshSessions()
    return release
  })
  // Recordings: load when the Sessions tab opens, and again whenever the live-session set changes —
  // a session starting or ending flips its recording's "live" state / finalizes it. (Recordings stay
  // listable after the console is disabled, so this doesn't require consoleEnabled.)
  $effect(() => {
    if (activeTab !== 'sessions' || !canOpenConsole) return
    liveSessions.length
    loadRecordings()
  })

  // kernel-maintenance job status (absent unless a kernel update has run). Each phase
  // maps to a dot color + human label so a long, reboot-spanning job is legible.
  const kernel = $derived(report?.kernel || null)
  const kernelPhase = {
    installing:     { dot: 'bg-info',        label: 'Installing new kernel' },
    reboot_pending: { dot: 'bg-warning',     label: 'Reboot pending' },
    cleanup_pending:{ dot: 'bg-warning',     label: 'Rebooting & cleaning up' },
    done:           { dot: 'bg-success',     label: 'Kernel up to date' },
    failed:         { dot: 'bg-destructive', label: 'Kernel update failed' },
  }
  const kphase = $derived(kernel ? (kernelPhase[kernel.phase] || { dot: 'bg-muted-foreground', label: kernel.phase }) : null)

  // On-host CrowdSec bans (most severe first). File-integrity (FIM) changes ride their own
  // out-of-band feed (fleet_fim) and open in a modal — the report only carries the count.
  const feed = $derived.by(() =>
    (intr?.decisions || []).map((d) => ({
      tone: 'crit', body: `Banned ${d.value}`, meta: d.scenario || d.type || 'ban',
    }))
  )
  // Per-filesystem usage (df-style, live) and running-service memory — both from the agent facts.
  const disks = $derived(facts?.disks || [])
  const services = $derived(facts?.services || null)
  // Longest top-service bar is scaled to the heaviest consumer in the list.
  const svcMax = $derived(Math.max(1, ...(services?.top || []).map((s) => s.mem || 0)))

  // FIM change count comes from the periodic report; the full list is fetched on demand.
  const fimCount = $derived(facts?.fim_count || 0)
  let fimOpen = $state(false)
  let fimEvents = $state([])
  let fimTotal = $state(0)
  let fimLoading = $state(false)
  async function openFim() {
    fimOpen = true
    if (fimEvents.length) return // keep what's loaded until the modal is reopened stale
    fimLoading = true
    try {
      const res = await apiGet('/api/fleet/fim?machine_id=' + encodeURIComponent(machine.id) + '&limit=500')
      fimEvents = res?.events || []
      fimTotal = res?.total || fimEvents.length
    } catch { fimEvents = [] } finally { fimLoading = false }
  }

  let commands = $state([])
  // machine-level CVE roll-up (unique CVEs, affected packages, fixable) — the report's cves
  // summary only has raw findings + severity, so we pull the richer numbers from the panel.
  let cveSummary = $state(null)
  // One request returns { report, commands } (same shape as the live WS push).
  async function loadReport() {
    try {
      const res = await apiGet('/api/fleet/report?id=' + encodeURIComponent(machine.id))
      report = res?.report ?? null
      if (res?.commands) commands = res.commands
    } catch { report = null } finally { loading = false }
  }
  // CVE summary only changes on a rescan, so it's refetched only when a new scan lands (a
  // report arrives with a newer scanned_at) — never on a timer.
  async function loadCves() {
    try { cveSummary = (await apiGet('/api/fleet/cves/groups?machine_id=' + encodeURIComponent(machine.id)))?.summary || null } catch { /* keep last */ }
  }
  const load = () => loadReport()
  const refresh = () => { loadReport(); loadCves() }

  // Usage history — CPU/mem/disk over time, averaged into 5-min buckets on the panel
  // (the report only carries the live snapshot). `stat` flips the lines between the
  // bucket average and its peak; both come in one payload so the toggle never refetches.
  let histRange = $state('24h')
  let histStat = $state('avg')
  let histPoints = $state([])
  let histLoading = $state(false)
  async function loadHistory() {
    histLoading = true
    try {
      const res = await apiGet(`/api/fleet/metrics?id=${encodeURIComponent(machine.id)}&range=${histRange}`)
      histPoints = res?.points || []
    } catch { histPoints = [] } finally { histLoading = false }
  }
  // Refetch when the range (or the machine) changes; runs once on mount too.
  $effect(() => { histRange; machine.id; loadHistory() })

  const histSeries = [
    { label: 'CPU', stroke: '--cpu' },
    { label: 'Memory', stroke: '--mem' },
    { label: 'Disk', stroke: '--tx' },
  ]
  // uPlot columnar shape: [xs, cpu, mem, disk] pulled from the chosen stat (avg|max).
  const chartData = $derived.by(() => {
    const p = histPoints
    if (!p.length) return []
    const k = histStat === 'max' ? 'max' : 'avg'
    return [
      p.map((d) => d.t),
      p.map((d) => d[`cpu_${k}`]),
      p.map((d) => d[`mem_${k}`]),
      p.map((d) => d[`disk_${k}`]),
    ]
  })

  onMount(() => {
    refresh()             // initial HTTP populate
    subscribe('fleet')    // ask the panel to push this machine's reports over WS

    // Live updates: the panel broadcasts each agent check-in. Apply the pushed report for
    // THIS machine instantly (no polling while the socket is up); refresh the command log,
    // and refetch the CVE roll-up only when the scan timestamp changed.
    const unsub = fleetStore.subscribe((msg) => {
      if (!msg || msg.machine_id !== machine.id) return
      // Command log now rides the push (report broadcast + queue/ack broadcasts),
      // so no more polling /api/fleet/machine/commands on every check-in.
      if (msg.commands) commands = msg.commands
      if (!msg.report) return
      const prevScan = report?.cves?.scanned_at
      report = msg.report
      loading = false
      if (msg.report?.cves?.scanned_at && msg.report.cves.scanned_at !== prevScan) loadCves()
    })

    // Fallback poll ONLY while the WS is disconnected (much lighter than the old 10s timer).
    const t = setInterval(() => { if (!get(wsConnected)) load() }, 20000)
    return () => { unsub(); clearInterval(t); unsubscribe('fleet') }
  })

  const cmdStatus = { pending: 'text-warning', delivered: 'text-info', done: 'text-success', error: 'text-destructive' }

  async function cmd(type, payload = null, opts = {}) {
    const ok = await confirm({
      title: `${opts.title || type} · ${machine.name}`,
      message: opts.message || `Queue "${type}" for ${machine.name}? It runs on the machine's next check-in (~10s).`,
      confirmText: opts.confirmText || 'Queue',
      variant: opts.variant || 'primary',
      alert: opts.alert || false,
    })
    if (!ok) return

    const endpoint = opts.endpoint || '/api/fleet/command'
    const base = opts.endpoint ? { machine_id: machine.id } : { machine_id: machine.id, type, payload }
    const send = async (extra = {}) => {
      const res = await apiPost(endpoint, { ...base, ...extra })
      toast(opts.done ? opts.done(res) : `${type} queued`, 'success')
      if (opts.after) opts.after()
    }

    try {
      await send()
    } catch (e) {
      // Destructive (confirm-tier) commands require step-up re-authentication: the panel
      // answers 428 until the operator's current password is supplied. Prompt and retry once.
      if (e.status === 428) {
        const su = await stepUpConfirm({
          title: `Confirm "${opts.title || type}"`,
          message: `This is a sensitive action on ${machine.name}. Re-enter your credentials to authorize it.`,
          confirmText: 'Authorize', variant: 'destructive',
        })
        if (!su?.confirmed || !su?.password) return
        try {
          await send({ currentPassword: su.password, totpCode: su.totp || '' })
        } catch (e2) {
          toast('Failed: ' + e2.message, 'error')
        }
        return
      }
      toast('Failed: ' + e.message, 'error')
    }
  }

  async function blockOn() {
    const ip = blockIP.trim()
    if (!ip) return
    await cmd('block', { ip }, { title: 'Block IP', message: `Block ${ip} on ${machine.name}?`, after: () => (blockIP = '') })
  }

  const pushBlocks = () => cmd('sync-blocks', null, {
    endpoint: '/api/fleet/push-blocks', title: 'Push / update panel blocklist',
    message: `Push the panel's entire explicit blocklist (manual + auto-blocked IPs, ranges, and country/ASN CIDRs) onto ${machine.name}? It REPLACES the machine's panel-blocklist set (a rule separate from CrowdSec/manual bans), so re-pushing just updates it.`,
    done: (r) => `Replacing panel blocklist on ${machine.name} with ${r.count} entries`,
  })
  const clearBlocks = () => cmd('clear-blocks', null, {
    endpoint: '/api/fleet/clear-blocks', title: 'Clear panel blocklist', variant: 'destructive', confirmText: 'Clear',
    message: `Empty the panel-pushed blocklist on ${machine.name}? CrowdSec and manual blocks are NOT affected — only the entries you pushed from the panel are removed.`,
    done: () => `Clearing panel blocklist on ${machine.name}`,
  })
  const applyUpdates = () => cmd('apply-updates', null, { title: 'Apply updates', message: `Run system package updates on ${machine.name}? OS-package CVEs are fixed by this; a kernel CVE also needs a reboot.` })
  const setDryRun = (enabled) => cmd('set-dry-run', { enabled }, {
    title: enabled ? 'Switch to dry-run' : 'Go live',
    message: enabled
      ? `Put ${machine.name} in DRY-RUN? It will LOG firewall/update actions instead of applying them.`
      : `Take ${machine.name} LIVE? It will enforce firewall blocks and apply updates for real.`,
    confirmText: enabled ? 'Dry-run' : 'Go live', variant: enabled ? 'primary' : 'destructive',
  })
  const rescan = () => cmd('rescan', null, { title: 'Rescan', message: `Re-run the Trivy CVE scan on ${machine.name} now?` })
  const updateAgent = () => cmd('update-agent', null, {
    title: 'Update agent',
    message: `Update the wgscout agent on ${machine.name}${agentUpdate.cur && agentUpdate.latest ? ` from ${agentUpdate.cur} to ${agentUpdate.latest}` : ' to the latest release'}? It downloads the release binary, verifies its checksum, checks it runs, swaps it in (keeping a backup), and restarts the agent — a brief reconnect, no reboot.`,
    confirmText: 'Update agent',
  })

  // Unblock a single IP (the typed one, or a specific one from the enforced list).
  async function unblockOn(ip = null) {
    const t = (ip ?? blockIP).trim()
    if (!t) return
    await cmd('unblock', { ip: t }, { title: 'Unblock IP', message: `Unblock ${t} on ${machine.name}?`, after: () => { if (ip == null) blockIP = '' } })
  }
  const updateKernel = () => cmd('update-kernel', null, {
    title: 'Update kernel', variant: 'destructive', confirmText: 'Update & reboot', alert: true,
    message: `Run the full kernel update on ${machine.name}? It installs the newest kernel, AUTO-REBOOTS to activate, then purges old kernels and rescans. The host is briefly offline. Honors dry-run.`,
  })
  const restartAgents = () => cmd('restart', { target: 'tools' }, { title: 'Restart sub-agents', message: `Restart the CrowdSec / osquery sub-agents on ${machine.name}? Safe — no reboot.` })
  const rebootHost = () => cmd('restart', { target: 'host' }, {
    title: 'Reboot host', variant: 'destructive', confirmText: 'Reboot', alert: true,
    message: `REBOOT ${machine.name}? The whole host restarts and is offline for a bit.`,
  })
  const setLogLevel = (level) => cmd('set-log-level', { level }, {
    title: level === 'debug' ? 'Enable debug logs' : 'Return to quiet logs',
    message: level === 'debug'
      ? `Turn on verbose debug logging on ${machine.name}? CrowdSec and osquery go to info level and the agent logs more — useful for troubleshooting. It restarts the sub-agents. Switch back to quiet when you're done.`
      : `Return ${machine.name} to quiet logging (warnings & errors only)? It restarts the sub-agents.`,
    confirmText: level === 'debug' ? 'Enable debug' : 'Go quiet',
  })

  // WG cell: pubkey (shortened) + assigned IP when we have it — one combined "WG" fact.
  const wgVal = $derived(
    [machine.wg_pubkey ? (machine.wg_pubkey.length > 14 ? machine.wg_pubkey.slice(0, 14) + '…' : machine.wg_pubkey) : '', machine.wg_ip || '']
      .filter(Boolean).join(' · '),
  )
  // Host facts shown in the Host tab (icon · label · value). 12 → a clean 3×4 grid.
  const hostFacts = $derived([
    ['device-desktop', 'OS', [facts?.os?.name, facts?.os?.version].filter(Boolean).join(' ')],
    ['box', 'Kernel', facts?.kernel || ''],
    ['cpu', 'CPU', facts?.system?.cpu_brand],
    ['database', 'RAM', facts?.system?.physical_memory ? formatBytes(Number(facts.system.physical_memory)) : ''],
    ['world', 'Server IP', facts?.system?.primary_ip || ''],
    ['clock-hour-4', 'Timezone', facts?.system?.timezone || ''],
    ['clock', 'Uptime', m.uptime ? fmtUptime(m.uptime) : ''],
    ['server', 'Host', report?.host],
    ['activity', 'Last report', report?.time ? timeAgo(report.time) : ''],
    ['calendar', 'Enrolled', machine.enrolled_at ? timeAgo(machine.enrolled_at) : ''],
    ['certificate', 'Cert', (machine.cert_fp || '').replace('sha256:', '').slice(0, 12)],
    ['key', 'WG', wgVal],
  ])
  // IPs this host is currently enforcing a block on (from the live report).
  const blockedIPs = $derived(report?.blocked || [])
  const panelBlocked = $derived(report?.panel_blocked ?? 0)
  // A push/clear is in flight until the agent runs it — disable the buttons meanwhile.
  const blocklistBusy = $derived(commands.some((c) => (c.type === 'sync-blocks' || c.type === 'clear-blocks') && (c.status === 'pending' || c.status === 'delivered')))

  async function del() {
    await cmd(null, null, {
      endpoint: '/api/fleet/machine/delete', title: `Delete ${machine.name}`,
      message: `Delete ${machine.name} for good? Its certificate is invalidated immediately — the agent can no longer connect and must re-enroll with a fresh token to return. Queued commands are removed too.`,
      confirmText: 'Delete machine', variant: 'destructive', alert: true,
      done: () => `${machine.name} deleted`, after: () => ondeleted?.(),
    })
  }

  const toneDot = { crit: 'bg-destructive', warn: 'bg-warning', ok: 'bg-success' }

  // Well-known port → service label (client-side; the agent only sends addr/port/proto).
  const PORT_NAMES = {
    22: 'SSH', 53: 'DNS', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS', 123: 'NTP',
    3306: 'MySQL', 5432: 'Postgres', 6379: 'Redis', 27017: 'MongoDB', 11211: 'Memcached',
    9100: 'node_exporter', 8420: 'CrowdSec', 51820: 'WireGuard', 3000: 'app', 8080: 'HTTP-alt',
  }
  const proto = (p) => (p === '6' ? 'tcp' : p === '17' ? 'udp' : p || '')
  const scopeOf = (addr) =>
    !addr || addr === '0.0.0.0' || addr === '::' ? 'exposed'
    : addr === '127.0.0.1' || addr === '::1' ? 'local' : 'iface'
  // Group listening ports by exposure so "what's open to the world" reads at a glance.
  const portGroups = $derived.by(() => {
    const g = { exposed: [], iface: [], local: [] }
    for (const p of facts?.ports || []) (g[scopeOf(p.address)] ||= []).push(p)
    return g
  })
  const scopeMeta = {
    exposed: { label: 'Exposed (all interfaces)', tone: 'text-warning', dot: 'bg-warning' },
    iface: { label: 'Bound to an interface', tone: 'text-info', dot: 'bg-info' },
    local: { label: 'Local only', tone: 'text-success', dot: 'bg-success' },
  }
</script>

<!-- one listening-port pill with a service name when we know it -->
{#snippet portPill(p)}
  <span class="inline-flex items-center gap-1 font-mono text-[11px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
    <span class="text-foreground">{p.address || '*'}:{p.port}</span>
    <span class="opacity-60">/{proto(p.protocol)}</span>
    {#if PORT_NAMES[+p.port]}<span class="not-italic text-[9px] px-1 rounded bg-background text-muted-foreground">{PORT_NAMES[+p.port]}</span>{/if}
  </span>
{/snippet}

<!-- card header: icon tile + title + source subtitle -->
{#snippet head(icon, title, sub, tint = 'text-muted-foreground')}
  <div class="flex items-center gap-2.5 mb-3">
    <span class="w-9 h-9 rounded-lg grid place-items-center bg-muted border border-border shrink-0 {tint}"><Icon name={icon} size={17} /></span>
    <div class="min-w-0">
      <div class="text-[13px] font-semibold text-foreground">{title}</div>
      {#if sub}<div class="text-[11px] text-muted-foreground truncate">{sub}</div>{/if}
    </div>
  </div>
{/snippet}

<!-- persistent plain-language note (mockup's dashed footer) -->
{#snippet note(text)}
  <div class="text-[11px] text-muted-foreground mt-3 pt-3 border-t border-dashed border-border">{text}</div>
{/snippet}

<!-- A capability that runs as a console panel: explain it, then open the console straight onto that
     panel — resuming your live session on this host if there is one, else a fresh shell. Same gates
     as the console itself (enabled + operator+), with the matching explanation when they're not met. -->
{#snippet consoleTool(icon, title, sub, desc, panel, label)}
  <div class="bg-card border border-border rounded-xl p-4">
    {@render head(icon, title, sub, 'text-primary')}
    {#if canOpenConsole && consoleEnabled}
      <p class="text-sm text-muted-foreground mb-3">{desc}</p>
      <Button variant="primary" size="sm" {icon} onclick={() => openConsole(liveSessions[0]?.id ?? null, panel)}>{label}</Button>
    {:else if canManageConsole && !consoleEnabled}
      <p class="text-sm text-muted-foreground">Enable the console (on the Sessions tab) first — this runs over the same gated channel.</p>
    {:else if !consoleEnabled}
      <p class="text-sm text-muted-foreground">The console is disabled for this machine, so this is off.</p>
    {:else}
      <p class="text-sm text-muted-foreground">You don't have permission to use the console on this machine.</p>
    {/if}
    {@render note('Runs over the console channel, so it needs the console enabled and the operator+ role — the same gates. Read-only shares cannot use it.')}
  </div>
{/snippet}

<!-- placeholder for a capability that isn't wired yet — honest "what this will do", no fake data -->
{#snippet soon(icon, title, desc)}
  <div class="bg-card border border-border rounded-xl p-8">
    <EmptyState {icon} {title} description={desc} />
    <div class="mt-4 flex justify-center">
      <span class="text-[10px] uppercase tracking-wide text-muted-foreground border border-dashed border-border rounded px-2 py-1">Coming soon</span>
    </div>
  </div>
{/snippet}

<div class="space-y-4">
  <!-- Header: status · name · live chips · primary actions -->
  <div class="flex items-start gap-3 flex-wrap">
    <button onclick={onback} title="Back to fleet"
      class="h-8 w-8 grid place-items-center rounded-lg border border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground transition cursor-pointer shrink-0">
      <Icon name="arrow-left" size={16} />
    </button>
    <span class="w-2.5 h-2.5 rounded-full shrink-0 mt-2 {st.dot}"></span>
    <div class="min-w-[150px] flex-1">
      <div class="text-lg font-semibold text-foreground truncate leading-tight">{machine.name || machine.id}</div>
      <div class="text-[11px] text-muted-foreground font-mono flex flex-wrap items-center gap-x-2 gap-y-0.5">
        <span>{st.label}</span>
        {#if machine.last_seen}<span>· seen {timeAgo(machine.last_seen)}</span>{/if}
        {#if report?.agent}<span>· agent {report.agent}</span>{/if}
        {#if report}
          <span class="text-foreground">· CPU {round(m.cpu)}%</span>
          <span class="text-foreground">MEM {round(m.mem)}%</span>
          <span class="text-foreground">load {(m.load1 ?? 0).toFixed(2)}</span>
        {/if}
      </div>
    </div>
    <!-- live/dry-run pill -->
    {#if report}
      <span class="hidden sm:flex items-center gap-1.5 text-xs mt-1.5 shrink-0">
        <span class="w-2 h-2 rounded-full {dryRun ? 'bg-warning' : 'bg-success'}"></span>
        <span class="font-medium">{dryRun ? 'Dry-run' : 'Live'}</span>
      </span>
    {/if}
    <!-- grouped actions -->
    <div class="flex items-center rounded-lg border border-border overflow-hidden shrink-0 divide-x divide-border">
      <button onclick={refresh} class="flex items-center gap-1.5 px-3 py-1.5 text-xs text-muted-foreground hover:bg-muted hover:text-foreground transition cursor-pointer">
        <Icon name="refresh" size={14} />Refresh
      </button>
      {#if canOpenConsole && consoleEnabled}
        <button onclick={() => openConsole()} class="flex items-center gap-1.5 px-3 py-1.5 text-xs text-primary hover:bg-primary/10 transition cursor-pointer">
          <Icon name="terminal-2" size={14} />Console
        </button>
      {/if}
      <button onclick={del} class="flex items-center gap-1.5 px-3 py-1.5 text-xs text-destructive hover:bg-destructive/10 transition cursor-pointer">
        <Icon name="trash" size={14} />Delete
      </button>
    </div>
  </div>

  {#if loading && !report}
    <div class="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">Loading report…</div>
  {:else if !report}
    <div class="bg-card border border-border rounded-xl p-8">
      <EmptyState icon="clock" title="No report yet"
        description="This machine hasn't checked in with a report. It appears once the agent's first metrics/scan cycle completes." />
    </div>
  {:else}
    <div class="flex flex-col lg:flex-row gap-4">
      <!-- sub-nav: horizontal scroller on mobile, vertical rail on desktop -->
      <nav class="flex lg:flex-col gap-1 overflow-x-auto lg:overflow-visible lg:w-52 shrink-0 pb-2 lg:pb-0 border-b lg:border-b-0 lg:border-r border-border lg:pr-3">
        {#each navList as item}
          <button type="button" onclick={() => go(item.id)}
            class="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm whitespace-nowrap shrink-0 transition cursor-pointer {activeTab === item.id ? 'bg-primary/10 text-primary font-medium' : 'text-muted-foreground hover:bg-muted hover:text-foreground'}">
            <Icon name={item.icon} size={16} class="shrink-0" />
            <span>{item.label}</span>
            {#if item.badge !== undefined}<span class="lg:ml-auto"><Badge variant="destructive" size="sm">{item.badge}</Badge></span>{/if}
            {#if item.soon}<span class="lg:ml-auto text-[9px] uppercase tracking-wide text-muted-foreground/70 border border-border rounded px-1 py-0.5">soon</span>{/if}
          </button>
        {/each}
      </nav>

      <div class="min-w-0 flex-1 space-y-4">
    {#if activeTab === 'overview'}
      <!-- Gauges -->
      <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div class="bg-card border border-border rounded-xl p-4 flex flex-col items-center justify-center">
          <Gauge value={round(m.cpu)} label="CPU" size={150} />
          <div class="text-[11px] text-muted-foreground mt-1">utilization</div>
        </div>
        <div class="bg-card border border-border rounded-xl p-4 flex flex-col items-center justify-center">
          <Gauge value={round(m.mem)} label="Memory" size={150} />
          <div class="text-[11px] text-muted-foreground mt-1 tabular-nums">
            {#if m.mem_total}{formatBytes(m.mem_used)} / {formatBytes(m.mem_total)}{:else}&nbsp;{/if}
          </div>
        </div>
        <div class="bg-card border border-border rounded-xl p-4 flex flex-col items-center justify-center">
          <Gauge value={round(m.disk)} label="Disk" size={150} />
          <div class="text-[11px] text-muted-foreground mt-1 tabular-nums">
            {#if m.disk_total}{formatBytes(m.disk_used)} / {formatBytes(m.disk_total)}{:else}&nbsp;{/if}
          </div>
        </div>
        <div class="bg-card border border-border rounded-xl p-4 flex flex-col items-center justify-center text-center">
          <div class="text-[10px] uppercase tracking-wide text-muted-foreground">Load</div>
          <div class="text-4xl font-bold tabular-nums leading-none mt-2">{(m.load1 ?? 0).toFixed(2)}</div>
          <div class="text-[11px] text-muted-foreground mt-2">uptime {fmtUptime(m.uptime)}</div>
        </div>
      </div>

      <!-- Security glance → Security tab -->
      <button type="button" onclick={() => go('security')}
        class="w-full bg-card border border-border rounded-xl p-3 flex items-center gap-3 text-left hover:bg-muted/30 transition cursor-pointer">
        <span class="w-9 h-9 rounded-lg grid place-items-center bg-muted border border-border shrink-0 {secBadge || feed.length || fimCount ? 'text-warning' : 'text-success'}"><Icon name="shield-lock" size={17} /></span>
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1 flex-1 min-w-0 text-sm">
          <span class="flex items-center gap-1.5"><Icon name="package" size={14} class="text-muted-foreground" /><span class="font-medium">{(cves?.total ?? 0).toLocaleString()}</span><span class="text-muted-foreground">CVEs</span>{#if secBadge}<Badge variant="destructive" size="sm">{secBadge} crit/high</Badge>{/if}</span>
          <span class="flex items-center gap-1.5"><Icon name="ban" size={14} class="text-muted-foreground" /><span class="font-medium">{feed.length}</span><span class="text-muted-foreground">bans</span></span>
          <span class="flex items-center gap-1.5"><Icon name="file-search" size={14} class="text-muted-foreground" /><span class="font-medium">{fimCount}</span><span class="text-muted-foreground">file changes</span></span>
        </div>
        <Icon name="chevron-right" size={16} class="text-muted-foreground shrink-0" />
      </button>

      <!-- Usage history -->
      <div class="bg-card border border-border rounded-xl p-4">
        <div class="flex items-center gap-2.5 mb-3 flex-wrap">
          <span class="w-9 h-9 rounded-lg grid place-items-center bg-muted border border-border shrink-0 text-muted-foreground"><Icon name="chart-line" size={17} /></span>
          <div class="min-w-0 flex-1">
            <div class="text-[13px] font-semibold text-foreground">Usage history</div>
            <div class="text-[11px] text-muted-foreground truncate">CPU · memory · disk over time</div>
          </div>
          <!-- average vs peak (both stored; no refetch) -->
          <div class="inline-flex items-center gap-0.5 rounded-lg bg-muted/60 border border-border p-0.5 text-xs shrink-0">
            {#each [['avg', 'Avg'], ['max', 'Peak']] as [v, l]}
              <button onclick={() => histStat = v} class="px-2.5 py-1 rounded-md transition cursor-pointer {histStat === v ? 'bg-card shadow-sm text-foreground font-medium' : 'text-muted-foreground hover:text-foreground'}">{l}</button>
            {/each}
          </div>
          <!-- time range -->
          <div class="inline-flex items-center gap-0.5 rounded-lg bg-muted/60 border border-border p-0.5 text-xs shrink-0">
            {#each ['24h', '7d', '30d'] as r}
              <button onclick={() => histRange = r} class="px-2.5 py-1 rounded-md transition cursor-pointer {histRange === r ? 'bg-card shadow-sm text-foreground font-medium' : 'text-muted-foreground hover:text-foreground'}">{r}</button>
            {/each}
          </div>
        </div>
        {#if histLoading && histPoints.length === 0}
          <div class="h-[188px] grid place-items-center text-xs text-muted-foreground">Loading history…</div>
        {:else if histPoints.length < 2}
          <div class="h-[188px] grid place-items-center text-center text-xs text-muted-foreground px-4">
            Not enough history yet — usage is charted as the agent checks in (every&nbsp;~15s). Check back in a few minutes.
          </div>
        {:else}
          <UPlotChart data={chartData} series={histSeries} height={188} yRange={[0, 100]} yUnit="%" />
        {/if}
        {@render note('Averaged into 5-minute buckets, kept for 30 days. “Peak” shows the highest reading in each bucket — a brief CPU or disk spike the average smooths away.')}
      </div>

      <!-- Disk space (per-filesystem, live) -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('database', 'Disk space', 'mounted filesystems · live', 'text-info')}
        {#if disks.length}
          <div class="space-y-2.5">
            {#each disks as d}
              {@const pct = d.total ? Math.round((d.used / d.total) * 100) : 0}
              <div class="text-xs">
                <div class="flex items-center gap-2 mb-1">
                  <span class="font-mono truncate">{d.mount}</span>
                  <span class="text-[10px] text-muted-foreground">{d.fstype}</span>
                  <span class="ml-auto text-muted-foreground tabular-nums shrink-0">{formatBytes(d.used)} / {formatBytes(d.total)}</span>
                  <span class="w-9 text-right tabular-nums font-medium shrink-0">{pct}%</span>
                </div>
                <span class="block h-2 rounded-full bg-muted overflow-hidden">
                  <span class="block h-full rounded-full {usageColor(pct)}" style="width:{Math.min(pct, 100)}%"></span>
                </span>
              </div>
            {/each}
          </div>
        {:else}
          <div class="text-sm text-muted-foreground py-1">No filesystem usage reported.</div>
        {/if}
        {@render note('On-disk filesystems only (tmpfs and other virtual mounts are hidden). A filesystem near 100% is what fills logs and stalls services — watch the fullest one.')}
      </div>
    {/if}

    {#if activeTab === 'sessions'}
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('terminal-2', 'Console', 'interactive shell to this machine', 'text-primary')}
        {#if canOpenConsole || canManageConsole}
          <div class="flex flex-wrap items-center gap-2">
            {#if canOpenConsole && consoleEnabled}
              <Button variant="primary" size="sm" icon="terminal-2" onclick={() => openConsole()}>New session</Button>
              <Button variant="ghost" size="sm" icon="refresh" onclick={refreshSessions}>Refresh</Button>
            {/if}
            {#if canManageConsole}
              <Button variant={consoleEnabled ? 'outline' : 'primary'} size="sm" icon="power" loading={consoleBusy} onclick={() => setConsole(!consoleEnabled)}>
                {consoleEnabled ? 'Disable console' : 'Enable console'}
              </Button>
              <!-- Recording policy: Off / Always (every session on this machine), never per session. -->
              <div class="flex items-center gap-1.5 ml-auto text-[11px] text-muted-foreground">
                <span>Recording</span>
                <div class="inline-flex rounded-lg border border-border overflow-hidden">
                  {#each [[false, 'Off'], [true, 'Always']] as [val, label] (label)}
                    <button type="button" disabled={consoleBusy} onclick={() => setRecording(val)}
                      class="px-2.5 py-1 cursor-pointer transition {consoleRecord === val ? (val ? 'bg-destructive/15 text-destructive font-medium' : 'bg-muted text-foreground font-medium') : 'hover:bg-muted/60'}">
                      {#if val}<span class="inline-block w-1.5 h-1.5 rounded-full bg-destructive mr-1 align-middle"></span>{/if}{label}
                    </button>
                  {/each}
                </div>
              </div>
            {/if}
            {#if !consoleEnabled && !canManageConsole}
              <span class="text-sm text-muted-foreground">Console is disabled for this machine.</span>
            {/if}
          </div>

          <!-- Resumable sessions: a shell survives a browser drop (tmux), so reattach after a reload. -->
          {#if consoleEnabled && canOpenConsole}
            <div class="mt-3 pt-3 border-t border-border">
              <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Your live sessions</div>
              {#if liveSessions.length}
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {#each liveSessions as s (s.id)}
                    <SessionCard session={s} machine={{ id: machine.id, name: machine.name }}
                      onresume={(x) => openConsole(x.id)} onkill={killSession} />
                  {/each}
                </div>
              {:else}
                <div class="text-xs text-muted-foreground py-1">No resumable sessions yet. Start one — it survives a disconnect, so you can reattach after a reload or dropped connection.</div>
              {/if}
            </div>
          {/if}

          <!-- Recorded sessions (one continuous recording per session; own, or everyone's for admins). -->
          {#if canOpenConsole && (consoleRecord || recordings.length)}
            <div class="mt-3 pt-3 border-t border-border">
              <div class="flex items-center gap-2 mb-2">
                <span class="text-[10px] uppercase tracking-wide text-muted-foreground">Recordings</span>
                <span class="text-[10px] text-muted-foreground/70">· kept {retentionDays} days · output only, keystrokes are never recorded</span>
                <button type="button" onclick={loadRecordings} title="Refresh" class="ml-auto p-1 rounded text-muted-foreground hover:text-foreground cursor-pointer"><Icon name="refresh" size={13} /></button>
              </div>
              {#if recordings.length}
                <div class="divide-y divide-border border border-border rounded-lg overflow-hidden">
                  {#each recordings as rec (rec.name)}
                    <div class="flex items-center gap-3 px-3 py-2 text-sm">
                      <Icon name="player-play" size={14} class="text-muted-foreground shrink-0" />
                      <div class="min-w-0 flex-1">
                        <div class="flex items-center gap-2">
                          <span class="font-medium truncate">{rec.title}</span>
                          {#if rec.live}<Badge variant="danger" size="sm">● recording</Badge>{/if}
                          {#if rec.capped}<Badge variant="warning" size="sm">size limit reached</Badge>{/if}
                        </div>
                        <div class="text-[11px] text-muted-foreground truncate">
                          {rec.user} · {new Date(rec.started * 1000).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                          · {fmtUptime(Math.max(0, rec.ended - rec.started))} · {formatBytes(rec.size)}
                        </div>
                      </div>
                      <Button variant="ghost" size="xs" icon="player-play" onclick={() => (playingRec = rec)}>Play</Button>
                      <button type="button" onclick={() => downloadRecording(rec)} title="Download .cast"
                        class="p-1.5 rounded text-muted-foreground hover:text-foreground hover:bg-muted cursor-pointer"><Icon name="download" size={14} /></button>
                      {#if canManageConsole}
                        <button type="button" onclick={() => deleteRecording(rec)} disabled={rec.live}
                          title={rec.live ? 'Still recording — stop the session first' : 'Delete recording'}
                          class="p-1.5 rounded text-muted-foreground hover:text-destructive hover:bg-muted disabled:opacity-40 disabled:cursor-not-allowed"><Icon name="trash" size={14} /></button>
                      {/if}
                    </div>
                  {/each}
                </div>
              {:else}
                <div class="text-xs text-muted-foreground py-1">No recordings yet. With recording on, every session on this machine is recorded from the moment it opens.</div>
              {/if}
            </div>
          {/if}
        {:else}
          <div class="text-sm text-muted-foreground">You don't have permission to use the console.</div>
        {/if}
        {@render note('A remote interactive shell is gated: enable per-machine (admin, re-authenticate), then open (operator+). Sessions resume server-side (tmux) — reattach from the list above after a reload. With recording set to Always, every session is recorded (output only) for audit; operators see their own recordings, admins see everyone’s, and each playback is logged. Recordings are encrypted on disk; only an admin can delete one (re-authenticated, logged).')}
      </div>
    {/if}
    {#if playingRec}
      <RecordingPlayer machineId={machine.id} rec={playingRec} onclose={() => (playingRec = null)} />
    {/if}

    {#if activeTab === 'services'}
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('stack-2', 'Services', `${services?.active ?? 0} running · top memory`, 'text-info')}
        {#if services?.top?.length}
          <div class="space-y-2.5">
            {#each services.top as s}
              <div class="text-xs">
                <div class="flex items-center gap-2 mb-1">
                  <span class="font-mono truncate">{s.name}</span>
                  <span class="ml-auto text-muted-foreground tabular-nums shrink-0">{formatBytes(s.mem)}</span>
                </div>
                <span class="block h-2 rounded-full bg-muted overflow-hidden">
                  <span class="block h-full rounded-full bg-info" style="width:{Math.max(2, Math.round((s.mem / svcMax) * 100))}%"></span>
                </span>
              </div>
            {/each}
          </div>
        {:else}
          <div class="text-sm text-muted-foreground py-1">No systemd services reported.</div>
        {/if}
        {#if services?.agent}
          <div class="flex items-center gap-2 mt-3 pt-3 border-t border-border text-xs">
            <Icon name="robot" size={15} class="text-muted-foreground" />
            <span class="text-muted-foreground">wgscout agent</span>
            <span class="ml-auto tabular-nums font-medium">{formatBytes(services.agent.mem)}</span>
            <span class="text-muted-foreground tabular-nums">· {(services.agent.cpu || 0).toFixed(1)}% CPU</span>
          </div>
        {/if}
        {@render note('Running systemd services and the five using the most memory (from each service’s cgroup), plus what the wgscout agent itself uses — so the monitoring’s own footprint is visible.')}
      </div>
    {/if}

    {#if activeTab === 'network'}
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('network', 'Exposure', 'listening ports · osquery', 'text-info')}
        {#if facts?.ports?.length}
          <div class="space-y-2">
            {#each ['exposed', 'iface', 'local'] as scope}
              {#if portGroups[scope].length}
                <div>
                  <div class="flex items-center gap-1.5 mb-1">
                    <span class="w-1.5 h-1.5 rounded-full {scopeMeta[scope].dot}"></span>
                    <span class="text-[11px] font-medium {scopeMeta[scope].tone}">{scopeMeta[scope].label}</span>
                    <span class="text-[10px] text-muted-foreground">· {portGroups[scope].length}</span>
                  </div>
                  <div class="flex flex-wrap gap-1.5">
                    {#each portGroups[scope] as p}{@render portPill(p)}{/each}
                  </div>
                </div>
              {/if}
            {/each}
          </div>
        {:else}
          <div class="text-sm text-muted-foreground py-1">No listening ports reported.</div>
        {/if}
        {@render note('“Exposed” ports are open on all interfaces (reachable from the internet unless firewalled); “local” ones only from the box itself. An unexpected exposed port is worth a look.')}
      </div>
    {/if}

    {#if activeTab === 'security'}
      <!-- Vulnerabilities -->
      <div class="bg-card border border-border rounded-xl p-4">
        <div class="flex items-start gap-2.5 mb-3">
          <span class="w-9 h-9 rounded-lg grid place-items-center bg-muted border border-border shrink-0 text-warning"><Icon name="package" size={17} /></span>
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <span class="text-[13px] font-semibold text-foreground">Vulnerabilities</span>
              <span class="ml-auto text-[11px] text-muted-foreground shrink-0">
                {#if cveSummary}{cveSummary.unique_cves.toLocaleString()} CVEs · {cveSummary.packages.toLocaleString()} pkgs{:else}{(cves?.total ?? 0).toLocaleString()} findings{/if}{cves?.scanned_at ? ` · ${timeAgo(cves.scanned_at)}` : ''}
              </span>
            </div>
            <div class="text-[11px] text-muted-foreground">Trivy · OS packages + app lockfiles</div>
          </div>
        </div>
        {#if cves?.total}
          <div class="flex flex-wrap items-center gap-1.5">
            {#each ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as sev}
              {#if cves?.counts?.[sev]}<Badge variant={sevVariant(sev)} size="sm">{cves.counts[sev].toLocaleString()} {sev.toLowerCase()}</Badge>{/if}
            {/each}
            {#if cveSummary?.fixable}
              <span class="inline-flex items-center gap-1 text-xs ml-1"><Icon name="tool" size={13} class="text-success" /><span class="font-semibold text-foreground">{cveSummary.fixable.toLocaleString()}</span><span class="text-muted-foreground">fixable</span></span>
            {/if}
          </div>
        {:else}
          <div class="text-sm text-success flex items-center gap-2 py-1"><Icon name="circle-check" size={15} />No known vulnerabilities found.</div>
        {/if}
        <div class="flex items-center gap-2 mt-3 flex-wrap">
          {#if cves?.total}<Button variant="primary" size="sm" icon="list-details" onclick={() => onviewcves?.(machine)}>View all & fix</Button>{/if}
        </div>
        {@render note('Fixable OS-package CVEs clear via “Apply updates” on the Maintenance tab; kernel CVEs via “Update kernel”. “View all & fix” opens the full list grouped by OS/project to upgrade only selected packages.')}
      </div>

      <!-- Security events -->
      <div class="bg-card border rounded-xl p-4 {feed.length || fimCount ? 'border-destructive/40' : 'border-border'}">
        {@render head('shield-lock', 'Security events', 'CrowdSec bans + file-integrity changes', 'text-warning')}
        {#if feed.length}
          <div class="max-h-72 overflow-y-auto -mr-1 pr-1">
            {#each feed.slice(0, 100) as e}
              <div class="flex items-baseline gap-2.5 py-1.5 border-t border-border first:border-t-0 text-sm">
                <span class="w-1.5 h-1.5 rounded-full shrink-0 self-center {toneDot[e.tone]}"></span>
                <span class="flex-1 min-w-0 break-all"><span class="font-mono text-xs">{e.body}</span>{#if e.meta}<span class="text-muted-foreground text-xs"> — {e.meta}</span>{/if}</span>
                <span class="text-[9px] text-muted-foreground shrink-0">crowdsec</span>
              </div>
            {/each}
          </div>
        {:else}
          <div class="text-sm text-success flex items-center gap-2 py-2"><Icon name="circle-check" size={15} />No active bans.</div>
        {/if}
        <!-- FIM roll-up: count + drill-down (the full list rides its own /fim endpoint) -->
        <div class="flex items-center gap-2 mt-3 pt-3 border-t border-border">
          <Icon name="file-search" size={16} class={fimCount ? 'text-warning' : 'text-muted-foreground'} />
          <span class="text-sm flex-1 min-w-0">
            {#if fimCount}<span class="font-medium">{fimCount.toLocaleString()}</span> file-integrity change{fimCount === 1 ? '' : 's'}{:else}<span class="text-muted-foreground">No file-integrity changes</span>{/if}
          </span>
          {#if fimCount}<Button size="sm" variant="ghost" icon="eye" onclick={openFim}>View all</Button>{/if}
        </div>
        {@render note('CrowdSec bans attackers on-host automatically. File-integrity changes (a watched file changed) are the "someone got in" signals worth investigating.')}
      </div>

      <!-- Blocking -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('ban', 'Blocking', `${blockedIPs.length} IP${blockedIPs.length === 1 ? '' : 's'} blocked (CrowdSec + manual)`, 'text-destructive')}
        <div class="flex flex-wrap items-center gap-2">
          <div class="flex-1 min-w-[180px]">
            <Input bind:value={blockIP} prefixIcon="world" placeholder="IP to block / unblock" class="font-mono"
              onkeydown={(e) => e.key === 'Enter' && blockOn()} />
          </div>
          <Button variant="destructive" size="sm" icon="ban" onclick={blockOn} disabled={!blockIP.trim()}>Block</Button>
          <Button variant="outline" size="sm" icon="circle-check" onclick={() => unblockOn()} disabled={!blockIP.trim()}>Unblock</Button>
        </div>
        {#if blockedIPs.length}
          <div class="mt-3 max-h-48 overflow-y-auto -mr-1 pr-1">
            {#each blockedIPs as ip}
              <div class="flex items-center gap-2 py-1.5 border-t border-border first:border-t-0 text-sm">
                <Icon name="ban" size={13} class="text-destructive shrink-0" />
                <span class="font-mono truncate flex-1">{ip}</span>
                <button onclick={() => unblockOn(ip)} class="text-[11px] text-muted-foreground hover:text-foreground transition cursor-pointer shrink-0">unblock</button>
              </div>
            {/each}
          </div>
        {:else}
          <div class="mt-3 text-[12px] text-muted-foreground">No CrowdSec or manual blocks right now.</div>
        {/if}

        <!-- panel-pushed blocklist: a SEPARATE nftables set, replaced/cleared wholesale -->
        <div class="mt-3 pt-3 border-t border-border">
          <div class="flex items-center gap-2 flex-wrap">
            <Icon name="list" size={14} class="text-muted-foreground shrink-0" />
            <div class="min-w-0 flex-1">
              <div class="text-[13px] font-medium text-foreground">Panel blocklist</div>
              <div class="text-[11px] text-muted-foreground">
                {#if panelBlocked > 0}{panelBlocked.toLocaleString()} entr{panelBlocked === 1 ? 'y' : 'ies'} pushed · separate rule from bans{:else}Not pushed to this host yet{/if}
              </div>
            </div>
            <Button variant="outline" size="sm" icon="arrow-down" onclick={pushBlocks} loading={blocklistBusy} disabled={blocklistBusy}>{blocklistBusy ? 'Syncing…' : panelBlocked > 0 ? 'Update' : 'Push'}</Button>
            {#if panelBlocked > 0}<Button variant="ghost" size="sm" icon="trash" onclick={clearBlocks} disabled={blocklistBusy}>Clear</Button>{/if}
          </div>
        </div>
      </div>
    {/if}

    {#if activeTab === 'maintenance'}
      <!-- Agent + run state -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('robot', 'Agent', report?.agent ? `wgscout ${report.agent}` : 'wgscout')}
        <div class="flex flex-wrap items-center gap-3 text-xs">
          {#if agentUpdate.state === 'current'}
            <span class="inline-flex items-center gap-1 text-success"><Icon name="circle-check" size={13} /> up to date</span>
          {:else if agentUpdate.state === 'updatable'}
            <button onclick={updateAgent} class="inline-flex items-center gap-1 px-2 py-1 rounded-md bg-primary/10 text-primary hover:bg-primary/20 transition cursor-pointer font-medium">
              <Icon name="arrow-up" size={13} /> Update → {agentUpdate.latest}
            </button>
          {:else if agentUpdate.state === 'reinstall'}
            <span class="inline-flex items-center gap-1 text-warning cursor-help" data-kt-tooltip>
              <Icon name="alert-triangle" size={13} /> {agentUpdate.latest} available — reinstall
              <span data-kt-tooltip-content class="kt-tooltip hidden">This agent predates in-panel self-update (added in {MIN_SELFUPDATE}). Reinstall once via the install command to enable one-click updates.</span>
            </span>
          {/if}
          <span class="inline-flex items-center gap-1.5 ml-auto">
            <span class="w-2 h-2 rounded-full {dryRun ? 'bg-warning' : 'bg-success'}"></span>
            <span class="font-medium">{dryRun ? 'Dry-run' : 'Live'}</span>
            <span class="text-muted-foreground">{dryRun ? '— logs actions' : '— enforcing'}</span>
          </span>
          {#if dryRun}
            <Button variant="destructive" size="xs" icon="bolt" onclick={() => setDryRun(false)}>Go live</Button>
          {:else}
            <Button variant="outline" size="xs" icon="player-pause" onclick={() => setDryRun(true)}>Dry-run</Button>
          {/if}
        </div>

        {#if kernel && kphase}
          <div class="mt-3 flex items-start gap-2 rounded-lg border border-border bg-muted/40 px-2.5 py-2">
            <span class="w-2 h-2 rounded-full mt-1.5 shrink-0 {kphase.dot} {kernel.phase === 'installing' || kernel.phase === 'cleanup_pending' ? 'animate-pulse' : ''}"></span>
            <div class="min-w-0">
              <div class="text-xs font-medium flex items-center gap-1.5"><Icon name="cpu" size={12} /> {kphase.label}{#if kernel.target}<span class="font-mono text-[10px] text-muted-foreground">{kernel.target}</span>{/if}</div>
              {#if kernel.message}<div class="text-[11px] text-muted-foreground mt-0.5 break-words">{kernel.message}</div>{/if}
              {#if kernel.removed?.length}<div class="text-[10px] text-muted-foreground mt-0.5">Removed {kernel.removed.length} old package(s)</div>{/if}
            </div>
          </div>
        {/if}
      </div>

      <!-- Actions: patching + lifecycle -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('tool', 'Actions', 'patching · lifecycle')}
        <div class="space-y-2.5">
          <div>
            <div class="text-[10px] text-muted-foreground mb-1">Patching</div>
            <div class="flex flex-wrap gap-1.5">
              <Button variant="outline" size="xs" icon="download" onclick={applyUpdates}>Apply updates</Button>
              <Button variant="outline" size="xs" icon="cpu" onclick={updateKernel}>Update kernel</Button>
              <Button variant="outline" size="xs" icon="scan" onclick={rescan}>Rescan</Button>
            </div>
          </div>
          <div>
            <div class="text-[10px] text-muted-foreground mb-1">Lifecycle</div>
            <div class="flex flex-wrap gap-1.5">
              <Button variant="outline" size="xs" icon="refresh" onclick={restartAgents}>Restart agents</Button>
              {#if report?.log_level === 'debug'}
                <Button variant="outline" size="xs" icon="file-text" onclick={() => setLogLevel('quiet')}>Quiet logs</Button>
              {:else if report?.log_level}
                <Button variant="outline" size="xs" icon="file-text" onclick={() => setLogLevel('debug')}>Debug logs</Button>
              {/if}
              <Button variant="destructive" size="xs" icon="power" onclick={rebootHost}>Reboot host</Button>
            </div>
          </div>
        </div>
      </div>

      <!-- Recent commands -->
      {#if commands.length}
        <div class="bg-card border border-border rounded-xl p-4">
          {@render head('history', 'Recent commands', 'queued actions + results')}
          <div class="max-h-60 overflow-y-auto -mr-1 pr-1">
            {#each commands as c}
              <div class="flex items-center gap-2 py-1 border-t border-border first:border-t-0 text-xs">
                <span class="font-mono">{c.type}</span>
                {#if c.status === 'pending' || c.status === 'delivered'}<Icon name="loader-2" size={11} class="animate-spin {cmdStatus[c.status] || 'text-muted-foreground'}" />{/if}
                <span class="capitalize {cmdStatus[c.status] || 'text-muted-foreground'}">{c.status}</span>
                {#if c.result}<span class="text-muted-foreground truncate flex-1" title={c.result}>· {c.result}</span>{/if}
                <span class="text-[10px] text-muted-foreground ml-auto shrink-0">{timeAgo(c.done_at || c.created_at)}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}
    {/if}

    {#if activeTab === 'host'}
      <!-- Host facts -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('server', 'Host facts', 'os · hardware · identity')}
        <div class="grid grid-cols-2 sm:grid-cols-3 gap-px bg-border rounded-lg overflow-hidden border border-border">
          {#each hostFacts as [ic, k, v]}
            <div class="bg-card px-2.5 py-2 flex items-center gap-2 min-w-0">
              <Icon name={ic} size={14} class="text-muted-foreground shrink-0" />
              <div class="min-w-0">
                <div class="text-[9px] uppercase tracking-wide text-muted-foreground leading-tight">{k}</div>
                <div class="text-xs font-medium truncate {v ? '' : 'text-muted-foreground'}">{v || '—'}</div>
              </div>
            </div>
          {/each}
        </div>
        {#if facts?.sessions?.length}
          <div class="mt-3 pt-3 border-t border-border">
            <div class="text-[10px] uppercase tracking-wide text-muted-foreground mb-1">Login sessions</div>
            {#each facts.sessions as s}
              <div class="flex items-center gap-2 py-0.5 text-xs">
                <span class="w-1.5 h-1.5 rounded-full shrink-0 {s.active ? 'bg-success' : 'bg-muted-foreground/40'}" title={s.active ? 'active' : 'idle'}></span>
                <span class="font-mono text-foreground shrink-0">{s.user}</span>
                <span class="text-muted-foreground font-mono truncate">{s.host || s.tty || 'local'}</span>
                <span class="text-muted-foreground ml-auto shrink-0">{s.when ? timeAgo(s.when) : ''}</span>
              </div>
            {/each}
          </div>
        {/if}
      </div>

      <!-- Tags -->
      <div class="bg-card border border-border rounded-xl p-4">
        {@render head('tag', 'Tags', 'access scoping')}
        <div class="flex items-center gap-2 flex-wrap text-xs">
          {#each tags as t (t)}
            <span class="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-muted-foreground">
              {t}
              <button onclick={() => removeTag(t)} class="hover:text-destructive cursor-pointer" title="Remove tag"><Icon name="x" size={11} /></button>
            </span>
          {/each}
          <input bind:value={newTag} onkeydown={(e) => e.key === 'Enter' && addTag()} placeholder="add tag…"
            class="bg-transparent border-b border-dashed border-border text-xs w-24 focus:outline-none focus:border-primary" />
        </div>
        {@render note('Tags scope operator/viewer access — an operator can be limited to machines carrying a given tag. Editing tags is admin-only (enforced on the panel).')}
      </div>
    {/if}

    {#if activeTab === 'files'}
      {@render consoleTool('folder', 'File browser', 'browse · upload · download · edit · delete',
        'Browse, select, upload, download, edit and delete files on this host over the encrypted agent channel.', 'files', 'Open files')}
    {/if}
    {#if activeTab === 'docker'}
      {@render consoleTool('brand-docker', 'Docker', 'containers · logs · start / stop / restart',
        'List this host’s containers, read their logs and start, stop or restart them.', 'docker', 'Open Docker')}
    {/if}
    {#if activeTab === 'diagnostics'}
      {@render consoleTool('stethoscope', 'Diagnostics', 'ping · traceroute · DNS',
        'Check reachability and name resolution from this host’s point of view — useful when a peer or service “can’t be reached”.', 'diag', 'Open diagnostics')}
    {/if}
    {#if activeTab === 'forwards'}
      {@render consoleTool('arrows-exchange', 'Port forwards', 'reach a service this host can see',
        'Open a web service that only this host can reach (e.g. localhost:8080) in your browser, tunneled through the agent. Forwards are private to you and expire after 2 hours.', 'forwards', 'Open forwards')}
    {/if}
    {#if activeTab === 'ai'}
      {@render soon('sparkles', 'AI tools', 'Explain command output and suggest commands. Opt-in — it sends only the text you choose to an AI provider, so it stays off by default.')}
    {/if}
      </div>
    </div>
  {/if}
</div>

<!-- FILE-INTEGRITY DRILL-DOWN -->
<Modal bind:open={fimOpen} size="xl" title="File-integrity changes" bodyClass="p-0">
  {#if fimLoading}
    <div class="p-8 text-center text-muted-foreground text-sm">Loading…</div>
  {:else if fimEvents.length}
    <div class="px-4 py-2 text-xs text-muted-foreground border-b border-border">
      Showing {fimEvents.length.toLocaleString()} of {fimTotal.toLocaleString()} watched-file changes, most recent first.
    </div>
    <div class="max-h-[60vh] overflow-y-auto">
      <table class="w-full text-sm">
        <thead class="sticky top-0 bg-card">
          <tr class="text-left text-xs text-muted-foreground border-b border-border">
            <th class="font-medium px-4 py-2">Action</th>
            <th class="font-medium px-4 py-2">Path</th>
            <th class="font-medium px-4 py-2 text-right">When</th>
          </tr>
        </thead>
        <tbody>
          {#each fimEvents as e}
            <tr class="border-b border-border/60 align-top">
              <td class="px-4 py-1.5 whitespace-nowrap">
                <span class="w-1.5 h-1.5 rounded-full inline-block mr-1.5 align-middle {e.action === 'DELETED' ? 'bg-destructive' : 'bg-warning'}"></span>
                <span class="text-xs">{(e.action || 'CHANGED').toLowerCase()}</span>
              </td>
              <td class="px-4 py-1.5 font-mono text-xs break-all">{e.path}</td>
              <td class="px-4 py-1.5 text-right text-xs text-muted-foreground whitespace-nowrap">{e.time ? timeAgo(Number(e.time) ? new Date(Number(e.time) * 1000).toISOString() : e.time) : ''}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <div class="p-8 text-center text-success flex items-center justify-center gap-2 text-sm"><Icon name="circle-check" size={16} />No file-integrity changes recorded.</div>
  {/if}
</Modal>

