<script>
  /**
   * MachineDetail — the per-machine hub, laid out WebTerm-style: a header (status, live
   * CPU/MEM/load, primary actions) beside a left sub-nav rail of capabilities (Overview /
   * Sessions / Files / Docker / Diagnostics / Services / Network / Security /
   * Maintenance / Host / AI). The open sub-page is kept in the URL hash (#m=<id>&s=<sub>) so a
   * refresh returns to it. All state, handlers and the live WS subscription live once in this
   * container; panels only re-home the existing cards — no gate, handler or data path changes.
   */
  import { onMount } from 'svelte'
  import { get } from 'svelte/store'
  import { apiGet, apiPost, toast, confirm, stepUpConfirm, withStepUp, STEPUP_CANCELLED, currentUser, hasRole, hashParam, setHashParam } from '../stores/app.js'
  import { consoleSessions, openConsoleEvents, refreshSessions, closeSession, openConsoleAt } from '../lib/consoleEvents.js'
  import { subscribe, unsubscribe, fleetStore, wsConnected } from '../stores/websocket.js'
  import Icon from './Icon.svelte'
  import Button from './Button.svelte'
  import AddMachineModal from './AddMachineModal.svelte'
  import Badge from './Badge.svelte'
  import Input from './Input.svelte'
  import EmptyState from './EmptyState.svelte'
  import Modal from './Modal.svelte'
  import Segmented from './Segmented.svelte'
  import Sparkline from './Sparkline.svelte'
  import SessionCard from './SessionCard.svelte'
  import TagEditor from './TagEditor.svelte'
  import Checkbox from './Checkbox.svelte'
  import SectionNav from './SectionNav.svelte'
  import RecordingList from './RecordingList.svelte'
  import UPlotChart from './UPlotChart.svelte'
  import { timeAgo, formatBytes, formatDate, formatExpiryDate } from '$lib/utils/format.js'
  import { usageColor, usageTone, statusInfo, round, fmtUptime, SEV } from '$lib/fleet.js'
  import ScanHistory from './ScanHistory.svelte'
  import ScanDialog from './ScanDialog.svelte'
  import JobProgress from './JobProgress.svelte'

  let { machine, latestAgent = null, onback, ondeleted, onviewcves } = $props()

  // --- Browser console (point 7) ---
  const canOpenConsole = $derived(hasRole($currentUser, 'operator'))
  const isAdmin = $derived(hasRole($currentUser, 'admin'))
  let reenrollOpen = $state(false) // the re-enroll dialog (a new certificate for this same machine)
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
  function openConsole(session = null) {
    if (!consoleEnabled) {
      toast('Console is disabled for this machine', 'error')
      return
    }
    openConsoleAt({
      machine_id: machine.id,
      machine_name: machine.name,
      session,
      label: session ? liveSessions.find((s) => s.id === session)?.label : null,
      fresh: !session,
    }, { view: 'clients', hash: 'm=' + encodeURIComponent(machine.id) }) // close → back to this machine
  }

  // Resumable sessions (tmux) the caller owns on this host — drives the Sessions tab's reattach
  // list. A session survives a browser drop, so this lets you climb back into it after a reload.
  // This machine's live sessions come from the shared console-events WS (pushed, no polling).
  const liveSessions = $derived($consoleSessions.filter((s) => s.machine_id === machine.id))
  const killSession = (s) => closeSession({ ...s, machine_id: machine.id }, machine.name)

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

  // Machine tags — drive operator/viewer scoping. Editing is admin+ (backend-enforced).
  let tags = $state([])
  $effect.pre(() => { tags = [...(machine.tags || [])] })
  async function saveTags(next) {
    await apiPost('/api/fleet/machine/tags', { machine_id: machine.id, tags: next })
    tags = next
  }

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
  // Agent-version state for the Agent card: current vs latest published. "Check for updates"
  // asks the panel to look again now (its answer is otherwise cached for 30 minutes).
  let checkedLatest = $state(null)
  let checkingLatest = $state(false)
  const latest = $derived(checkedLatest || latestAgent)
  const agentUpdate = $derived.by(() => {
    const cur = report?.agent
    if (!cur || !latest) return { state: 'unknown', cur }        // no data / GitHub unreachable
    if (cmpVer(cur, latest) >= 0) return { state: 'current', cur }
    if (cmpVer(cur, MIN_SELFUPDATE) < 0) return { state: 'reinstall', cur, latest }
    return { state: 'updatable', cur, latest }          // self-update will work
  })
  async function checkLatest() {
    checkingLatest = true
    try {
      checkedLatest = (await apiPost('/api/fleet/agent-version', {}))?.agent_version || checkedLatest
      if (!checkedLatest) toast('Couldn\'t reach the release page; try again later', 'error')
    } catch (e) { toast('Check failed: ' + (e?.message || e), 'error') } finally { checkingLatest = false }
  }

  let report = $state(null)
  let loading = $state(true)
  let blockIP = $state('')

  // Presence pushed live (online when the link connects/drops, last check-in) on top of the record
  // the page opened with.
  let live = $state({})
  const st = $derived(statusInfo({ ...machine, ...live }))
  const lastSeen = $derived(live.last_seen || machine.last_seen)
  const dryRun = $derived(report?.dry_run ?? true)
  const m = $derived(report?.metrics || {})
  const cves = $derived(report?.cves || null)
  const intr = $derived(report?.intrusion || null)
  const facts = $derived(report?.facts || null)

  // --- Sub-nav (WebTerm-style left rail; horizontal scroller on mobile) ---
  // Badge the Security item with the count that actually needs action now (critical+high CVEs).
  const secBadge = $derived(((cves?.counts?.CRITICAL || 0) + (cves?.counts?.HIGH || 0)) || undefined)
  // `soon` items are capabilities not built yet (AI), shown with an honest placeholder — no fake
  // data, no backend call. Files, Docker and diagnostics live inside the console itself.
  const navList = $derived([
    { id: 'overview', label: 'Overview', icon: 'dashboard' },
    { id: 'sessions', label: 'Sessions', icon: 'terminal-2' },
    { id: 'security', label: 'Security', icon: 'shield-lock', badge: secBadge },
    { id: 'maintenance', label: 'Maintenance', icon: 'tool' },
    { id: 'ai', label: 'AI tools', icon: 'sparkles', soon: true },
  ])
  const navIds = ['overview', 'sessions', 'security', 'maintenance', 'ai']

  // Remember the open sub-page in the URL hash (#m=<id>&s=<sub>) so a refresh lands back on it.
  // We only touch the `s` param (the clients page owns `m`) and use replaceState so switching
  // sub-pages doesn't fire hashchange — that would re-run the parent's hash reconciler.
  const sub = hashParam('s')
  let activeTab = $state(sub && navIds.includes(sub) ? sub : 'overview')
  function go(id) {
    activeTab = id
    setHashParam('s', id === 'overview' ? null : id)
  }

  // Keep the resumable-session list fresh while the Sessions tab is open by subscribing to the shared
  // console-events WS (it pushes updates on open/close; no polling). A refresh asks for a live list.
  $effect(() => {
    if (activeTab !== 'sessions' || !consoleEnabled || !canOpenConsole) return
    const release = openConsoleEvents()
    refreshSessions()
    return release
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
  // What the monitoring costs on this host, one row per part the agent runs (agent footprint)
  const FOOTPRINT = {
    agent: ['robot', 'Motte agent'],
    crowdsec: ['shield-lock', 'CrowdSec'],
    osquery: ['file-search', 'osquery · file watch'],
    scan: ['package', 'Vulnerability scan'],
    console: ['terminal-2', 'Console sessions'],
    maintenance: ['tool', 'Updates (apt)'],
  }
  const footprint = $derived(services?.footprint || null)
  const footprintTotal = $derived((footprint?.parts || []).reduce((t, p) => ({ mem: t.mem + (p.mem || 0), cpu: t.cpu + (p.cpu || 0) }), { mem: 0, cpu: 0 }))
  const scanRunning = $derived((footprint?.parts || []).some((p) => p.name === 'scan'))

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
  // Scans are on demand and run in the background on the machine; the report says when one runs.
  const scanning = $derived(!!report?.scanning)
  // The agent refuses installs, restarts and reboots while a scan runs (security commands still
  // go through), so those buttons wait for it too.
  const jobRunning = $derived(report?.job?.status === 'running') // a package job; one at a time
  // A finished job stays on screen for a while, then leaves (its outcome stays in Recent commands).
  const JOB_SHOWN_AFTER = 10 * 60 * 1000
  let nowMs = $state(Date.now())
  $effect(() => {
    if (!report?.job?.ended_at) return
    const t = setInterval(() => (nowMs = Date.now()), 30000)
    return () => clearInterval(t)
  })
  // A finished job's card can also be closed by hand (✕). Which one was closed is remembered in
  // this browser (a per-viewer convenience), so a refresh doesn't bring it back; the next job shows.
  const jobKey = $derived(report?.job ? `${machine.id}:${report.job.started_at}` : '')
  const JOB_CLOSED = 'motte.jobClosed'
  let jobClosed = $state((() => { try { return localStorage.getItem(JOB_CLOSED) || '' } catch { return '' } })())
  function closeJob() {
    jobClosed = jobKey
    try { localStorage.setItem(JOB_CLOSED, jobKey) } catch { /* private mode: closed for this visit only */ }
  }
  const jobShown = $derived(!!report?.job && jobKey !== jobClosed &&
    (jobRunning || nowMs - new Date(report.job.ended_at).getTime() < JOB_SHOWN_AFTER))

  // Agent tools a machine can turn off (Settings). report.tools is absent on an agent too old to
  // report it; those tools are treated as on.
  const TOOLS = [
    { id: 'crowdsec', label: 'CrowdSec', desc: 'Reads login and service logs and bans attackers on its own.',
      off: 'Its automatic bans are lifted and it is removed from the machine. Manual and panel blocks stay.' },
    { id: 'osquery', label: 'File watch (osquery)', desc: 'Records changes to system files and programs.',
      off: 'File-change tracking stops and its data is removed from the machine.' },
    { id: 'trivy', label: 'Vulnerability scanning', desc: 'Scans installed packages and app lockfiles for known CVEs when you ask.',
      off: 'The scanner and its database are removed from the machine. The scan history stays in the panel.' },
  ]
  const toolOn = (id) => report?.tools?.[id]?.enabled ?? true
  // A switch change is "pending" from the moment it's sent until the agent reports the result
  // (or an error); the agent also reports a tool as busy while it works on it, so a refresh or
  // another browser shows the change in progress too. No answer within TOOL_WAIT unlocks it.
  const TOOL_WAIT = 3 * 60 * 1000
  let toolPending = $state({}) // id -> { on, at, seq } (seq: the agent's finished-change count when sent)
  let toolRev = $state(0) // re-renders the switches after a cancelled confirm
  let toolNow = $state(Date.now())
  $effect(() => {
    if (!Object.keys(toolPending).length) return
    const iv = setInterval(() => (toolNow = Date.now()), 5000)
    return () => clearInterval(iv)
  })
  // Drop a pending change once the agent reports it finished: its change count has moved past
  // the one we saw when sending (an old error or state can't end it early) and it's not busy.
  $effect(() => {
    const tools = report?.tools
    if (!tools) return
    for (const [id, p] of Object.entries(toolPending)) {
      const t = tools[id]
      if (t && !t.busy && (t.seq ?? 0) > p.seq) {
        const { [id]: _, ...rest } = toolPending
        toolPending = rest
      }
    }
  })
  // What a switch shows: { on, busy, text, tone }
  function toolView(id) {
    const t = report?.tools?.[id]
    const p = toolPending[id]
    if (t?.busy) return { on: t.busy === 'turning-on', busy: true, text: t.busy === 'turning-on' ? 'turning on…' : 'turning off…' }
    if (p && toolNow - p.at < TOOL_WAIT) return { on: p.on, busy: true, text: p.on ? 'turning on…' : 'turning off…' }
    if (p) return { on: toolOn(id), busy: false, text: 'no answer from the machine yet', tone: 'text-warning' }
    if (t?.error) return { on: toolOn(id), busy: false, text: t.error, tone: 'text-destructive' }
    if (!t) return { on: true, busy: false, text: '' }
    if (!t.enabled) return { on: false, busy: false, text: 'off' }
    if (!t.installed) return { on: true, busy: false, text: id === 'trivy' ? 'installs on the first scan' : 'installing…' }
    return { on: true, busy: false, text: id === 'trivy' || t.running ? '' : 'not running', tone: 'text-warning' }
  }
  async function setTool(t, on) {
    await cmd('set-tool', { tool: t.id, enabled: on }, {
      title: `Turn ${on ? 'on' : 'off'} ${t.label}`,
      message: on ? `Install and start ${t.label} on ${machine.name}? It downloads the pinned, checksum-verified release.`
        : `Turn off ${t.label} on ${machine.name}? ${t.off}`,
      confirmText: on ? 'Turn on' : 'Turn off', variant: on ? 'primary' : 'destructive',
      done: () => `Turning ${on ? 'on' : 'off'} ${t.label}…`,
      after: () => { toolNow = Date.now(); toolPending = { ...toolPending, [t.id]: { on, at: toolNow, seq: report?.tools?.[t.id]?.seq ?? 0 } } },
    })
    toolRev++ // a cancelled confirm leaves the switch where the real state is
  }
  const canMaintain = $derived(st.reachable && !scanning)
  const scanned = $derived(!!cves?.scanned_at || !!cves?.total || !!cveSummary?.unique_cves)
  const sevRows = $derived(SEV.map((s) => ({ ...s, n: cves?.counts?.[s.sev] || 0 })).filter((s) => s.n))
  const sevTotal = $derived(sevRows.reduce((a, s) => a + s.n, 0))
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
  // Refetch when the range (or the machine) changes; runs once on mount too. An uninstalled
  // machine has no history left to show (its data was deleted), so it loads nothing.
  $effect(() => { if (st.gone) return; histRange; machine.id; loadHistory() })

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

  // The vitals strip: each value's trend is its average line from the usage history above.
  const ofTotal = (used, total) => (total ? `${formatBytes(used)} of ${formatBytes(total)}` : '')
  const vitals = $derived([
    { key: 'cpu', icon: 'cpu', label: 'CPU', value: m.cpu, sub: 'utilization' },
    { key: 'mem', icon: 'database', label: 'Memory', value: m.mem, sub: ofTotal(m.mem_used, m.mem_total) },
    { key: 'disk', icon: 'device-floppy', label: 'Disk', value: m.disk, sub: ofTotal(m.disk_used, m.disk_total) + (m.disk_total ? ' on /' : '') },
  ].map((v) => ({ ...v, trend: histPoints.map((d) => d[`${v.key}_avg`]) })))
  const loadTrend = $derived(histPoints.map((d) => d.load_avg))

  onMount(() => {
    if (st.gone) { loading = false; return } // nothing left to load or watch
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
      if (typeof msg.online === 'boolean') live.online = msg.online
      if (msg.last_seen) live.last_seen = msg.last_seen
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

  const cmdStatus = { pending: 'text-warning', delivered: 'text-info', done: 'text-success', error: 'text-destructive', expired: 'text-muted-foreground' }

  async function cmd(type, payload = null, opts = {}) {
    const ok = await confirm({
      title: `${opts.title || type} · ${machine.name}`,
      message: opts.message || `Queue "${type}" for ${machine.name}? It runs right away.`,
      confirmText: opts.confirmText || 'Queue',
      variant: opts.variant || 'primary',
      alert: opts.alert || false,
    })
    if (!ok) return

    const endpoint = opts.endpoint || '/api/fleet/command'
    const base = opts.endpoint ? { machine_id: machine.id } : { machine_id: machine.id, type, payload }
    try {
      const res = await withStepUp((extra) => apiPost(endpoint, { ...base, ...extra }), stepUpFor(opts.title || type))
      if (res === STEPUP_CANCELLED) return
      toast(opts.done ? opts.done(res) : `${type} queued`, 'success')
      if (opts.after) opts.after()
    } catch (e) {
      toast('Failed: ' + e.message, 'error')
    }
  }

  // The re-auth prompt for a sensitive action on this machine (see withStepUp).
  const stepUpFor = (what) => ({
    title: `Confirm "${what}"`,
    message: `This is a sensitive action on ${machine.name}. Re-enter your credentials to authorize it.`,
    confirmText: 'Authorize', variant: 'destructive',
  })

  async function blockOn() {
    const ip = blockIP.trim()
    if (!ip) return
    await cmd('block', { ip }, { title: 'Block IP', message: `Block ${ip} on ${machine.name}?`, after: () => (blockIP = '') })
  }

  const pushBlocks = () => cmd('sync-blocks', null, {
    endpoint: '/api/fleet/push-blocks', title: 'Push / update panel blocklist',
    message: `Push the panel's blocked IPs and ranges (manual and auto-blocked) onto ${machine.name}? Country and ASN blocks stay on the panel only. It REPLACES the machine's panel list (separate from its CrowdSec and manual blocks), so pushing again updates it. Later changes on the panel need another push.`,
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
      ? `Put ${machine.name} in DRY-RUN? Its firewall blocks are lifted (the list is kept) and updates are only logged, so nothing is blocked until it goes live again.`
      : `Take ${machine.name} LIVE? Every block on its list is enforced at once, and updates are applied for real.`,
    confirmText: enabled ? 'Dry-run' : 'Go live', variant: enabled ? 'primary' : 'destructive',
  })
  // Scan opens the dialog (folders to leave out); the dialog is the confirmation.
  let scanDialog = $state(false)
  const rescan = () => (scanDialog = true)
  // Adding folders to skip is admin-only and asks for the password (it hides findings in every
  // later scan); the same or a shorter list doesn't. False keeps the dialog open.
  async function startScan(exclude) {
    try {
      const res = await withStepUp((extra) => apiPost('/api/fleet/command', { machine_id: machine.id, type: 'rescan', payload: { exclude }, ...extra }), stepUpFor('Skip folders in scans'))
      if (res === STEPUP_CANCELLED) return false
      toast('Scan started', 'success')
      return true
    } catch (e) {
      toast('Scan not started: ' + (e?.message || e), 'error')
      return false
    }
  }
  const updateAgent = () => cmd('update-agent', null, {
    title: 'Update agent',
    message: `Update the Motte agent on ${machine.name}${agentUpdate.cur && agentUpdate.latest ? ` from ${agentUpdate.cur} to ${agentUpdate.latest}` : ' to the latest release'}? It downloads the release binary, verifies its checksum, checks it runs, swaps it in (keeping a backup), and restarts the agent — a brief reconnect, no reboot.`,
    confirmText: 'Update agent',
  })

  // Unblock a single IP (the typed one, or a specific one from the enforced list).
  async function unblockOn(ip = null) {
    const t = (ip ?? blockIP).trim()
    if (!t) return
    await cmd('unblock', { ip: t }, { title: 'Unblock IP', message: `Unblock ${t} on ${machine.name}? If CrowdSec banned it, that ban is removed too, so it isn't blocked again.`, after: () => { if (ip == null) blockIP = '' } })
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
    // The agent renews its certificate by itself well before it expires.
    ['certificate', 'Cert', [(machine.cert_fp || '').replace('sha256:', '').slice(0, 8), machine.cert_expires ? formatExpiryDate(machine.cert_expires).toLowerCase() : ''].filter(Boolean).join(' · ')],
    ['key', 'WG', wgVal],
  ])
  // IPs this host is currently enforcing a block on (from the live report).
  const blockedIPs = $derived(report?.blocks || []) // [{ ip, sources: ['manual'|'crowdsec'] }]
  const SOURCE = { manual: 'manual', crowdsec: 'CrowdSec' }
  const panelBlocked = $derived(report?.panel_blocked ?? 0)
  // A push/clear is in flight until the agent runs it — disable the buttons meanwhile.
  const blocklistBusy = $derived(commands.some((c) => (c.type === 'sync-blocks' || c.type === 'clear-blocks') && (c.status === 'pending' || c.status === 'delivered')))

  async function del() {
    await cmd(null, null, st.gone ? {
      endpoint: '/api/fleet/machine/delete', title: `Remove ${machine.name}`,
      message: `Remove ${machine.name} from the panel? Everything kept for it is deleted: reports, vulnerabilities, history and console recordings. The audit log keeps the record.`,
      confirmText: 'Remove', variant: 'destructive',
      done: () => `${machine.name} removed`, after: () => ondeleted?.(),
    } : {
      endpoint: '/api/fleet/machine/delete', title: `Delete ${machine.name}`,
      message: `Delete ${machine.name} for good? Its certificate stops working at once — the agent can no longer connect and must be installed again to return — and everything stored for it is deleted: reports, vulnerabilities, history and console recordings.`,
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

<!-- card header: icon tile + title + source subtitle, optional controls on the right -->
{#snippet head(icon, title, sub, tint = '', actions)}
  <div class="panel-head">
    <span class="panel-icon {tint}"><Icon name={icon} size={17} /></span>
    <div class="min-w-0 flex-1">
      <div class="panel-title">{title}</div>
      {#if sub}<div class="panel-sub">{sub}</div>{/if}
    </div>
    {@render actions?.()}
  </div>
{/snippet}

<!-- persistent plain-language note (mockup's dashed footer) -->
{#snippet row(title, desc, control)}
  <div class="flex flex-wrap items-center gap-3 py-2.5 first:pt-0 last:pb-0">
    <div class="min-w-0 flex-1">
      <div class="text-sm font-medium text-foreground">{title}</div>
      <div class="text-[11px] text-muted-foreground">{desc}</div>
    </div>
    {@render control()}
  </div>
{/snippet}

{#snippet note(text)}
  <div class="panel-note">{text}</div>
{/snippet}

<!-- a security tool turned off on this machine: the card stays, saying so -->
{#snippet toolOff(text)}
  <div class="flex items-start gap-3 rounded-lg border border-dashed border-border bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
    <Icon name="power" size={16} class="mt-0.5 shrink-0" />
    <span>{text}{#if isAdmin}{' '}Turn it back on in <button type="button" class="text-primary hover:underline cursor-pointer" onclick={() => go('overview')}>Overview → Settings</button>.{/if}</span>
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

<!-- Header: back · name with status · live facts · grouped actions. Lives in the content column. -->
{#snippet header()}
  <div class="flex items-start gap-3">
    <button onclick={onback} title="Back to all clients" aria-label="Back to all clients"
      class="h-8 w-8 grid place-items-center rounded-lg border border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground transition cursor-pointer shrink-0">
      <Icon name="arrow-left" size={16} />
    </button>
    <div class="min-w-0 flex-1">
      <!-- Up/down is the headline; dry-run is flagged only when on (enforcing is the normal state). -->
      <div class="flex items-center gap-2">
        <h2 class="truncate text-lg font-semibold leading-tight text-foreground">{machine.name || machine.id}</h2>
        <Badge variant={st.variant} size="sm"><span class="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-current"></span><span class="capitalize">{st.label}</span></Badge>
        {#if scanning}
          <span title="A vulnerability scan is running. Updates, restarts and reboot wait until it finishes."><Badge variant="info" size="sm"><Icon name="loader-2" size={11} class="mr-1 animate-spin" />Scanning</Badge></span>
        {/if}
        {#if report && dryRun}
          <span title="Dry-run: nothing is blocked and updates are only logged; the block list is kept for going live"><Badge variant="warning" size="sm">Dry-run</Badge></span>
        {/if}
      </div>
      <div class="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-muted-foreground">
        {#if lastSeen}<span class="inline-flex items-center gap-1 {st.online ? '' : 'font-medium text-foreground'}"><Icon name="clock" size={11} />{st.online ? 'seen' : st.gone ? 'uninstalled' : 'last seen'} {timeAgo(lastSeen)}</span>{/if}
        {#if report?.agent}<span class="inline-flex items-center gap-1"><Icon name="robot" size={11} />agent {report.agent}</span>{/if}
        {#if report}<span class="hidden items-center gap-1 tabular-nums sm:inline-flex"><Icon name="cpu" size={11} />{st.online ? '' : 'last known · '}CPU {round(m.cpu)}% · MEM {round(m.mem)}% · load {(m.load1 ?? 0).toFixed(2)}</span>{/if}
      </div>
    </div>
    {#if !st.gone}<div class="kt-btn-group shrink-0">
      <Button variant="surface" iconOnly icon="refresh" tooltip="Refresh" aria-label="Refresh" onclick={refresh} />
      {#if canOpenConsole && consoleEnabled}
        <Button variant="surface" iconOnly icon="terminal-2" class="text-primary hover:bg-primary/10" tooltip="Open console" aria-label="Open console" onclick={() => openConsole()} />
      {/if}
      <Button variant="surface" iconOnly icon="trash" class="text-destructive hover:bg-destructive/10" tooltip="Delete machine" aria-label="Delete machine" onclick={del} />
    </div>{/if}
  </div>
{/snippet}

<!-- An uninstalled machine: its agent signed off (its history is kept until it's removed), so
     instead of empty tabs this says what happened and offers the one thing left to do. -->
{#snippet uninstalled()}
  <div class="panel overflow-hidden !p-0">
    <div class="flex flex-col items-center gap-3 border-b border-dashed border-border bg-muted/30 px-6 py-8 text-center">
      <span class="relative grid h-14 w-14 place-items-center rounded-2xl border border-border bg-card text-muted-foreground shadow-sm">
        <Icon name="plug-connected-x" size={26} />
        <span class="absolute -right-1 -top-1 grid h-5 w-5 place-items-center rounded-full border-2 border-card bg-destructive text-white"><Icon name="x" size={11} /></span>
      </span>
      <div>
        <h3 class="text-base font-semibold text-foreground">Agent uninstalled</h3>
        <p class="mx-auto mt-1 max-w-md text-sm text-balance text-muted-foreground">
          The agent was removed from <span class="whitespace-nowrap font-medium text-foreground">{machine.name}</span> and signed off from the panel. This server can no longer connect.
        </p>
      </div>
    </div>

    <div class="grid gap-6 px-6 py-5 sm:grid-cols-2">
      <div>
        <div class="mb-3 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Timeline</div>
        <ol class="relative space-y-4 border-l border-dashed border-border pl-5">
          {#each [
            { dot: 'bg-success', label: 'Added to the panel', at: machine.enrolled_at },
            { dot: 'bg-destructive', label: 'Agent uninstalled', at: machine.last_seen },
          ] as e (e.label)}
            <li class="relative">
              <span class="absolute -left-[25px] top-1 h-2.5 w-2.5 rounded-full ring-4 ring-card {e.dot}"></span>
              <div class="text-sm font-medium text-foreground">{e.label}</div>
              <div class="text-[11px] tabular-nums text-muted-foreground">{e.at ? `${formatDate(e.at)} · ${timeAgo(e.at)}` : '—'}</div>
            </li>
          {/each}
          <!-- the possible next step: hollow dot, not an event that happened -->
          <li class="relative">
            <span class="absolute -left-[25px] top-1 h-2.5 w-2.5 rounded-full border-2 border-dashed border-muted-foreground bg-card ring-4 ring-card"></span>
            <div class="text-sm font-medium text-muted-foreground">Bring it back</div>
            <div class="text-[11px] text-muted-foreground">Re-enroll it: a one-time command installs the agent again as this same machine, history included.</div>
          </li>
        </ol>
      </div>
      <div>
        <div class="mb-3 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">What happened</div>
        <ul class="space-y-3">
          {#each [
            { icon: 'certificate', title: 'Certificate revoked', text: "The server's identity no longer works, so it can't reconnect." },
            { icon: 'database', title: 'History kept', text: 'Vulnerabilities, scan and file-change history, commands and console recordings stay until you remove it: the machine itself can’t erase them.' },
            { icon: 'history', title: 'Kept in the audit log', text: 'Activity still shows when it was added and removed.' },
          ] as f (f.title)}
            <li class="flex items-start gap-3">
              <span class="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-muted text-muted-foreground"><Icon name={f.icon} size={14} /></span>
              <div class="min-w-0">
                <div class="text-sm font-medium text-foreground">{f.title}</div>
                <div class="text-[11px] text-muted-foreground">{f.text}</div>
              </div>
            </li>
          {/each}
        </ul>
      </div>
    </div>

    <div class="flex justify-end gap-2 border-t border-dashed border-border px-6 py-4">
      {#if isAdmin}<Button variant="outline" size="sm" icon="certificate" onclick={() => (reenrollOpen = true)}>Re-enroll</Button>{/if}
      <Button variant="destructive" size="sm" icon="trash" onclick={del}>Remove from panel</Button>
    </div>
  </div>
{/snippet}

<!-- Menu on the left from the top (desktop); everything else, header first, in the right column. -->
<div class="flex flex-col gap-4 lg:min-h-[calc(100dvh-8rem)] lg:flex-row">
  {#if report && !st.gone}<SectionNav only="rail" items={navList} active={activeTab} onselect={go} label="Machine sections" />{/if}
  <!-- an uninstalled machine is a single panel: header and panel share one narrower column -->
  <div class="min-w-0 flex-1 space-y-4 {st.gone ? 'mx-auto w-full max-w-3xl' : ''}">
    {@render header()}
  {#if st.gone}
    {@render uninstalled()}
  {:else if loading && !report}
    <div class="panel p-8 text-center text-sm text-muted-foreground">Loading report…</div>
  {:else if !report}
    <div class="panel p-8">
      <EmptyState icon="clock" title="No report yet"
        description="This machine hasn't checked in with a report. It appears once the agent's first metrics/scan cycle completes." />
    </div>
  {:else}
    <SectionNav only="select" mobile="bottom" items={navList} active={activeTab} onselect={go} label="Machine sections" />
    {#if activeTab === 'overview'}
      <!-- Vitals: one surface with hairline dividers. Each shows the value now, what it's out of,
           and its trend over the usage-history range (the same points; no extra request). -->
      <section aria-label="Vitals" class="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-border bg-border lg:grid-cols-4">
        {#each vitals as v (v.key)}
          {@const pct = round(v.value)}
          <div class="flex min-w-0 flex-col gap-2 bg-card p-4">
            <div class="flex items-center gap-2 text-[11px] font-medium text-muted-foreground">
              <Icon name={v.icon} size={14} />{v.label}
              {#if v.trend.length > 1}<span class="ms-auto text-[10px] font-normal">{histRange}</span>{/if}
            </div>
            <div class="flex items-baseline gap-1.5">
              <span class="text-2xl font-bold leading-none tabular-nums text-foreground">{pct}<span class="text-sm font-medium text-muted-foreground">%</span></span>
              <span class="h-2 w-2 self-center rounded-full" style="background: var(--{usageTone(pct)})" title={usageTone(pct) === 'success' ? 'Fine' : usageTone(pct) === 'warning' ? 'High' : 'Very high'}></span>
            </div>
            {#if v.trend.length > 1}
              <Sparkline values={v.trend} color="var(--{usageTone(pct)})" label="{v.label} over {histRange}" />
            {:else}
              <span class="my-3.5 block h-1 overflow-hidden rounded-full bg-muted"><span class="block h-full rounded-full {usageColor(pct)}" style="width:{Math.min(pct, 100)}%"></span></span>
            {/if}
            <div class="mt-auto truncate text-[11px] tabular-nums text-muted-foreground">{v.sub}</div>
          </div>
        {/each}
        <div class="flex min-w-0 flex-col gap-2 bg-card p-4">
          <div class="flex items-center gap-2 text-[11px] font-medium text-muted-foreground"><Icon name="activity" size={14} />Load
            {#if loadTrend.length > 1}<span class="ms-auto text-[10px] font-normal">{histRange}</span>{/if}
          </div>
          <span class="text-2xl font-bold leading-none tabular-nums text-foreground">{(m.load1 ?? 0).toFixed(2)}</span>
          {#if loadTrend.length > 1}
            <!-- no fixed ceiling for load: scaled to the range's own peak (at least 1) -->
            <Sparkline values={loadTrend} max={Math.max(1, ...loadTrend.filter((x) => x != null)) * 1.15} color="var(--info)" label="Load over {histRange}" />
          {/if}
          <div class="mt-auto truncate text-[11px] tabular-nums text-muted-foreground">1-min average · up {m.uptime ? fmtUptime(m.uptime) : '—'}</div>
        </div>
      </section>

      <!-- Security glance → Security tab -->
      <button type="button" onclick={() => go('security')}
        class="w-full bg-card border border-border rounded-xl p-3 flex items-center gap-3 text-left hover:bg-muted/30 transition cursor-pointer">
        <span class="panel-icon {secBadge || feed.length || fimCount ? 'text-warning' : 'text-success'}"><Icon name="shield-lock" size={17} /></span>
        <div class="flex flex-wrap items-center gap-x-4 gap-y-1 flex-1 min-w-0 text-sm">
          <span class="flex items-center gap-1.5"><Icon name="package" size={14} class="text-muted-foreground" /><span class="font-medium">{(cves?.total ?? 0).toLocaleString()}</span><span class="text-muted-foreground">CVEs</span>{#if secBadge}<Badge variant="destructive" size="sm">{secBadge} crit/high</Badge>{/if}</span>
          <span class="flex items-center gap-1.5"><Icon name="ban" size={14} class="text-muted-foreground" /><span class="font-medium">{feed.length}</span><span class="text-muted-foreground">bans</span></span>
          <span class="flex items-center gap-1.5"><Icon name="file-search" size={14} class="text-muted-foreground" /><span class="font-medium">{fimCount}</span><span class="text-muted-foreground">file changes</span></span>
        </div>
        <Icon name="chevron-right" size={16} class="text-muted-foreground shrink-0" />
      </button>

      <!-- Host facts, with who is logged in beside them -->
      <div class="panel">
        {@render head('server', 'Host facts', 'os · hardware · identity · logins')}
        <div class="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <div class="grid grid-cols-2 sm:grid-cols-3 2xl:grid-cols-4 gap-px bg-border rounded-lg overflow-hidden border border-border self-start">
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
          <!-- divider: a rule above on phones, a line on the left beside the facts -->
          <div class="min-w-0 border-t border-border pt-3 lg:border-l lg:border-t-0 lg:pl-4 lg:pt-0">
            <div class="mb-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground">
              Login sessions{#if facts?.sessions?.length}<span class="tabular-nums">· {facts.sessions.length}</span>{/if}
            </div>
            {#each facts?.sessions || [] as s}
              <div class="flex items-center gap-2 py-0.5 text-xs">
                <span class="w-1.5 h-1.5 rounded-full shrink-0 {s.active ? 'bg-success' : 'bg-muted-foreground/40'}" title={s.active ? 'active' : 'idle'}></span>
                <span class="font-mono text-foreground shrink-0">{s.user}</span>
                <span class="text-muted-foreground font-mono truncate">{s.host || s.tty || 'local'}</span>
                <span class="text-muted-foreground ml-auto shrink-0">{s.when ? timeAgo(s.when) : ''}</span>
              </div>
            {:else}
              <div class="py-0.5 text-xs text-muted-foreground">No one is logged in.</div>
            {/each}
          </div>
        </div>
      </div>

      <!-- Settings beside what runs on the machine -->
      <div class="grid gap-4 xl:grid-cols-2 xl:items-start">
        <!-- Settings: console access, recording and tags (who can see this machine) -->
        <div class="panel">
          {@render head('settings', 'Settings', 'console · recording · security tools · tags')}
          <div class="space-y-4">
            <div class="flex items-start justify-between gap-3">
              <div class="min-w-0">
                <div class="text-sm font-medium text-foreground">Browser console</div>
                <div class="text-[11px] text-muted-foreground">A remote shell from the panel. Turning it on asks for your password again.</div>
              </div>
              {#if isAdmin}
                <Checkbox variant="switch" checked={consoleEnabled} disabled={consoleBusy} onchange={() => setConsole(!consoleEnabled)} aria-label="Browser console" />
              {:else}
                <Badge variant={consoleEnabled ? 'success' : 'muted'} size="sm">{consoleEnabled ? 'On' : 'Off'}</Badge>
              {/if}
            </div>
            <div class="flex items-start justify-between gap-3 border-t border-dashed border-border pt-4">
              <div class="min-w-0">
                <div class="text-sm font-medium text-foreground">Record sessions</div>
                <div class="text-[11px] text-muted-foreground">Always: every console session on this machine is recorded (screen output only) for audit.</div>
              </div>
              {#if isAdmin}
                <Segmented size="sm" label="Recording" value={consoleRecord} disabled={consoleBusy} onchange={setRecording}
                  options={[{ value: false, label: 'Off' }, { value: true, label: 'Always', tone: 'destructive' }]} />
              {:else}
                <Badge variant={consoleRecord ? 'destructive' : 'muted'} size="sm">{consoleRecord ? 'Always' : 'Off'}</Badge>
              {/if}
            </div>
            {#each TOOLS as t (t.id)}
              {@const v = toolView(t.id)}
              <div class="flex items-start justify-between gap-3 border-t border-dashed border-border pt-4">
                <div class="min-w-0">
                  <div class="flex flex-wrap items-center gap-x-1.5 text-sm font-medium text-foreground">
                    {t.label}
                    {#if v.busy}<Icon name="loader-2" size={12} class="animate-spin text-info" />{/if}
                    {#if v.text}<span class="text-[11px] font-normal {v.busy ? 'text-info' : v.tone || 'text-muted-foreground'}">{v.text}</span>{/if}
                  </div>
                  <div class="text-[11px] text-muted-foreground">{t.desc}</div>
                </div>
                {#if isAdmin}
                  {#key `${t.id}:${v.on}:${toolRev}`}
                    <Checkbox variant="switch" checked={v.on} disabled={v.busy || !st.reachable || jobRunning || (t.id === 'trivy' && scanning)}
                      onchange={() => setTool(t, !v.on)} aria-label={t.label} />
                  {/key}
                {:else}
                  <Badge variant={v.on ? 'success' : 'muted'} size="sm">{v.busy ? '…' : v.on ? 'On' : 'Off'}</Badge>
                {/if}
              </div>
            {/each}
            <div class="flex items-start justify-between gap-3 border-t border-dashed border-border pt-4">
              <div class="min-w-0">
                <div class="text-sm font-medium text-foreground">Certificate</div>
                <div class="text-[11px] text-muted-foreground">{machine.cert_expires ? formatExpiryDate(machine.cert_expires) + '. ' : ''}The agent renews it by itself while online. If it expired while the machine was offline, re-enroll it.</div>
              </div>
              {#if isAdmin}<Button variant="outline" size="sm" icon="certificate" onclick={() => (reenrollOpen = true)}>Re-enroll</Button>{/if}
            </div>
            <div class="border-t border-dashed border-border pt-4">
              <div class="mb-2 text-sm font-medium text-foreground">Tags</div>
              <TagEditor {tags} canEdit={isAdmin} onsave={saveTags} />
            </div>
          </div>
          {@render note('Operators and viewers can be limited to machines with given tags (Settings → Team). Only admins change these settings; switching the console or a security tool asks for your password again, and each change is logged.')}
        </div>

        <!-- Services -->
        <div class="panel">
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
          {#if footprint?.parts?.length}
            <div class="mt-4 border-t border-dashed border-border pt-3">
              <div class="mb-1.5 flex items-center gap-2 text-[11px] font-medium text-foreground">
                Agent footprint
                <span class="ml-auto tabular-nums text-muted-foreground">{formatBytes(footprintTotal.mem)} · {footprintTotal.cpu.toFixed(1)}% CPU</span>
              </div>
              {#each footprint.parts as p (p.name)}
                {@const [icon, label] = FOOTPRINT[p.name] || ['circle', p.name]}
                <div class="flex items-center gap-2 py-1 text-xs">
                  <Icon name={icon} size={14} class="shrink-0 text-muted-foreground" />
                  <span class="truncate">{label}</span>
                  {#if p.name === 'scan'}<span class="h-1.5 w-1.5 shrink-0 animate-pulse rounded-full bg-info" title="running"></span>{/if}
                  <span class="ml-auto shrink-0 tabular-nums font-medium">{formatBytes(p.mem)}</span>
                  <span class="w-16 shrink-0 text-right tabular-nums text-muted-foreground">{(p.cpu || 0).toFixed(1)}% CPU</span>
                </div>
              {/each}
              {#if !scanRunning && footprint.last_scan}
                <div class="flex items-center gap-2 py-1 text-xs text-muted-foreground">
                  <Icon name="package" size={14} class="shrink-0" />
                  <span class="truncate">Vulnerability scan · idle</span>
                  <span class="ml-auto shrink-0 tabular-nums">last run {Math.round(footprint.last_scan.seconds)}s · peak {formatBytes(footprint.last_scan.peak_mem)}</span>
                </div>
              {/if}
            </div>
          {/if}
          {@render note('Running systemd services and the five using the most memory (from each service’s cgroup). Below them, what the monitoring itself costs: the agent and each helper it runs, sampled every minute. The vulnerability scan runs at low priority in its own space, capped at half the machine’s memory.')}
        </div>
      </div>

      <!-- Disk space beside what listens -->
      <div class="grid gap-4 xl:grid-cols-2 xl:items-start">
        <!-- Disk space (per-filesystem, live) -->
        <div class="panel">
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

        <!-- Exposure -->
        <div class="panel">
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
      </div>

      <!-- Usage history -->
      <div class="panel">
        <!-- average vs peak (both stored; no refetch) + time range; their own row on phones -->
        {#snippet histControls()}
          <div class="flex w-full gap-2 sm:w-auto">
            <Segmented size="sm" label="Statistic" bind:value={histStat} options={[{ value: 'avg', label: 'Avg' }, { value: 'max', label: 'Peak' }]} />
            <Segmented size="sm" label="Time range" bind:value={histRange} options={['24h', '7d', '30d'].map((r) => ({ value: r, label: r }))} />
          </div>
        {/snippet}
        {@render head('chart-line', 'Usage history', 'CPU · memory · disk over time', '', histControls)}
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

    {/if}

    {#if activeTab === 'sessions'}
      <div class="panel">
        {#snippet sessionControls()}
          {#if canOpenConsole && consoleEnabled}
            <button type="button" class="link-action" onclick={() => openConsole()}><Icon name="plus" size={12} />New session</button>
            <Button variant="ghost" size="xs" iconOnly icon="refresh" onclick={refreshSessions} tooltip="Refresh" />
          {/if}
        {/snippet}
        {@render head('terminal-2', 'Console sessions',
          consoleEnabled ? `${liveSessions.length} live · they keep running when you close the browser` : 'the console is off for this machine',
          'text-primary', sessionControls)}
        {#if !canOpenConsole}
          <div class="text-sm text-muted-foreground">You don't have permission to use the console.</div>
        {:else if !consoleEnabled}
          <div class="flex items-center gap-3 rounded-lg border border-dashed border-border px-4 py-4 text-sm text-muted-foreground">
            <Icon name="lock" size={16} class="shrink-0" />
            {#if isAdmin}The console is off. Turn it on in Overview → Settings.{:else}The console is off for this machine.{/if}
          </div>
        {:else if liveSessions.length}
          <div class="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {#each liveSessions as s (s.id)}
              <SessionCard session={s} machine={{ id: machine.id, name: machine.name }} onresume={(x) => openConsole(x.id)} onkill={killSession} />
            {/each}
          </div>
        {:else}
          <div class="flex items-center gap-3 rounded-lg border border-dashed border-border px-4 py-4 text-sm text-muted-foreground">
            <Icon name="terminal-2" size={16} class="shrink-0" />No live sessions. Start one — you can reattach after a reload or a dropped connection.
          </div>
        {/if}
        <!-- Recordings stay listable after the console is turned off; reload as sessions change. -->
        {#if canOpenConsole}
          <RecordingList machineId={machine.id} live={liveSessions.length} hideEmpty={!consoleRecord} class="mt-4 border-t border-dashed border-border pt-4"
            emptyText="With recording on, every session on this machine is recorded from the moment it opens." />
        {/if}
        {@render note('Opening a session may ask for your password again (step-up). Sessions run in tmux on the machine, so they survive a disconnect. Recordings are encrypted on disk, each playback is logged, and only an admin can delete one.')}
      </div>
    {/if}

    {#if activeTab === 'security'}
      <!-- Vulnerabilities -->
      <div class="panel">
        {#snippet cveScanned()}
          <span class="shrink-0 text-[11px] {scanning ? 'text-info' : 'text-muted-foreground'}">
            {scanning ? 'scanning…' : cves?.scanned_at ? `scanned ${timeAgo(cves.scanned_at)}` : scanned ? '' : 'never scanned'}
          </span>
        {/snippet}
        {@render head('package', 'Vulnerabilities', 'Trivy · OS packages + app lockfiles', 'text-warning', cveScanned)}
        {#if !toolOn('trivy')}
          {@render toolOff('Vulnerability scanning is off for this machine, so it has no scanner installed and can\'t be scanned.')}
        {:else if !scanned}
          <div class="flex items-start gap-3 rounded-lg border border-dashed border-border px-4 py-3 text-sm text-muted-foreground">
            <Icon name="scan" size={16} class="mt-0.5 shrink-0" />
            <span>Not scanned yet. Scans run only when you ask: they read every installed package, so they take a few minutes and some CPU on the machine.</span>
          </div>
        {:else if cves?.total || cveSummary?.unique_cves}
          <div class="space-y-2.5">
            <div class="text-sm text-muted-foreground tabular-nums">
              {#if cveSummary?.unique_cves}
                <span class="font-semibold text-foreground">{cveSummary.unique_cves.toLocaleString()}</span> CVEs in
                <span class="font-semibold text-foreground">{cveSummary.packages.toLocaleString()}</span> packages
                {#if cveSummary.fixable}· <span class="font-semibold text-success">{cveSummary.fixable.toLocaleString()}</span> fixable{/if}
              {:else}
                <span class="font-semibold text-foreground">{cves.total.toLocaleString()}</span> findings
              {/if}
            </div>
            {#if sevTotal}
              <!-- one bar, one segment per severity, sized by its share -->
              <div class="flex h-2 gap-0.5 overflow-hidden rounded-full bg-muted">
                {#each sevRows as s (s.sev)}<div class={s.bar} style="width: {(s.n / sevTotal) * 100}%" title="{s.n} {s.label}"></div>{/each}
              </div>
              <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs">
                {#each sevRows as s (s.sev)}
                  <span class="inline-flex items-center gap-1.5"><span class="h-2 w-2 rounded-full {s.bar}"></span><span class="font-medium tabular-nums text-foreground">{s.n.toLocaleString()}</span><span class="text-muted-foreground">{s.label}</span></span>
                {/each}
              </div>
            {/if}
          </div>
        {:else}
          <div class="text-sm text-success flex items-center gap-2 py-1"><Icon name="circle-check" size={15} />No known vulnerabilities found.</div>
        {/if}
        {#if kernel && kphase}
          <div class="mt-4 flex items-start gap-2 rounded-lg border border-border bg-muted/40 px-2.5 py-2">
            <span class="w-2 h-2 rounded-full mt-1.5 shrink-0 {kphase.dot} {kernel.phase === 'installing' || kernel.phase === 'cleanup_pending' ? 'animate-pulse' : ''}"></span>
            <div class="min-w-0">
              <div class="text-xs font-medium flex items-center gap-1.5"><Icon name="cpu" size={12} /> {kphase.label}{#if kernel.target}<span class="font-mono text-[10px] text-muted-foreground">{kernel.target}</span>{/if}</div>
              {#if kernel.message}<div class="text-[11px] text-muted-foreground mt-0.5 break-words">{kernel.message}</div>{/if}
              {#if kernel.removed?.length}<div class="text-[10px] text-muted-foreground mt-0.5">Removed {kernel.removed.length} old package(s)</div>{/if}
            </div>
          </div>
        {/if}
        <div class="mt-4 flex flex-wrap items-center gap-2">
          {#if toolOn('trivy')}<Button variant="outline" size="sm" icon="scan" loading={scanning} disabled={!st.reachable || scanning || jobRunning} onclick={rescan}>{scanning ? 'Scanning…' : scanned ? 'Scan again' : 'Scan now'}</Button>{/if}
          <Button variant="outline" size="sm" icon="download" loading={jobRunning && report?.job?.kind === 'apply-updates'} disabled={!canMaintain || jobRunning} onclick={applyUpdates}>Apply updates</Button>
          <Button variant="outline" size="sm" icon="cpu" loading={jobRunning && report?.job?.kind === 'update-kernel'} disabled={!canMaintain || jobRunning} onclick={updateKernel}>Update kernel</Button>
          {#if toolOn('trivy') && (cves?.total || cveSummary?.unique_cves)}<Button variant="primary" size="sm" icon="list-details" class="sm:ml-auto" onclick={() => onviewcves?.(machine)}>View all & fix</Button>{/if}
        </div>
        {#if jobShown}<JobProgress job={report.job} onclose={closeJob} />{/if}
        {#if report?.scan_error && !scanning}
          <div class="mt-2 flex items-start gap-1.5 text-[11px] text-destructive"><Icon name="alert-triangle" size={12} class="mt-px shrink-0" /><span class="break-words">Last scan failed: {report.scan_error}</span></div>
        {/if}
        {#if !st.reachable}<div class="mt-2 text-[11px] text-muted-foreground">The machine is {st.label}: scans and updates can run once it's back online.</div>{/if}
        {@render note('“Apply updates” installs pending package updates, which clears fixable OS-package CVEs. “Update kernel” installs the newest kernel and reboots. “View all & fix” lists every finding by OS and project so you can upgrade only the packages you pick.')}
      </div>

      <ScanDialog bind:open={scanDialog} {machine} excluded={report?.scan_exclude || []} onscan={startScan} />
      <ScanHistory machineId={machine.id} reloadKey={`${cves?.scanned_at || ''}|${report?.scan_error || ''}`} />

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
        {:else if !toolOn('crowdsec')}
          {@render toolOff('CrowdSec is off for this machine: nothing bans attackers automatically. Manual and panel blocks still apply.')}
        {:else}
          <div class="text-sm text-success flex items-center gap-2 py-2"><Icon name="circle-check" size={15} />No active bans.</div>
        {/if}
        <!-- FIM roll-up: count + drill-down (the full list rides its own /fim endpoint); when file
             watch is off, the same "off" note as CrowdSec's above -->
        {#if !fimCount && !toolOn('osquery')}
          <div class="mt-3">{@render toolOff("File watch is off for this machine: file changes aren't tracked.")}</div>
        {:else}
          <div class="flex items-center gap-2 mt-3 pt-3 border-t border-border">
            <Icon name="file-search" size={16} class={fimCount ? 'text-warning' : 'text-muted-foreground'} />
            <span class="text-sm flex-1 min-w-0">
              {#if fimCount}<span class="font-medium">{fimCount.toLocaleString()}</span> file-integrity change{fimCount === 1 ? '' : 's'}{:else}<span class="text-muted-foreground">No file-integrity changes</span>{/if}
            </span>
            {#if fimCount}<Button size="sm" variant="ghost" icon="eye" onclick={openFim}>View all</Button>{/if}
          </div>
        {/if}
        {@render note('CrowdSec bans attackers on-host automatically. File-integrity changes (a watched file changed) are the "someone got in" signals worth investigating.')}
      </div>

      <!-- Blocking -->
      <div class="panel">
        {@render head('ban', 'Blocking', `${blockedIPs.length} IP${blockedIPs.length === 1 ? '' : 's'} blocked (${toolOn('crowdsec') ? 'CrowdSec + manual' : 'manual; CrowdSec is off'})`, 'text-destructive')}
        <div class="flex flex-wrap items-center gap-2">
          <div class="flex-1 min-w-[180px]">
            <Input bind:value={blockIP} prefixIcon="world" placeholder="IP to block / unblock" class="font-mono"
              onkeydown={(e) => e.key === 'Enter' && blockOn()} />
          </div>
          <Button variant="destructive" size="sm" icon="ban" onclick={blockOn} disabled={!blockIP.trim()}>Block</Button>
          <Button variant="outline" size="sm" icon="circle-check" onclick={() => unblockOn()} disabled={!blockIP.trim()}>Unblock</Button>
        </div>
        {#if report?.block_error}
          <div class="mt-3 flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            <Icon name="alert-triangle" size={14} class="mt-px shrink-0" />
            <span class="min-w-0 break-words">The firewall rules couldn't be applied, so these blocks may not be enforced right now. The agent retries every minute. ({report.block_error})</span>
          </div>
        {/if}
        {#if blockedIPs.length}
          <div class="mt-3 max-h-48 overflow-y-auto -mr-1 pr-1">
            {#each blockedIPs as b (b.ip)}
              <div class="flex items-center gap-2 py-1.5 border-t border-border first:border-t-0 text-sm">
                <Icon name="ban" size={13} class="text-destructive shrink-0" />
                <span class="font-mono truncate">{b.ip}</span>
                {#each b.sources || [] as src (src)}
                  <span class="shrink-0 rounded px-1.5 py-px text-[10px] {src === 'crowdsec' ? 'bg-warning/10 text-warning' : 'bg-muted text-muted-foreground'}">{SOURCE[src] || src}</span>
                {/each}
                <button onclick={() => unblockOn(b.ip)} class="ml-auto text-[11px] text-muted-foreground hover:text-foreground transition cursor-pointer shrink-0">unblock</button>
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
      <!-- Agent: one row per setting or action (what it does + its control); reboot sits apart. -->
      <div class="panel">
        {@render head('robot', 'Agent', 'version · mode · logging · restart')}
        <div class="divide-y divide-dashed divide-border">
          {#snippet version()}
            <Button variant="ghost" size="xs" icon="refresh" loading={checkingLatest} onclick={checkLatest}>Check for updates</Button>
            {#if agentUpdate.state === 'current'}
              <span class="inline-flex items-center gap-1 text-xs text-success"><Icon name="circle-check" size={13} />Up to date</span>
            {:else if agentUpdate.state === 'updatable'}
              <Button size="sm" icon="arrow-up" disabled={!canMaintain} onclick={updateAgent}>Update to {agentUpdate.latest}</Button>
            {:else if agentUpdate.state === 'reinstall'}
              <span class="inline-flex items-center gap-1 text-xs text-warning cursor-help" data-kt-tooltip>
                <Icon name="alert-triangle" size={13} />{agentUpdate.latest} available: reinstall
                <span data-kt-tooltip-content class="kt-tooltip hidden">This agent predates in-panel self-update (added in {MIN_SELFUPDATE}). Reinstall once via the install command to enable one-click updates.</span>
              </span>
            {/if}
          {/snippet}
          {@render row('Version', report?.agent ? `motte-agent ${report.agent}` : 'Not reported yet', version)}

          {#snippet mode()}
            {#if dryRun}
              <Button variant="destructive" size="sm" icon="bolt" disabled={!st.reachable} onclick={() => setDryRun(false)}>Go live</Button>
            {:else}
              <Button variant="outline" size="sm" icon="player-pause" disabled={!st.reachable} onclick={() => setDryRun(true)}>Switch to dry-run</Button>
            {/if}
          {/snippet}
          {@render row(dryRun ? 'Mode: dry-run' : 'Mode: enforcing',
            dryRun ? 'Nothing is blocked and updates are only logged. The block list is kept and applied when it goes live.' : 'Firewall blocks and updates are applied for real.', mode)}

          {#if report?.log_level}
            {#snippet logs()}
              <Button variant="outline" size="sm" icon="file-text" disabled={!canMaintain}
                onclick={() => setLogLevel(report.log_level === 'debug' ? 'quiet' : 'debug')}>{report.log_level === 'debug' ? 'Back to quiet' : 'Turn on debug'}</Button>
            {/snippet}
            {@render row(report.log_level === 'debug' ? 'Logging: debug' : 'Logging: quiet',
              report.log_level === 'debug' ? 'Verbose logs for troubleshooting. Switch back when done.' : 'Warnings and errors only.', logs)}
          {/if}

          {#snippet tools()}
            <Button variant="outline" size="sm" icon="refresh" disabled={!canMaintain} onclick={restartAgents}>Restart</Button>
          {/snippet}
          {@render row('Sub-agents', 'CrowdSec and osquery. Restarting is safe, no reboot.', tools)}
        </div>

        <!-- danger zone -->
        <div class="mt-4 flex flex-wrap items-center gap-3 rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2.5">
          <div class="min-w-0 flex-1">
            <div class="text-sm font-medium text-foreground">Reboot host</div>
            <div class="text-[11px] text-muted-foreground">Restarts the whole machine. It's offline for a minute or two.</div>
          </div>
          <Button variant="destructive" size="sm" icon="power" disabled={!canMaintain} onclick={rebootHost}>Reboot</Button>
        </div>
        {#if !st.reachable}<div class="mt-2 text-[11px] text-muted-foreground">The machine is {st.label}: these actions can run once it's back online.</div>
        {:else if scanning}<div class="mt-2 text-[11px] text-muted-foreground">A vulnerability scan is running: updates, restarts and reboot wait until it finishes.</div>{/if}
      </div>

      <!-- Recent commands -->
      {#if commands.length}
        <div class="panel">
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

    {#if activeTab === 'ai'}
      {@render soon('sparkles', 'AI tools', 'Explain command output and suggest commands. Opt-in — it sends only the text you choose to an AI provider, so it stays off by default.')}
    {/if}
  {/if}
  </div>
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

{#if isAdmin}<AddMachineModal bind:open={reenrollOpen} {machine} />{/if}
