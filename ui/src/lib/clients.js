// The unified client list (GET /api/clients: WireGuard peers, Tailscale nodes, agent machines and
// LAN devices), kept live and shared by the sidebar, Overview and the Clients page: one fetch per
// server change signal, however many are watching. The server applies the caller's role and
// machine scope to every fetch.
import { writable, get } from 'svelte/store'
import { apiGet, openView } from '../stores/app.js'
import { subscribe, unsubscribe, clientsStore } from '../stores/websocket.js'

export const KINDS = {
  wireguard: { label: 'WireGuard', group: 'WireGuard peers', icon: 'shield', color: 'var(--client-wg)' },
  tailscale: { label: 'Tailscale', group: 'Tailscale nodes', icon: 'cloud', color: 'var(--client-ts)' },
  machine: { label: 'Machine', group: 'Machines', icon: 'device-desktop', color: 'var(--client-mc)' },
  lan: { label: 'LAN device', group: 'LAN devices', icon: 'router', color: 'var(--client-lan)' },
}

// A VPN client that is also an agent machine counts as both.
export const isKind = (c, k) => c.kind === k || (k === 'machine' && c.machine)

const EMPTY = { clients: [], unavailable: [], loaded: false, error: '' }
export const clientsList = writable(EMPTY)

let watchers = 0
let stopSignal = null
let inflight = null
let queued = null

async function fetchList() {
  try {
    const res = await apiGet('/api/clients')
    // Nobody watching any more (e.g. signed out mid-request): don't keep the answer around.
    if (watchers) clientsList.set({ clients: res.clients || [], unavailable: res.unavailable || [], loaded: true, error: '' })
  } catch (e) {
    if (watchers) clientsList.update((l) => ({ ...l, loaded: true, error: e.message }))
    throw e
  }
}

// reloadClients fetches the list now. Callers share a request already running; one that started
// before the caller's change (say, a peer just added) is followed by a single fresh one.
export function reloadClients() {
  if (!inflight) return (inflight = fetchList().finally(() => (inflight = null)))
  return (queued ??= inflight.catch(() => {}).then(() => { queued = null; return reloadClients() }))
}

// watchClients keeps the list live while at least one caller holds it; returns the release.
// The last release drops the data, so the next user to sign in never sees the previous one's.
export function watchClients() {
  if (watchers++ === 0) {
    subscribe('clients')
    let seen = get(clientsStore)
    stopSignal = clientsStore.subscribe((n) => {
      if (n > seen) { seen = n; reloadClients().catch(() => {}) }
    })
    reloadClients().catch(() => {})
  }
  let released = false
  return () => {
    if (released) return
    released = true
    if (--watchers === 0) {
      stopSignal()
      unsubscribe('clients')
      clientsList.set(EMPTY)
    }
  }
}

const RANK = { destructive: 0, warning: 1 }
const rank = (tone) => RANK[tone] ?? 2

// summarize counts clients (online / total, per kind) and lists the clients that need someone to
// act, each with its issues: flags the server marks as needing action (critical CVEs, expiring
// credentials, approvals…) and an uninstalled agent. States an admin chose (disabled, no
// internet, blocked) are left out. Worst first.
export function summarize(clients) {
  const kinds = Object.fromEntries(Object.keys(KINDS).map((k) => [k, { total: 0, online: 0 }]))
  const attention = []
  const issues = { destructive: 0, warning: 0 }
  for (const c of clients) {
    for (const k of Object.keys(KINDS)) {
      if (isKind(c, k)) { kinds[k].total++; if (c.online) kinds[k].online++ }
    }
    const items = (c.flags || []).filter((f) => f.act).map((f) => ({ label: f.label, tone: f.tone, icon: f.icon }))
    if (c.gone) items.push({ label: 'Agent uninstalled', tone: 'muted', icon: 'plug-connected-x' })
    if (!items.length) continue
    items.sort((a, b) => rank(a.tone) - rank(b.tone))
    for (const i of items) if (i.tone in issues) issues[i.tone]++
    attention.push({ c, items, tone: items[0].tone })
  }
  attention.sort((a, b) => rank(a.tone) - rank(b.tone) || a.c.name.localeCompare(b.c.name))
  return { total: clients.length, online: clients.filter((c) => c.online).length, kinds, attention, issues }
}

// A request to show the Clients page narrowed to one kind ('' = all kinds); the page applies it
// and resets it to null.
export const clientsFilter = writable(null)
export function openClients(kind = '') {
  clientsFilter.set(kind)
  openView('clients')
}

// openClient goes to where a client is managed: a machine's own page, else its kind on Clients.
export function openClient(c) {
  if (c.open?.machine) openView('clients', 'm=' + encodeURIComponent(c.open.machine))
  else openClients(c.kind)
}
