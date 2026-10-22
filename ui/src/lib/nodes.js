// VPN client helpers shared by the client detail and add-peer modals (and the Nodes page).
import { apiGetText, toast } from '../stores/app.js'
import { copyWithToast } from '../stores/helpers.js'

// toNode turns a /api/vpn/clients entry into the node shape the client modal works with: the
// source data (WireGuard peer or Headscale node) plus _type/_ip/_online/_displayName.
export function toNode(client) {
  const raw = client.rawData || {}
  if (client.type === 'wireguard') {
    return {
      id: `wg-${client.externalId}`,
      _wgId: client.externalId,
      _type: 'wireguard',
      _displayName: client.name,
      _ip: client.ip,
      _online: raw.online || false,
      online: raw.online || false,
      lastHandshake: raw.lastHandshake,
      name: client.name,
      givenName: client.name,
      ipAddresses: [client.ip],
      createdAt: raw.createdAt || client.createdAt,
      lastSeen: raw.lastSeen,
      user: { name: 'WireGuard' },
      enabled: raw.enabled !== false,
      blockInternet: client.blockInternet === true,
      publicKey: raw.publicKey,
      privateKey: raw.privateKey,
      presharedKey: raw.presharedKey,
      totalTx: client.totalTx || 0,
      totalRx: client.totalRx || 0,
    }
  }
  return {
    ...raw,
    id: client.externalId,
    _type: 'tailscale',
    _displayName: raw.givenName || raw.name || client.name,
    _ip: client.ip,
    _online: raw.online || false,
    ipAddresses: raw.ipAddresses || [client.ip],
    user: raw.user || { name: 'Unknown' },
  }
}

// deviceIcon guesses a device icon from a Tailscale node's name; WireGuard peers get a lock.
export function deviceIcon(node) {
  if (node._type === 'wireguard') return 'lock'
  const lower = node.name?.toLowerCase() || ''
  if (lower.includes('iphone') || lower.includes('android') || lower.includes('pixel')) return 'device-mobile'
  if (lower.includes('ipad') || lower.includes('tablet')) return 'device-tablet'
  if (lower.includes('macbook') || lower.includes('laptop')) return 'device-laptop'
  return 'device-desktop'
}

// tailscaleUpCommand is the command a device runs to join Headscale with a pre-auth key.
export const tailscaleUpCommand = (serverUrl, key) => `tailscale up --login-server=${serverUrl} --authkey=${key}`

const peerConfig = (peerId, mode) => apiGetText(`/api/wg/peers/${peerId}/config` + (mode ? `?mode=${mode}` : ''))

// downloadPeerConfig saves a WireGuard peer's config file (mode: 'full' | 'split'; default full).
export async function downloadPeerConfig(peerId, name, mode) {
  try {
    const url = URL.createObjectURL(new Blob([await peerConfig(peerId, mode)], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `${name}.conf`
    a.click()
    URL.revokeObjectURL(url)
    toast('Configuration downloaded', 'success')
  } catch (e) {
    toast('Failed: ' + e.message, 'error')
  }
}

export async function copyPeerConfig(peerId, mode) {
  try {
    await copyWithToast(await peerConfig(peerId, mode), toast)
  } catch (e) {
    toast('Failed: ' + e.message, 'error')
  }
}
