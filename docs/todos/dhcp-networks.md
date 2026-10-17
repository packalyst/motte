# Private networks (dnsmasq DHCP + routing + VPN reachability)

Let the panel act as the **gateway/router** for an isolated private network behind it, hand out
IPs to devices on it via DHCP, surface those devices as a new entity type, and make them
reachable over WireGuard under the existing default-deny ACL model.

- **Status:** Built (2026-10-17) — all 4 phases + UI + dnsmasq container. Approach chosen with
  the operator: interface brought up scoped with `ip addr replace` (never a global
  `netplan apply`) + validated netplan drop-in for persistence; `dnsmasq --test` pre-reload gate
  (dnsmasq-base in the api image); reload by restarting the dnsmasq container via the
  socket-proxy. Needs real-host verification (netplan/nsenter, DHCP hand-out, reachability).
- **Priority:** Medium — net-new capability. Phase 1 (interface safety) overlaps the P0
  lockout-safety work from the security audit and should land with it.

## Motivating case
Operator created a Proxmox **internal** network (no physical uplink), attached the panel VM
to it, and gave the VM `ens19 = 10.20.20.1/24`. Other VMs on that network have no config.
Goal: drop a VM onto the network → it auto-gets `10.20.20.x` → it shows up in the panel →
by default **nobody can reach it** → tick a VPN client and reach it over WireGuard
(`ssh nas.lan`). Optional internet-out (NAT), **off by default** (true sandbox).

## Why dnsmasq, and why DHCP-only
- WireGuard is L3 (no broadcast/L2), so DHCP can never run over `wg0` — only over a real L2
  segment (a NIC / VLAN / bridge). This feature is strictly for **LAN segments the box
  gateways**, not for VPN peers (peers keep getting their IP from their WG config).
- The stack already runs **AdGuard Home** (host-networked) as DNS, and the panel already
  pushes `DNS =` to peers. So dnsmasq runs **DHCP-only** (`port=0`, no `:53` conflict) and
  hands clients DHCP option 6 (DNS) → AdGuard, option 3 (gateway) → the box's LAN IP.

## New entity: DHCP clients
Third kind alongside **Nodes** (VPN peers) and **Machines** (fleet agents). A lease =
`{ name, ip, mac, lease-expiry }`, keyed by **MAC** (see audit note below). New "Networks"
page lists networks + their live leases.

## Reachability = existing ACL, per-client, default-deny
Reuse the Virtual-IP model (`vpn_virtual_ips` / `vpn_virtual_ip_acl`): the whole
`10.20.20.0/24` is exposed over the VPN via an **nftables forward rule gated by source client
IP, default-deny** — opt specific VPN clients in. Enforce in the **nft forward chain**, never
the Headscale ACL (the isolation audit confirmed the Headscale ACL blanket-grants the WG range
and is advisory only — data-plane is the real gate).

## Build phases (each: validate → apply → health-check → auto-revert on failure; fail-closed)
1. **Managed interfaces (the safe foundation).**
   - UI: pick a non-WAN internal NIC, set subnet/CIDR, gateway IP (must be inside subnet),
     DHCP pool (inside subnet, no clash with gateway / WG range / other managed nets).
   - Panel **owns** a netplan drop-in per managed net (e.g. `/etc/netplan/90-wgpanel-ens19.yaml`)
     so the gateway IP is not a fragile manual edit. Apply with a **`netplan try`-style
     commit + auto-rollback**; detect drift; if the interface/IP is missing, DHCP refuses
     with a clear UI error.
   - **Shares the P0 apply-then-confirm-or-auto-revert machinery** from the security audit
     (see `docs/todos` security follow-ups). Build once, use for both firewall and netplan.
2. **dnsmasq DHCP-only service.**
   - Host-networked container + `NET_ADMIN` (DHCP needs L2 broadcast on the NIC; same pattern
     as `adguard` / `vpn-router`). One `/etc/dnsmasq.d/<net>.conf` per network.
   - **Validate with `dnsmasq --test` before reload** (mirrors the `nft -c` gate). SIGHUP for
     reservation/lease changes; restart only for structural changes.
   - Parse `/var/lib/misc/dnsmasq.leases` → DHCP-clients entity.
3. **Registration + reservations.**
   - UI toggle: **auto** (any lease appears/works) vs **approve** (unknown MAC gets nothing
     until approved). All keyed by **MAC → reservation** (same IP/name every boot).
   - Per-client `name.lan` via the AdGuard rewrite path (same as `/api/vpn/clients/{id}/dns`),
     but **replace, not append** (audit found AdGuard rewrites stack duplicate A-records).
   - Lease time / pool / domain all UI-editable.
4. **Reachability + internet.**
   - Per-client ACL (nft forward `wg0→ens19`, default-deny) + push `10.20.20.0/24` into the
     allowed clients' routes.
   - Internet-out NAT as **one toggle, off by default**: `ip_forward` + masquerade
     `10.20.20.0/24` out the WAN + allow forward out / drop forward in (isolation).

## Hard guards (the "must be extremely secure" asks)
- Never run DHCP on the **WAN / default-route** interface.
- Pool/gateway/CIDR fully validated; no overlap with WG range or other managed nets.
- Fail-closed: a missing interface/IP stops DHCP rather than half-working.
- Validate every generated config (`dnsmasq --test`, `netplan generate/try`, `nft -c`) before
  commit; auto-revert on failed health-check.

## Notes carried from the security audit (fold in)
- Key DHCP clients by **MAC** — `vpn_clients.name` is not unique and the name→host mapping is
  lossy/collision-prone; don't repeat that.
- AdGuard rewrites must **replace, not append** (duplicate-answer / internal-name poisoning).
- When revoking a client's access, consider a **conntrack flush** — tightening policy leaves
  established flows accepted until timeout.
- NAT consistency: existing WG NAT is **iptables** in `wireguard/interface.go` while the
  firewall is **nftables**; keep the new NAT in the nft model.

## Related
- [[virtual-ips-feature-design]] — the ACL/default-deny pattern this reuses.
- Security audit (2026-10-17) P0 lockout-safety (apply-then-revert) — shared with Phase 1.
- AdGuard DNS + per-client DNS toggle (`/api/vpn/clients/{id}/dns`) — reused for naming.
