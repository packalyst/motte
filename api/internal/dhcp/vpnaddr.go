package dhcp

import (
	"database/sql"
	"errors"
	"net/netip"

	"api/internal/database"
	"api/internal/domains"
	"api/internal/helper"
)

// A LAN device's VPN address: an address inside the WireGuard range that VPN clients already route
// into their tunnel (WireGuard split configs, and the vpn-router's subnet route for Headscale), so
// granting access needs no change on any client. The box swaps it for the device's real address.

var errNoVPNAddress = errors.New("no free address in the WireGuard range for this device")

// vpnSpace is what decides whether a stored VPN address may be used.
type vpnSpace struct {
	wg     netip.Prefix      // the WireGuard range; invalid when WireGuard isn't configured
	server string            // the box's own WireGuard address
	owners map[string]string // every address in use, by owner (database.VPNAddressOwners)
}

func (s *Service) loadVPNSpace() (vpnSpace, error) {
	v := vpnSpace{server: helper.GetEnvOptional("WG_SERVER_IP", "")}
	if p, isRange, err := helper.ParseIPv4(helper.GetEnvOptional("WG_IP_RANGE", "")); err == nil && isRange {
		v.wg = p
	}
	owners, err := s.db.VPNAddressOwners()
	v.owners = owners
	return v, err
}

// usable reports whether ip may be a LAN device's VPN address: a valid IPv4 host inside the
// WireGuard range, not the box's own, and held by a LAN device alone (never also by a VPN client or
// a virtual IP, whose traffic it would otherwise capture).
func (v vpnSpace) usable(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && a.Is4() && v.wg.IsValid() && v.wg.Contains(a) && a != v.wg.Addr() &&
		ip != v.server && v.owners[ip] == database.VPNAddrLAN
}

// assignVPNIP gives a device its VPN address unless it has one (its VPN access switched on). The write only lands while no
// VPN client or virtual IP holds the address, and the unique index keeps two devices apart, so a
// race with another allocation retries on a fresh pick instead of sharing an address.
func (s *Service) assignVPNIP(deviceID int64) error {
	lastErr := errNoVPNAddress
	for attempt := 0; ; attempt++ {
		var cur string
		if err := s.db.QueryRow(`SELECT vpn_ip FROM dhcp_clients WHERE id = ?`, deviceID).Scan(&cur); err != nil {
			return err
		}
		if cur != "" {
			return nil
		}
		if attempt == 3 {
			return lastErr
		}
		v, err := s.loadVPNSpace()
		if err != nil {
			return err
		}
		ip := ""
		if v.wg.IsValid() {
			ip = helper.FreeUpperHalfIPv4(v.wg.String(), func(ip string) bool { return ip == v.server || v.owners[ip] != "" })
		}
		if ip == "" {
			return errNoVPNAddress
		}
		if _, err := s.db.Exec(`UPDATE dhcp_clients SET vpn_ip = ? WHERE id = ? AND vpn_ip = ''
			AND NOT EXISTS (SELECT 1 FROM vpn_clients WHERE ip = ?)
			AND NOT EXISTS (SELECT 1 FROM vpn_virtual_ips WHERE ip = ?)`, ip, deviceID, ip, ip); err != nil {
			lastErr = err // most likely another device took it first: pick again
		}
	}
}

// clearVPNAccess removes a device's VPN address, every grant and every domain route to it in one
// transaction, so neither can outlive the address it was given through. The returned routes still
// have to be applied (Removed.Apply) once it has committed.
func (s *Service) clearVPNAccess(deviceID int64) (domains.Removed, error) {
	return s.inTx(func(tx *sql.Tx) (domains.Removed, error) {
		removed, err := domains.DeleteLANDeviceRoutes(tx, deviceID)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`DELETE FROM dhcp_client_acl WHERE device_id = ?`, deviceID); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`UPDATE dhcp_clients SET vpn_ip = '' WHERE id = ?`, deviceID); err != nil {
			return nil, err
		}
		return removed, nil
	})
}

// inTx runs fn in a transaction and commits it, returning the routes fn removed.
func (s *Service) inTx(fn func(tx *sql.Tx) (domains.Removed, error)) (domains.Removed, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	removed, err := fn(tx)
	if err != nil {
		return nil, err
	}
	return removed, tx.Commit()
}
