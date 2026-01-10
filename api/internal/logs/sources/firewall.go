package sources

import (
	"log"

	"api/internal/database"
	"api/internal/logs"
)

// InsertFirewallLog inserts a firewall attempt into the unified logs table.
// Called from firewall service when recording connection attempts.
func InsertFirewallLog(srcIP string, destPort int, protocol, jailName, status string) {
	db, err := database.GetDB()
	if err != nil {
		log.Printf("InsertFirewallLog: failed to get db: %v", err)
		return
	}

	_, err = db.Exec(`
		INSERT INTO logs (logs_type, logs_src_ip, logs_dest_port, logs_protocol, logs_service, logs_status)
		VALUES (?, ?, ?, ?, ?, ?)
	`, logs.LogTypeFirewall, srcIP, destPort, protocol, jailName, status)

	if err != nil {
		log.Printf("InsertFirewallLog: failed to insert: %v", err)
	}
}
