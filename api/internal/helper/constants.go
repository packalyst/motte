package helper

import "time"

// ACL Policy constants
const (
	ACLPolicyBlockAll = "block_all" // Client is isolated - can't reach anyone, nobody can reach them
	ACLPolicySelected = "selected"  // Client can reach only selected targets
	ACLPolicyAllowAll = "allow_all" // Client can reach everyone
)

// Default ACL values
const (
	DefaultACLPolicy = ACLPolicySelected
)

// ValidACLPolicies is the set of valid ACL policy values
var ValidACLPolicies = map[string]bool{
	ACLPolicyBlockAll: true,
	ACLPolicySelected: true,
	ACLPolicyAllowAll: true,
}

// IsValidACLPolicy checks if a policy value is valid
func IsValidACLPolicy(policy string) bool {
	return ValidACLPolicies[policy]
}

// VPN Router configuration defaults
const (
	DefaultRouterName     = "vpn-router"
	DefaultRouterImage    = "tailscale/tailscale:latest"
	DefaultRouterDataPath = "/var/lib/tailscale-vpn-router"
)

// Timeout constants
const (
	RouterRegistrationTimeout = 30 * time.Second
	PreAuthKeyExpiration      = 1 * time.Hour
	PeerOnlineThreshold       = 3 * time.Minute
	DockerRequestTimeout      = 60 * time.Second
	DockerQuickTimeout        = 5 * time.Second
	HTTPClientTimeout         = 10 * time.Second
	WebSocketReadTimeout      = 10 * time.Second
	PortScanTimeout           = 5 * time.Minute
	GeoDBDownloadTimeout      = 5 * time.Minute
	LoginLockoutWindow        = 15 * time.Minute
	LoginLockoutDuration      = 15 * time.Minute
)

// Path constants
const (
	DefaultNFTablesACLPath  = "/etc/nftables.d/vpn-acl.nft"
	DefaultHeadscaleACLPath = "/etc/headscale/acl.json"
	DefaultOutputInterface  = "eth0"
	ConfigsDir              = "/app/configs"
	CommonPortsConfigPath   = "/app/configs/common-ports.json"
	BlocklistSourcesPath    = "/app/configs/blocklist-sources.json"
	CountriesConfigPath     = "/app/configs/countries.json"
	GeolocationConfigPath   = "/app/configs/geolocation.json"
)

// SSH config paths (in order of preference)
var SSHConfigPaths = []string{"/etc/ssh/sshd_config", "/etc/sshd_config"}

// Pagination constants
const (
	DefaultPaginationLimit = 25
	LargePaginationLimit   = 100
)

// Authentication constants
const (
	TOTPIssuer = "Wireguard"
)

// GetRouterName returns the configured router container name
func GetRouterName() string {
	return GetEnvOptional("VPN_ROUTER_NAME", DefaultRouterName)
}

// GetRouterImage returns the configured router image
func GetRouterImage() string {
	return GetEnvOptional("VPN_ROUTER_IMAGE", DefaultRouterImage)
}

// GetRouterDataPath returns the configured router data path
func GetRouterDataPath() string {
	return GetEnvOptional("VPN_ROUTER_DATA", DefaultRouterDataPath)
}

// GetNFTablesACLPath returns the configured nftables ACL path
func GetNFTablesACLPath() string {
	return GetEnvOptional("NFTABLES_ACL_PATH", DefaultNFTablesACLPath)
}

// GetHeadscaleACLPath returns the configured Headscale ACL path
func GetHeadscaleACLPath() string {
	return GetEnvOptional("HEADSCALE_ACL_PATH", DefaultHeadscaleACLPath)
}

// GetOutputInterface returns the configured output interface for NAT
func GetOutputInterface() string {
	return GetEnvOptional("OUTPUT_INTERFACE", DefaultOutputInterface)
}
