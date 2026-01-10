# WireGuard Admin Panel

A self-hosted web dashboard for managing WireGuard VPN peers, Headscale (Tailscale-compatible) nodes, AdGuard Home DNS filtering, and firewall rules.

## Overview

This project provides a unified administration interface for a complete VPN stack. It combines manual WireGuard peer management with Headscale for Tailscale client support, integrated DNS filtering via AdGuard Home, and a nftables-based firewall with intrusion detection.

## Features

### VPN Management
- WireGuard peer management with QR code generation for mobile clients
- Headscale integration for Tailscale-compatible clients
- Unified VPN client view across both protocols
- VPN-to-VPN access control rules (ACL) with nftables enforcement
- Cross-network routing between WireGuard and Headscale networks
- Port scanning for connected VPN clients

### Security
- Session-based authentication with bcrypt password hashing
- Two-factor authentication (TOTP) with QR code setup
- API key support for programmatic access
- Rate limiting on authentication endpoints
- Session management with device tracking and revocation

### Firewall
- nftables-based firewall rule management
- Port allowlisting with protocol support (TCP/UDP)
- IP blocking with manual and automatic modes
- Fail2ban-style jails with log pattern monitoring
- CIDR escalation for repeat offenders
- Blocklist import from external sources

### Geolocation
- Country-based traffic blocking (inbound/outbound)
- IP geolocation lookup via MaxMind GeoLite2 or IP2Location
- IPdeny CIDR zone files for country blocking
- Automatic database updates

### DNS Filtering
- AdGuard Home integration for DNS query logging
- DNS rewrites for VPN client hostnames
- Query statistics and filtering controls

### Monitoring
- Real-time VPN traffic logging with connection tracking
- WebSocket-based live updates for node status and traffic
- Combined log view (VPN traffic, Traefik HTTP, AdGuard DNS)
- Docker container status and log streaming

### Infrastructure
- Traefik reverse proxy configuration management
- Docker container lifecycle control (start/stop/restart)
- SSH port configuration

## Tech Stack

### Backend
- Go 1.21+
- SQLite database
- gorilla/websocket for real-time updates
- wgctrl for WireGuard interface management
- MaxMind/IP2Location for geolocation

### Frontend
- Svelte 5
- Tailwind CSS 4
- Vite 7
- KTUI component framework

### Infrastructure
- Docker and Docker Compose
- Traefik reverse proxy
- Headscale (Tailscale control plane)
- AdGuard Home DNS server
- nftables firewall

## Installation

### Prerequisites

- Linux server with root access
- Docker and Docker Compose
- WireGuard kernel module

### Quick Start

1. Clone the repository:
```bash
git clone https://github.com/packalyst/wireguard-admin-panel.git
cd wireguard-admin-panel
```

2. Run the management script:
```bash
chmod +x manage.sh
./manage.sh
```

The script will:
- Check and install missing dependencies
- Auto-detect your public IP address
- Guide you through interactive setup
- Generate required configuration files
- Start all services

### Access

After installation:
- Dashboard: `http://YOUR_SERVER_IP/`
- Traefik dashboard: `http://YOUR_SERVER_IP:8080`
- AdGuard Home: `http://YOUR_SERVER_IP:8083`
- API: `http://YOUR_SERVER_IP:8081`

### First Login

Default credentials:
- Username: `admin`
- Password: `admin`

Change these immediately after first login.

## Configuration

### Environment Variables

Core settings in `.env`:

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_IP` | Public IP of your server | Required |
| `ENCRYPTION_SECRET` | Secret for encrypting sensitive data | Required (generate with `openssl rand -hex 32`) |
| `WG_INTERFACE` | WireGuard interface name | `wg0` |
| `WG_PORT` | WireGuard UDP port | `51820` |
| `WG_IP_RANGE` | IP range for WireGuard peers | `10.8.0.0/16` |
| `WG_SERVER_IP` | WireGuard server gateway IP | `10.8.0.1` |
| `HEADSCALE_IP_RANGE` | IP range for Headscale clients | `100.64.0.0/16` |
| `HEADSCALE_BASE_DOMAIN` | DNS base domain for Headscale | `vpn.local` |

Service ports:

| Variable | Description | Default |
|----------|-------------|---------|
| `HTTP_PORT` | Traefik HTTP port | `80` |
| `HTTPS_PORT` | Traefik HTTPS port | `443` |
| `TRAEFIK_PORT` | Traefik dashboard port | `8080` |
| `API_PORT` | Backend API port | `8081` |
| `ADGUARD_PORT` | AdGuard web UI port | `8083` |
| `DNS_PORT` | AdGuard DNS port | `53` |
| `STUN_PORT` | DERP/STUN NAT traversal port | `3478` |

Security settings:

| Variable | Description | Default |
|----------|-------------|---------|
| `TRUSTED_PROXIES` | IPs allowed to set X-Forwarded-For | Traefik container IP |
| `IGNORE_NETWORKS` | Networks excluded from firewall | Private ranges |

See `.env.example` for the complete list.

### SSL/HTTPS

To enable Let's Encrypt certificates:

```bash
SSL_ENABLED=true
SSL_DOMAIN=vpn.example.com
LETSENCRYPT_EMAIL=admin@example.com
```

## Development

Enable hot reload during setup:

```bash
./manage.sh
# Choose "y" when asked: "Enable development mode with hot reload?"
```

Or set in `.env`:
```bash
DEV_MODE=true
```

Changes to Svelte files will reflect instantly without rebuilding.

## Project Structure

```
├── api/                    # Go backend
│   ├── cmd/               # Application entry point
│   ├── internal/          # Core packages
│   │   ├── auth/         # Authentication and 2FA
│   │   ├── database/     # SQLite database
│   │   ├── firewall/     # nftables and traffic logging
│   │   ├── geolocation/  # IP lookup and country blocking
│   │   ├── vpn/          # Unified VPN client management
│   │   ├── wireguard/    # WireGuard peer management
│   │   ├── headscale/    # Headscale API proxy
│   │   ├── adguard/      # AdGuard API proxy
│   │   ├── traefik/      # Traefik configuration
│   │   ├── docker/       # Container management
│   │   └── ws/           # WebSocket service
│   └── configs/          # Endpoint configuration
├── ui/                    # Svelte frontend
│   └── src/
│       ├── views/        # Page components
│       ├── components/   # Reusable UI components
│       └── lib/          # API client and utilities
├── headscale/            # Headscale configuration
├── traefik/              # Traefik configuration
├── adguard/              # AdGuard Home configuration
├── docker-compose.yml    # Container orchestration
└── manage.sh             # Management script
```

## API Endpoints

The API is organized by service:

- `/api/auth` - Authentication, sessions, 2FA
- `/api/wg` - WireGuard peer management
- `/api/hs` - Headscale node management
- `/api/vpn` - Unified VPN clients and ACL
- `/api/fw` - Firewall, ports, jails, traffic
- `/api/geo` - Geolocation and country blocking
- `/api/traefik` - Traefik route configuration
- `/api/adguard` - AdGuard DNS settings
- `/api/docker` - Container management
- `/api/settings` - Application settings
- `/api/ws` - WebSocket for real-time updates

## Security Notes

- All API endpoints require authentication except initial setup
- Private keys are stripped from WireGuard peer data before database storage
- Sensitive settings (API keys, tokens) are encrypted at rest
- Headscale API access is restricted to VPN networks
- Docker socket access is proxied through docker-socket-proxy with limited permissions
- Rate limiting is applied to authentication and sensitive endpoints
- Security headers are set on all responses

## License

MIT
