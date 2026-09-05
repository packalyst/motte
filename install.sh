#!/bin/bash
#
# Wire Panel installer — clones the panel into /opt/wire-panel, registers a
# systemd service + a `wire-panel` command, and runs first-time setup.
#
#   curl -fsSL https://raw.githubusercontent.com/packalyst/wireguard-admin-panel/main/install.sh | sudo bash
#   # or: download it, then: sudo ./install.sh
#
# To move an EXISTING checkout into this layout instead, use: ./manage.sh migrate
#
set -e

INSTALL_DIR="/opt/wire-panel"
REPO="https://github.com/packalyst/wireguard-admin-panel.git"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${GREEN}=== Wire Panel Installer ===${NC}"
echo ""

# Everything below needs root (writing /opt, /etc/systemd, /usr/local/bin).
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Root required — re-running with sudo...${NC}"
    exec sudo bash "$0" "$@"
fi

# Preflight.
for cmd in git docker; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}✗ '$cmd' is required but not installed.${NC}"
        exit 1
    fi
done

# Conflict guard — never clobber an existing install.
if [ -e "$INSTALL_DIR" ]; then
    echo -e "${RED}✗ $INSTALL_DIR already exists.${NC}"
    echo -e "  Manage the existing install with 'wire-panel', or remove the folder to reinstall."
    exit 1
fi

echo -e "${CYAN}Cloning into $INSTALL_DIR...${NC}"
git clone "$REPO" "$INSTALL_DIR"
cd "$INSTALL_DIR"
chmod +x manage.sh
chmod 750 "$INSTALL_DIR"

# Register the systemd unit + `wire-panel` CLI. Reuses manage.sh so the install
# logic lives in exactly one place.
./manage.sh install-service

echo ""
if [ -t 0 ]; then
    echo -e "${GREEN}Files installed.${NC} Starting first-time setup..."
    echo ""
    # manage.sh creates .env (which carries COMPOSE_PROJECT_NAME from
    # .env.example), runs the interactive config, and brings the stack up.
    exec ./manage.sh
else
    # Piped install (curl | bash): no TTY for the interactive prompts.
    echo -e "${GREEN}Install complete.${NC} Run ${CYAN}sudo wire-panel${NC} to configure and start the stack."
fi
