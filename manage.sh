#!/bin/bash
set -e

# ===========================================
# VPN Stack Smart Management Script
# Dependency checking, Docker management, and interactive setup
# ===========================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== VPN Stack Management ===${NC}"
echo ""

# ===========================================
# Command Line Arguments
# ===========================================

# Handle direct commands before anything else
case "${1:-}" in
    update|--update|-u)
        # Source the functions first, then check for updates
        # (Functions are defined below, so we use a flag)
        RUN_UPDATE_CHECK=true
        ;;
    backup|--backup|-b)
        # Backup SSL certificates
        RUN_BACKUP=true
        ;;
    help|--help|-h)
        echo "Usage: ./manage.sh [command]"
        echo ""
        echo "Commands:"
        echo "  (none)     Interactive mode - manage containers"
        echo "  update     Check for and install updates"
        echo "  backup     Backup SSL certificates"
        echo "  help       Show this help message"
        echo ""
        exit 0
        ;;
esac

# ===========================================
# Helper Functions
# ===========================================

detect_public_ip() {
    # Try multiple services to detect public IP
    local ip=""
    ip=$(curl -s --max-time 3 ifconfig.me 2>/dev/null) || \
    ip=$(curl -s --max-time 3 icanhazip.com 2>/dev/null) || \
    ip=$(curl -s --max-time 3 ipinfo.io/ip 2>/dev/null) || \
    ip=$(curl -s --max-time 3 api.ipify.org 2>/dev/null)
    echo "$ip"
}

validate_domain_dns() {
    local domain="$1"
    local expected_ip="$2"

    # Check if dig is available, otherwise use host or nslookup
    local resolved_ip=""

    # Use || true to prevent set -e from exiting on grep failure
    if command -v dig &> /dev/null; then
        resolved_ip=$(dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || true)
    elif command -v host &> /dev/null; then
        resolved_ip=$(host "$domain" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}' || true)
    elif command -v nslookup &> /dev/null; then
        resolved_ip=$(nslookup "$domain" 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -1 || true)
    else
        echo "no-dns-tool"
        return 2
    fi

    if [ -z "$resolved_ip" ]; then
        echo "unresolved"
        return 1
    fi

    if [ "$resolved_ip" = "$expected_ip" ]; then
        echo "$resolved_ip"
        return 0
    else
        echo "$resolved_ip"
        return 1
    fi
}

validate_email() {
    local email="$1"
    # Basic email validation regex
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_domain_format() {
    local domain="$1"
    # Domain format validation:
    # - Must contain at least one dot
    # - Cannot start/end with dot or hyphen
    # - Only alphanumeric, dots, and hyphens allowed
    # - Each label max 63 chars, total max 253 chars
    if [[ ${#domain} -gt 253 ]]; then
        return 1
    fi
    if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$ ]]; then
        return 0
    else
        return 1
    fi
}

# Cloudflare IP ranges (cached)
CF_IPS=""

fetch_cloudflare_ips() {
    if [ -n "$CF_IPS" ]; then
        echo "$CF_IPS"
        return 0
    fi

    echo -e "${YELLOW}Fetching Cloudflare IP ranges...${NC}" >&2
    CF_IPS=$(curl -s --max-time 5 "https://www.cloudflare.com/ips-v4/" 2>/dev/null) || true

    if [ -z "$CF_IPS" ]; then
        echo -e "${RED}Failed to fetch Cloudflare IPs${NC}" >&2
        echo ""
        return 0
    fi

    echo "$CF_IPS"
}

is_cloudflare_ip() {
    local ip="$1"
    local cf_ranges="$2"

    # Convert IP to integer for comparison
    local ip_int=0
    local i=0
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        ip_int=$((ip_int * 256 + octet))
    done

    # Check each CIDR range
    while IFS= read -r cidr; do
        [ -z "$cidr" ] && continue

        local network="${cidr%/*}"
        local prefix="${cidr#*/}"

        # Convert network to integer
        local net_int=0
        IFS='.' read -ra octets <<< "$network"
        for octet in "${octets[@]}"; do
            net_int=$((net_int * 256 + octet))
        done

        # Calculate mask
        local mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))

        # Check if IP is in range
        if [ $((ip_int & mask)) -eq $((net_int & mask)) ]; then
            return 0
        fi
    done <<< "$cf_ranges"

    return 1
}

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local response

    if [ "$default" = "y" ]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    read -p "$prompt" response
    response=${response:-$default}

    [[ "$response" =~ ^[Yy] ]]
}

CERT_BACKUP_DIR="/usr/local/wgadmin/certs"
TRAEFIK_MAIN_LOG="traefik/logs/traefik.log"

# Backup all certificates (whole acme.json) - uses SSL_DOMAIN from .env
backup_certificates() {
    # Load SSL_DOMAIN from .env if not already set
    if [ -z "${SSL_DOMAIN:-}" ] && [ -f ".env" ]; then
        SSL_DOMAIN=$(grep "^SSL_DOMAIN=" .env 2>/dev/null | cut -d'=' -f2)
    fi

    if [ -z "${SSL_DOMAIN:-}" ]; then
        echo -e "${YELLOW}No SSL_DOMAIN configured - nothing to backup${NC}"
        return 1
    fi

    if [ ! -f "traefik/acme.json" ]; then
        echo -e "${YELLOW}No acme.json found - nothing to backup${NC}"
        return 1
    fi

    # Check if acme.json has any certificates
    if command -v jq &>/dev/null; then
        local certs=$(cat traefik/acme.json 2>/dev/null | jq -r '.letsencrypt.Certificates // empty' 2>/dev/null)
        if [ -z "$certs" ] || [ "$certs" = "null" ]; then
            echo -e "${YELLOW}No certificates in acme.json - nothing to backup${NC}"
            return 1
        fi
    fi

    # Use existing backup_certificate function with SSL_DOMAIN
    backup_certificate "$SSL_DOMAIN"
}

backup_certificate() {
    local domain="$1"

    if [ ! -f "traefik/acme.json" ]; then
        return 1
    fi

    # Check if certificate exists in acme.json
    if ! command -v jq &>/dev/null; then
        return 1
    fi

    local certs=$(cat traefik/acme.json 2>/dev/null | jq -r '.letsencrypt.Certificates // empty' 2>/dev/null)
    if [ -z "$certs" ] || [ "$certs" = "null" ]; then
        return 1
    fi

    # Create backup directory
    sudo mkdir -p "$CERT_BACKUP_DIR"
    sudo chmod 700 "$CERT_BACKUP_DIR"

    # Backup with timestamp
    local backup_file="${CERT_BACKUP_DIR}/acme_${domain}_$(date +%Y%m%d_%H%M%S).json"
    local latest_link="${CERT_BACKUP_DIR}/acme_${domain}_latest.json"

    sudo cp traefik/acme.json "$backup_file"
    sudo chmod 600 "$backup_file"
    sudo ln -sf "$backup_file" "$latest_link"

    echo -e "${GREEN}✓ Certificate backed up to: ${backup_file}${NC}"
    return 0
}

restore_certificate() {
    local domain="$1"
    local backup_file="${CERT_BACKUP_DIR}/acme_${domain}_latest.json"

    if [ ! -f "$backup_file" ]; then
        return 1
    fi

    # Verify backup has valid certificates
    if command -v jq &>/dev/null; then
        local certs=$(sudo cat "$backup_file" 2>/dev/null | jq -r '.letsencrypt.Certificates // empty' 2>/dev/null)
        if [ -z "$certs" ] || [ "$certs" = "null" ]; then
            echo -e "${YELLOW}Backup exists but contains no valid certificates${NC}"
            return 1
        fi
    fi

    # Restore
    sudo cp "$backup_file" traefik/acme.json
    chmod 600 traefik/acme.json

    echo -e "${GREEN}✓ Certificate restored from backup${NC}"
    return 0
}

check_certificate_backup() {
    local domain="$1"
    local backup_file="${CERT_BACKUP_DIR}/acme_${domain}_latest.json"

    if [ ! -f "$backup_file" ]; then
        return 1
    fi

    # Get backup info
    local backup_date=$(stat -c %y "$backup_file" 2>/dev/null | cut -d' ' -f1 || stat -f %Sm -t %Y-%m-%d "$backup_file" 2>/dev/null)
    local backup_size=$(stat -c %s "$backup_file" 2>/dev/null || stat -f %z "$backup_file" 2>/dev/null)

    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}✓ Certificate backup found${NC}                                ${CYAN}║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}                                                            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Domain: ${YELLOW}${domain}${NC}"
    printf "${CYAN}║${NC}  %-56s ${CYAN}║${NC}\n" ""
    echo -e "${CYAN}║${NC}  Backup date: ${backup_date:-unknown}                              "
    echo -e "${CYAN}║${NC}  Size: ${backup_size:-0} bytes                                      "
    echo -e "${CYAN}║${NC}                                                            ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    return 0
}

check_cert_rate_limit() {
    local domain="$1"
    echo -e "${YELLOW}Checking Let's Encrypt rate limits for ${domain}...${NC}"

    # Query crt.sh for recent certificates
    local week_ago=$(date -u -d '7 days ago' '+%Y-%m-%d' 2>/dev/null || date -u -v-7d '+%Y-%m-%d' 2>/dev/null)

    if [ -z "$week_ago" ]; then
        echo -e "  ${YELLOW}⚠${NC} Could not calculate date range, skipping rate limit check"
        return 0
    fi

    # Fetch certificate count from crt.sh
    local response
    response=$(curl -s --max-time 10 "https://crt.sh/?q=${domain}&output=json" 2>/dev/null)

    if [ -z "$response" ] || [ "$response" = "null" ]; then
        echo -e "  ${YELLOW}⚠${NC} Could not query crt.sh, skipping rate limit check"
        return 0
    fi

    # Count certificates issued in last 7 days
    local recent_count
    if command -v jq &>/dev/null; then
        recent_count=$(echo "$response" | jq "[.[] | select(.not_before > \"${week_ago}\")] | length" 2>/dev/null || echo "0")
    else
        echo -e "  ${YELLOW}⚠${NC} jq not installed, skipping rate limit check"
        return 0
    fi

    # Handle empty or invalid response
    if [ -z "$recent_count" ] || ! [[ "$recent_count" =~ ^[0-9]+$ ]]; then
        recent_count=0
    fi

    if [ "$recent_count" -ge 5 ]; then
        echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║${NC}  ${YELLOW}⚠ LET'S ENCRYPT RATE LIMIT WARNING${NC}                        ${RED}║${NC}"
        echo -e "${RED}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${RED}║${NC}                                                            ${RED}║${NC}"
        echo -e "${RED}║${NC}  ${recent_count} certificates issued for ${domain} in the last 7 days"
        printf "${RED}║${NC}  %-56s ${RED}║${NC}\n" ""
        echo -e "${RED}║${NC}  Let's Encrypt limit: 5 duplicate certs per 7 days        ${RED}║${NC}"
        echo -e "${RED}║${NC}                                                            ${RED}║${NC}"
        echo -e "${RED}║${NC}  You may encounter rate limiting errors.                  ${RED}║${NC}"
        echo -e "${RED}║${NC}  Check: https://crt.sh/?q=${domain}                        "
        echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        if ! prompt_yes_no "Continue anyway? (may fail to get certificate)" "n"; then
            return 1
        fi
    elif [ "$recent_count" -gt 0 ]; then
        echo -e "  ${GREEN}✓${NC} Rate limit OK (${recent_count}/5 certs issued in last 7 days)"
    else
        echo -e "  ${GREEN}✓${NC} No recent certificates found - rate limit OK"
    fi

    return 0
}

update_env_value() {
    local key="$1"
    local value="$2"

    # Escape special sed characters in value
    local escaped_value
    escaped_value=$(printf '%s' "$value" | sed 's/[&/\|]/\\&/g')

    if grep -q "^${key}=" .env 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${escaped_value}|g" .env
    else
        echo "${key}=${value}" >> .env
    fi
}

check_dependency() {
    local cmd="$1"
    local name="$2"

    if command -v "$cmd" &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $name"
        return 0
    else
        echo -e "  ${RED}✗${NC} $name ${YELLOW}(missing)${NC}"
        return 1
    fi
}

install_docker() {
    echo -e "${YELLOW}Installing Docker...${NC}"

    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo -e "${RED}Cannot detect OS${NC}"
        return 1
    fi

    case "$OS" in
        ubuntu|debian)
            sudo apt-get update
            sudo apt-get install -y ca-certificates curl gnupg
            sudo install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/$OS/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            sudo chmod a+r /etc/apt/keyrings/docker.gpg
            echo \
              "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
              $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
              sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
        centos|rhel|fedora)
            sudo yum install -y yum-utils
            sudo yum-config-manager --add-repo https://download.docker.com/linux/$OS/docker-ce.repo
            sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            sudo systemctl start docker
            sudo systemctl enable docker
            ;;
        *)
            echo -e "${RED}Unsupported OS: $OS${NC}"
            echo "Please install Docker manually: https://docs.docker.com/engine/install/"
            return 1
            ;;
    esac

    echo -e "${GREEN}✓ Docker installed${NC}"
}

install_wireguard() {
    echo -e "${YELLOW}Installing WireGuard...${NC}"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo -e "${RED}Cannot detect OS${NC}"
        return 1
    fi

    case "$OS" in
        ubuntu|debian)
            sudo apt-get update
            sudo apt-get install -y wireguard wireguard-tools
            ;;
        centos|rhel|fedora)
            sudo yum install -y epel-release elrepo-release
            sudo yum install -y kmod-wireguard wireguard-tools
            ;;
        *)
            echo -e "${RED}Unsupported OS: $OS${NC}"
            echo "Please install WireGuard manually: https://www.wireguard.com/install/"
            return 1
            ;;
    esac

    echo -e "${GREEN}✓ WireGuard installed${NC}"
}

# ===========================================
# Update Checker Functions
# ===========================================

check_for_updates() {
    echo -e "${BLUE}=== Update Checker ===${NC}"
    echo ""

    # Check if git is available
    if ! command -v git &> /dev/null; then
        echo -e "${RED}Git is not installed. Cannot check for updates.${NC}"
        return 1
    fi

    # Check if we're in a git repository
    if ! git rev-parse --git-dir &> /dev/null 2>&1; then
        echo -e "${RED}Not a git repository. Cannot check for updates.${NC}"
        return 1
    fi

    # Get current branch
    CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
    if [ -z "$CURRENT_BRANCH" ]; then
        echo -e "${RED}Cannot determine current branch${NC}"
        return 1
    fi

    echo -e "${YELLOW}Fetching updates from remote...${NC}"
    git fetch origin "$CURRENT_BRANCH" 2>/dev/null || {
        echo -e "${RED}Failed to fetch from remote${NC}"
        return 1
    }

    # Get current and remote commit
    LOCAL_COMMIT=$(git rev-parse HEAD)
    REMOTE_COMMIT=$(git rev-parse origin/"$CURRENT_BRANCH" 2>/dev/null)

    if [ -z "$REMOTE_COMMIT" ]; then
        echo -e "${RED}Cannot find remote branch origin/${CURRENT_BRANCH}${NC}"
        return 1
    fi

    LOCAL_SHORT=$(git rev-parse --short HEAD)
    REMOTE_SHORT=$(git rev-parse --short origin/"$CURRENT_BRANCH")

    echo ""
    echo -e "${CYAN}Current branch:${NC} $CURRENT_BRANCH"
    echo -e "${CYAN}Local commit:${NC}  $LOCAL_SHORT"
    echo -e "${CYAN}Remote commit:${NC} $REMOTE_SHORT"
    echo ""

    # Check if up to date
    if [ "$LOCAL_COMMIT" = "$REMOTE_COMMIT" ]; then
        echo -e "${GREEN}✓ You are up to date!${NC}"
        echo ""
        return 0
    fi

    # Count commits behind
    COMMITS_BEHIND=$(git rev-list --count HEAD..origin/"$CURRENT_BRANCH")
    COMMITS_AHEAD=$(git rev-list --count origin/"$CURRENT_BRANCH"..HEAD)

    if [ "$COMMITS_AHEAD" -gt 0 ]; then
        echo -e "${YELLOW}⚠ You are $COMMITS_AHEAD commit(s) ahead of remote${NC}"
        echo "  (You have local commits not pushed to remote)"
        echo ""
    fi

    if [ "$COMMITS_BEHIND" -eq 0 ]; then
        echo -e "${GREEN}✓ No new updates available${NC}"
        return 0
    fi

    echo -e "${YELLOW}⚠ You are $COMMITS_BEHIND commit(s) behind${NC}"
    echo ""

    # Show commits
    echo -e "${BLUE}Available updates:${NC}"
    echo -e "${CYAN}─────────────────────────────────────────────────────────────${NC}"

    # Store commits in array for selection
    COMMIT_LIST=()
    COMMIT_INDEX=1

    while IFS= read -r line; do
        COMMIT_HASH=$(echo "$line" | cut -d'|' -f1)
        COMMIT_DATE=$(echo "$line" | cut -d'|' -f2)
        COMMIT_MSG=$(echo "$line" | cut -d'|' -f3)

        COMMIT_LIST+=("$COMMIT_HASH")
        echo -e "  ${GREEN}[$COMMIT_INDEX]${NC} ${YELLOW}$COMMIT_HASH${NC} - $COMMIT_DATE"
        echo -e "      $COMMIT_MSG"

        # Show changed files for this commit
        FILES_CHANGED=$(git diff-tree --no-commit-id --name-only -r "$COMMIT_HASH" 2>/dev/null | head -5)
        if [ -n "$FILES_CHANGED" ]; then
            echo -e "      ${CYAN}Files:${NC}"
            while IFS= read -r file; do
                echo -e "        - $file"
            done <<< "$FILES_CHANGED"

            TOTAL_FILES=$(git diff-tree --no-commit-id --name-only -r "$COMMIT_HASH" 2>/dev/null | wc -l)
            if [ "$TOTAL_FILES" -gt 5 ]; then
                echo -e "        ${YELLOW}... and $((TOTAL_FILES - 5)) more files${NC}"
            fi
        fi
        echo ""

        ((COMMIT_INDEX++))
    done < <(git log --oneline --format="%h|%cr|%s" HEAD..origin/"$CURRENT_BRANCH" | head -10)

    if [ "$COMMITS_BEHIND" -gt 10 ]; then
        echo -e "  ${YELLOW}... and $((COMMITS_BEHIND - 10)) more commits${NC}"
        echo ""
    fi

    echo -e "${CYAN}─────────────────────────────────────────────────────────────${NC}"
    echo ""

    # Check for local modifications
    echo -e "${BLUE}Checking for local modifications...${NC}"
    LOCAL_CHANGES=$(git status --porcelain 2>/dev/null)

    if [ -n "$LOCAL_CHANGES" ]; then
        echo -e "${YELLOW}⚠ You have local modifications:${NC}"
        echo ""

        # Categorize changes
        MODIFIED_FILES=$(echo "$LOCAL_CHANGES" | grep "^ M\| M " | awk '{print $2}')
        UNTRACKED_FILES=$(echo "$LOCAL_CHANGES" | grep "^??" | awk '{print $2}')

        if [ -n "$MODIFIED_FILES" ]; then
            echo -e "  ${YELLOW}Modified files:${NC}"
            while IFS= read -r file; do
                [ -n "$file" ] && echo -e "    ${RED}M${NC} $file"
            done <<< "$MODIFIED_FILES"
        fi

        if [ -n "$UNTRACKED_FILES" ]; then
            echo -e "  ${CYAN}Untracked files (won't be affected):${NC}"
            while IFS= read -r file; do
                [ -n "$file" ] && echo -e "    ${CYAN}?${NC} $file"
            done <<< "$UNTRACKED_FILES"
        fi
        echo ""

        HAS_MODIFICATIONS=true
    else
        echo -e "${GREEN}✓ No local modifications${NC}"
        echo ""
        HAS_MODIFICATIONS=false
    fi

    # Update options
    echo -e "${YELLOW}Update options:${NC}"
    echo "  1) Update to latest (commit $REMOTE_SHORT)"
    if [ ${#COMMIT_LIST[@]} -gt 1 ]; then
        echo "  2) Choose specific commit"
    fi
    echo "  3) View full changelog"
    echo "  4) Cancel"
    echo ""

    read -p "Enter your choice: " update_choice

    case "$update_choice" in
        1)
            perform_update "$REMOTE_COMMIT" "$HAS_MODIFICATIONS"
            ;;
        2)
            if [ ${#COMMIT_LIST[@]} -gt 1 ]; then
                echo ""
                read -p "Enter commit number [1-${#COMMIT_LIST[@]}]: " commit_num
                if [[ "$commit_num" =~ ^[0-9]+$ ]] && [ "$commit_num" -ge 1 ] && [ "$commit_num" -le ${#COMMIT_LIST[@]} ]; then
                    TARGET_COMMIT="${COMMIT_LIST[$((commit_num-1))]}"
                    # Get full hash
                    FULL_HASH=$(git rev-parse "$TARGET_COMMIT")
                    perform_update "$FULL_HASH" "$HAS_MODIFICATIONS"
                else
                    echo -e "${RED}Invalid selection${NC}"
                fi
            else
                echo -e "${RED}Invalid option${NC}"
            fi
            ;;
        3)
            echo ""
            echo -e "${BLUE}Full changelog:${NC}"
            git log --oneline HEAD..origin/"$CURRENT_BRANCH"
            echo ""
            read -p "Press Enter to continue..."
            check_for_updates
            ;;
        4)
            echo -e "${BLUE}Update cancelled${NC}"
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            ;;
    esac
}

perform_update() {
    local TARGET_COMMIT="$1"
    local HAS_MODIFICATIONS="$2"

    echo ""

    if [ "$HAS_MODIFICATIONS" = true ]; then
        echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║${NC}  ${RED}⚠ LOCAL MODIFICATIONS DETECTED${NC}                           ${YELLOW}║${NC}"
        echo -e "${YELLOW}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}  How would you like to handle local changes?              ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}  1) Stash changes (save & restore after update)           ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}  2) Discard changes (lose local modifications)            ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}  3) Keep changes (may cause conflicts)                    ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}  4) Cancel update                                         ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
        echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        read -p "Enter your choice [1-4]: " mod_choice

        case "$mod_choice" in
            1)
                echo -e "${YELLOW}Stashing local changes...${NC}"
                STASH_MSG="Auto-stash before update to $(git rev-parse --short $TARGET_COMMIT)"
                git stash push -m "$STASH_MSG"
                echo -e "${GREEN}✓ Changes stashed${NC}"
                RESTORE_STASH=true
                ;;
            2)
                echo -e "${YELLOW}Discarding local changes...${NC}"
                git checkout -- .
                git clean -fd
                echo -e "${GREEN}✓ Changes discarded${NC}"
                RESTORE_STASH=false
                ;;
            3)
                echo -e "${YELLOW}Keeping local changes, attempting merge...${NC}"
                RESTORE_STASH=false
                ;;
            4)
                echo -e "${BLUE}Update cancelled${NC}"
                return 0
                ;;
            *)
                echo -e "${RED}Invalid choice, cancelling${NC}"
                return 1
                ;;
        esac
    else
        RESTORE_STASH=false
    fi

    echo ""

    # Backup certificates before update
    if [ -f "traefik/acme.json" ]; then
        echo -e "${YELLOW}Backing up SSL certificates before update...${NC}"
        backup_certificates || true
        echo ""
    fi

    echo -e "${YELLOW}Updating to commit $(git rev-parse --short $TARGET_COMMIT)...${NC}"

    # Stop containers before update
    echo -e "${YELLOW}Stopping containers...${NC}"
    docker compose down 2>/dev/null || true

    # Perform the update
    if git merge "$TARGET_COMMIT" --no-edit 2>/dev/null; then
        echo -e "${GREEN}✓ Update successful${NC}"
    else
        # Check for merge conflicts
        if git diff --name-only --diff-filter=U | grep -q .; then
            echo -e "${RED}✗ Merge conflicts detected${NC}"
            echo ""
            echo "Conflicting files:"
            git diff --name-only --diff-filter=U
            echo ""
            echo -e "${YELLOW}Options:${NC}"
            echo "  1) Abort update and restore previous state"
            echo "  2) Accept all incoming changes (theirs)"
            echo "  3) Keep all local changes (ours)"
            echo ""
            read -p "Enter your choice [1-3]: " conflict_choice

            case "$conflict_choice" in
                1)
                    git merge --abort
                    echo -e "${YELLOW}Update aborted${NC}"
                    if [ "$RESTORE_STASH" = true ]; then
                        git stash pop
                        echo -e "${GREEN}✓ Local changes restored${NC}"
                    fi
                    return 1
                    ;;
                2)
                    git checkout --theirs .
                    git add .
                    git commit -m "Resolved conflicts: accepted incoming changes"
                    echo -e "${GREEN}✓ Conflicts resolved (accepted incoming)${NC}"
                    ;;
                3)
                    git checkout --ours .
                    git add .
                    git commit -m "Resolved conflicts: kept local changes"
                    echo -e "${GREEN}✓ Conflicts resolved (kept local)${NC}"
                    ;;
                *)
                    git merge --abort
                    echo -e "${RED}Invalid choice, aborting${NC}"
                    return 1
                    ;;
            esac
        else
            echo -e "${RED}✗ Update failed${NC}"
            return 1
        fi
    fi

    # Restore stashed changes if applicable
    if [ "$RESTORE_STASH" = true ]; then
        echo ""
        echo -e "${YELLOW}Restoring stashed changes...${NC}"
        if git stash pop 2>/dev/null; then
            echo -e "${GREEN}✓ Local changes restored${NC}"
        else
            echo -e "${YELLOW}⚠ Could not auto-restore changes (conflicts)${NC}"
            echo "  Your changes are saved in git stash. Run 'git stash pop' manually."
        fi
    fi

    echo ""
    echo -e "${GREEN}✓ Update complete!${NC}"
    echo ""

    # Ask to rebuild
    if prompt_yes_no "Rebuild and restart containers?" "y"; then
        echo ""
        echo -e "${YELLOW}Rebuilding containers...${NC}"

        # Regenerate configs
        if [ -f ".env" ]; then
            set -a
            source .env
            set +a
        fi

        # Run the rest of the script to rebuild
        exec "$0"
    else
        echo ""
        echo -e "${CYAN}Run ./manage.sh to rebuild when ready${NC}"
    fi
}

# ===========================================
# Handle Update Command
# ===========================================

if [ "${RUN_UPDATE_CHECK:-}" = true ]; then
    check_for_updates
    exit 0
fi

if [ "${RUN_BACKUP:-}" = true ]; then
    backup_certificates
    exit 0
fi

# ===========================================
# Check if Docker is already running
# ===========================================

DOCKER_RUNNING=false
if command -v docker &> /dev/null; then
    if docker compose ps 2>/dev/null | grep -q "Up\|running"; then
        DOCKER_RUNNING=true
    fi
fi

if [ "$DOCKER_RUNNING" = true ]; then
    echo -e "${CYAN}Docker containers are already running.${NC}"
    echo ""
    docker compose ps
    echo ""

    echo -e "${YELLOW}What would you like to do?${NC}"
    echo "  1) Stop containers"
    echo "  2) Restart containers"
    echo "  3) View logs"
    echo "  4) Clean everything (stop, remove containers, volumes, images)"
    echo "  5) Continue to reconfigure and restart"
    echo "  6) Check for updates"
    echo "  7) Backup SSL certificates"
    echo "  8) Exit"
    echo ""

    read -p "Enter your choice [1-8]: " choice

    case "$choice" in
        1)
            echo -e "${YELLOW}Stopping containers...${NC}"
            docker compose down
            echo -e "${GREEN}✓ Containers stopped${NC}"
            exit 0
            ;;
        2)
            echo -e "${YELLOW}Restarting containers...${NC}"
            docker compose restart
            echo -e "${GREEN}✓ Containers restarted${NC}"
            docker compose ps
            exit 0
            ;;
        3)
            echo -e "${YELLOW}Choose service to view logs:${NC}"
            echo "  1) All services"
            echo "  2) UI"
            echo "  3) API"
            echo "  4) Traefik"
            echo "  5) Headscale"
            echo "  6) AdGuard"
            echo ""
            read -p "Enter your choice [1-6]: " log_choice

            case "$log_choice" in
                1) docker compose logs -f ;;
                2) docker compose logs -f ui ;;
                3) docker compose logs -f api ;;
                4) docker compose logs -f traefik ;;
                5) docker compose logs -f headscale ;;
                6) docker compose logs -f adguard ;;
                *) echo -e "${RED}Invalid choice${NC}"; exit 1 ;;
            esac
            exit 0
            ;;
        4)
            echo -e "${RED}⚠ WARNING: This will remove all containers, volumes, and images!${NC}"
            if prompt_yes_no "Are you sure?" "n"; then
                echo -e "${YELLOW}Cleaning everything...${NC}"
                docker compose down -v --rmi all --remove-orphans

                # Clean generated configs
                rm -f headscale/config/config.yaml
                rm -f traefik/traefik.yml
                rm -f traefik/dynamic.yml
                rm -f traefik/acme.json
                rm -f adguard/conf/AdGuardHome.yaml

                # Clean data directories
                rm -rf headscale/data/*
                rm -rf adguard/work/*
                rm -rf traefik/logs/*

                # Clean nftables tables created by the application
                echo -e "${YELLOW}Cleaning nftables tables...${NC}"
                sudo nft delete table inet wgadmin_firewall 2>/dev/null && echo -e "  ${GREEN}✓${NC} Removed inet wgadmin_firewall table" || true
                sudo nft delete table inet wgadmin_vpn_acl 2>/dev/null && echo -e "  ${GREEN}✓${NC} Removed inet wgadmin_vpn_acl table" || true

                echo -e "${GREEN}✓ Everything cleaned${NC}"
            fi
            exit 0
            ;;
        5)
            echo -e "${YELLOW}Stopping containers for reconfiguration...${NC}"
            docker compose down
            echo ""
            ;;
        6)
            check_for_updates
            exit 0
            ;;
        7)
            backup_certificates
            exit 0
            ;;
        8)
            echo -e "${BLUE}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac
fi

# ===========================================
# Check Dependencies
# ===========================================

echo -e "${BLUE}Checking dependencies...${NC}"
MISSING_DEPS=()

if ! check_dependency "docker" "Docker"; then
    MISSING_DEPS+=("docker")
fi

# Check Docker Compose (plugin or standalone)
if command -v docker &> /dev/null; then
    if docker compose version &> /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Docker Compose"
    elif command -v docker-compose &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} Docker Compose (standalone)"
    else
        echo -e "  ${RED}✗${NC} Docker Compose ${YELLOW}(missing)${NC}"
        MISSING_DEPS+=("docker-compose")
    fi
else
    echo -e "  ${RED}✗${NC} Docker Compose ${YELLOW}(missing)${NC}"
    MISSING_DEPS+=("docker-compose")
fi

if ! check_dependency "envsubst" "envsubst (gettext)"; then
    MISSING_DEPS+=("envsubst")
fi

if ! check_dependency "curl" "curl"; then
    MISSING_DEPS+=("curl")
fi

# Check WireGuard
if ! lsmod | grep -q wireguard && ! check_dependency "wg" "WireGuard"; then
    MISSING_DEPS+=("wireguard")
fi

echo ""

# Install missing dependencies
if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Missing dependencies detected:${NC}"
    for dep in "${MISSING_DEPS[@]}"; do
        echo "  - $dep"
    done
    echo ""

    if prompt_yes_no "Install missing dependencies?" "y"; then
        for dep in "${MISSING_DEPS[@]}"; do
            case "$dep" in
                docker|docker-compose)
                    install_docker || exit 1
                    ;;
                wireguard)
                    install_wireguard || exit 1
                    ;;
                envsubst)
                    echo -e "${YELLOW}Installing gettext...${NC}"
                    if [ -f /etc/debian_version ]; then
                        sudo apt-get update && sudo apt-get install -y gettext-base
                    elif [ -f /etc/redhat-release ]; then
                        sudo yum install -y gettext
                    fi
                    echo -e "${GREEN}✓ gettext installed${NC}"
                    ;;
                curl)
                    echo -e "${YELLOW}Installing curl...${NC}"
                    if [ -f /etc/debian_version ]; then
                        sudo apt-get update && sudo apt-get install -y curl
                    elif [ -f /etc/redhat-release ]; then
                        sudo yum install -y curl
                    fi
                    echo -e "${GREEN}✓ curl installed${NC}"
                    ;;
            esac
        done
        echo ""
    else
        echo -e "${RED}Cannot proceed without required dependencies${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓ All dependencies satisfied${NC}"
echo ""

# ===========================================
# Check Port 53 (DNS) Availability
# ===========================================

echo -e "${BLUE}Checking port 53 availability...${NC}"

if ss -tulpn 2>/dev/null | grep -q ':53 ' || netstat -tulpn 2>/dev/null | grep -q ':53 '; then
    echo -e "${YELLOW}⚠ Port 53 is already in use${NC}"

    # Check if it's systemd-resolved
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "  ${YELLOW}systemd-resolved is running and using port 53${NC}"
        echo ""
        echo "AdGuard needs port 53 for DNS. systemd-resolved must be disabled."
        echo ""

        if prompt_yes_no "Disable systemd-resolved to free port 53?" "y"; then
            echo -e "${YELLOW}Disabling systemd-resolved...${NC}"

            sudo systemctl stop systemd-resolved
            sudo systemctl disable systemd-resolved

            # Backup and replace resolv.conf
            if [ -L /etc/resolv.conf ]; then
                sudo rm /etc/resolv.conf
            elif [ -f /etc/resolv.conf ]; then
                sudo mv /etc/resolv.conf /etc/resolv.conf.backup
            fi

            echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf > /dev/null
            echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf > /dev/null

            echo -e "${GREEN}✓ systemd-resolved disabled${NC}"
            echo -e "${GREEN}✓ DNS temporarily set to 8.8.8.8 and 1.1.1.1${NC}"
        else
            echo -e "${RED}Cannot proceed - port 53 is required for AdGuard DNS${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Port 53 is in use by another service${NC}"
        echo "Please stop the service using port 53 and try again."
        echo "Check with: sudo ss -tulpn | grep :53"
        exit 1
    fi
else
    echo -e "  ${GREEN}✓${NC} Port 53 is available"
fi

echo ""

# ===========================================
# Check Firewall Conflicts (UFW/Fail2ban)
# ===========================================

echo -e "${BLUE}Checking for firewall conflicts...${NC}"

FIREWALL_CONFLICTS=()

# Check UFW
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null | head -1)
    if [[ "$UFW_STATUS" == "Status: active" ]]; then
        FIREWALL_CONFLICTS+=("ufw")
        echo -e "  ${YELLOW}⚠${NC} UFW is active"
    else
        echo -e "  ${GREEN}✓${NC} UFW is inactive"
    fi
else
    echo -e "  ${GREEN}✓${NC} UFW not installed"
fi

# Check Fail2ban
if command -v fail2ban-client &> /dev/null; then
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        FIREWALL_CONFLICTS+=("fail2ban")
        echo -e "  ${YELLOW}⚠${NC} Fail2ban is running"
    else
        echo -e "  ${GREEN}✓${NC} Fail2ban is inactive"
    fi
else
    echo -e "  ${GREEN}✓${NC} Fail2ban not installed"
fi

# Check iptables rules (that might conflict with nftables)
IPTABLES_RULES=$(sudo iptables -L -n 2>/dev/null | grep -v "^Chain\|^target\|^$" | wc -l)
if [ "$IPTABLES_RULES" -gt 0 ]; then
    echo -e "  ${YELLOW}⚠${NC} iptables has $IPTABLES_RULES active rules"
fi

echo ""

# Handle conflicts
if [ ${#FIREWALL_CONFLICTS[@]} -gt 0 ]; then
    echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║${NC}  ${RED}⚠ FIREWALL CONFLICT DETECTED${NC}                              ${YELLOW}║${NC}"
    echo -e "${YELLOW}╠════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  Wireguard Admin uses nftables for its firewall.          ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  The following services may conflict:                     ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
    for conflict in "${FIREWALL_CONFLICTS[@]}"; do
        printf "${YELLOW}║${NC}    • %-50s ${YELLOW}║${NC}\n" "$conflict"
    done
    echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  Running both may cause:                                   ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}    - Rule conflicts and unexpected blocking               ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}    - Performance issues                                   ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}    - Duplicate firewall management                        ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    echo -e "${CYAN}What would you like to do?${NC}"
    echo "  1) Disable conflicting services (recommended)"
    echo "  2) Continue anyway (may cause issues)"
    echo "  3) Exit and resolve manually"
    echo ""

    read -p "Enter your choice [1-3]: " fw_choice

    case "$fw_choice" in
        1)
            echo ""
            for conflict in "${FIREWALL_CONFLICTS[@]}"; do
                case "$conflict" in
                    ufw)
                        echo -e "${YELLOW}Disabling UFW...${NC}"
                        sudo ufw disable
                        echo -e "${GREEN}✓ UFW disabled${NC}"
                        ;;
                    fail2ban)
                        echo -e "${YELLOW}Stopping Fail2ban...${NC}"
                        sudo systemctl stop fail2ban
                        sudo systemctl disable fail2ban
                        echo -e "${GREEN}✓ Fail2ban stopped and disabled${NC}"
                        ;;
                esac
            done
            echo ""
            echo -e "${GREEN}✓ Firewall conflicts resolved${NC}"
            echo -e "${CYAN}Note: Wireguard Admin will manage firewall rules via nftables${NC}"
            ;;
        2)
            echo -e "${YELLOW}Continuing with potential conflicts...${NC}"
            echo -e "${RED}⚠ You may experience firewall issues${NC}"
            ;;
        3)
            echo -e "${BLUE}Exiting...${NC}"
            echo ""
            echo "To resolve manually:"
            for conflict in "${FIREWALL_CONFLICTS[@]}"; do
                case "$conflict" in
                    ufw)
                        echo "  sudo ufw disable"
                        ;;
                    fail2ban)
                        echo "  sudo systemctl stop fail2ban && sudo systemctl disable fail2ban"
                        ;;
                esac
            done
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac
    echo ""
else
    echo -e "${GREEN}✓ No firewall conflicts detected${NC}"
    echo ""
fi

# ===========================================
# Environment File Setup
# ===========================================

if [ ! -f ".env" ]; then
    echo -e "${YELLOW}No .env file found. Creating from template...${NC}"
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${GREEN}✓ Created .env from .env.example${NC}"
    else
        echo -e "${RED}ERROR: .env.example not found${NC}"
        exit 1
    fi
fi

# Generate ENCRYPTION_SECRET if not set
if ! grep -q "^ENCRYPTION_SECRET=.\+" .env 2>/dev/null; then
    ENCRYPTION_SECRET=$(openssl rand -hex 32)
    update_env_value "ENCRYPTION_SECRET" "$ENCRYPTION_SECRET"
    echo -e "${GREEN}✓ Generated ENCRYPTION_SECRET${NC}"
fi

# Load existing environment
set -a
source .env 2>/dev/null || true
set +a

# ===========================================
# Check Docker Network Subnet Conflicts
# ===========================================

echo -e "${BLUE}Checking Docker network availability...${NC}"

# Check if our subnet is already used by another network
check_subnet_conflict() {
    local target_subnet="$1"
    local target_base="${target_subnet%.*}"  # e.g., 172.18.0

    docker network ls --format '{{.Name}}' 2>/dev/null | while read net; do
        [ "$net" = "vpn-network" ] && continue
        [ "$net" = "bridge" ] && continue
        [ "$net" = "host" ] && continue
        [ "$net" = "none" ] && continue

        SUBNET=$(docker network inspect "$net" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)
        if [ -n "$SUBNET" ]; then
            NET_BASE="${SUBNET%.*}"
            if [ "$NET_BASE" = "$target_base" ]; then
                echo "$net:$SUBNET"
                return
            fi
        fi
    done
}

CONFLICT=$(check_subnet_conflict "$DOCKER_SUBNET")

if [ -n "$CONFLICT" ]; then
    CONFLICT_NET="${CONFLICT%%:*}"
    CONFLICT_SUBNET="${CONFLICT#*:}"

    echo -e "${YELLOW}⚠ Subnet conflict detected!${NC}"
    echo -e "  Desired subnet: ${CYAN}${DOCKER_SUBNET}${NC}"
    echo -e "  Conflicting network: ${RED}${CONFLICT_NET}${NC} (${CONFLICT_SUBNET})"
    echo ""
    echo -e "${CYAN}What would you like to do?${NC}"
    echo "  1) Delete conflicting network '${CONFLICT_NET}'"
    echo "  2) Change subnet (will update .env automatically)"
    echo "  3) Exit"
    echo ""
    read -p "Enter your choice [1-3]: " subnet_choice

    case "$subnet_choice" in
        1)
            echo -e "${YELLOW}Removing network ${CONFLICT_NET}...${NC}"
            # Check for attached containers
            ATTACHED=$(docker network inspect "$CONFLICT_NET" --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | xargs)
            if [ -n "$ATTACHED" ]; then
                echo -e "  Stopping attached containers: ${CYAN}${ATTACHED}${NC}"
                for container in $ATTACHED; do
                    docker stop "$container" 2>/dev/null || true
                done
            fi
            docker network rm "$CONFLICT_NET" 2>/dev/null || {
                echo -e "${RED}Failed to remove network${NC}"
                echo "Try manually: docker network rm ${CONFLICT_NET}"
                exit 1
            }
            echo -e "${GREEN}✓ Network removed${NC}"
            ;;
        2)
            # Find an available subnet
            echo -e "${YELLOW}Finding available subnet...${NC}"
            CURRENT_BASE="${DOCKER_SUBNET%%.0.0/*}"  # e.g., 172.18
            CURRENT_THIRD="${CURRENT_BASE#*.}"       # e.g., 18

            NEW_THIRD=$((CURRENT_THIRD + 1))
            while [ $NEW_THIRD -lt 255 ]; do
                NEW_SUBNET="172.${NEW_THIRD}.0.0/24"
                NEW_CHECK=$(check_subnet_conflict "$NEW_SUBNET")
                if [ -z "$NEW_CHECK" ]; then
                    break
                fi
                NEW_THIRD=$((NEW_THIRD + 1))
            done

            if [ $NEW_THIRD -ge 255 ]; then
                echo -e "${RED}Could not find available subnet${NC}"
                exit 1
            fi

            NEW_SUBNET="172.${NEW_THIRD}.0.0/24"
            NEW_GATEWAY="172.${NEW_THIRD}.0.1"
            NEW_TRAEFIK_IP="172.${NEW_THIRD}.0.2"
            NEW_HEADSCALE_IP="172.${NEW_THIRD}.0.3"
            NEW_UI_IP="172.${NEW_THIRD}.0.4"

            echo -e "  New subnet: ${GREEN}${NEW_SUBNET}${NC}"
            echo ""

            # Update .env file
            echo -e "${YELLOW}Updating .env file...${NC}"
            update_env_value "DOCKER_SUBNET" "$NEW_SUBNET"
            update_env_value "DOCKER_GATEWAY" "$NEW_GATEWAY"
            update_env_value "TRAEFIK_CONTAINER_IP" "$NEW_TRAEFIK_IP"
            update_env_value "HEADSCALE_CONTAINER_IP" "$NEW_HEADSCALE_IP"
            update_env_value "UI_CONTAINER_IP" "$NEW_UI_IP"

            # Reload environment
            export DOCKER_SUBNET="$NEW_SUBNET"
            export DOCKER_GATEWAY="$NEW_GATEWAY"
            export TRAEFIK_CONTAINER_IP="$NEW_TRAEFIK_IP"
            export HEADSCALE_CONTAINER_IP="$NEW_HEADSCALE_IP"
            export UI_CONTAINER_IP="$NEW_UI_IP"

            echo -e "${GREEN}✓ Updated .env:${NC}"
            echo "    DOCKER_SUBNET=$NEW_SUBNET"
            echo "    DOCKER_GATEWAY=$NEW_GATEWAY"
            echo "    TRAEFIK_CONTAINER_IP=$NEW_TRAEFIK_IP"
            echo "    HEADSCALE_CONTAINER_IP=$NEW_HEADSCALE_IP"
            echo "    UI_CONTAINER_IP=$NEW_UI_IP"
            ;;
        3)
            echo -e "${BLUE}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice${NC}"
            exit 1
            ;;
    esac
else
    echo -e "  ${GREEN}✓${NC} Subnet ${DOCKER_SUBNET} is available"
fi

echo ""

# ===========================================
# Interactive Configuration
# ===========================================

echo -e "${BLUE}Configuration:${NC}"
echo ""

# 1. Detect and configure SERVER_IP
echo -e "${YELLOW}[1/5] Detecting public IP address...${NC}"
DETECTED_IP=$(detect_public_ip)

if [ -n "$DETECTED_IP" ]; then
    echo -e "Detected IP: ${GREEN}${DETECTED_IP}${NC}"
    if [ -n "$SERVER_IP" ] && [ "$SERVER_IP" != "YOUR_SERVER_IP" ]; then
        echo -e "Current IP in .env: ${YELLOW}${SERVER_IP}${NC}"
    fi

    if prompt_yes_no "Use detected IP ($DETECTED_IP)?" "y"; then
        SERVER_IP="$DETECTED_IP"
        update_env_value "SERVER_IP" "$SERVER_IP"
        echo -e "${GREEN}✓ SERVER_IP set to: ${SERVER_IP}${NC}"
    else
        read -p "Enter your server IP address: " SERVER_IP
        update_env_value "SERVER_IP" "$SERVER_IP"
        echo -e "${GREEN}✓ SERVER_IP set to: ${SERVER_IP}${NC}"
    fi
else
    echo -e "${YELLOW}Could not auto-detect IP address${NC}"
    if [ -z "$SERVER_IP" ] || [ "$SERVER_IP" = "YOUR_SERVER_IP" ]; then
        read -p "Enter your server IP address: " SERVER_IP
        update_env_value "SERVER_IP" "$SERVER_IP"
        echo -e "${GREEN}✓ SERVER_IP set to: ${SERVER_IP}${NC}"
    else
        echo -e "Using existing IP from .env: ${GREEN}${SERVER_IP}${NC}"
    fi
fi

# Reload environment
set -a
source .env
set +a

echo ""

# 2. Development Mode
echo -e "${YELLOW}[2/5] Development Mode:${NC}"
echo "  - Production: Optimized build, nginx server"
echo "  - Development: Hot reload, instant code changes"
echo ""

if prompt_yes_no "Enable development mode with hot reload?" "n"; then
    DEV_MODE="true"
    echo -e "${GREEN}✓ Development mode enabled${NC}"
else
    DEV_MODE="false"
    echo -e "${GREEN}✓ Production mode enabled${NC}"
fi

echo ""

# 3. Admin Panel Domain (VPN-only)
echo -e "${YELLOW}[3/5] Admin Panel Domain (VPN-only):${NC}"
echo "  Configure a custom domain for the admin panel (requires VPN connection)"
echo ""

ADMIN_DOMAIN_VALID="false"
while [ "$ADMIN_DOMAIN_VALID" = "false" ]; do
    read -p "Enter domain name [manage.me]: " ADMIN_DOMAIN
    ADMIN_DOMAIN=${ADMIN_DOMAIN:-manage.me}

    if ! validate_domain_format "$ADMIN_DOMAIN"; then
        echo -e "${RED}✗ Invalid domain format: ${ADMIN_DOMAIN}${NC}"
        echo -e "  Domain must be a valid format like: manage.me or admin.local"
        if ! prompt_yes_no "Try again?" "y"; then
            ADMIN_DOMAIN="manage.me"
            echo -e "${YELLOW}Using default: manage.me${NC}"
            break
        fi
        continue
    fi

    ADMIN_DOMAIN_VALID="true"
done

update_env_value "ADMIN_DOMAIN" "$ADMIN_DOMAIN"
echo -e "${GREEN}✓ Admin domain set to: ${ADMIN_DOMAIN}${NC}"
echo ""

# 4. SSL/HTTPS Configuration
echo -e "${YELLOW}[4/5] SSL/HTTPS Configuration:${NC}"
echo "  Enable automatic HTTPS with Let's Encrypt certificates"
echo ""

# Load existing values
CURRENT_SSL_DOMAIN="${SSL_DOMAIN:-}"
CURRENT_SSL_EMAIL="${LETSENCRYPT_EMAIL:-}"

if prompt_yes_no "Enable HTTPS with Let's Encrypt?" "y"; then
    SSL_ENABLED="true"
    echo ""

    # Domain input with validation and retry loop
    DOMAIN_VALID="false"
    while [ "$DOMAIN_VALID" = "false" ]; do
        # Get domain
        if [ -n "$CURRENT_SSL_DOMAIN" ]; then
            echo -e "Current SSL domain: ${CYAN}${CURRENT_SSL_DOMAIN}${NC}"
            read -p "Enter domain for SSL certificate (or press Enter to keep current): " SSL_DOMAIN_INPUT
            SSL_DOMAIN="${SSL_DOMAIN_INPUT:-$CURRENT_SSL_DOMAIN}"
        else
            read -p "Enter domain for SSL certificate (e.g., vpn.example.com): " SSL_DOMAIN
        fi

        # Check if empty
        if [ -z "$SSL_DOMAIN" ]; then
            echo -e "${RED}✗ Domain is required for SSL${NC}"
            if ! prompt_yes_no "Try again?" "y"; then
                SSL_ENABLED="false"
                break
            fi
            continue
        fi

        # Validate domain format
        if ! validate_domain_format "$SSL_DOMAIN"; then
            echo -e "${RED}✗ Invalid domain format: ${SSL_DOMAIN}${NC}"
            echo -e "  Domain must be a valid format like: vpn.example.com"
            if ! prompt_yes_no "Try again?" "y"; then
                SSL_ENABLED="false"
                break
            fi
            continue
        fi

        DOMAIN_VALID="true"
    done

    # DNS validation with Cloudflare proxy support
    if [ "$SSL_ENABLED" = "true" ] && [ -n "$SSL_DOMAIN" ]; then
        echo ""

        # Ask about Cloudflare proxy
        BEHIND_CLOUDFLARE="false"
        if prompt_yes_no "Is this domain behind Cloudflare proxy (orange cloud)?" "n"; then
            BEHIND_CLOUDFLARE="true"
        fi

        # DNS validation loop
        DNS_VALID="false"
        while [ "$DNS_VALID" = "false" ] && [ "$SSL_ENABLED" = "true" ]; do
            echo -e "${YELLOW}Validating domain DNS...${NC}"

            # Capture result and status
            set +e
            DNS_RESULT=$(validate_domain_dns "$SSL_DOMAIN" "$SERVER_IP" 2>/dev/null)
            DNS_STATUS=$?
            set -e

            # Handle empty result
            if [ -z "$DNS_RESULT" ]; then
                DNS_RESULT="unresolved"
                DNS_STATUS=1
            fi

            if [ $DNS_STATUS -eq 2 ]; then
                # No DNS tool available - skip validation
                echo -e "${YELLOW}⚠ No DNS lookup tool available (dig/host/nslookup)${NC}"
                echo -e "  Make sure ${CYAN}$SSL_DOMAIN${NC} points to ${CYAN}$SERVER_IP${NC}"
                DNS_VALID="true"
            elif [ $DNS_STATUS -eq 0 ]; then
                # DNS matches
                echo -e "${GREEN}✓ Domain $SSL_DOMAIN resolves to $SERVER_IP${NC}"
                DNS_VALID="true"
            elif [ "$DNS_RESULT" = "unresolved" ]; then
                # Domain doesn't resolve
                echo -e "${RED}✗ Domain $SSL_DOMAIN does not resolve to any IP${NC}"
                echo -e "  Please add an A record pointing to: ${CYAN}${SERVER_IP}${NC}"
            else
                # Domain resolves to different IP - check if it's Cloudflare
                if [ "$BEHIND_CLOUDFLARE" = "true" ]; then
                    echo -e "${YELLOW}Domain resolves to: ${DNS_RESULT}${NC}"
                    CF_RANGES=$(fetch_cloudflare_ips) || true
                    if [ -n "$CF_RANGES" ] && is_cloudflare_ip "$DNS_RESULT" "$CF_RANGES"; then
                        echo -e "${GREEN}✓ IP ${DNS_RESULT} is a Cloudflare proxy IP${NC}"
                        echo -e "${GREEN}✓ Domain is correctly proxied through Cloudflare${NC}"
                        DNS_VALID="true"
                    else
                        echo -e "${RED}✗ IP ${DNS_RESULT} does not appear to be a Cloudflare IP${NC}"
                    fi
                else
                    echo -e "${RED}✗ Domain $SSL_DOMAIN resolves to ${DNS_RESULT}, not ${SERVER_IP}${NC}"
                    echo -e "  ${CYAN}Tip: If using Cloudflare proxy, select 'Change domain' and enable proxy${NC}"
                fi
            fi

            # If DNS not valid, show options
            if [ "$DNS_VALID" = "false" ]; then
                echo ""
                echo -e "Options:"
                echo -e "  ${CYAN}1)${NC} Retry DNS check"
                echo -e "  ${CYAN}2)${NC} Change domain"
                echo -e "  ${CYAN}3)${NC} Disable SSL"
                echo ""
                read -p "Select option [1-3]: " DNS_CHOICE
                case "$DNS_CHOICE" in
                    1)
                        echo ""
                        ;;
                    2)
                        echo ""
                        read -p "Enter new domain: " SSL_DOMAIN
                        if [ -z "$SSL_DOMAIN" ]; then
                            echo -e "${RED}Domain cannot be empty${NC}"
                            continue
                        fi
                        # Re-ask about Cloudflare
                        BEHIND_CLOUDFLARE="false"
                        if prompt_yes_no "Is this domain behind Cloudflare proxy?" "n"; then
                            BEHIND_CLOUDFLARE="true"
                        fi
                        ;;
                    3)
                        SSL_ENABLED="false"
                        echo -e "${YELLOW}SSL disabled${NC}"
                        ;;
                    *)
                        echo -e "${YELLOW}Invalid option, retrying...${NC}"
                        ;;
                esac
            fi
        done
    fi

    # Get email for Let's Encrypt
    if [ "$SSL_ENABLED" = "true" ]; then
        echo ""
        EMAIL_VALID="false"
        while [ "$EMAIL_VALID" = "false" ] && [ "$SSL_ENABLED" = "true" ]; do
            if [ -n "$CURRENT_SSL_EMAIL" ]; then
                echo -e "Current email: ${CYAN}${CURRENT_SSL_EMAIL}${NC}"
                read -p "Enter email for Let's Encrypt (or press Enter to keep current): " SSL_EMAIL_INPUT
                LETSENCRYPT_EMAIL="${SSL_EMAIL_INPUT:-$CURRENT_SSL_EMAIL}"
            else
                read -p "Enter email for Let's Encrypt notifications: " LETSENCRYPT_EMAIL
            fi

            if [ -n "$LETSENCRYPT_EMAIL" ]; then
                if validate_email "$LETSENCRYPT_EMAIL"; then
                    echo -e "${GREEN}✓ Email validated${NC}"
                    EMAIL_VALID="true"
                else
                    echo -e "${RED}✗ Invalid email format${NC}"
                    echo ""
                    echo -e "Options:"
                    echo -e "  ${CYAN}1)${NC} Try again"
                    echo -e "  ${CYAN}2)${NC} Disable SSL"
                    echo ""
                    read -p "Select option [1-2]: " EMAIL_CHOICE
                    case "$EMAIL_CHOICE" in
                        2)
                            SSL_ENABLED="false"
                            echo -e "${YELLOW}SSL disabled${NC}"
                            ;;
                        *)
                            ;;
                    esac
                fi
            else
                echo -e "${RED}✗ Email is required for Let's Encrypt${NC}"
                echo ""
                echo -e "Options:"
                echo -e "  ${CYAN}1)${NC} Try again"
                echo -e "  ${CYAN}2)${NC} Disable SSL"
                echo ""
                read -p "Select option [1-2]: " EMAIL_CHOICE
                case "$EMAIL_CHOICE" in
                    2)
                        SSL_ENABLED="false"
                        echo -e "${YELLOW}SSL disabled${NC}"
                        ;;
                    *)
                        ;;
                esac
            fi
        done
    fi

    # Save SSL configuration
    if [ "$SSL_ENABLED" = "true" ]; then
        echo ""

        # Check for existing backup
        RESTORE_FROM_BACKUP="false"
        if check_certificate_backup "$SSL_DOMAIN"; then
            if prompt_yes_no "Restore certificate from backup? (avoids rate limits)" "y"; then
                RESTORE_FROM_BACKUP="true"
            fi
        fi

        # Check rate limits if not restoring
        if [ "$RESTORE_FROM_BACKUP" = "false" ]; then
            if ! check_cert_rate_limit "$SSL_DOMAIN"; then
                echo -e "${YELLOW}SSL disabled due to rate limit concerns${NC}"
                SSL_ENABLED="false"
                update_env_value "SSL_ENABLED" "false"
            fi
        fi

        if [ "$SSL_ENABLED" = "true" ]; then
            update_env_value "SSL_ENABLED" "true"
            update_env_value "SSL_DOMAIN" "$SSL_DOMAIN"
            update_env_value "LETSENCRYPT_EMAIL" "$LETSENCRYPT_EMAIL"

            # Store for later restore
            export RESTORE_FROM_BACKUP
            export SSL_DOMAIN

            echo ""
            echo -e "${GREEN}✓ SSL enabled for: ${SSL_DOMAIN}${NC}"
            if [ "$RESTORE_FROM_BACKUP" = "true" ]; then
                echo -e "${GREEN}✓ Will restore certificate from backup${NC}"
            else
                echo -e "${GREEN}✓ Certificates will be auto-renewed${NC}"
            fi
        fi
    else
        update_env_value "SSL_ENABLED" "false"
    fi
else
    SSL_ENABLED="false"
    update_env_value "SSL_ENABLED" "false"
    echo -e "${YELLOW}✓ SSL disabled - using HTTP only${NC}"
    echo -e "  ${CYAN}Tip: Use Cloudflare Flexible SSL if you want HTTPS without local certs${NC}"
fi

echo ""

# 5. Check AdGuard credentials
echo -e "${YELLOW}[5/5] Checking AdGuard credentials...${NC}"

GENERATED_PASSWORD=""

if [ -z "$ADGUARD_PASS_HASH" ] || [ "$ADGUARD_PASS_HASH" = "YOUR_BCRYPT_HASH_HERE" ]; then
    echo -e "${YELLOW}AdGuard password not configured. Generating secure password...${NC}"

    # Generate random 16-character password
    GENERATED_PASSWORD=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16)

    # Generate bcrypt hash using htpasswd or python
    if command -v htpasswd &> /dev/null; then
        ADGUARD_PASS_HASH=$(htpasswd -nbB admin "$GENERATED_PASSWORD" | cut -d: -f2)
    elif command -v python3 &> /dev/null; then
        ADGUARD_PASS_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw('$GENERATED_PASSWORD'.encode(), bcrypt.gensalt()).decode())" 2>/dev/null)
    else
        echo -e "${RED}ERROR: Cannot generate password hash${NC}"
        echo "Please install apache2-utils (htpasswd) or python3 with bcrypt"
        echo "  Ubuntu/Debian: sudo apt install apache2-utils"
        echo "  Or: pip3 install bcrypt"
        exit 1
    fi

    # Save to .env (escape $ for Docker Compose)
    ADGUARD_PASS_HASH_ESCAPED=$(echo "$ADGUARD_PASS_HASH" | sed 's/\$/\$\$/g')
    update_env_value "ADGUARD_PASS_HASH" "$ADGUARD_PASS_HASH_ESCAPED"

    echo -e "${GREEN}✓ Generated secure password${NC}"
fi

if [ -z "$ADGUARD_USER" ]; then
    ADGUARD_USER="admin"
    update_env_value "ADGUARD_USER" "$ADGUARD_USER"
fi

echo -e "${GREEN}✓ AdGuard credentials configured${NC}"
echo ""

# ===========================================
# List of Required Variables
# ===========================================

REQUIRED_VARS=(
    "SERVER_IP"
    "HTTP_PORT"
    "HTTPS_PORT"
    "TRAEFIK_PORT"
    "API_PORT"
    "ADGUARD_PORT"
    "HEADSCALE_INTERNAL_PORT"
    "STUN_PORT"
    "WG_PORT"
    "DNS_PORT"
    "WG_INTERFACE"
    "WG_IP_RANGE"
    "WG_SERVER_IP"
    "WG_DNS"
    "HEADSCALE_IP_RANGE"
    "HEADSCALE_IP_RANGE_V6"
    "HEADSCALE_BASE_DOMAIN"
    "HEADSCALE_METRICS_PORT"
    "HEADSCALE_GRPC_PORT"
    "DERP_REGION_ID"
    "DERP_REGION_CODE"
    "DERP_REGION_NAME"
    "UPSTREAM_DNS_1"
    "UPSTREAM_DNS_2"
    "UPSTREAM_DNS_3"
    "UPSTREAM_DNS_DOH_1"
    "UPSTREAM_DNS_DOH_2"
    "ADGUARD_USER"
    "ADGUARD_PASS_HASH"
    "ADGUARD_PPROF_PORT"
    "IGNORE_NETWORKS"
    "ADMIN_DOMAIN"
    "TRAEFIK_API"
    "RATE_LIMIT_AVERAGE"
    "RATE_LIMIT_BURST"
    "RATE_LIMIT_STRICT_AVERAGE"
    "RATE_LIMIT_STRICT_BURST"
)

# Check all required variables are set
echo -e "${YELLOW}Validating environment variables...${NC}"
MISSING=()
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var+x}" ]; then
        MISSING+=("$var")
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo -e "${RED}ERROR: Missing required environment variables:${NC}"
    for var in "${MISSING[@]}"; do
        echo "  - $var"
    done
    echo ""
    echo "Please check your .env file and ensure all variables are set."
    exit 1
fi

echo -e "${GREEN}✓ All variables validated${NC}"
echo ""

# ===========================================
# Generate Configs from Templates
# ===========================================

echo -e "${YELLOW}Generating config files from templates...${NC}"

# Create acme.json for SSL certificates (if SSL enabled)
if [ "$SSL_ENABLED" = "true" ]; then
    # Remove if Docker accidentally created it as a directory
    if [ -d "traefik/acme.json" ]; then
        rm -rf traefik/acme.json
    fi
    if [ ! -f "traefik/acme.json" ]; then
        touch traefik/acme.json
        chmod 600 traefik/acme.json
        echo "  ✓ traefik/acme.json (created with 600 permissions)"
    else
        # Ensure permissions are correct
        chmod 600 traefik/acme.json
        echo "  ✓ traefik/acme.json (permissions verified)"
    fi

    # Restore certificate from backup if requested
    if [ "${RESTORE_FROM_BACKUP:-}" = "true" ] && [ -n "${SSL_DOMAIN:-}" ]; then
        echo ""
        if restore_certificate "$SSL_DOMAIN"; then
            echo -e "${GREEN}✓ Certificate restored - Traefik will use existing cert${NC}"
        else
            echo -e "${YELLOW}⚠ Could not restore certificate, will request new one${NC}"
        fi
    fi
fi

# Headscale config
if [ -f "headscale/config/config.yaml.template" ]; then
    envsubst < headscale/config/config.yaml.template > headscale/config/config.yaml
    echo "  ✓ headscale/config/config.yaml"
fi

# Traefik configs - with SSL support
if [ "$SSL_ENABLED" = "true" ]; then
    echo -e "  ${GREEN}SSL enabled${NC} - configuring Let's Encrypt for ${SSL_DOMAIN}"

    # Generate traefik.yml with SSL configuration
    cat > traefik/traefik.yml << EOF
# Traefik Static Configuration (SSL enabled)
api:
  dashboard: true
  insecure: true

experimental:
  localPlugins:
    sentinel:
      moduleName: local/sentinel

entryPoints:
  web:
    address: ":${HTTP_PORT}"
  websecure:
    address: ":${HTTPS_PORT}"
  traefik:
    address: ":${TRAEFIK_PORT}"

providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true

certificatesResolvers:
  letsencrypt:
    acme:
      email: ${LETSENCRYPT_EMAIL}
      storage: /etc/traefik/acme.json
      httpChallenge:
        entryPoint: web

log:
  level: INFO
  filePath: /var/log/traefik/traefik.log

accessLog:
  filePath: /var/log/traefik/access.log
  format: json
  fields:
    headers:
      defaultMode: drop
      names:
        User-Agent: keep
        X-Forwarded-For: keep
        X-Real-IP: keep
EOF
    echo "  ✓ traefik/traefik.yml (with SSL)"
elif [ -f "traefik/traefik.yml.template" ]; then
    # Generate traefik.yml without SSL
    envsubst < traefik/traefik.yml.template > traefik/traefik.yml
    echo "  ✓ traefik/traefik.yml"
fi

if [ -f "traefik/dynamic.yml.template" ]; then
    # Create dynamic config directory for Traefik
    mkdir -p traefik/dynamic

    # Convert IGNORE_NETWORKS from comma-separated to YAML list format
    IFS=',' read -ra NETS <<< "$IGNORE_NETWORKS"
    VPN_SOURCE_RANGE=""
    for net in "${NETS[@]}"; do
        VPN_SOURCE_RANGE+="            - \"$net\""$'\n'
    done
    export VPN_SOURCE_RANGE="${VPN_SOURCE_RANGE%$'\n'}"  # Remove trailing newline

    # Generate base dynamic config (core.yml)
    envsubst < traefik/dynamic.yml.template > traefik/dynamic/core.yml

    # If SSL enabled, insert SSL routers before the services section
    if [ "$SSL_ENABLED" = "true" ] && [ -f "traefik/dynamic-ssl-routers.yml.template" ]; then
        # Remove headscale-control-secure from base config (SSL template has its own with certResolver)
        sed -i '/headscale-control-secure:/,/^    # Headscale API/{ /headscale-control-secure:/,/tls: {}/d }' traefik/dynamic/core.yml

        # Read SSL routers template and substitute variables
        SSL_ROUTERS=$(envsubst < traefik/dynamic-ssl-routers.yml.template)

        # Insert SSL routers before "  services:" line
        # Using awk to insert content before the services section
        awk -v ssl="$SSL_ROUTERS" '
            /^  services:/ { print ssl }
            { print }
        ' traefik/dynamic/core.yml > traefik/dynamic/core.yml.tmp && mv traefik/dynamic/core.yml.tmp traefik/dynamic/core.yml

        echo "  ✓ traefik/dynamic/core.yml (with SSL routers)"
    else
        echo "  ✓ traefik/dynamic/core.yml"
    fi

    # Create empty domains.yml if it doesn't exist (will be managed by API)
    if [ ! -f "traefik/dynamic/domains.yml" ]; then
        echo "# Domain routes - managed by API" > traefik/dynamic/domains.yml
        echo "  ✓ traefik/dynamic/domains.yml (placeholder)"
    fi
fi

# AdGuard config
if [ -f "adguard/conf/AdGuardHome.yaml.template" ]; then
    export ADGUARD_QUERYLOG_INTERVAL="${ADGUARD_QUERYLOG_INTERVAL:-720h}"
    export ADGUARD_STATS_INTERVAL="${ADGUARD_STATS_INTERVAL:-720h}"
    envsubst < adguard/conf/AdGuardHome.yaml.template > adguard/conf/AdGuardHome.yaml
    echo "  ✓ adguard/conf/AdGuardHome.yaml"
fi

# Logrotate config for Traefik logs
if [ -f "traefik/logrotate.conf" ]; then
    LOGROTATE_CONF="/etc/logrotate.d/wgadmin-traefik"
    export TRAEFIK_LOGS_DIR="$(pwd)/traefik/logs"
    export TRAEFIK_LOG_ROTATE_COUNT="${TRAEFIK_LOG_ROTATE_COUNT:-7}"
    export TRAEFIK_LOG_MAX_SIZE="${TRAEFIK_LOG_MAX_SIZE:-50M}"
    if envsubst < traefik/logrotate.conf | sudo tee "$LOGROTATE_CONF" > /dev/null 2>&1; then
        sudo chmod 644 "$LOGROTATE_CONF"
        echo "  ✓ $LOGROTATE_CONF"
    fi
fi

echo ""

# ===========================================
# Start Docker Compose
# ===========================================

echo -e "${YELLOW}Starting docker compose...${NC}"

if [ "$DEV_MODE" = "true" ]; then
    echo -e "${BLUE}Mode: Development (hot reload enabled)${NC}"
    docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build "$@"
else
    echo -e "${BLUE}Mode: Production (optimized build)${NC}"
    docker compose up -d --build "$@"
fi

echo ""

# Post-deploy SSL certificate check
if [ "$SSL_ENABLED" = "true" ]; then
    echo -e "${YELLOW}Waiting for SSL certificate...${NC}"

    CERT_TIMEOUT=90
    CERT_INTERVAL=5
    CERT_ELAPSED=0
    CERT_OBTAINED="false"
    CERT_ERROR=""

    # Poll until certificate obtained, error, or timeout
    while [ $CERT_ELAPSED -lt $CERT_TIMEOUT ]; do
        sleep $CERT_INTERVAL
        CERT_ELAPSED=$((CERT_ELAPSED + CERT_INTERVAL))

        # Check for certificate errors in Traefik logs (for this specific domain)
        if [ -f "$TRAEFIK_MAIN_LOG" ]; then
            CERT_ERROR=$(grep -i "$SSL_DOMAIN" "$TRAEFIK_MAIN_LOG" 2>/dev/null | grep -i "rateLimited\|acme.*error\|unable to generate a certificate" | tail -1 || true)
            if [ -n "$CERT_ERROR" ]; then
                break
            fi
        fi

        # Check if certificates were obtained
        if [ -f "traefik/acme.json" ] && command -v jq &>/dev/null; then
            CERTS=$(cat traefik/acme.json 2>/dev/null | jq -r '.letsencrypt.Certificates // empty' 2>/dev/null)
            if [ -n "$CERTS" ] && [ "$CERTS" != "null" ]; then
                CERT_OBTAINED="true"
                break
            fi
        fi

        # Show progress
        printf "\r  Waiting... %ds / %ds" "$CERT_ELAPSED" "$CERT_TIMEOUT"
    done
    printf "\r                              \r"  # Clear progress line

    if [ -n "$CERT_ERROR" ]; then
        echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║${NC}  ${YELLOW}⚠ SSL CERTIFICATE ERROR${NC}                                    ${RED}║${NC}"
        echo -e "${RED}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${RED}║${NC}                                                            ${RED}║${NC}"
        if echo "$CERT_ERROR" | grep -q "rateLimited"; then
            echo -e "${RED}║${NC}  Rate limited by Let's Encrypt!                           ${RED}║${NC}"
            echo -e "${RED}║${NC}  Wait 7 days or use a different domain.                  ${RED}║${NC}"
        else
            echo -e "${RED}║${NC}  Certificate error detected in Traefik logs.             ${RED}║${NC}"
        fi
        echo -e "${RED}║${NC}                                                            ${RED}║${NC}"
        echo -e "${RED}║${NC}  Check: tail -f $TRAEFIK_MAIN_LOG                   ${RED}║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
    elif [ "$CERT_OBTAINED" = "true" ]; then
        echo -e "${GREEN}✓ SSL certificate active${NC}"
        # Backup the certificate (only if not restored from backup)
        if [ "${RESTORE_FROM_BACKUP:-}" != "true" ]; then
            if backup_certificate "$SSL_DOMAIN"; then
                echo -e "${GREEN}✓ Certificate backed up for future restores${NC}"
            fi
        else
            echo -e "${CYAN}✓ Using restored certificate from backup${NC}"
        fi
        echo ""
    else
        echo -e "${YELLOW}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║${NC}  ${CYAN}⏳ CERTIFICATE PENDING${NC}                                      ${YELLOW}║${NC}"
        echo -e "${YELLOW}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}  Certificate not obtained within ${CERT_TIMEOUT}s timeout.            ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}  This may be normal if Let's Encrypt is slow.             ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}  Monitor progress:                                         ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}    tail -f $TRAEFIK_MAIN_LOG                        ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}                                                            ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}  Check certificate status:                                 ${YELLOW}║${NC}"
        echo -e "${YELLOW}║${NC}    cat traefik/acme.json | jq '.letsencrypt.Certificates'  ${YELLOW}║${NC}"
        echo -e "${YELLOW}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
    fi
fi

echo -e "${GREEN}=== VPN Stack Started ===${NC}"
echo ""
echo -e "${BLUE}Access your services:${NC}"
if [ "$SSL_ENABLED" = "true" ]; then
    echo -e "  ${GREEN}Dashboard:${NC}   https://${SSL_DOMAIN}/ ${CYAN}(SSL enabled)${NC}"
    echo -e "                 or http://${ADMIN_DOMAIN} via VPN"
else
    echo -e "  ${GREEN}Dashboard:${NC}   http://${SERVER_IP}/ (or http://${ADMIN_DOMAIN} via VPN)"
fi
echo -e "  ${GREEN}Traefik:${NC}     http://${SERVER_IP}:${TRAEFIK_PORT}"
echo -e "  ${GREEN}AdGuard:${NC}     http://${SERVER_IP}:${ADGUARD_PORT}"
echo -e "  ${GREEN}API:${NC}         http://${SERVER_IP}:${API_PORT}"
echo ""

if [ "$SSL_ENABLED" = "true" ]; then
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}✓ SSL/HTTPS enabled with Let's Encrypt${NC}                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  Domain: ${YELLOW}${SSL_DOMAIN}${NC}"
    printf "${CYAN}║${NC}  %-56s ${CYAN}║${NC}\n" ""
    echo -e "${CYAN}║${NC}  Certificates will be auto-renewed.                       ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                                                            ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}Cloudflare settings:${NC}                                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}    SSL/TLS → Full (strict)                                ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
fi

if [ -n "$GENERATED_PASSWORD" ]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}  ${YELLOW}AdGuard Credentials (SAVE THESE!)${NC}                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Username: ${CYAN}${ADGUARD_USER}${NC}                                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Password: ${CYAN}${GENERATED_PASSWORD}${NC}                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                                                            ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  ${RED}⚠ This password will not be shown again!${NC}                 ${GREEN}║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
else
    echo -e "${YELLOW}AdGuard credentials:${NC} ${ADGUARD_USER} / (password in .env)"
fi

echo -e "${CYAN}Tip: Run ./manage.sh again to manage running containers${NC}"
echo ""
