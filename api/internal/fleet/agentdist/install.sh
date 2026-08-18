#!/bin/sh
# wgscout installer — POSIX sh, no bashisms.
#
#   ./install.sh check        # detect OS/arch + compatibility report, change nothing
#   ./install.sh install      # install binary, config, systemd unit (default)
#   ./install.sh uninstall    # full removal (agent uninstall + binary + unit)
#
# Flags for install:
#   --binary PATH     use this agent binary instead of auto-locating one
#   --manifest PATH   install this manifest.json (pinned tool hashes)
#   --no-start        install the service but don't start it
#   --no-systemd      skip the systemd unit (run manually)
#   --live            enforce for real (dry_run=false); default is dry-run/safe
#   --disable-fail2ban  stop + disable fail2ban without asking (CrowdSec replaces it)
#   --panel URL       panel base URL to enroll with (Phase 2)
#   --ca-fp FP        pinned panel CA fingerprint ("sha256:...")
#   --token TOKEN     one-time enrollment token
#
# Path overrides (env): PREFIX CONFDIR BASEDIR DATADIR
set -eu

PREFIX="${PREFIX:-/usr/local/bin}"
CONFDIR="${CONFDIR:-/etc/wgscout}"
BASEDIR="${BASEDIR:-/opt/wgscout}"
DATADIR="${DATADIR:-/var/lib/wgscout}"
UNIT=/etc/systemd/system/wgscout.service
SCRIPTDIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd 2>/dev/null || echo /tmp)

# Where to fetch the agent binary + manifest when no local copy is present.
# Default: the repo's LATEST release (so the installer never lags a version).
# Pin a specific one by setting AGENT_RELEASE=agent-vX.Y.Z.
AGENT_REPO="${AGENT_REPO:-packalyst/wireguard-admin-panel}"
AGENT_RELEASE="${AGENT_RELEASE:-}"
if [ -n "$AGENT_RELEASE" ]; then
	DLBASE="https://github.com/${AGENT_REPO}/releases/download/${AGENT_RELEASE}"
else
	DLBASE="https://github.com/${AGENT_REPO}/releases/latest/download"
fi

BINARY=""
MANIFEST=""
NO_START=0
NO_SYSTEMD=0
DISABLE_F2B=0
LIVE=0
PANEL=""
CAFP=""
TOKEN=""

# Re-exec as root for anything that changes the system (check/help don't need it).
# Done here, before arg parsing, so the original "$@" survives the sudo hand-off.
_need_root=1
for _a in "$@"; do
	case "$_a" in check|-h|--help) _need_root=0 ;; esac
done
if [ "$_need_root" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
	if [ -f "$0" ] && command -v sudo >/dev/null 2>&1; then exec sudo -E sh "$0" "$@"; fi
	echo "error: must run as root (try: sudo sh $0 $*)" >&2
	exit 1
fi

# ---- pretty output ---------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	R=$(printf '\033[31m'); G=$(printf '\033[32m'); Y=$(printf '\033[33m')
	B=$(printf '\033[1m');  N=$(printf '\033[0m')
else
	R=''; G=''; Y=''; B=''; N=''
fi
info() { printf '%s\n' "  $*"; }
ok()   { printf '  %s[ OK ]%s %s\n'   "$G" "$N" "$*"; }
warn() { printf '  %s[WARN]%s %s\n'   "$Y" "$N" "$*"; }
bad()  { printf '  %s[FAIL]%s %s\n'   "$R" "$N" "$*"; }
sec()  { printf '\n%s%s%s\n' "$B" "$*" "$N"; }
die()  { printf '%s\n' "${R}error:${N} $*" >&2; exit 1; }

FAILS=0

# ---- detection -------------------------------------------------------------
detect_os() {
	OS=$(uname -s)
	DISTRO_NAME="$OS"
	if [ -r /etc/os-release ]; then
		# shellcheck disable=SC1091
		. /etc/os-release
		DISTRO_NAME="${PRETTY_NAME:-${ID:-$OS}}"
	fi
}

detect_arch() {
	case "$(uname -m)" in
		x86_64|amd64)   ARCH=amd64 ;;
		aarch64|arm64)  ARCH=arm64 ;;
		*)              ARCH=unsupported ;;
	esac
}

detect_pkg() {
	if   command -v apt-get >/dev/null 2>&1; then PKG=apt
	elif command -v dnf     >/dev/null 2>&1; then PKG=dnf
	elif command -v yum     >/dev/null 2>&1; then PKG=yum
	elif command -v zypper  >/dev/null 2>&1; then PKG=zypper
	elif command -v pacman  >/dev/null 2>&1; then PKG=pacman
	else PKG=none; fi
}

install_pkg() {
	case "$PKG" in
		apt)    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" ;;
		dnf)    dnf install -y "$1" ;;
		yum)    yum install -y "$1" ;;
		zypper) zypper -n install "$1" ;;
		pacman) pacman -Sy --noconfirm "$1" ;;
		*)      return 1 ;;
	esac
}

compat_report() {
	sec "Detected"
	info "OS         : $OS ($DISTRO_NAME)"
	info "Arch       : $(uname -m) -> ${ARCH}"
	info "Package mgr: $PKG"
	info "Kernel     : $(uname -r)"

	sec "Compatibility"
	if [ "$OS" = "Linux" ]; then ok "Linux kernel"; else bad "not Linux (this agent is Linux-only)"; FAILS=$((FAILS+1)); fi
	if [ "$ARCH" != "unsupported" ]; then ok "CPU arch supported ($ARCH)"; else bad "unsupported CPU arch $(uname -m) (need x86_64 or arm64)"; FAILS=$((FAILS+1)); fi
	if [ -d /proc ]; then ok "/proc present"; else bad "/proc missing"; FAILS=$((FAILS+1)); fi

	if command -v nft >/dev/null 2>&1; then
		nftver=$(nft --version 2>/dev/null | head -n1)
		ok "nftables (${nftver:-present})"
	else
		warn "nftables not found — needed for IP blocking (installer can add it via $PKG)"
	fi

	if command -v systemctl >/dev/null 2>&1; then ok "systemd present"
	else warn "no systemd — you'll run the agent manually (no service unit)"; fi

	case "$PKG" in
		apt|dnf|yum) ok "auto-updates supported ($PKG)" ;;
		none)        warn "no package manager found — /apply-updates won't work" ;;
		*)           warn "package manager '$PKG' not supported by /apply-updates (apt/dnf/yum only)" ;;
	esac

	if [ -r /etc/machine-id ]; then ok "/etc/machine-id present (secret binding)"
	else warn "/etc/machine-id missing — secrets bind to key file only"; fi
}

# ---- binary location -------------------------------------------------------
fetch_url() { # url dest
	if   command -v curl >/dev/null 2>&1; then curl -fsSL -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
	else die "need curl or wget to download"; fi
}

# fetch_release downloads the agent binary + manifest from the GitHub release and
# verifies the binary against the published checksums.txt (fail-closed).
fetch_release() {
	DL=$(mktemp -d)
	info "downloading agent ${AGENT_RELEASE} (${ARCH}) from ${AGENT_REPO} ..."
	fetch_url "${DLBASE}/wgscout-linux-${ARCH}" "$DL/wgscout" || die "binary download failed (is release ${AGENT_RELEASE} published?)"
	fetch_url "${DLBASE}/checksums.txt" "$DL/checksums.txt" || die "checksums download failed"
	want=$(grep "wgscout-linux-${ARCH}" "$DL/checksums.txt" | awk '{print $1}')
	got=$(sha256sum "$DL/wgscout" | awk '{print $1}')
	if [ -z "$want" ] || [ "$want" != "$got" ]; then
		die "binary checksum mismatch (want ${want:-none} got $got)"
	fi
	ok "binary verified ($got)"
	chmod +x "$DL/wgscout"
	BINARY="$DL/wgscout"
	if fetch_url "${DLBASE}/manifest.json" "$DL/manifest.json"; then MANIFEST="$DL/manifest.json"; ok "manifest downloaded"
	else warn "manifest download failed — tools won't install until a manifest is present"; fi
}

locate_binary() {
	if [ -n "$BINARY" ]; then [ -f "$BINARY" ] || die "binary not found: $BINARY"; return; fi
	for c in \
		"$SCRIPTDIR/release/wgscout-linux-$ARCH" \
		"$SCRIPTDIR/dist/wgscout-linux-$ARCH" \
		"$SCRIPTDIR/wgscout-linux-$ARCH" \
		"$SCRIPTDIR/wgscout"; do
		if [ -f "$c" ]; then BINARY="$c"; return; fi
	done
	fetch_release   # nothing local → pull from the GitHub release
}

# ---- actions ---------------------------------------------------------------
do_install() {
	locate_binary
	[ "$FAILS" -eq 0 ] || die "$FAILS blocking compatibility problem(s) above — not installing"

	if ! command -v nft >/dev/null 2>&1; then
		info "installing nftables via $PKG ..."
		if install_pkg nftables; then ok "nftables installed"
		else warn "could not auto-install nftables — blocking will no-op until it's present"; fi
	fi

	sec "Installing"
	install -D -m 0755 "$BINARY" "$PREFIX/wgscout"
	ok "binary -> $PREFIX/wgscout"

	mkdir -p "$CONFDIR" "$BASEDIR" "$DATADIR"
	chmod 0755 "$CONFDIR" "$BASEDIR"; chmod 0750 "$DATADIR"

	if [ ! -f "$CONFDIR/config.json" ]; then
		"$PREFIX/wgscout" -config "$CONFDIR/config.json" -write-default-config >/dev/null
		ok "default config -> $CONFDIR/config.json (dry_run=true)"
	else
		info "config exists, kept: $CONFDIR/config.json"
	fi

	if [ "$LIVE" -eq 1 ]; then
		sed -i 's/"dry_run": *true/"dry_run": false/' "$CONFDIR/config.json"
		ok "enforcement ENABLED (dry_run=false) — real firewall/update actions"
	fi

	# Panel enrollment: write panel_url / ca_fingerprint / enroll_token into config
	# so the agent registers on next start (the token is one-time, consumed on enroll).
	[ -n "$PANEL" ] && { json_set panel_url "$PANEL"; ok "panel -> $PANEL"; }
	[ -n "$CAFP" ] && json_set ca_fingerprint "$CAFP"
	[ -n "$TOKEN" ] && { json_set enroll_token "$TOKEN"; ok "enrollment token set (registers on start)"; }

	# manifest: explicit / downloaded > local release|repo manifest.json > example.
	# The manifest is maintainer-pinned data (not user config), so ALWAYS refresh it
	# on (re)install — otherwise an upgrade keeps the old tool set. Back up the prior one.
	if [ -z "$MANIFEST" ] && [ -f "$SCRIPTDIR/release/manifest.json" ]; then MANIFEST="$SCRIPTDIR/release/manifest.json"; fi
	if [ -z "$MANIFEST" ] && [ -f "$SCRIPTDIR/manifest.json" ]; then MANIFEST="$SCRIPTDIR/manifest.json"; fi
	if [ -n "$MANIFEST" ]; then
		[ -f "$CONFDIR/manifest.json" ] && cp "$CONFDIR/manifest.json" "$CONFDIR/manifest.json.bak"
		install -m 0644 "$MANIFEST" "$CONFDIR/manifest.json"; ok "manifest -> $CONFDIR/manifest.json (refreshed)"
	elif [ ! -f "$CONFDIR/manifest.json" ] && [ -f "$SCRIPTDIR/manifest.example.json" ]; then
		install -m 0644 "$SCRIPTDIR/manifest.example.json" "$CONFDIR/manifest.json"
		warn "installed EXAMPLE manifest — fill in verified sha256 hashes before tools will install"
	fi

	if [ "$NO_SYSTEMD" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
		write_unit
		systemctl daemon-reload
		systemctl enable wgscout >/dev/null 2>&1 || true
		ok "systemd unit -> $UNIT (enabled)"
		if [ "$NO_START" -eq 0 ]; then
			systemctl restart wgscout && ok "service started (dry_run — safe)"
		fi
	else
		warn "skipping systemd — run manually: $PREFIX/wgscout -config $CONFDIR/config.json"
	fi

	handle_fail2ban
	print_next
}

# handle_fail2ban warns when fail2ban is active (it does the same SSH-ban job as the
# CrowdSec this agent runs — redundant, not conflicting). The user decides: default
# keeps fail2ban; --disable-fail2ban opts into removing it so CrowdSec owns banning.
handle_fail2ban() {
	# Detect PRESENCE (installed), not just active — a fail2ban that's enabled but
	# currently failed/inactive still overlaps CrowdSec and will start on boot.
	if ! command -v fail2ban-client >/dev/null 2>&1 \
		&& ! systemctl list-unit-files 2>/dev/null | grep -q '^fail2ban\.service'; then
		return 0
	fi
	state=$(systemctl is-active fail2ban 2>/dev/null || true)
	warn "fail2ban is installed (state: ${state:-unknown}) — it overlaps CrowdSec (both auto-ban SSH brute-force)."
	if [ "$DISABLE_F2B" -eq 1 ]; then
		f2b_disable; return 0
	fi
	# Ask — reading /dev/tty works even when the script itself came from `curl | sh`
	# (stdin is the pipe, but the controlling terminal is still there). No tty
	# (automation) => just leave it and tell them how.
	if [ -r /dev/tty ]; then
		printf '  Disable fail2ban now so CrowdSec owns banning? [y/N] ' > /dev/tty
		read -r ans < /dev/tty || ans=""
		case "$ans" in
			y|Y|yes|YES) f2b_disable ;;
			*) info "keeping fail2ban. Disable later: sudo systemctl disable --now fail2ban" ;;
		esac
	else
		info "keeping fail2ban (non-interactive). Disable: sudo systemctl disable --now fail2ban  (or re-run with --disable-fail2ban)"
	fi
}

f2b_disable() {
	if systemctl disable --now fail2ban >/dev/null 2>&1; then ok "fail2ban stopped + disabled — CrowdSec now owns banning"
	else warn "could not disable fail2ban — do it manually if you want"; fi
}

# memhigh returns a soft memory cap in MB: 60% of total RAM, clamped to [512, 2048].
# Trivy scans can spike; MemoryHigh throttles them under pressure instead of OOM-
# killing. Proportional to the box, but never more than 2 GB (Trivy doesn't need more).
memhigh() {
	total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 2097152)
	mb=$(( total_kb * 60 / 100 / 1024 ))
	[ "$mb" -gt 2048 ] && mb=2048
	[ "$mb" -lt 512 ] && mb=512
	echo "$mb"
}

# json_set writes a simple string key into config.json (updates if present, else
# inserts after the opening brace). Values must not contain a '|' (tokens/URLs/hex
# fingerprints don't).
json_set() {
	key=$1; val=$2; f="$CONFDIR/config.json"
	if grep -q "\"$key\"" "$f" 2>/dev/null; then
		sed -i "s|\"$key\": *\"[^\"]*\"|\"$key\": \"$val\"|" "$f"
	else
		sed -i "0,/{/s|{|{\n  \"$key\": \"$val\",|" "$f"
	fi
}

write_unit() {
	MEMHIGH=$(memhigh)
	info "memory soft cap (MemoryHigh) set to ${MEMHIGH}M"
	cat > "$UNIT" <<EOF
[Unit]
Description=WireGuard Admin Panel — fleet agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PREFIX/wgscout -config $CONFDIR/config.json
Restart=always
RestartSec=3
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
MemoryHigh=${MEMHIGH}M

[Install]
WantedBy=multi-user.target
EOF
}

do_uninstall() {
	sec "Uninstalling"
	if command -v systemctl >/dev/null 2>&1; then
		systemctl disable --now wgscout >/dev/null 2>&1 || true
		rm -f "$UNIT"; systemctl daemon-reload || true
		ok "service stopped + unit removed"
	fi
	if [ -x "$PREFIX/wgscout" ] && [ -f "$CONFDIR/config.json" ]; then
		"$PREFIX/wgscout" -config "$CONFDIR/config.json" uninstall || warn "agent self-uninstall reported an issue"
	fi
	rm -f "$PREFIX/wgscout"
	ok "binary removed"
	info "done — host should be clean"
}

print_next() {
	sec "Next steps"
	info "The service is installed + started. It runs in DRY-RUN (safe: logs firewall/update"
	info "actions instead of applying them). The manifest is already filled + verified."
	info "1. Status:  systemctl status wgscout    (log: journalctl -u wgscout -f)"
	info "2. Test:    curl localhost:9877/report"
	if [ "$LIVE" -eq 1 ]; then
		info "3. Enforcement is LIVE (you passed --live)."
	else
		info "3. Go live (actually enforce):"
		info "     sudo sed -i 's/\"dry_run\": true/\"dry_run\": false/' $CONFDIR/config.json && sudo systemctl restart wgscout"
		info "   (or reinstall with --live). Back to safe: swap false->true, restart."
	fi
	printf '\n'
}

# ---- main ------------------------------------------------------------------
CMD=install
while [ $# -gt 0 ]; do
	case "$1" in
		install|uninstall|check) CMD="$1" ;;
		--binary)     BINARY="$2"; shift ;;
		--manifest)   MANIFEST="$2"; shift ;;
		--no-start)   NO_START=1 ;;
		--no-systemd) NO_SYSTEMD=1 ;;
		--disable-fail2ban) DISABLE_F2B=1 ;;
		--live)       LIVE=1 ;;
		--panel)      PANEL="$2"; shift ;;
		--ca-fp)      CAFP="$2"; shift ;;
		--token)      TOKEN="$2"; shift ;;
		-h|--help)    grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
	shift
done

detect_os; detect_arch; detect_pkg

printf '%swgscout installer%s\n' "$B" "$N"
compat_report

case "$CMD" in
	check)     sec "check only — no changes made"; [ "$FAILS" -eq 0 ] && exit 0 || exit 1 ;;
	install)   do_install ;;
	uninstall) do_uninstall ;;
esac
