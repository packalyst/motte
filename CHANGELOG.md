# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project is pre-1.0, so dated
releases will be tagged as they are cut.

## [Unreleased]

### Added
- **Replace the fleet CA** (Settings → Certificates, admins), for its expiry or a leaked key,
  without cutting machines off: the current CA stays in use while machines move to the new one
  by themselves (agent 0.1.67 or later, within about an hour while online); Finish is offered
  once every machine moved, or "Finish anyway" cuts off the ones left, which must be re-enrolled.
  Each step asks for the password. Restoring a backup from before a replacement warns first.
- **Machine certificate lifetime** (Settings → Agents): 30, 60, 90 (default), 180 or 365 days,
  changed with a password confirm. The panel accepts renewal only in the last third of a
  certificate's life; agents from 0.1.67 renew right then and keep their trusted panel CAs up to
  date, older ones keep asking from 28 days before expiry and renew once it's accepted. An expired
  certificate is never accepted.
- **Re-enroll** a machine (machine page, admins): a one-time command, issued after a password
  confirm, gives a machine whose certificate expired, or an uninstalled one being reinstalled, a
  new certificate as the same machine, keeping its history.
- **Certificates** (Settings → Certificates, admins): every certificate the panel depends on
  in one place: the websites' Let's Encrypt certificates, the fleet CA, the agent listener's
  certificate (with Renew now) and the machines' certificates, each with its expiry and what
  needs attention. A website that can't renew because Cloudflare-only blocks Let's Encrypt's
  check is flagged. Admins get a "Certificate expiring" notification (push, webhook, email;
  can be turned off in Profile) when one gets close to expiry without renewing, once per step,
  and the menu item shows how many need attention.
- **DNS rewrites, reworked**: a searchable list with each rewrite's type (IPv4, IPv6, alias,
  wildcard), an on/off switch, editing in one step (AdGuard's update, so a failed change never
  loses the old rewrite) and a confirmation before delete. Rewrites kept by Domain Routes are
  marked and locked there. Tooltips inside dialogs now sit next to their label.
- **DNS block rules, reworked**: one searchable list with Blocked / Allowed filters, the panel's
  per-client exceptions shown as "Allowed for *client*" (locked, linked to the client) and rules
  written by hand in AdGuard shown read-only. Rules are now added and removed one at a time:
  saving no longer sends back the whole list, which could drop a client exception added
  meanwhile, and only plain domain names are accepted.
- **DNS blocklists, reworked**: a searchable table with each list's source, rule count, last
  update and on/off, a warning on a list that never downloaded, and a confirmation before removal.
  A blocklist address must be a public `https://` link: never this server, the private or VPN
  networks, or an address with a login in it (it is AdGuard that downloads it). The Overview's
  "active blocklists" count no longer reads 0 until the Filters tab was opened.
- **One-line install on a fresh server**: the installer now adds git, Docker (from Docker's
  repository), WireGuard and the tools setup needs, checks the Docker version (Docker 24 or newer;
  an available update is offered, never forced) and states which systems are supported (Ubuntu 24.04
  tested; Ubuntu 22.04 and Debian 12/13 expected to work; others stop).
- **`motte uninstall`**: removes Motte and its data, and offers to restore what setup turned off
  (the system nftables firewall, UFW, Fail2ban). Setup now also detects a **system nftables firewall**
  (`/etc/nftables.conf`) that drops traffic Motte allows (it silently blocked WireGuard) and can hand
  it over to Motte, keeping a backup.
- **`motte cleanup`** and an offer after each interactive build to free the Docker build cache.
- **Factory reset** (menu option 8, confirmed by typing `RESET`) now removes everything the install
  created: all four firewall tables, the panel-created containers, the WireGuard interface and the
  host files, which the old "Clean" option left behind.

- **DHCP / managed private networks** — the panel can gateway an isolated LAN segment: a
  DHCP-only `dnsmasq` sidecar, interface addressing via a panel-owned netplan drop-in brought up
  scoped (never a global `netplan apply`) with validate → health-check → rollback, MAC-keyed
  DHCP clients with auto/approve registration, and default-deny VPN reachability via a new nft
  table (internet-out NAT off by default). New **Networks** page.
- **"Firewall not active" warning** surfaced in the UI when the firewall layer fails to start,
  instead of only a boot log line.
- **CI/CD & supply-chain**: blocking CI (build/vet/gofmt/test + ui build), advisory security &
  quality scanners (gosec, govulncheck, staticcheck, deadcode, dupl, Trivy, gitleaks, hadolint,
  npm audit), CodeQL, and Dependabot across both Go modules, the ui, Actions, and Dockerfiles.
- **Project governance**: AGPL-3.0 `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, this changelog,
  `.editorconfig`, and architecture decision records under `docs/adr/`.

### Changed
- **Allowed ports** (Settings → Firewall) redesigned: amber when open to the internet, green when
  VPN & LAN only, each port with its service, whether it's a system port, yours or
  Docker's, and one control for Public / Private plus remove (your ports) or a lock explaining why it
  stays. **Jails** use the same layout: how many IPs each has banned, its rule, and On / Off with
  edit and delete; turning a jail off now asks first. The Firewall section reads Port Scanner,
  Jails, Allowed Ports, and the jail form's fields carry icons (dropdowns can show one too now).
- **Off-host backup destinations** are compact cards (type, name, where backups go) whose form
  opens under them; removing one asks first, and "Unsaved changes" shows next to Save.
- **Docker settings**: a summary strip of containers, running and stopped; Restart asks first and
  Stop asks for your password (the server always required it, but the page never asked).
- **Settings on phones** uses the bottom bar like the machine page; a bar with more than five
  sections scrolls sideways and keeps the open one in view.
- **Client window**: Traffic is part of the Overview now (top destinations under the client's
  details, one request instead of two); "QR & Config" is called **Config**; the name and type icon
  are one rename badge (the LAN device window too); virtual IP cards fit a phone (name and
  addresses beside the actions, switches one per line, Port and Add on one line); Ad blocking shows
  the panel's outline while it loads instead of jumping.
- **Renamed to Motte** (breaking — reinstall, then import a backup). Install path `/opt/motte`,
  service and command `motte`, compose project `motte`; firewall tables `motte_*`; session cookie
  `motte_session`; AdGuard clients the panel manages are named `motte-managed …`; DHCP and netplan
  files `motte-<iface>`. The fleet agent is now **`motte-agent`** (folders, service, its
  `motte_agent` firewall table and its release files) — existing agents must be reinstalled.
- Grouped the panel-built helper images (`dnsmasq`, `turbotunnels`) under `containers/`; the
  repo root now holds only the first-class modules (`api`, `ui`, `agent`).
- Update flow now prunes dangling images after a successful rebuild so repeated updates don't
  fill the disk (dangling-only; tagged/in-use images, volumes and build cache are untouched).

### Fixed
- **fleet**: the certificate agents check the panel with lasted one year from the API's start and
  only listed the server's addresses at that moment, so a year without a restart, or a new IP,
  disconnected every agent. It now lasts 90 days, is replaced automatically 30 days before it
  expires, and is reissued within 10 minutes when the server's addresses or domain change.
- Changing the SSH port, creating a Headscale auth key or API key, and removing the VPN router
  failed with "current password is incorrect": the page never asked for your password, and the
  server lost the rest of the request after checking it. They now ask for your password and work.
- A port that is no longer essential (such as the old server's SSH port after restoring a backup
  on a new server) stays open but can now be removed from Allowed Ports.
- **Change password**: a mistyped current password no longer logs you out; the page shows
  "current password is incorrect".
- Logging in with a password on an account with 2FA showed "2FA code required" with no field to
  type the code, so only a passkey could get in; the code step now opens.
- Error messages show the server's message instead of its raw JSON reply.
- A hover tooltip no longer stays up over a window opened by a tap, on tablets and phones that
  also report a mouse.
- Emptying a stored password field in an off-host backup destination no longer erases the
  stored password on save.
- An SFTP destination's pinned host key no longer follows it to a different host or port (it broke
  every backup with a host-key mismatch); a test of an edited, unsaved host no longer pins its key
  into the saved destination; restore accepts a plain archive name only.
- A QR code that failed to load was requested again without pause (hundreds of requests and error
  toasts); it is now tried once per tab or tunnel-mode change.
- Adding a virtual IP with a mistyped port (`abc`, `0`) no longer forwards every port: the form
  refuses it until the port is 1–65535 or blank.
- The tab bar no longer drags up and down on iOS.
- **Backups** now carry DHCP networks, off-host backup settings, alert rules, notification channels
  and the **WireGuard server key**, so a restore on a new server keeps WireGuard clients working.
  The file format is now `motte-backup` (older `wg-panel-backup` files are no longer read). An
  import that can't re-encrypt a secret stops instead of storing it as plaintext.
- A missing `server_public.key` no longer makes the panel generate a new WireGuard identity.
- Setup no longer writes a **blank AdGuard password** when `htpasswd` is missing and Python has no
  `bcrypt`: `apache2-utils` is installed, and an empty hash stops setup.
- **vpn**: virtual-IP targets inside the VPN range are rejected (a mis-pointed quarantine could
  otherwise cut off an unrelated peer); DNS-name collisions are detected instead of stacking
  duplicate AdGuard rewrites; established flows for a newly-isolated peer are flushed from
  conntrack so isolation takes effect immediately; Headscale host names are made unique.
- **auth**: with `TRUSTED_PROXIES` unset the panel now falls back to `TRAEFIK_CONTAINER_IP`, so
  the per-IP login rate-limit no longer collapses into one global bucket.

### Security
- **Nothing kept in memory can grow without limit**: every per-address or per-key list the
  panel keeps in memory (request limit, login / 2FA / password lockouts, passkey sign-ins, the
  tunnel key guard and throttles, console grants and step-up windows, the 2FA replay guard, jail
  counters, traffic flows) now goes through one shared, size-capped store. When one is full, the
  security guards turn new addresses away (a flood can't erase a lockout), jails forget the
  address seen longest ago, and traffic accounting counts a new connection once it closes. The
  traffic counter's limit now matches the kernel's own connection table, and the outbound log's
  DNS cache, which was never filled, is removed.
- **Limits can't be dodged with IPv6 addresses**: the request limit, the login lockout, the
  passkey sign-in cap and the tunnel key guard count an IPv6 client by its /64 network (one
  connection usually owns a whole /64), so changing address no longer buys more password or key
  guesses. The request limiter also tracks at most 100,000 clients at once, so a flood of new
  addresses can't fill the panel's memory.
- **Headscale auth keys are shown once**: the whole key appears only when it's created (copy the
  command then). The Auth Keys list shows just the start of each key, and Expire works by the
  key's id, the panel looking up the key itself, so the browser never holds an existing key.
- Notification preferences store only the known notification types; any other name sent by a
  browser is ignored.
- **fleet**: an agent signing off (uninstall) no longer deletes its machine's history: file
  changes, scans, vulnerabilities, commands and console recordings stay until an admin removes the
  machine, so an intruder on that machine can't erase the evidence; the sign-off is logged.
- **fleet console**: an open console re-checks access every 30 seconds and closes once the
  operator's session is revoked or locked, their role or machine access is taken away, or the
  machine's console is switched off (it used to stay open up to 12 hours).
- **fleet password window**: the 10 minutes without re-typing the password belong to the login
  session that typed it (not every session of the user) and end 1 hour after it was typed,
  however busy.
- **fleet agents**: each agent is limited to 30 requests at once, then one per second, so a
  hacked agent can't keep the panel's database busy; new installs never get an agent release older
  than the one already served.
- **email alerts**: with STARTTLS chosen, a mail server that doesn't offer it now gets nothing
  instead of the alert in plain text.
- **audit log**: a failed or blocked login is logged under the typed username only when that user
  exists ("(unknown user)" otherwise), so a password typed into the username field isn't stored.
- **AdGuard password**: re-running setup over an existing install left the new password in a
  plain-text file on disk while the panel kept the old one; the panel now always takes the file's
  password, encrypts it and deletes the file.
- **`motte rotate-key`**: after a verified rotation, deleting the backup that holds the old key is
  now the default. **setup** creates `.env` readable by root only.
- **panel API port** (8081): no longer reachable from the internet. It answered in plain HTTP and
  skipped what Traefik adds (VPN-only, rate limits, the block list); browsers never needed it, since
  the panel opens through Traefik on 80/443 by domain or by IP. It still answers from the server,
  Traefik, the VPN and the LAN, and can't be made public in Ports. The "Direct IP Access" switch is
  gone, along with its `motte_panel_access` table.
- **Headscale join keys**: a viewer could read the join key each Headscale device registered with
  from the client, device and route lists (Headscale sends it with every device), and a reusable
  one lets anyone add a device to the VPN. The panel now removes it before passing device data on
  or saving it.
- **passkeys**: adding a passkey and logging in with one now always need the device's PIN,
  fingerprint or face. A passkey login skips the TOTP code, so a security key without a PIN let
  anyone holding it in with a touch; such a key is now asked to set a PIN first.
- **password re-checks**: re-entering your password (before sensitive actions, to unlock an idle
  session, to change it or to turn 2FA off) locks out for 15 minutes after 5 wrong tries, like the
  login page; a stolen session could guess it without limit. At most 4 password or backup
  passphrase checks run at once (each takes 64 MB), so a flood of logins or backup previews can't
  exhaust the server's memory.
- **passkey sign-in**: at most 5 sign-ins may wait for a passkey from one IP, 1,000 in total;
  anyone could start them without limit and fill the server's memory.
- **turning 2FA off** now checks the code like every other step-up: a used code can't be replayed,
  2FA marked on without a secret is refused instead of switched off, and a wrong password no longer
  logs you out.
- **isolated clients**: a VPN client set to Block All now reaches nothing on the server itself
  either: SSH, the panel API on its own port, DNS and ping were still answering it. Its tunnel stays
  up; un-isolating restores access at once.
- **trusted networks**: one list decides who may open the panel in VPN-only mode and who the
  firewall jails never ban. It always holds the WireGuard and Headscale ranges (locked in Settings →
  Traefik); extra ranges added there are saved and survive `motte update`, which used to reset them.
  `IGNORE_NETWORKS` only fills the extras on first start. A VPN-only list with no valid entry now
  blocks everyone instead of letting everyone in. The traffic logs recognise VPN clients by the real
  `WG_IP_RANGE` / `HEADSCALE_IP_RANGE`, so a client outside `10.8.0.x` (or a Headscale node outside
  `100.64.x`) is no longer missed.
- **managed LAN**: approved devices are recognised by IP and MAC together, so a device that copies
  an approved device's IP gets none of its access. A device still waiting for approval can only get
  an address and use DNS on the server; SSH, the panel API and everything else are closed to it.
- **firewall**: a block can no longer lock you out. Adding one IP or range, bulk add, list import,
  auto-ban and /24 escalation all refuse a block that covers private or VPN addresses, this server
  or your own IP, checking the whole range rather than its first address. Ranges wider than /8 are
  refused for block and allow, by the server rather than only the page. Blocking `10.0.0.0/8` or
  `0.0.0.0/1` + `128.0.0.0/1` used to cut off everyone, VPN included.
- **IP checks**: one shared helper decides what counts as an IPv4 value and which addresses are not
  public. As a result, the outbound traffic log and the Phone-home card treat the whole VPN overlay
  (100.64.0.0/10) as internal, and a DHCP network that spills into public space (`10.0.0.0/7`) is
  refused.
- **firewall**: the Cloudflare-only gate keeps its last-known state on a transient
  DB read error instead of failing open; global IPv6 is dropped on any interface, not just WAN.
- **setup**: the first-run Headscale connection test blocks SSRF to link-local/metadata even when
  reached via a hostname that resolves there.
- **fleet**: an agent's client certificate is revoked on uninstall, killing its mTLS access
  immediately rather than at cert expiry.
- **backup**: passphrase sealing hardened to Argon2id with a passphrase floor + generator.
- **vpn**: the generated Headscale policy is aligned with the nftables data-plane gate (no
  blanket wireguard-network grant; allow_all peers get the matching inbound rule).
