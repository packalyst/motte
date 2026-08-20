# sshd_config: mount a drop-in dir, not the whole file

The `api` container mounts the host's `/etc/ssh/sshd_config` read-write (that's how the
"change SSH port" feature works). Giving a container write access to the whole SSH server
config is risky — a compromised `api` could weaken SSH. Narrow it to a drop-in.

- **Status:** Open
- **Priority:** Medium (from the full-app security audit)

## Plan
- Change the SSH-port feature to write a small drop-in file under `/etc/ssh/sshd_config.d/`
  (e.g. an `override.conf` with just `Port <n>`) instead of editing the main config.
- Mount ONLY that drop-in directory into the `api` container (read-write), not the whole
  `/etc/ssh/sshd_config`.

## Risk
Touches the port-change code + `docker-compose.yml`. Test carefully so SSH isn't broken /
locked out (verify the drop-in is honored by the host's sshd, and that a bad write can't
wedge sshd on restart).
