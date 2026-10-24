# Drop docker-socket-proxy EXEC=1 (headscale via REST)

Remove `EXEC=1` from the `docker-socket-proxy` in `docker-compose.yml`, so the Docker API the
api holds can't run commands inside containers. Other containers and local users can no longer
reach the proxy at all (it listens only on a root-only socket file mounted into `api` alone);
this narrows what the api itself is allowed to do.

- **Status:** Open (NOT fixed — only the misleading compose comment was corrected)
- **Priority:** Low (defense-in-depth: only the api can reach the proxy)

## Why EXEC=1 exists
Only 3 call sites still exec into the headscale container; everything else already uses the
Headscale REST API:
1. `api/internal/setup/setup.go` — `headscale apikeys create -o json` (first-run: mints the FIRST api key)
2. `api/internal/setup/setup.go` — `headscale apikeys list -o json` (setup key check)
3. `api/internal/vpn/headscale_acl.go` — `kill -HUP 1` (reload headscale after writing a new ACL file)

## Plan
- Reload (#3): replace `kill -HUP 1` with headscale's policy REST endpoint (or file-watch
  auto-reload) → removes that EXEC use.
- API key (#1/#2): bootstrap chicken-and-egg — `POST /api/v1/apikey` needs an existing key,
  but at first-run there is none. Move first-key creation OUT of the running panel and INTO
  install-time (the setup/provisioning script generates it, hands it to the panel via config).
  Runtime panel then only ever uses REST.
- Then remove `EXEC=1` + delete `setup.go`'s `dockerExec` and `helper.DockerExec`. The proxy
  keeps CONTAINERS/POST/START (Docker management page); nothing else uses exec.

## Effort / risk
Medium. The reload swap is small; the setup-key move touches the fresh-install flow and needs
careful testing so first installs don't break.
