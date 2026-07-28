#!/usr/bin/env python3
"""Launch turbotunnels HTTP forward-proxies from TUNNELS_JSON.

Config contract (injected by the admin panel as the TUNNELS_JSON env var):

    {"tunnels": [
        {"port": 3128, "user": "u_ab12", "pass": "…",
         "upstream": {"host": "1.2.3.4", "port": 8080, "user": "", "pass": ""}}
    ]}

Each tunnel becomes one `turbo-tunnel` process listening on 0.0.0.0:<port> as an
authenticated HTTP proxy:
  - no `upstream`  -> direct  (traffic exits from this host's IP)
  - with `upstream` -> chained (traffic is forwarded through that proxy and
                       exits from the upstream's IP)

There is no config file and no control server: to change tunnels the panel
recreates the container with a new TUNNELS_JSON. Auth is enforced by the patched
turbo_tunnel HTTP handler (see https.py), which also logs failures for the
firewall jail.
"""
import json
import os
import signal
import subprocess
import sys

LISTEN_HOST = "0.0.0.0"

# Live child processes (one per tunnel).
procs = []


def endpoint(host, port, user="", passwd=""):
    """Build a proxy endpoint 'http://[user:pass@]host:port'."""
    auth = f"{user}:{passwd}@" if user else ""
    return f"http://{auth}{host}:{port}"


def start(tunnels):
    for i, tunnel in enumerate(tunnels):
        label = f"tunnel #{i + 1}"
        try:
            port = int(tunnel["port"])
        except (KeyError, ValueError, TypeError):
            print(f"[run] SKIP {label}: missing/invalid 'port'", flush=True)
            continue

        listen = endpoint(LISTEN_HOST, port, tunnel.get("user", ""), tunnel.get("pass", ""))
        # argv as a list with shell=False (default): config values can never be
        # interpreted by a shell, so there is no command-injection surface.
        cmd = ["turbo-tunnel", "-l", listen]

        upstream = tunnel.get("upstream") or {}
        chained = str(upstream.get("host", "")).strip() != ""
        if chained:
            cmd += [
                "-t",
                endpoint(
                    upstream["host"], int(upstream["port"]),
                    upstream.get("user", ""), upstream.get("pass", ""),
                ),
            ]

        proc = subprocess.Popen(cmd)
        procs.append(proc)
        mode = "chained" if chained else "direct"
        print(f"[run] {label}: HTTP proxy on :{port} ({mode}) pid={proc.pid}", flush=True)


def shutdown(*_):
    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
    sys.exit(0)


def main():
    raw = os.environ.get("TUNNELS_JSON", "").strip()
    if not raw:
        print("[run] TUNNELS_JSON is empty — nothing to start", flush=True)
        return
    try:
        tunnels = json.loads(raw).get("tunnels", [])
    except json.JSONDecodeError as exc:
        print(f"[run] invalid TUNNELS_JSON: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
    if not tunnels:
        print("[run] no tunnels configured", flush=True)
        return

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    start(tunnels)
    if not procs:
        print("[run] no tunnels started", flush=True)
        sys.exit(1)

    # Reap children; if all exit, exit non-zero so Docker's restart policy
    # brings the container back rather than leaving it idle.
    while procs:
        pid, status = os.wait()
        print(f"[run] child pid={pid} exited (status={status})", flush=True)
        procs[:] = [p for p in procs if p.poll() is None]
    print("[run] all tunnels exited", flush=True)
    sys.exit(1)


if __name__ == "__main__":
    main()
