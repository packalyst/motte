#!/usr/bin/env python3
"""Generate tunnels.yaml from a JSON config at container start.

Config source priority (first match wins):
  1. TUNNELS_JSON       - inline JSON string (env var)
  2. TUNNELS_JSON_FILE  - path to a JSON file
                          (default: baked-in tunnels.default.json)

Environment variables referenced inside string values (e.g. "${HOST_IP}")
are expanded, so the same JSON works across hosts without editing.

Precedence (see ensure_config): if a YAML already exists at TUNNELS_YAML it is
used as-is (bring-your-own, e.g. mounted via a volume). Otherwise the YAML is
generated from JSON. This means the container has a working default with no env
at all, TUNNELS_JSON overrides the whole tunnel set from the environment, and a
mounted tunnels.yaml wins over both.
"""
import json
import os
import sys

import yaml

DEFAULT_JSON_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "tunnels.default.json"
)
DEFAULT_YAML_FILE = "/app/tunnels.yaml"


def expand_env(value):
    """Recursively expand ${VAR} / $VAR references in string values."""
    if isinstance(value, str):
        return os.path.expandvars(value)
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    return value


def load_config():
    inline = os.environ.get("TUNNELS_JSON")
    if inline and inline.strip():
        return json.loads(inline)
    path = os.environ.get("TUNNELS_JSON_FILE", DEFAULT_JSON_FILE)
    with open(path, "r") as file:
        return json.load(file)


def validate_tunnel(tunnel, index):
    """Return a list of human-readable warnings for one tunnel entry.

    An entry is only useful if it has an upstream target to forward to
    (tunnel_url + tunnel_ip). Missing values produce a doomed turbo-tunnel
    command like `-t http://:3128`, so warn clearly instead.
    """
    warnings = []
    label = f"tunnel #{index + 1}"
    if not str(tunnel.get("tunnel_url", "")).strip():
        warnings.append(f"{label}: missing 'tunnel_url' (upstream protocol)")
    if not str(tunnel.get("tunnel_ip", "")).strip():
        warnings.append(f"{label}: missing 'tunnel_ip' (upstream target host)")
    if not str(tunnel.get("listen_url", "")).strip():
        warnings.append(f"{label}: missing 'listen_url' (local listen protocol)")
    return warnings


def validate(config):
    """Validate all tunnels; return (valid_tunnels, all_warnings)."""
    valid, all_warnings = [], []
    for index, tunnel in enumerate(config.get("tunnels", [])):
        warnings = validate_tunnel(tunnel, index)
        if warnings:
            all_warnings.extend(warnings)
        else:
            valid.append(tunnel)
    return valid, all_warnings


def generate():
    config = expand_env(load_config())
    config.setdefault("tunnels", [])
    _, warnings = validate(config)
    for warning in warnings:
        print(f"[gen_config] WARNING: {warning} — this tunnel will be skipped")
    if warnings:
        print(
            "[gen_config] WARNING: fix turbotunnels/tunnels.default.json "
            "or set TUNNELS_JSON with a real upstream target."
        )
    out_path = os.environ.get("TUNNELS_YAML", DEFAULT_YAML_FILE)
    with open(out_path, "w") as file:
        yaml.safe_dump(config, file, default_flow_style=False, sort_keys=False)
    print(f"[gen_config] wrote {len(config['tunnels'])} tunnel(s) to {out_path}")
    return out_path


def ensure_config():
    """Make sure a usable YAML exists at TUNNELS_YAML and return its path.

    If the YAML already exists (e.g. a mounted bring-your-own config) it is used
    as-is; otherwise it is generated from JSON. Warnings are printed either way
    so a broken upstream target is obvious regardless of the source.
    """
    out_path = os.environ.get("TUNNELS_YAML", DEFAULT_YAML_FILE)
    if os.path.exists(out_path):
        with open(out_path, "r") as file:
            config = yaml.safe_load(file) or {}
        _, warnings = validate(config)
        for warning in warnings:
            print(f"[gen_config] WARNING: {warning} — this tunnel will be skipped")
        print(f"[gen_config] using existing config at {out_path} (as-is)")
        return out_path
    return generate()


if __name__ == "__main__":
    try:
        ensure_config()
    except Exception as exc:  # noqa: BLE001 - surface any config error at startup
        print(f"[gen_config] failed: {exc}", file=sys.stderr)
        sys.exit(1)
