"""
config.py — Load config.yaml into a SimpleNamespace for dot-access.

Handles:
- Nested dicts → nested namespaces (cfg.baseline.min_samples_for_hourly)
- SLACK_WEBHOOK_URL env-var override
- CIDR notation in whitelist_ips (e.g. "105.113.16.0/24")
"""

import ipaddress
import os
import yaml
from types import SimpleNamespace


def _to_ns(d: dict) -> SimpleNamespace:
    """Recursively convert a dict to SimpleNamespace."""
    ns = SimpleNamespace()
    for k, v in d.items():
        setattr(ns, k, _to_ns(v) if isinstance(v, dict) else v)
    return ns


def load_config(path: str = "/app/config.yaml") -> SimpleNamespace:
    with open(path, "r") as fh:
        raw = yaml.safe_load(fh)

    # Allow env-var to override the webhook URL
    env_webhook = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if env_webhook:
        raw["slack"]["webhook_url"] = env_webhook

    return _to_ns(raw)


def ip_in_whitelist(ip: str, whitelist: list) -> bool:
    """
    Check whether `ip` matches any entry in the whitelist.
    Entries may be plain IPs ("127.0.0.1") or CIDR ranges ("105.113.16.0/24").
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for entry in whitelist:
        entry = str(entry).strip()
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if addr == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False
