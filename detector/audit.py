"""
audit.py — Structured audit log writer.

Spec format (exact):
  [timestamp] ACTION ip | condition | rate | baseline | duration

Written for: every BAN, every UNBAN, every BASELINE_RECALC.
This module has zero imports from other detector modules — safe to import anywhere.
"""

import os
import threading
from datetime import datetime, timezone

_AUDIT_PATH = os.environ.get("AUDIT_LOG_PATH", "/var/log/detector/audit.log")
_lock       = threading.Lock()


def write_audit(
    action:    str,
    ip:        str,
    condition: str,
    rate:      float,
    baseline:  float,
    duration:  str,
    extra:     str = "",
) -> None:
    """
    Write one structured line to the audit log in the spec-required format:
      [timestamp] ACTION ip | condition | rate=X.XX | baseline=X.XX | duration=Y

    The `condition` arg holds the statistical trigger text.
    `rate` and `baseline` are always the numeric values in req/s.
    `extra` is optional; used by BASELINE_RECALC to record stddev and sample count.
    """
    ts   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = (
        f"[{ts}] {action} {ip} | {condition} | "
        f"rate={rate:.4f} | baseline={baseline:.4f} | duration={duration}"
    )
    if extra:
        line += f" | {extra}"
    line += "\n"

    with _lock:
        try:
            os.makedirs(os.path.dirname(_AUDIT_PATH), exist_ok=True)
            with open(_AUDIT_PATH, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass  # never crash the daemon over a log write failure
