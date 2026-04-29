"""
blocker.py — iptables-based IP blocking with escalating ban schedule.

Ban lifecycle (per spec): 10 min → 30 min → 2 hours → permanent
Each expiry triggers an escalation to the next ban level.
Slack alert is sent within 10 seconds of every ban.

LOCK-CONTENTION FIX
--------------------
The original code called iptables subprocesses (5-second timeout each)
*inside* the RLock inside unban().  This blocked all threads that need
the lock (including the monitor thread) for up to 10 seconds per unban.

Fix: collect the iptables commands to run inside the lock, then execute
them *after* releasing the lock.  The in-memory state update (dict
mutation) is still atomic under the lock; iptables just runs free.
"""

import logging
import subprocess
import threading
import time
from types import SimpleNamespace
from typing import TYPE_CHECKING

from audit import write_audit

if TYPE_CHECKING:
    from notifier import Notifier

log = logging.getLogger("blocker")


def _iptables(*args: str) -> bool:
    """Run an iptables command. Returns True on success."""
    cmd = ["iptables"] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if r.returncode != 0:
            log.error("iptables error: %s", r.stderr.strip())
            return False
        return True
    except FileNotFoundError:
        log.error("iptables not found — NET_ADMIN capability required.")
        return False
    except subprocess.TimeoutExpired:
        log.error("iptables timed out: %s", cmd)
        return False


class BanRecord:
    """Holds all state for one active ban."""
    __slots__ = ("ip", "condition", "rate", "baseline", "level", "banned_at", "unban_at")

    def __init__(
        self,
        ip:        str,
        condition: str,
        rate:      float,
        baseline:  float,
        level:     int,
        unban_after_minutes: int | None,
    ) -> None:
        self.ip        = ip
        self.condition = condition
        self.rate      = rate
        self.baseline  = baseline
        self.level     = level
        self.banned_at = time.time()
        self.unban_at  = (
            self.banned_at + unban_after_minutes * 60
            if unban_after_minutes is not None
            else None
        )


class Blocker:

    def __init__(self, cfg: SimpleNamespace, notifier: "Notifier") -> None:
        self._cfg      = cfg
        self._notifier = notifier
        self._lock     = threading.RLock()
        self._bans: dict[str, BanRecord] = {}
        self._schedule: list[int] = list(cfg.blocking.unban_schedule_minutes)

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._bans

    def get_bans(self) -> list[BanRecord]:
        with self._lock:
            return list(self._bans.values())

    def ban(self, ip: str, condition: str, rate: float, baseline: float) -> None:
        """
        Add an iptables DROP rule and record the ban.
        Slack alert is sent in this same call — must complete within 10 seconds.
        iptables is called OUTSIDE the lock to avoid blocking other threads.
        """
        with self._lock:
            if ip in self._bans:
                return  # already banned

            level       = 0
            unban_after = self._schedule[0] if self._schedule else None
            record      = BanRecord(ip, condition, rate, baseline, level, unban_after)
            self._bans[ip] = record

        # ── iptables and Slack are intentionally OUTSIDE the lock ─────────
        duration_str = f"{unban_after} min" if unban_after is not None else "permanent"
        log.warning("BANNING %s | %s | rate=%.2f/s | duration=%s", ip, condition, rate, duration_str)

        _iptables("-I", "INPUT", "1", "-s", ip, "-j", "DROP")

        write_audit(
            action    = "BAN",
            ip        = ip,
            condition = condition,
            rate      = rate,
            baseline  = baseline,
            duration  = duration_str,
        )

        # Slack alert — spec requires within 10 seconds of ban
        self._notifier.send_ban_alert(ip, condition, rate, baseline, duration_str)

    def unban(self, ip: str) -> BanRecord | None:
        """
        Remove the DROP rule, escalate the ban level, re-ban at the next duration.
        Sends a Slack notification on every unban (per spec).

        iptables calls are executed OUTSIDE the lock so they do not block other
        threads waiting on the lock for up to 10 seconds (2 × 5s timeout).
        """
        # ── Update in-memory state under the lock ────────────────────────
        with self._lock:
            record = self._bans.pop(ip, None)
            if record is None:
                return None

            next_level = record.level + 1

            if next_level < len(self._schedule):
                next_minutes = self._schedule[next_level]
                duration_str = f"{next_minutes} min (level {next_level + 1})"
                new_record   = BanRecord(
                    ip, record.condition, record.rate, record.baseline,
                    next_level, next_minutes,
                )
            else:
                duration_str = "permanent"
                new_record   = BanRecord(
                    ip, record.condition, record.rate, record.baseline,
                    next_level, None,
                )

            self._bans[ip] = new_record

        # ── iptables and notifications OUTSIDE the lock ───────────────────
        # Remove old rule, immediately add new one — brief gap is unavoidable
        # but keeping it outside the lock means we don't stall other threads.
        _iptables("-D", "INPUT", "-s", ip, "-j", "DROP")
        _iptables("-I", "INPUT", "1", "-s", ip, "-j", "DROP")

        write_audit(
            action    = "UNBAN",
            ip        = ip,
            condition = f"level={record.level}→{next_level}",
            rate      = record.rate,
            baseline  = record.baseline,
            duration  = duration_str,
        )
        self._notifier.send_unban_alert(ip, record.level, duration_str, condition=record.condition, rate=record.rate, baseline=record.baseline)
        log.info("UNBAN %s → escalated to %s", ip, duration_str)
        return record
