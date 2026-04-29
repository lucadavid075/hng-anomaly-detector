"""
unbanner.py — Background thread that checks every 30 seconds for expired bans.

Per spec: auto-unban on schedule 10 min → 30 min → 2 hours → permanent.
The actual escalation logic lives in blocker.unban() — unbanner just triggers it.
Slack notification on every unban is sent from within blocker.unban().
"""

import logging
import time
from types import SimpleNamespace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from blocker  import Blocker
    from notifier import Notifier

log = logging.getLogger("unbanner")


class Unbanner:

    def __init__(self, cfg: SimpleNamespace, blocker: "Blocker", notifier: "Notifier") -> None:
        self._blocker = blocker
        # notifier is not used here — blocker.unban() handles all notifications.
        # Kept in the signature so main.py wiring stays consistent.

    def run(self) -> None:
        """Blocking loop — runs in its own thread."""
        log.info("Unbanner started.")
        while True:
            time.sleep(30)
            # catch all exceptions so a single bad record (e.g. a transient
            # iptables failure or a Slack timeout) does not permanently kill this
            # thread. The loop must keep running for the full 12-hour window.
            try:
                self._check_expired()
            except Exception as exc:
                log.error("Unbanner error (continuing): %s", exc)

    def _check_expired(self) -> None:
        now  = time.time()
        bans = self._blocker.get_bans()

        for record in bans:
            if record.unban_at is None:
                continue  # permanent — never auto-expires
            if now >= record.unban_at:
                log.info(
                    "Ban expired: %s (level %d, age %.0fs)",
                    record.ip, record.level, now - record.banned_at,
                )
                try:
                    self._blocker.unban(record.ip)
                except Exception as exc:
                    # Log the failure for this specific IP but keep processing
                    # the rest of the expired bans in the same cycle.
                    log.error("Failed to unban %s: %s", record.ip, exc)
