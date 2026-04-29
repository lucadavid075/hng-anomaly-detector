"""
monitor.py — Continuously tail and parse the Nginx JSON access log.

Spec requirements met:
  - Tails line by line (not batched)
  - Parses: source_ip, timestamp, method, path, status, response_size
  - Handles log rotation via inode comparison
  - 50 ms poll interval on EOF — no busy loop
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detector import AnomalyDetector

log = logging.getLogger("monitor")

REQUIRED_FIELDS = {"source_ip", "timestamp", "method", "path", "status", "response_size"}


def _parse_line(line: str) -> dict | None:
    """
    Parse one JSON log line from Nginx.
    Returns a dict with normalised types, or None on any parse failure.
    Adds a 'ts' key containing a UTC datetime object.
    """
    line = line.strip()
    if not line:
        return None
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        log.debug("Non-JSON line skipped: %.120s", line)
        return None

    if not REQUIRED_FIELDS.issubset(entry.keys()):
        log.debug("Incomplete entry (missing fields): %s", entry)
        return None

    try:
        entry["status"]        = int(entry["status"])
        entry["response_size"] = int(entry["response_size"])
    except (ValueError, TypeError):
        return None

    # Parse Nginx ISO-8601 timestamp → UTC datetime
    try:
        entry["ts"] = datetime.fromisoformat(entry["timestamp"]).astimezone(timezone.utc)
    except Exception:
        entry["ts"] = datetime.now(timezone.utc)

    return entry


class LogMonitor:
    """
    Tails cfg.log.nginx_access_log line by line, calling detector.process()
    for every successfully parsed entry. Runs forever in its own thread.
    """

    def __init__(self, cfg, detector: "AnomalyDetector") -> None:
        self._path     = cfg.log.nginx_access_log
        self._detector = detector

    def tail(self) -> None:
        """Blocking tail loop — intended to run in its own thread."""
        log.info("LogMonitor: waiting for log file %s …", self._path)
        self._wait_for_file()
        log.info("LogMonitor: tailing %s", self._path)

        while True:
            try:
                self._tail_inner()
            except Exception as exc:
                log.error("LogMonitor error: %s — retrying in 2 s", exc)
                time.sleep(2)

    def _wait_for_file(self) -> None:
        while not os.path.exists(self._path):
            time.sleep(1)

    def _tail_inner(self) -> None:
        with open(self._path, "r", encoding="utf-8", errors="replace") as fh:
            # Seek to end — only process NEW traffic, not historical log entries
            fh.seek(0, os.SEEK_END)
            log.info("LogMonitor: seeking to end of log — processing live lines only.")

            inode = os.fstat(fh.fileno()).st_ino

            while True:
                line = fh.readline()

                if not line:
                    # EOF — check for log rotation
                    try:
                        current_inode = os.stat(self._path).st_ino
                    except FileNotFoundError:
                        log.warning("Log file disappeared — waiting.")
                        time.sleep(1)
                        break

                    if current_inode != inode:
                        log.info("Log rotation detected — reopening.")
                        break  # outer loop reopens

                    time.sleep(0.05)  # 50 ms poll — no busy loop
                    continue

                entry = _parse_line(line)
                if entry:
                    self._detector.process(entry)
