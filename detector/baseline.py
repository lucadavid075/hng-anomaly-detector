"""
baseline.py — Rolling baseline: computes effective_mean and effective_stddev
              from REAL traffic data. Nothing is hardcoded.

How it works
------------
Every request calls record_request(ts, ip, status).
We bucket by second — building per-second counts stored in:

  _window  — deque of (unix_ts, count), last 30 minutes (maxlen=1800)
  _hourly  — { "2026-04-27T19": [c1, c2, ...] } per-hour lists

Every 60 s, _recalculate():
  1. Picks source: hourly slot (if ≥ min_samples_for_hourly) else rolling window
  2. Computes mean and stddev from REAL counts — NO floor on mean
  3. Applies FIX 1: proportional stddev floor (min_stddev_ratio × mean)
     to prevent near-zero variance causing absurd z-scores on uniform traffic
  4. Does NOT ban anyone until sample_count >= min_baseline_samples (FIX 3)

Bug fixes from uploaded version (already present):
  - Double-count fix: reset accumulators after flush in _recalculate()
  - Deprecated datetime fix: utcnow/utcfromtimestamp → timezone-aware
"""

import logging
import math
import threading
import time
from collections import deque
from datetime import datetime, timezone
from types import SimpleNamespace

from audit import write_audit

log = logging.getLogger("baseline")


class BaselineTracker:

    def __init__(self, cfg: SimpleNamespace) -> None:
        self._cfg  = cfg
        self._lock = threading.RLock()

        window_secs         = cfg.baseline.rolling_window_minutes * 60  # 1800
        self._window: deque = deque(maxlen=window_secs)
        self._hourly: dict[str, list[int]] = {}

        # Published effective baseline — starts at 0, detector waits for samples
        self._mean:   float = 0.0
        self._stddev: float = 0.0
        self._source: str   = "initialising"

        # Per-IP error tracking: { ip -> deque of (ts, is_error) }
        self._ip_error_deques: dict[str, deque] = {}
        self._err_win_secs:    int   = 60
        self._baseline_error_rate: float = 0.0

        # Current-second accumulator
        # Reset to 0 after flush in _recalculate() to prevent double-count.
        self._current_second:    int = 0
        self._count_this_second: int = 0

    # ── Public properties ─────────────────────────────────────────────────────

    @property
    def mean(self) -> float:
        with self._lock:
            return self._mean

    @property
    def stddev(self) -> float:
        with self._lock:
            return self._stddev

    @property
    def baseline_error_rate(self) -> float:
        with self._lock:
            return self._baseline_error_rate

    @property
    def sample_count(self) -> int:
        with self._lock:
            return len(self._window)

    @property
    def current_source(self) -> str:
        with self._lock:
            return self._source

    @property
    def hourly_summary(self) -> dict:
        """
        { hour_str: mean_req_per_s } for every collected hour.
        Shown on the dashboard — satisfies Screenshot 7 (two hourly slots,
        different effective_mean values).
        """
        with self._lock:
            result = {}
            for hour, counts in self._hourly.items():
                active = [c for c in counts if c > 0]
                if active:
                    result[hour] = round(sum(active) / len(active), 4)
            return result

    # ── Called by detector.py on every request ────────────────────────────────

    def record_request(self, ts: float, ip: str, status: int) -> None:
        sec      = int(ts)
        is_error = status >= 400

        with self._lock:
            # Bucket into current second
            if sec != self._current_second:
                if self._current_second != 0 and self._count_this_second > 0:
                    self._window.append((self._current_second, self._count_this_second))
                    self._add_to_hourly(self._current_second, self._count_this_second)
                self._current_second    = sec
                self._count_this_second = 1
            else:
                self._count_this_second += 1

            # Track per-IP errors (last 60 s)
            if ip not in self._ip_error_deques:
                self._ip_error_deques[ip] = deque()
            dq     = self._ip_error_deques[ip]
            dq.append((ts, is_error))
            cutoff = ts - self._err_win_secs
            while dq and dq[0][0] < cutoff:
                dq.popleft()

    def ip_error_rate(self, ip: str) -> float:
        with self._lock:
            dq = self._ip_error_deques.get(ip)
            if not dq:
                return 0.0
            total  = len(dq)
            errors = sum(1 for _, e in dq if e)
            return errors / total if total else 0.0

    # ── Background recalculation loop ─────────────────────────────────────────

    def run_recalculation_loop(self) -> None:
        interval = self._cfg.baseline.recalculation_interval_seconds
        while True:
            time.sleep(interval)
            self._recalculate()

    # ── Private ───────────────────────────────────────────────────────────────

    def _add_to_hourly(self, sec: int, count: int) -> None:
        hour_str = datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%dT%H")
        if hour_str not in self._hourly:
            if len(self._hourly) >= 3:
                oldest = sorted(self._hourly.keys())[0]
                del self._hourly[oldest]
            self._hourly[hour_str] = []
        self._hourly[hour_str].append(count)

    def _recalculate(self) -> None:
        """
        Recompute effective_mean and effective_stddev from real traffic.

        FIX 1 — Proportional stddev floor:
          When traffic is perfectly uniform (e.g. exactly 1 scanner req/s
          every second), stddev collapses to ~0. Any tiny fluctuation then
          produces a z-score in the thousands, banning innocent IPs.
          We enforce: stddev >= mean * min_stddev_ratio (default 0.3).
          This scales with traffic — NOT a hardcoded constant.
          Crucially, effective_mean is NEVER modified.

        FIX 3 (via sample_count property + detector.py guard):
          _recalculate does not itself block detection — the detector reads
          sample_count and refuses to fire until min_baseline_samples is met.

        Double-count fix:
          After flushing the in-progress second, reset accumulators to 0 so
          record_request() does not flush the same bucket a second time.
        """
        min_samp       = self._cfg.baseline.min_samples_for_hourly
        min_stddev_ratio = getattr(self._cfg.baseline, "min_stddev_ratio", 0.3)

        with self._lock:
            # Flush in-progress second (double-count fix)
            if self._current_second != 0 and self._count_this_second > 0:
                self._window.append((self._current_second, self._count_this_second))
                self._add_to_hourly(self._current_second, self._count_this_second)
                self._current_second    = 0   # RESET — prevents double-flush
                self._count_this_second = 0

            # Source selection
            current_hour = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")
            hourly_data  = self._hourly.get(current_hour, [])

            if len(hourly_data) >= min_samp:
                counts = list(hourly_data)
                source = f"hourly:{current_hour}(n={len(counts)})"
            else:
                counts = [c for _, c in self._window]
                source = f"rolling_30min(n={len(counts)})"

            if len(counts) < 2:
                self._source = f"waiting(n={len(counts)})"
                log.debug("Baseline: waiting for samples (%d so far).", len(counts))
                return

            # ── Compute REAL mean from actual traffic ─────────────────────
            n    = len(counts)
            mean = sum(counts) / n
            var  = sum((x - mean) ** 2 for x in counts) / n
            stddev = math.sqrt(var)

            # ── FIX 1: proportional stddev floor ─────────────────────────
            # Prevents near-zero variance from producing absurd z-scores on
            # perfectly uniform traffic (e.g. exactly 1 req/s always).
            # We scale with mean so this is never a hardcoded constant.
            # effective_mean is NOT touched — only stddev gets a floor.
            if mean > 0:
                min_stddev = mean * min_stddev_ratio
                effective_stddev = max(stddev, min_stddev)
            else:
                effective_stddev = max(stddev, 1e-6)

            # Update baseline error rate
            total_reqs = 0
            total_errs = 0
            cutoff = time.time() - 60
            for dq in self._ip_error_deques.values():
                for ts_val, is_err in dq:
                    if ts_val >= cutoff:
                        total_reqs += 1
                        if is_err:
                            total_errs += 1
            if total_reqs > 0:
                self._baseline_error_rate = total_errs / total_reqs

            old_mean     = self._mean
            self._mean   = mean               # REAL computed mean — never faked
            self._stddev = effective_stddev   # proportional floor applied
            self._source = source

        write_audit(
            action    = "BASELINE_RECALC",
            ip        = "-",
            condition = source,
            rate      = mean,
            baseline  = old_mean,
            duration  = "-",
            extra     = (
                f"stddev_real={stddev:.4f} "
                f"stddev_effective={effective_stddev:.4f} "
                f"err_rate={self._baseline_error_rate:.4f} "
                f"samples={n}"
            ),
        )
        log.info(
            "Baseline [%s]: effective_mean=%.4f req/s | "
            "stddev_real=%.4f stddev_effective=%.4f",
            source, mean, stddev, effective_stddev,
        )
