"""
detector.py — Sliding-window anomaly detection engine.

Sliding Window Design (per spec)
---------------------------------
Two deque-based windows — NOT per-minute counters:

  _ip_windows[ip]  — deque of Unix float timestamps per IP
  _global_window   — deque of Unix float timestamps, all traffic

Eviction:
  On every new request, append the timestamp to the right, then popleft()
  all entries older than 60 seconds. O(1) per eviction.
  len(deque) after eviction = requests in the last 60 seconds.

Unit consistency:
  Baseline mean/stddev are in req/s (per-second bucket counts).
  Window count is raw req/60s → divide by window_seconds to get req/s.
  All comparisons happen in req/s — no unit mismatch.

Anomaly Detection (per spec — exact wording):
  "Flag an IP or global rate as anomalous if the z-score exceeds 3.0
   OR the rate is more than 5x the baseline mean — whichever fires first."

  Implementation:
    zscore = (rate_per_s - mean) / stddev
    anomalous = zscore > 3.0  OR  rate_per_s > 5 × mean

  No additional gates. The spec's two conditions are sufficient.

 
Error Surge:
  If an IP's 4xx/5xx rate >= 3× the global baseline error rate,
  halve both z_thresh and spike_mul for that IP only.
  This is a tightening (more sensitive), not an additional gate.

Cold-start guard:
  Do not fire any bans until baseline.sample_count >= min_baseline_samples.
  This prevents acting on an immature baseline without hardcoding effective_mean.
  Config: min_baseline_samples = 120 (2 minutes of active traffic).

Alert cooldown:
  Same entity (IP or global) is not re-alerted within 30s (IP) or 60s (global).
  Prevents alert storms during a sustained flood.
"""

import logging
import threading
import time
from collections import deque, defaultdict
from types import SimpleNamespace
from typing import TYPE_CHECKING

from config import ip_in_whitelist

if TYPE_CHECKING:
    from baseline import BaselineTracker
    from blocker  import Blocker
    from notifier import Notifier

log = logging.getLogger("detector")


class AnomalyDetector:

    def __init__(
        self,
        cfg:      SimpleNamespace,
        baseline: "BaselineTracker",
        blocker:  "Blocker",
        notifier: "Notifier",
    ) -> None:
        self._cfg      = cfg
        self._baseline = baseline
        self._blocker  = blocker
        self._notifier = notifier

        win_cfg = cfg.sliding_window
        self._ip_win_secs   = win_cfg.per_ip_window_seconds   # 60
        self._glob_win_secs = win_cfg.global_window_seconds   # 60

        # ── Per-IP deques: { ip → deque of Unix float timestamps } ────────
        # One timestamp per request. Evicted when older than 60s.
        self._ip_windows:  dict[str, deque]          = defaultdict(deque)
        self._ip_locks:    dict[str, threading.Lock] = defaultdict(threading.Lock)
        self._ip_dict_lock = threading.Lock()

        # ── Global deque ───────────────────────────────────────────────────
        self._global_window: deque = deque()
        self._global_lock = threading.Lock()

        # ── Dashboard stats (true req/s) ───────────────────────────────────
        self._global_rps: float = 0.0
        self._top_ips: list[tuple[str, int]] = []
        self._last_top_refresh: float = 0.0

        # ── Alert cooldown ─────────────────────────────────────────────────
        self._last_alerted: dict[str, float] = {}
        self._alert_lock = threading.Lock()

        # ── Whitelist (plain IPs and CIDR ranges) ──────────────────────────
        self._whitelist: list = list(getattr(cfg.blocking, "whitelist_ips", []))

        # ── Cold-start guard ───────────────────────────────────────────────
        # Do not fire until this many per-second buckets exist in the baseline.
        # Prevents acting on an immature baseline without hardcoding mean.
        self._min_samples: int = getattr(cfg.baseline, "min_baseline_samples", 120)

    # ── Public API ────────────────────────────────────────────────────────────

    def process(self, entry: dict) -> None:
        """Called by monitor.py for every parsed Nginx log line."""
        ip     = entry["source_ip"]
        ts     = entry["ts"].timestamp()
        status = entry["status"]

        # 1. Always feed baseline — builds rolling window regardless of detection state
        self._baseline.record_request(ts, ip, status)

        # 2. Update both sliding windows
        self._push_ip(ip, ts)
        self._push_global(ts)

        # 3. Evict stale entries, get raw counts (req/60s)
        ip_count     = self._evict_and_count_ip(ip, ts)
        global_count = self._evict_and_count_global(ts)

        # 4. Convert req/60s → req/s so units match baseline mean/stddev.
        #    This is critical: without the division, z-score is ~60× too large
        #    and the spike check fires at 1/12 of normal traffic.
        ip_rate_per_s     = ip_count     / self._ip_win_secs
        global_rate_per_s = global_count / self._glob_win_secs

        # 5. Update dashboard stats
        self._global_rps = global_rate_per_s
        self._maybe_refresh_top_ips(ts)

        # 6. Cold-start guard — require real baseline before any bans
        if self._baseline.sample_count < self._min_samples:
            return

        # 7. Detection
        if not ip_in_whitelist(ip, self._whitelist):
            self._check_ip(ip, ip_rate_per_s, ts)

        self._check_global(global_rate_per_s, ts)

    @property
    def global_rps(self) -> float:
        """Current global request rate in true req/s (window count ÷ 60)."""
        return self._global_rps

    @property
    def top_ips(self) -> list[tuple[str, int]]:
        return self._top_ips

    # ── Sliding window helpers ────────────────────────────────────────────────

    def _push_ip(self, ip: str, ts: float) -> None:
        with self._ip_dict_lock:
            lock = self._ip_locks[ip]
        with lock:
            self._ip_windows[ip].append(ts)

    def _push_global(self, ts: float) -> None:
        with self._global_lock:
            self._global_window.append(ts)

    def _evict_and_count_ip(self, ip: str, now: float) -> int:
        """
        Evict timestamps older than ip_win_secs (60s) from this IP's deque.
        Return len(deque) = requests from this IP in the last 60 seconds.

        popleft() is O(1) on a deque — safe to call on every request under load.
        This is the core sliding window eviction mechanism (per spec: no libraries).
        """
        cutoff = now - self._ip_win_secs
        with self._ip_dict_lock:
            lock = self._ip_locks[ip]
        with lock:
            dq = self._ip_windows[ip]
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)

    def _evict_and_count_global(self, now: float) -> int:
        """Evict timestamps older than 60s from the global deque. Return count."""
        cutoff = now - self._glob_win_secs
        with self._global_lock:
            dq = self._global_window
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)

    def _maybe_refresh_top_ips(self, now: float) -> None:
        """Recompute top-10 IPs by window count at most every 2 seconds."""
        if now - self._last_top_refresh < 2.0:
            return
        with self._ip_dict_lock:
            ips = list(self._ip_windows.keys())
        counts: dict[str, int] = {}
        cutoff = now - self._ip_win_secs
        for ip in ips:
            with self._ip_dict_lock:
                lock = self._ip_locks.get(ip)
            if not lock:
                continue
            with lock:
                dq = self._ip_windows.get(ip)
                if dq:
                    counts[ip] = sum(1 for t in dq if t >= cutoff)
        self._top_ips = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
        self._last_top_refresh = now

    # ── Detection logic ───────────────────────────────────────────────────────

    def _check_ip(self, ip: str, rate_per_s: float, now: float) -> None:
        """
        Per-spec detection for one IP.

        Spec (exact): "Flag an IP as anomalous if the z-score exceeds 3.0
        OR the rate is more than 5x the baseline mean — whichever fires first."

        Steps:
          1. Read mean/stddev from the baseline (real computed values, never hardcoded).
          2. Apply error-surge tightening if this IP's 4xx/5xx rate >= 3× global baseline.
          3. Compute z-score: (rate_per_s - mean) / stddev.
          4. Fire if: zscore > threshold  OR  rate > spike_mul × mean.
          5. No additional gates — the spec's two conditions are sufficient.
        """
        mean   = self._baseline.mean
        stddev = self._baseline.stddev

        # Guard only: if stddev is zero (not yet meaningful), skip.
        # This never modifies mean — it only prevents division-by-zero.
        if stddev == 0.0 or mean == 0.0:
            return

        # ── Error-surge tightening ──────────────────────────────
        # Compare this IP's error rate to the GLOBAL baseline error rate.
        # If IP error rate >= 3× global → IP is scanning/probing → halve thresholds.
        err_rate  = self._baseline.ip_error_rate(ip)
        base_err  = self._baseline.baseline_error_rate
        err_surge = (
            base_err > 0
            and err_rate >= self._cfg.detection.error_rate_multiplier * base_err
        )

        z_thresh  = self._cfg.detection.zscore_threshold   # 3.0 from config
        spike_mul = self._cfg.detection.spike_multiplier   # 5.0 from config

        if err_surge:
            # Tighten: halve both thresholds → easier to flag error-surging IPs
            z_thresh  *= 0.5   # 3.0 → 1.5
            spike_mul *= 0.5   # 5.0 → 2.5
            log.debug(
                "IP %s error-surge: ip_err=%.1f%% global_err=%.1f%% → thresholds halved",
                ip, err_rate * 100, base_err * 100,
            )

        # ── z-score OR spike, whichever fires first ────────
        # Both rate_per_s and mean are in req/s — units are consistent.
        zscore = (rate_per_s - mean) / stddev

        condition = None
        if zscore > z_thresh:
            # z-score fired first
            condition = (
                f"zscore={zscore:.2f} > {z_thresh}"
            )
        elif rate_per_s > spike_mul * mean:
            # Spike check fired first
            condition = (
                f"spike: {rate_per_s:.4f} req/s > {spike_mul}x mean={mean:.4f} req/s"
            )

        if condition:
            # Append rate and baseline so audit log has them without duplication
            full_condition = (
                f"{condition} | rate={rate_per_s:.4f} req/s | baseline={mean:.4f} req/s"
            )
            self._fire_ip_anomaly(ip, rate_per_s, mean, full_condition, now)

    def _check_global(self, rate_per_s: float, now: float) -> None:
        """
        Per-spec detection for global rate.
        Global anomaly → Slack alert only, no iptables ban.
        Same z-score / spike logic, no extra gates.
        """
        mean   = self._baseline.mean
        stddev = self._baseline.stddev

        if stddev == 0.0 or mean == 0.0:
            return

        z_thresh  = self._cfg.detection.zscore_threshold
        spike_mul = self._cfg.detection.spike_multiplier
        zscore    = (rate_per_s - mean) / stddev

        condition = None
        if zscore > z_thresh:
            condition = f"GLOBAL zscore={zscore:.2f} > {z_thresh}"
        elif rate_per_s > spike_mul * mean:
            condition = (
                f"GLOBAL spike: {rate_per_s:.4f} req/s > {spike_mul}x mean={mean:.4f} req/s"
            )

        if condition:
            full_condition = (
                f"{condition} | rate={rate_per_s:.4f} req/s | baseline={mean:.4f} req/s"
            )
            self._fire_global_anomaly(rate_per_s, mean, full_condition, now)

    # ── Event dispatch ────────────────────────────────────────────────────────

    def _in_cooldown(self, key: str, now: float, cooldown: float = 30.0) -> bool:
        """Return True if this entity was alerted within the cooldown window."""
        with self._alert_lock:
            last = self._last_alerted.get(key, 0.0)
            if now - last < cooldown:
                return True
            self._last_alerted[key] = now
            return False

    def _fire_ip_anomaly(
        self, ip: str, rate_per_s: float, mean: float, condition: str, now: float
    ) -> None:
        if self._in_cooldown(f"ip:{ip}", now):
            return
        if self._blocker.is_banned(ip):
            return
        log.warning("IP ANOMALY → BAN: %s | %s", ip, condition)
        # Run ban in a separate thread — spec requires iptables + Slack within 10s.
        # The ban thread runs concurrently so the monitor thread is never blocked.
        threading.Thread(
            target=self._blocker.ban,
            args=(ip, condition, rate_per_s, mean),
            daemon=True,
        ).start()

    def _fire_global_anomaly(
        self, rate_per_s: float, mean: float, condition: str, now: float
    ) -> None:
        if self._in_cooldown("global", now, cooldown=60.0):
            return
        log.warning("GLOBAL ANOMALY (Slack only, no ban): %s", condition)
        threading.Thread(
            target=self._notifier.send_global_alert,
            args=(condition, rate_per_s, mean),
            daemon=True,
        ).start()
