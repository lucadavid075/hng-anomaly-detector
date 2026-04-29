"""
notifier.py — Slack webhook notifications.

Per spec every alert must include:
  condition fired, current rate, baseline (effective_mean), timestamp,
  ban duration (where applicable).

All rates are explicitly labelled req/s — no unit ambiguity.
Uses Python's built-in urllib — no requests library dependency.
"""

import json
import logging
import urllib.request
from datetime import datetime, timezone
from types import SimpleNamespace

log = logging.getLogger("notifier")


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class Notifier:

    def __init__(self, cfg: SimpleNamespace) -> None:
        self._url = cfg.slack.webhook_url.strip()
        if not self._url:
            log.warning("No Slack webhook URL set — alerts disabled.")

    def send_ban_alert(
        self,
        ip:        str,
        condition: str,
        rate:      float,   # req/s
        baseline:  float,   # effective_mean in req/s
        duration:  str,
    ) -> None:
        ratio = f"{rate / baseline:.1f}x" if baseline > 0 else "N/A"
        text = (
            f":rotating_light: *IP BANNED* — `{ip}`\n"
            f">*Condition:* {condition}\n"
            f">*Rate (60s window):* `{rate:.4f} req/s` ({ratio} above normal)\n"
            f">*Effective mean (baseline):* `{baseline:.4f} req/s`\n"
            f">*Ban duration:* `{duration}`\n"
            f">*Time:* {_utcnow()}"
        )
        self._post(text)

    def send_unban_alert(
        self,
        ip:            str,
        prev_level:    int,
        next_duration: str,
        # these three kwargs were passed by blocker.unban() but the old
        # signature didn't accept them → TypeError → unbanner thread died.
        condition:     str   = "",
        rate:          float = 0.0,
        baseline:      float = 0.0,
    ) -> None:
        """
        Spec: 'Alerts must include the condition fired, current rate, baseline,
        timestamp, and ban duration where applicable.'

        An unban is directly tied to a ban — condition/rate/baseline from the
        original ban are included so ops knows what triggered the ban that is
        now being escalated/released.
        """
        text = (
            f":unlock: *IP UNBANNED / ESCALATED* — `{ip}`\n"
            f">*Previous ban level:* `{prev_level}`\n"
            f">*Next duration:* `{next_duration}`\n"
        )
        if condition:
            text += f">*Original condition:* {condition}\n"
        if rate:
            text += f">*Rate at ban time:* `{rate:.4f} req/s`\n"
        if baseline:
            text += f">*Baseline at ban time:* `{baseline:.4f} req/s`\n"
        text += f">*Time:* {_utcnow()}"
        self._post(text)

    def send_global_alert(self, condition: str, rate: float, baseline: float) -> None:
        ratio = f"{rate / baseline:.1f}x" if baseline > 0 else "N/A"
        text = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f">*Condition:* {condition}\n"
            f">*Global rate (60s window):* `{rate:.4f} req/s` ({ratio} above normal)\n"
            f">*Effective mean (baseline):* `{baseline:.4f} req/s`\n"
            f">*Time:* {_utcnow()}\n"
            f">_No IP-level block applied for global anomalies._"
        )
        self._post(text)

    def _post(self, text: str) -> None:
        if not self._url:
            log.info("Slack disabled: %s", text[:80])
            return
        payload = json.dumps({"text": text}).encode("utf-8")
        try:
            req = urllib.request.Request(
                self._url,
                data    = payload,
                headers = {"Content-Type": "application/json"},
                method  = "POST",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                if resp.status != 200:
                    log.error("Slack returned HTTP %s", resp.status)
                else:
                    log.info("Slack alert sent.")
        except Exception as exc:
            log.error("Slack alert failed: %s", exc)
