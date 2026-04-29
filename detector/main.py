"""
main.py — HNG Anomaly Detection Engine entry point.

Wires all modules together, launches four daemon threads, and blocks
until SIGTERM or SIGINT is received.

Thread layout:
  baseline  — recalculates effective_mean/stddev every 60 s
  unbanner  — checks ban expiry every 30 s
  monitor   — tails the Nginx access log line by line, forever
  dashboard — serves the live metrics HTTP dashboard on port 8080
"""

import logging
import signal
import sys
import threading

from config    import load_config
from monitor   import LogMonitor
from baseline  import BaselineTracker
from detector  import AnomalyDetector
from blocker   import Blocker
from unbanner  import Unbanner
from notifier  import Notifier
from dashboard import DashboardServer

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers= [logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("main")


def main() -> None:
    cfg = load_config("/app/config.yaml")
    log.info("Configuration loaded.")

    notifier  = Notifier(cfg)
    blocker   = Blocker(cfg, notifier)
    baseline  = BaselineTracker(cfg)
    detector  = AnomalyDetector(cfg, baseline, blocker, notifier)
    unbanner  = Unbanner(cfg, blocker, notifier)
    monitor   = LogMonitor(cfg, detector)
    dashboard = DashboardServer(cfg, blocker, baseline, detector)

    threads = [
        threading.Thread(target=baseline.run_recalculation_loop, name="baseline",  daemon=True),
        threading.Thread(target=unbanner.run,                    name="unbanner",  daemon=True),
        threading.Thread(target=monitor.tail,                    name="monitor",   daemon=True),
        threading.Thread(target=dashboard.serve,                 name="dashboard", daemon=True),
    ]

    for t in threads:
        log.info("Starting thread: %s", t.name)
        t.start()

    stop = threading.Event()

    def _shutdown(signum, frame):
        log.info("Signal %s received — shutting down.", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT,  _shutdown)

    log.info("HNG Anomaly Detection Engine is running.")
    stop.wait()
    log.info("Goodbye.")
    sys.exit(0)


if __name__ == "__main__":
    main()
