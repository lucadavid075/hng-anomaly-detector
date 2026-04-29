# HNG Anomaly Detection Engine

> A real-time DDoS / anomaly detection daemon built alongside [cloud.ng](https://cloud.ng) (Nextcloud) as part of the HNG DevSecOps challenge.

---

## Table of Contents
1. [What it does](#what-it-does)
2. [Architecture](#architecture)
3. [How the sliding window works](#how-the-sliding-window-works)
4. [How the baseline works](#how-the-baseline-works)
5. [Detection logic](#detection-logic)
6. [iptables blocking](#iptables-blocking)
7. [Setup — fresh VPS to fully running](#setup--fresh-vps-to-fully-running)
8. [Live endpoints](#live-endpoints)
9. [Language choice](#language-choice)
10. [Repository structure](#repository-structure)
11. [Blog post](#blog-post)

---

## What it does

The engine runs as a Docker container alongside Nextcloud and Nginx. It:

- **Tails** the Nginx JSON access log in real time (poll gap ≤ 50 ms, rotation-safe).
- **Tracks** per-IP and global request rates using two deque-based sliding windows (60-second each).
- **Learns** what normal traffic looks like via a rolling 30-minute baseline that recalculates every 60 seconds.
- **Flags** anomalies when a z-score exceeds 3.0 **or** the rate is more than 5× the baseline mean — whichever fires first.
- **Tightens** detection thresholds automatically for IPs whose 4xx/5xx error rate is ≥ 3× the global baseline error rate.
- **Blocks** offending IPs with an `iptables DROP` rule and sends a Slack alert within 10 seconds.
- **Unbans** IPs on an escalating backoff schedule: 10 min → 30 min → 2 hours → permanent. A Slack notification is sent on every transition.
- **Exposes** a live dashboard at your subdomain showing banned IPs, global req/s, top-10 IPs, CPU/memory, baseline stats, and uptime — refreshed every 3 seconds.

---

## Architecture

```
Internet
   │
   ▼
┌──────────────────────────────────────────────────────────────┐
│  Linux VPS  (iptables DROP rules live at the kernel level)   │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                    Docker Compose                        │ │
│  │                                                          │ │
│  │  ┌──────────┐  :80   ┌───────────┐                      │ │
│  │  │  nginx   │───────▶│ Nextcloud │                      │ │
│  │  │ (proxy)  │        │ (app)     │                      │ │
│  │  └────┬─────┘        └───────────┘                      │ │
│  │       │ writes JSON logs                                 │ │
│  │       ▼                                                  │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │  HNG-nginx-logs  (named Docker volume)              │ │ │
│  │  └────────────────────────┬────────────────────────────┘ │ │
│  │                           │ mounted read-only             │ │
│  │                           ▼                               │ │
│  │  ┌──────────────────────────────────────────────────────┐ │ │
│  │  │  detector  (host-network, NET_ADMIN)                 │ │ │
│  │  │                                                      │ │ │
│  │  │  monitor ──▶ detector ──▶ blocker ──▶ iptables DROP  │ │ │
│  │  │                │            │                        │ │ │
│  │  │           baseline       notifier ──▶ Slack          │ │ │
│  │  │                │                                     │ │ │
│  │  │           unbanner (backoff schedule)                │ │ │
│  │  │                                                      │ │ │
│  │  │  dashboard  :8080  ◀── nginx /metrics proxy          │ │ │
│  │  └──────────────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

See `docs/architecture.png` for the full annotated diagram.

---

## How the sliding window works

### Deque structure

Two `collections.deque` objects are maintained:

```python
_ip_windows:  dict[str, deque]   # one deque per source IP
_global_window: deque            # one deque for all traffic combined
```

Each entry is a **Unix float timestamp** — one per request. There are no counters,
buckets, or per-minute resets. The deque *is* the window.

### Eviction logic

On every incoming request for IP `X`:

1. Append `now` (Unix float) to `_ip_windows[X]` and to `_global_window`.
2. Evict from the *left* of each deque while the oldest entry is outside the 60-second window:

```python
cutoff = now - 60              # 60-second sliding window

while dq and dq[0] < cutoff:
    dq.popleft()               # O(1) — deque left-pop is constant time
```

3. `len(dq)` after eviction is the request count for the last 60 seconds.
4. Divide by the window duration to get the rate in **req/s**:

```python
rate_per_s = len(dq) / 60     # convert req/60s → req/s
```

This division is critical: the baseline mean is computed in req/s, so the sliding
window rate must be in the same unit before any comparison.

Because eviction happens on every request, the deques never grow unboundedly even
under a flood — an IP can hold at most `rate_per_s × 60` entries.

---

## How the baseline works

### Rolling 30-minute window

`baseline.py` maintains a `deque(maxlen=1800)` of `(unix_timestamp, count)` pairs —
one pair per second of traffic (1 800 s = 30 minutes). Every second boundary crossed
by an incoming request flushes the previous second's bucket:

```python
if new_second != current_second:
    window.append((current_second, count_this_second))
    current_second    = new_second
    count_this_second = 1
else:
    count_this_second += 1
```

### Per-hour slots

Simultaneously, per-second counts are stored in per-hour buckets:

```python
_hourly: dict[str, list[int]]
# example: { "2026-04-29T14": [1, 2, 1, 3, …] }
```

The baseline prefers the **current hour's slot** when it has ≥ 120 data points —
it is a sharper model of right-now than a cross-hour rolling window. The rolling
30-minute window is the fallback during warm-up or when an hour just rolled over.

### Recalculation (every 60 seconds)

```python
mean   = sum(counts) / len(counts)                      # real computed mean
var    = sum((x - mean)**2 for x in counts) / len(counts)
stddev = math.sqrt(var)

# Proportional stddev floor — scales with traffic, never hardcoded:
#   enforce stddev >= mean * 0.3
# This prevents near-zero variance (perfectly uniform traffic) from
# inflating z-scores into the thousands on tiny fluctuations.
# effective_mean is NEVER modified — it is always the real computed value.
if mean > 0:
    effective_stddev = max(stddev, mean * min_stddev_ratio)   # default: 0.3
else:
    effective_stddev = max(stddev, 1e-6)                      # division-by-zero guard only
```

Key properties:
- **`effective_mean` is always the real average of actual per-second counts** — it is never floored, clamped, or hardcoded.
- Only `stddev` receives a floor, and the floor is **proportional to mean** (`mean × 0.3`) so it scales with traffic level rather than being a fixed constant.
- Both values are written to the audit log on every recalculation.

### Cold-start guard

Detection does not fire until `baseline.sample_count >= 120` (≈ 2 minutes of active
traffic). This prevents banning on an immature baseline without hardcoding a fake mean.

---

## Detection logic

For every incoming request the detector:

1. Reads `mean` and `effective_stddev` from the baseline (always real computed values).
2. Computes per-second rates from both sliding windows:

```python
ip_rate_per_s     = len(ip_window)     / 60   # req/s
global_rate_per_s = len(global_window) / 60   # req/s
```

3. For each entity (IP and global):

```python
zscore = (rate_per_s - mean) / stddev   # units match: both req/s

if zscore > 3.0:                        # z-score threshold (from config)
    fire_anomaly(...)
elif rate_per_s > 5.0 * mean:           # spike multiplier — whichever fires first
    fire_anomaly(...)
```

Both thresholds are read from `config.yaml` — nothing is hardcoded in Python.

### Error-surge tightening

If an IP's 4xx/5xx fraction in the last 60 s is ≥ 3× the **global** baseline error rate,
its thresholds are halved for that request cycle:

```python
if ip_error_rate >= 3.0 * global_baseline_error_rate:
    z_threshold      *= 0.5   # 3.0 → 1.5 — easier to flag
    spike_multiplier *= 0.5   # 5.0 → 2.5
```

This automatically tightens detection for IPs that are scanning or probing (high error
rates) without changing the thresholds for normal traffic.

---

## iptables blocking

When a per-IP anomaly fires:

```python
subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])
```

`-I INPUT 1` inserts the rule at the **top** of the INPUT chain so it takes effect
immediately regardless of other rules.

The detector container runs with `network_mode: host` and the `NET_ADMIN` + `NET_RAW`
capabilities, which allow it to modify the host kernel's netfilter rules directly.
iptables calls are made **outside** the threading lock so they never stall the monitor
or unbanner threads (each call has a 5-second timeout).

Global anomalies trigger a Slack alert only — no iptables rule is added.

### Unban backoff schedule

| Level | Trigger | Duration |
|-------|---------|----------|
| 0 | First anomaly detected | Blocked for **10 minutes** |
| 1 | 10-min ban expires | Re-blocked for **30 minutes** |
| 2 | 30-min ban expires | Re-blocked for **2 hours** |
| 3+ | 2-hour ban expires | **Permanent** block |

Every level transition — including the final permanent block — sends a Slack
notification containing the original condition, rate at time of ban, and baseline
at time of ban.

---

## Setup — fresh VPS to fully running

### Prerequisites

- Ubuntu 22.04 LTS VPS — minimum 2 vCPU / 2 GB RAM
- A subdomain pointing to your VPS IP (for the HTTPS dashboard)
- Docker ≥ 24 and Docker Compose v2

### 1. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
```

### 2. Clone the repository

```bash
git clone https://github.com/lucadavid075/hng-anomaly-detector.git
cd hng-anomaly-detector
```

### 3. Configure environment

```bash
cp .env.example .env
nano .env
# Required: DB_ROOT_PASSWORD, DB_PASSWORD, NC_ADMIN_PASSWORD,
#           SERVER_IP, SLACK_WEBHOOK_URL
```

The Slack webhook URL is loaded exclusively from `SLACK_WEBHOOK_URL` in the `.env`
file.

### 4. Obtain a TLS certificate (first time only)


### 5. Start the stack

```bash
docker compose up -d --build
```

### 6. Verify everything is running

```bash
docker compose ps
docker compose logs -f detector
```

Expected output includes lines like:
```
[INFO] baseline — Configuration loaded.
[INFO] main — Starting thread: baseline
[INFO] main — Starting thread: unbanner
[INFO] main — Starting thread: monitor
[INFO] main — Starting thread: dashboard
[INFO] monitor — LogMonitor: tailing /var/log/nginx/hng-access.log
```

### 7. Confirm the dashboard

Open `https://ddos-detector.duckdns.org/metrics/` — you should see the live dashboard
updating every 3 seconds with real traffic data.

### 8. Test detection manually

```bash
# Simulate a burst from a test machine (or use ab / wrk)
for i in $(seq 1 300); do curl -s http://16.59.170.236/ > /dev/null; done
```

Within seconds you should see a Slack ban alert and the IP appear in the dashboard
banned-IPs table.

### 9. Confirm iptables rules

```bash
sudo iptables -L INPUT -n --line-numbers
# Expected: DROP rule for the test IP at the top of the INPUT chain
```

---

## Live endpoints

| Endpoint | Description |
|----------|-------------|
| `http://16.59.170.236/` | Nextcloud (accessible by raw IP only, per spec) |
| `https://ddos-detector.duckdns.org/metrics/` | Live anomaly detection dashboard (HTTPS) |

The dashboard is served over HTTPS via a Let's Encrypt certificate. Nextcloud is
kept IP-only.

---

## Language choice

**Python 3.12** was chosen because:

- `collections.deque` provides O(1) `popleft()`, making window eviction constant-time under any flood rate.
- `threading` gives clean daemon threads with a simple `threading.Event` shutdown signal.
- `http.server` from the standard library is sufficient for the dashboard — no web framework needed.
- `psutil` gives cross-platform CPU/memory stats with a single import.
- `subprocess` + `urllib` cover iptables and Slack without any external dependencies.
- Only two packages are required (`pyyaml`, `psutil`) — the Docker image is small and auditable.
- Python's readability makes the detection logic easy to review — important for security tooling.

No external rate-limiting or detection libraries are used. All windowing and detection
logic is hand-rolled per the spec.

---

## Repository structure

```
hng-anomaly-detector/
├── docker-compose.yml
├── .env.example
├── nginx/
│   └── nginx.conf              ← reverse proxy, JSON logs, TLS, real-IP trust
├── detector/
│   ├── Dockerfile
│   ├── requirements.txt        ← pyyaml, psutil only
│   ├── config.yaml             ← ALL thresholds live here
│   ├── config.py               ← YAML loader + env-var overrides
│   ├── main.py                 ← entry point, wires 4 daemon threads
│   ├── monitor.py              ← log tail & parse (50 ms poll, rotation-safe)
│   ├── baseline.py             ← rolling mean/stddev, per-hour slots
│   ├── detector.py             ← sliding windows + spec-compliant anomaly logic
│   ├── blocker.py              ← iptables ban/unban (outside lock)
│   ├── unbanner.py             ← backoff unban scheduler (30 s poll)
│   ├── notifier.py             ← Slack webhook alerts (urllib, no requests)
│   ├── dashboard.py            ← live metrics HTTP server (port 8080)
│   └── audit.py                ← structured audit log writer
├── docs/
│   └── architecture.png        ← full system architecture diagram
├── screenshots/
│   ├── tool-running.png        ← daemon running, processing log lines
│   ├── ban-slack.png           ← Slack ban notification
│   ├── unban-slack.png         ← Slack unban notification
│   ├── global-alert-slack.png  ← Slack global anomaly notification
│   ├── iptables-banned.png     ← sudo iptables -L -n showing blocked IP
│   ├── audit-log.png           ← structured log with ban/unban/recalc events
│   └── baseline-graph.png      ← baseline over time (two hourly slots)
└── README.md
```

---

## Blog post

📝 [Read the beginner-friendly blog post](https://dev.to/lucadavid075/how-i-built-a-real-time-ddos-detection-engine-from-scratch-3p6f)

The post covers:
- What the project does and why it matters for cloud security
- How the sliding window works (with annotated diagrams)
- How the baseline learns from real traffic — and why a proportional stddev floor matters
- How the detection logic makes a decision (z-score vs spike check)
- How iptables is used to block an IP at the kernel level — before TCP completes

---

*Built with ❤️ for the HNG DevSecOps challenge.*
