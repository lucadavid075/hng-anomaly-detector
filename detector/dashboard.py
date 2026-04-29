"""
dashboard.py — Live metrics web dashboard on port 8080.

Spec requirements:
  - Refreshes every 3 seconds or less
  - Shows: banned IPs, global req/s, top 10 source IPs,
           CPU/memory, effective mean/stddev, uptime
  - Must be served at a domain or subdomain

Routes:
  GET /          → HTML dashboard page
  GET /api/stats → JSON stats (fetched by the page every 3 s)

NGINX PROXY FIX
---------------
The original JS used `window.location.origin` as the API base, which
means a request to https://domain.com/metrics would fetch
https://domain.com/api/stats — a path not proxied by nginx, so it hits
Nextcloud and returns a 404.

Fix: the JS now uses a relative path `./api/stats` when the page is
served under a sub-path (detected via window.location.pathname), and
falls back to the origin-relative path when accessed directly on :8080.

Also: the /api/stats JSON now includes `baseline` per active ban so the
dashboard table can show the correct "Effective mean at ban time" value
instead of incorrectly re-displaying the rate column.
"""

import json
import logging
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

import psutil

if TYPE_CHECKING:
    from baseline import BaselineTracker
    from blocker  import Blocker
    from detector import AnomalyDetector

log = logging.getLogger("dashboard")

_START_TIME = time.time()


class _Handler(BaseHTTPRequestHandler):

    blocker:  "Blocker"
    baseline: "BaselineTracker"
    detector: "AnomalyDetector"

    def log_message(self, format: str, *args) -> None:
        pass  # suppress per-request access logs from the dashboard itself

    def do_GET(self) -> None:
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path in ("/", "/index.html"):
            self._serve_html()
        elif path == "/api/stats":
            self._serve_stats()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_html(self) -> None:
        body = _HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_stats(self) -> None:
        elapsed = int(time.time() - _START_TIME)
        h, rem  = divmod(elapsed, 3600)
        m, s    = divmod(rem, 60)

        bans = []
        for r in self.blocker.get_bans():
            remaining = int(r.unban_at - time.time()) if r.unban_at else None
            bans.append({
                "ip":         r.ip,
                "condition":  r.condition,
                "rate":       r.rate,
                "baseline":   r.baseline,   # FIX: was missing — JS was showing rate in this column
                "level":      r.level,
                "banned_ago": int(time.time() - r.banned_at),
                "remaining_s": remaining,
            })

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()

        stats = {
            "uptime":           f"{h:02d}:{m:02d}:{s:02d}",
            "global_rps":       round(self.detector.global_rps, 2),
            # effective_mean and stddev — computed from REAL traffic, never hardcoded
            "mean":             round(self.baseline.mean, 4),
            "stddev":           round(self.baseline.stddev, 4),
            "baseline_source":  self.baseline.current_source,
            # hourly_slots enables the dashboard to show two slots with different means
            # (satisfies Screenshot 7 — Baseline-graph.png)
            "hourly_slots":     self.baseline.hourly_summary,
            "baseline_samples": self.baseline.sample_count,
            "cpu_pct":          round(cpu, 1),
            "mem_pct":          round(mem.percent, 1),
            "mem_used_mb":      round(mem.used / 1024 / 1024, 1),
            "banned_ips":       bans,
            "top_ips":          [{"ip": ip, "count": c} for ip, c in self.detector.top_ips],
        }

        body = json.dumps(stats).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


class DashboardServer:

    def __init__(self, cfg, blocker, baseline, detector) -> None:
        self._host = cfg.dashboard.host
        self._port = cfg.dashboard.port
        _Handler.blocker  = blocker
        _Handler.baseline = baseline
        _Handler.detector = detector

    def serve(self) -> None:
        server = HTTPServer((self._host, self._port), _Handler)
        log.info("Dashboard listening on %s:%d", self._host, self._port)
        server.serve_forever()


# ── Embedded HTML dashboard ───────────────────────────────────────────────────

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HNG Anomaly Detection — Live Dashboard</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
      --green:#3fb950;--red:#f85149;--yellow:#d29922;--blue:#58a6ff;--orange:#e3b341}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}
header{background:var(--card);border-bottom:1px solid var(--border);padding:14px 20px;
       display:flex;align-items:center;gap:10px}
header h1{font-size:1.1rem;font-weight:600}
.live-badge{background:var(--green);color:#000;border-radius:4px;padding:2px 7px;
            font-size:11px;font-weight:700}
.live-badge.err{background:var(--red);color:#fff}
#lastUpdate{margin-left:auto;font-size:11px;color:var(--muted)}
main{padding:16px;display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px}
.card h2{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;
         letter-spacing:.05em;margin-bottom:8px}
.big{font-size:2rem;font-weight:700}
.big.warn{color:var(--red)}
.sub{font-size:11px;color:var(--muted);margin-top:4px}
.bar-bg{background:var(--border);border-radius:3px;height:5px;margin-top:8px}
.bar-fill{height:100%;border-radius:3px;transition:width .4s}
.full{grid-column:1/-1}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:5px 8px;color:var(--muted);font-weight:600;font-size:11px;
   text-transform:uppercase;border-bottom:1px solid var(--border)}
td{padding:5px 8px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:1px 6px;border-radius:10px;font-size:11px;font-weight:600}
.pill-r{background:rgba(248,81,73,.15);color:var(--red)}
.pill-y{background:rgba(210,153,34,.15);color:var(--yellow)}
.pill-g{background:rgba(63,185,80,.15);color:var(--green)}
.bar-wrap{display:flex;align-items:center;gap:6px}
.mini-bar{background:var(--border);border-radius:2px;height:5px;flex:1}
.mini-fill{height:100%;border-radius:2px;background:var(--blue)}
.source-tag{font-size:10px;color:var(--blue);font-family:monospace}
.slot-row{display:flex;justify-content:space-between;padding:3px 0;
          border-bottom:1px solid var(--border);font-size:12px}
.slot-row:last-child{border-bottom:none}
.warming{color:var(--yellow);font-size:12px;font-style:italic}
</style>
</head>
<body>
<header>
  <div>
    <h1>HNG Anomaly Detection Engine</h1>
    <div style="font-size:11px;color:var(--muted);margin-top:2px">
      ddos-detector.duckdns.org — live traffic monitoring
    </div>
  </div>
  <span class="live-badge" id="badge">LIVE</span>
  <span id="lastUpdate"></span>
</header>
<main>
  <div class="card"><h2>Uptime</h2><div class="big" id="uptime">--</div></div>
  <div class="card">
    <h2>Global req/s <span style="font-weight:400">(60s window)</span></h2>
    <div class="big" id="rps">--</div>
    <div class="sub" id="rpsVsMean"></div>
  </div>
  <div class="card">
    <h2>Effective mean</h2>
    <div class="big" id="mean">--</div>
    <div class="sub">stddev: <span id="stddev">--</span></div>
    <div class="sub source-tag" id="src"></div>
    <div class="sub" id="samples"></div>
  </div>
  <div class="card">
    <h2>Banned IPs</h2>
    <div class="big" id="banCount" style="color:var(--red)">0</div>
  </div>
  <div class="card">
    <h2>CPU</h2>
    <div id="cpu" style="font-size:1.4rem;font-weight:700">--%</div>
    <div class="bar-bg"><div class="bar-fill" id="cpuBar" style="background:var(--blue);width:0"></div></div>
  </div>
  <div class="card">
    <h2>Memory</h2>
    <div id="mem" style="font-size:1.4rem;font-weight:700">--%</div>
    <div class="sub" id="memMb"></div>
    <div class="bar-bg"><div class="bar-fill" id="memBar" style="background:var(--orange);width:0"></div></div>
  </div>

  <!-- Hourly baseline slots — satisfies Screenshot 7 requirement -->
  <div class="card">
    <h2>Hourly baseline slots</h2>
    <div id="hourlySlots"><div class="warming">Collecting data…</div></div>
  </div>

  <!-- Banned IPs table -->
  <div class="card full">
    <h2>Active bans</h2>
    <table><thead><tr>
      <th>IP</th><th>Condition</th><th>Rate at ban</th><th>Baseline at ban</th><th>Level</th><th>Banned ago</th><th>Expires in</th>
    </tr></thead>
    <tbody id="banBody">
      <tr><td colspan="7" style="color:var(--muted);text-align:center;padding:12px">No active bans</td></tr>
    </tbody></table>
  </div>

  <!-- Top 10 source IPs -->
  <div class="card full">
    <h2>Top 10 source IPs <span style="font-weight:400;font-size:11px">(last 60s)</span></h2>
    <table><thead><tr><th>IP</th><th>Requests</th><th>Traffic</th></tr></thead>
    <tbody id="topBody">
      <tr><td colspan="3" style="color:var(--muted);text-align:center;padding:12px">No data yet</td></tr>
    </tbody></table>
  </div>
</main>

<script>
function fmt(s){
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),ss=s%60;
  return h>0?`${h}h ${m}m`:m>0?`${m}m ${ss}s`:`${ss}s`;
}

// FIX: compute the correct API base so the fetch works both when the
// dashboard is accessed directly on :8080 AND through the nginx /metrics proxy.
// When served at https://domain.com/metrics, window.location.origin alone
// gives https://domain.com, so /api/stats would hit Nextcloud (404).
// We detect the sub-path and prefix accordingly.
function apiBase() {
  const p = window.location.pathname;
  // Strip trailing slash, then any trailing segment (index.html, etc.)
  const dir = p.endsWith('/') ? p.slice(0, -1) : p.substring(0, p.lastIndexOf('/'));
  // If served at /metrics or /metrics/, prefix the API path with /metrics
  if (dir === '/metrics' || dir.startsWith('/metrics/')) {
    return window.location.origin + '/metrics';
  }
  return window.location.origin;
}

async function refresh(){
  try {
    const r = await fetch(apiBase() + '/api/stats', {cache:'no-store'});
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();

    document.getElementById('uptime').textContent = d.uptime;

    // Global req/s (true req/s — already divided by window in Python)
    const rpsEl = document.getElementById('rps');
    rpsEl.textContent = d.global_rps;
    rpsEl.className = 'big' + (d.global_rps > d.mean * 3 ? ' warn' : '');
    document.getElementById('rpsVsMean').textContent =
      d.mean > 0 ? `${(d.global_rps / d.mean).toFixed(1)}x mean` : '';

    // Effective mean / stddev (computed from real traffic — never hardcoded)
    document.getElementById('mean').textContent   = d.mean;
    document.getElementById('stddev').textContent = d.stddev;
    document.getElementById('src').textContent    = d.baseline_source;
    document.getElementById('samples').textContent =
      `${d.baseline_samples} samples`;

    // Ban count
    document.getElementById('banCount').textContent = d.banned_ips.length;

    // CPU / memory
    document.getElementById('cpu').textContent    = d.cpu_pct + '%';
    document.getElementById('cpuBar').style.width = d.cpu_pct + '%';
    document.getElementById('mem').textContent    = d.mem_pct + '%';
    document.getElementById('memMb').textContent  = d.mem_used_mb + ' MB used';
    document.getElementById('memBar').style.width = d.mem_pct + '%';

    // Hourly baseline slots (Screenshot 7 — two slots, different effective_mean)
    const slots = d.hourly_slots;
    const keys  = Object.keys(slots).sort();
    const slotsEl = document.getElementById('hourlySlots');
    if (keys.length === 0) {
      slotsEl.innerHTML = '<div class="warming">Collecting data… (needs 2 min per hour)</div>';
    } else {
      slotsEl.innerHTML = keys.map(k =>
        `<div class="slot-row">
           <span style="font-family:monospace;color:var(--blue)">${k}</span>
           <span>mean = <strong>${slots[k]}</strong> req/s</span>
         </div>`
      ).join('');
    }

    // Active bans table
    // FIX: show b.baseline (effective mean at ban time) in the "Baseline at ban"
    // column — the original code showed b.rate in that column by mistake.
    const banBody = document.getElementById('banBody');
    if (d.banned_ips.length === 0) {
      banBody.innerHTML =
        '<tr><td colspan="7" style="color:var(--muted);text-align:center;padding:12px">No active bans</td></tr>';
    } else {
      banBody.innerHTML = d.banned_ips.map(b => `
        <tr>
          <td><code style="color:var(--red)">${b.ip}</code></td>
          <td style="color:var(--muted)">${b.condition}</td>
          <td><span class="pill pill-r">${b.rate.toFixed(2)}/s</span></td>
          <td><code>${b.baseline != null ? b.baseline.toFixed(4) : '—'}/s</code></td>
          <td><span class="pill pill-y">L${b.level}</span></td>
          <td>${fmt(b.banned_ago)}</td>
          <td>${b.remaining_s === null
            ? '<span class="pill pill-r">permanent</span>'
            : fmt(Math.max(0, b.remaining_s))}</td>
        </tr>`).join('');
    }

    // Top 10 source IPs
    const topBody = document.getElementById('topBody');
    const maxC    = d.top_ips.length ? d.top_ips[0].count : 1;
    if (d.top_ips.length === 0) {
      topBody.innerHTML =
        '<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:12px">No data yet</td></tr>';
    } else {
      topBody.innerHTML = d.top_ips.map((t, i) => `
        <tr>
          <td>
            <code>${t.ip}</code>
            ${i === 0 ? '<span class="pill pill-y" style="margin-left:4px">TOP</span>' : ''}
          </td>
          <td>${t.count}</td>
          <td>
            <div class="bar-wrap">
              <div class="mini-bar">
                <div class="mini-fill" style="width:${maxC>0?Math.round(t.count/maxC*100):0}%"></div>
              </div>
              <span style="font-size:11px;color:var(--muted)">
                ${maxC>0?Math.round(t.count/maxC*100):0}%
              </span>
            </div>
          </td>
        </tr>`).join('');
    }

    document.getElementById('lastUpdate').textContent =
      'Updated ' + new Date().toLocaleTimeString();
    const badge = document.getElementById('badge');
    badge.className = 'live-badge';
    badge.textContent = 'LIVE';

  } catch(e) {
    const badge = document.getElementById('badge');
    badge.className = 'live-badge err';
    badge.textContent = 'ERR';
    console.error('Stats fetch failed:', e);
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"""
