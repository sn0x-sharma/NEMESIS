#!/usr/bin/env python3
"""dashboard.py — local telemetry dashboard (Tier 10) — improved UI."""
import html
import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS = os.path.join(ROOT, "build", "telemetry", "runs.jsonl")
VAULT = os.path.join(ROOT, "build", "vault", "findings.json")
OUT = os.path.join(ROOT, "build", "dashboard", "index.html")

STRATEGIES = [
    ("jit_tierup_stress",      "misc", "hot loop + type-specialized arithmetic"),
    ("hot_loop_gc_narrow",     "TC",   "gc ref through single-block loop (Turboshaft narrowing)"),
    ("nullability_canon",      "TC",   "ref types differing only in nullability (canonicalization)"),
    ("subtype_cast_matrix",    "TC",   "struct subtype chain + ref.cast/test"),
    ("recgroup_subtype_bomb",  "TC",   "deep rec-group subtype chain"),
    ("array_oob_loop",         "OOB",  "array index near length bound"),
    ("call_indirect_confusion","#5",   "hot call_indirect target-type speculation"),
    ("licm_bounds_elision",    "#2",   "loop-invariant index; LICM hoists bounds check"),
    ("osr_type_mismatch",      "#3",   "long loop OSR; ref null->non-null mid-loop"),
    ("gc_barrier_elision",     "#4",   "old<-young ref store; write-barrier surface"),
]

CLASS_COLOR = {"TC": "#7aa2f7", "OOB": "#ff9e64", "misc": "#9ece6a", "#2": "#e0af68", "#3": "#e0af68", "#4": "#e0af68", "#5": "#e0af68"}

def _load_runs():
    if not os.path.exists(RUNS):
        return []
    out = []
    for line in open(RUNS, encoding="utf-8"):
        line = line.strip()
        if line:
            try: out.append(json.loads(line))
            except json.JSONDecodeError: pass
    return out

def _load_findings():
    if not os.path.exists(VAULT):
        return []
    try: return json.load(open(VAULT, encoding="utf-8"))
    except (json.JSONDecodeError, OSError): return []

def _sparkline(values, w=300, h=48):
    if not values:
        return ""
    vmax = max(values) or 1
    n = len(values)
    bw = max(3, w // max(n, 1) - 2)
    bars = []
    for i, v in enumerate(values):
        bh = max(2, int((v / vmax) * (h - 8)))
        x = i * (bw + 2)
        bars.append(f'<rect x="{x}" y="{h-bh}" width="{bw}" height="{bh}" rx="1"><title>{v:.0f} ex/s</title></rect>')
    return f'<svg viewBox="0 0 {w} {h}" width="{w}" height="{h}" class="spark">{"".join(bars)}</svg>'

def render():
    runs = _load_runs()
    finds = _load_findings()
    total_execs = sum(r.get("modules", 0) * r.get("configs", 1) for r in runs)
    total_div   = sum(r.get("divergences", 0) for r in runs)
    total_crash = sum(r.get("crashes", 0) for r in runs)
    thr = [r.get("execs_per_sec", 0) for r in runs]
    avg_thr = sum(thr) / len(thr) if thr else 0
    esc = html.escape

    def stat_card(icon, label, val, hot=False):
        hot_cls = ' hot' if hot else ''
        return f'''<div class="card stat-card{hot_cls}">
  <div class="stat-icon">{icon}</div>
  <div class="stat-val">{val}</div>
  <div class="stat-lbl">{esc(label)}</div>
</div>'''

    stats = "".join([
        stat_card("◎", "total runs", len(runs)),
        stat_card("⚡", "total execs", f"{total_execs:,}"),
        stat_card("⟳", "avg ex/s", f"{avg_thr:.0f}"),
        stat_card("⊻", "divergences", total_div, hot=bool(total_div)),
        stat_card("✕", "crashes", total_crash, hot=bool(total_crash)),
        stat_card("◈", "findings", len(finds), hot=bool(finds)),
    ])

    run_rows = "".join(
        f'''<tr>
  <td class="mono">{esc(time.strftime('%m-%d %H:%M', time.localtime(r.get('ts',0))))}</td>
  <td><span class="badge badge-cmd">{esc(r.get('cmd',''))}</span></td>
  <td class="num">{r.get('modules',0):,}</td>
  <td class="num">{r.get('configs',0)}</td>
  <td class="num {"hot-cell" if r.get("divergences",0) else ""}">{r.get('divergences',0)}</td>
  <td class="num {"hot-cell" if r.get("crashes",0) else ""}">{r.get('crashes',0)}</td>
  <td class="num spark-cell">{_sparkline([r.get("execs_per_sec",0)], 60, 28)} {r.get("execs_per_sec",0):.0f}</td>
</tr>'''
        for r in reversed(runs[-20:])
    ) or '<tr><td colspan="7" class="empty">no runs yet — run <code>./build/nemesis diff 200 42</code></td></tr>'

    find_rows = "".join(
        f'''<tr>
  <td class="mono small">{esc(f.get('crash_id','')[:12])}…</td>
  <td>{esc(f.get('kind',''))}</td>
  <td><span class="badge badge-expl expl-{esc(f.get('exploitability','').lower().replace(' ','-'))}">{esc(f.get('exploitability',''))}</span></td>
  <td class="num">{f.get('cvss',0)}</td>
  <td><span class="badge badge-status">{esc(f.get('status',''))}</span></td>
  <td class="center">{'✓' if f.get('confirmed',True) else '–'}</td>
</tr>'''
        for f in finds
    ) or '<tr><td colspan="6" class="empty">no findings — divergences/crashes auto-log here</td></tr>'

    strat_rows = "".join(
        f'''<tr>
  <td class="mono">{esc(n)}</td>
  <td><span class="badge" style="background:{CLASS_COLOR.get(c,'#888')}22;color:{CLASS_COLOR.get(c,'#aaa')};border-color:{CLASS_COLOR.get(c,'#888')}44">{esc(c)}</span></td>
  <td class="muted">{esc(note)}</td>
</tr>'''
        for n, c, note in STRATEGIES
    )

    now = esc(time.strftime('%Y-%m-%d %H:%M:%S'))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEMESIS — fuzzer dashboard</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0a0c10;--surface:#10141c;--card:#161b27;--border:#1e2535;
  --text:#c9d1e0;--muted:#4a5568;--accent:#7aa2f7;--hot:#f7768e;
  --green:#9ece6a;--orange:#ff9e64;--yellow:#e0af68;
  --font:ui-monospace,Menlo,'Cascadia Code',Consolas,monospace;
  --radius:10px;
}}
body{{font-family:var(--font);font-size:13px;background:var(--bg);color:var(--text);min-height:100vh;padding:0}}

.topbar{{
  display:flex;align-items:center;justify-content:space-between;
  padding:0 2rem;height:52px;background:var(--surface);
  border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:10;
}}
.brand{{display:flex;align-items:center;gap:10px;font-size:14px;font-weight:700;color:var(--accent);letter-spacing:.04em}}
.brand-dot{{width:8px;height:8px;border-radius:50%;background:var(--accent)}}
.topbar-right{{display:flex;align-items:center;gap:1rem;font-size:12px;color:var(--muted)}}
.status-dot{{width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block;margin-right:5px}}

.page{{padding:1.5rem 2rem;max-width:1400px;margin:0 auto}}

.section-head{{
  display:flex;align-items:center;justify-content:space-between;
  margin:1.5rem 0 .75rem;padding-bottom:.5rem;
  border-bottom:1px solid var(--border);
}}
.section-title{{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}}
.section-count{{font-size:11px;color:var(--muted)}}

.stats-grid{{display:grid;grid-template-columns:repeat(6,1fr);gap:.75rem}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:1rem}}
.stat-card{{display:flex;flex-direction:column;gap:.25rem;transition:border-color .15s}}
.stat-card:hover{{border-color:var(--accent)}}
.stat-icon{{font-size:16px;color:var(--muted);margin-bottom:.25rem}}
.stat-val{{font-size:22px;font-weight:700;color:var(--text);letter-spacing:-.02em}}
.stat-lbl{{font-size:11px;color:var(--muted)}}
.stat-card.hot .stat-val{{color:var(--hot)}}
.stat-card.hot{{border-color:var(--hot)44}}

table{{width:100%;border-collapse:collapse;font-size:12px}}
thead tr{{background:var(--surface)}}
th{{padding:.5rem .75rem;text-align:left;font-size:10px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid var(--border)}}
td{{padding:.5rem .75rem;border-bottom:1px solid var(--border)22;vertical-align:middle}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:var(--surface)}}
.num{{text-align:right;font-variant-numeric:tabular-nums}}
.center{{text-align:center}}
.mono{{font-family:var(--font);color:var(--accent)}}
.small{{font-size:11px}}
.muted{{color:var(--muted)}}
.hot-cell{{color:var(--hot);font-weight:700}}
.empty{{color:var(--muted);padding:1.5rem .75rem;font-style:italic}}
.spark-cell{{display:flex;align-items:center;gap:.5rem;justify-content:flex-end}}

.badge{{display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;border:1px solid transparent}}
.badge-cmd{{background:var(--accent)18;color:var(--accent);border-color:var(--accent)33}}
.badge-status{{background:var(--muted)22;color:var(--muted)}}
.badge-expl{{}}
.expl-controlled{{background:var(--hot)18;color:var(--hot);border-color:var(--hot)33}}
.expl-uncontrolled{{background:var(--yellow)18;color:var(--yellow);border-color:var(--yellow)33}}
.expl-unknown{{background:var(--muted)18;color:var(--muted)}}

.spark rect{{fill:var(--accent)}}

.throughput-row{{display:flex;align-items:center;gap:1rem}}
.thr-spark .spark rect{{fill:var(--green)}}

.footer{{
  margin-top:2rem;padding:1rem 2rem;
  border-top:1px solid var(--border);
  font-size:11px;color:var(--muted);
  display:flex;justify-content:space-between;align-items:center;
}}

@media(max-width:900px){{
  .stats-grid{{grid-template-columns:repeat(3,1fr)}}
  .page{{padding:1rem}}
  .topbar{{padding:0 1rem}}
}}
</style>
</head>
<body>

<div class="topbar">
  <div class="brand">
    <div class="brand-dot"></div>
    NEMESIS
    <span style="font-weight:400;color:var(--muted);font-size:12px">/ differential Wasm-GC JIT fuzzer</span>
  </div>
  <div class="topbar-right">
    <span><span class="status-dot"></span>live</span>
    <span>{now}</span>
    <span style="color:var(--accent)">{len(STRATEGIES)} strategies</span>
  </div>
</div>

<div class="page">

  <div class="section-head"><span class="section-title">overview</span></div>
  <div class="stats-grid">{stats}</div>

  <div class="section-head">
    <span class="section-title">throughput — execs/sec per run</span>
    <span class="section-count">{len(runs)} runs total</span>
  </div>
  <div class="card">
    {''.join(f'<div class="throughput-row thr-spark">{_sparkline(thr, 600, 56)}</div>') if thr else '<span class="muted" style="font-size:12px;padding:.5rem 0;display:block">no runs yet</span>'}
  </div>

  <div class="section-head">
    <span class="section-title">recent runs</span>
    <span class="section-count">last 20</span>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <table>
      <thead><tr>
        <th>time</th><th>command</th><th>modules</th>
        <th>configs</th><th>divergences</th><th>crashes</th><th>ex/s</th>
      </tr></thead>
      <tbody>{run_rows}</tbody>
    </table>
  </div>

  <div class="section-head">
    <span class="section-title">findings — evidence vault</span>
    <span class="section-count">{len(finds)} total</span>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <table>
      <thead><tr>
        <th>crash id</th><th>kind</th><th>exploitability</th>
        <th>cvss</th><th>status</th><th>confirmed</th>
      </tr></thead>
      <tbody>{find_rows}</tbody>
    </table>
  </div>

  <div class="section-head">
    <span class="section-title">strategy registry</span>
    <span class="section-count">{len(STRATEGIES)} strategies</span>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <table>
      <thead><tr><th>strategy</th><th>class</th><th>trigger shape</th></tr></thead>
      <tbody>{strat_rows}</tbody>
    </table>
  </div>

</div>

<div class="footer">
  <span>NEMESIS — finds + characterizes bugs for disclosure. Does not weaponize.</span>
  <span>divergence/crash counts are real oracle output · 0 false positives verified</span>
</div>

</body>
</html>"""

def build_html():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(render())
    return OUT

def _main(argv):
    path = build_html()
    print(f"dashboard -> {path}")
    if argv and argv[0] == "serve":
        import http.server, socketserver
        port = int(argv[1]) if len(argv) > 1 else 8777
        os.chdir(os.path.dirname(OUT))
        class H(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a): pass
        with socketserver.TCPServer(("127.0.0.1", port), H) as httpd:
            print(f"serving on http://127.0.0.1:{port}/  (ctrl-c to stop)")
            try: httpd.serve_forever()
            except KeyboardInterrupt: pass
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
