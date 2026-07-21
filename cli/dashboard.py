#!/usr/bin/env python3
"""dashboard.py — local telemetry dashboard (Tier 10).

WHY: A fuzzing campaign needs a glanceable view of throughput, findings, and which strategies
have been exercised. This reads the append-only run log (build/telemetry/runs.jsonl) and the
evidence vault (build/vault/findings.json), renders a single self-contained HTML page (no
external assets), and can serve it over localhost. It reports what actually happened — run
counts, execs/sec, real divergences/crashes — never a fabricated finding.
"""
import html
import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNS = os.path.join(ROOT, "build", "telemetry", "runs.jsonl")
VAULT = os.path.join(ROOT, "build", "vault", "findings.json")
OUT = os.path.join(ROOT, "build", "dashboard", "index.html")

# The strategy registry (name, class, one-line note) — kept in sync with strategies.hpp.
STRATEGIES = [
    ("jit_tierup_stress", "misc", "hot loop + type-specialized arithmetic"),
    ("hot_loop_gc_narrow", "TC", "gc ref through single-block loop (Turboshaft narrowing)"),
    ("nullability_canon", "TC", "ref types differing only in nullability (canonicalization)"),
    ("subtype_cast_matrix", "TC", "struct subtype chain + ref.cast/test"),
    ("recgroup_subtype_bomb", "TC", "deep rec-group subtype chain"),
    ("array_oob_loop", "OOB", "array index near length bound"),
    ("call_indirect_confusion", "#5", "hot call_indirect target-type speculation"),
    ("licm_bounds_elision", "#2", "loop-invariant index; LICM hoists bounds check"),
    ("osr_type_mismatch", "#3", "long loop OSR; ref null->non-null mid-loop"),
    ("gc_barrier_elision", "#4", "old<-young ref store; write-barrier surface"),
]


def _load_runs():
    if not os.path.exists(RUNS):
        return []
    out = []
    for line in open(RUNS):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def _load_findings():
    if not os.path.exists(VAULT):
        return []
    try:
        return json.load(open(VAULT))
    except (json.JSONDecodeError, OSError):
        return []


def _bars(values, w=520, h=90):
    """Inline SVG bar chart of execs/sec per run (no external chart lib)."""
    if not values:
        return "<p class=muted>no runs yet</p>"
    vmax = max(values) or 1
    n = len(values)
    bw = max(2, w // max(n, 1) - 2)
    bars = []
    for i, v in enumerate(values):
        bh = int((v / vmax) * (h - 12))
        x = i * (bw + 2)
        bars.append(f'<rect x="{x}" y="{h-bh}" width="{bw}" height="{bh}" '
                    f'rx="1"><title>{v:.0f} execs/s</title></rect>')
    return (f'<svg viewBox="0 0 {w} {h}" width="100%" height="{h}" '
            f'class="chart">{"".join(bars)}</svg>')


def render():
    runs = _load_runs()
    finds = _load_findings()
    total_execs = sum(r.get("modules", 0) * r.get("configs", 1) for r in runs)
    total_div = sum(r.get("divergences", 0) for r in runs)
    total_crash = sum(r.get("crashes", 0) for r in runs)
    thr = [r.get("execs_per_sec", 0) for r in runs]
    avg_thr = sum(thr) / len(thr) if thr else 0

    esc = html.escape

    def stat(label, val, cls=""):
        return (f'<div class="stat {cls}"><div class="v">{val}</div>'
                f'<div class="l">{esc(label)}</div></div>')

    stats = "".join([
        stat("runs", len(runs)),
        stat("total execs", f"{total_execs:,}"),
        stat("avg execs/s", f"{avg_thr:.0f}"),
        stat("divergences", total_div, "hot" if total_div else ""),
        stat("crashes", total_crash, "hot" if total_crash else ""),
        stat("findings", len(finds), "hot" if finds else ""),
    ])

    run_rows = "".join(
        f"<tr><td>{esc(time.strftime('%m-%d %H:%M', time.localtime(r.get('ts', 0))))}</td>"
        f"<td>{esc(r.get('cmd',''))}</td><td>{r.get('modules',0)}</td>"
        f"<td>{r.get('configs',0)}</td><td>{r.get('divergences',0)}</td>"
        f"<td>{r.get('crashes',0)}</td><td>{r.get('execs_per_sec',0):.0f}</td></tr>"
        for r in reversed(runs[-25:])
    ) or "<tr><td colspan=7 class=muted>no runs</td></tr>"

    find_rows = "".join(
        f"<tr><td><code>{esc(f.get('crash_id',''))}</code></td>"
        f"<td>{esc(f.get('kind',''))}</td><td>{esc(f.get('exploitability',''))}</td>"
        f"<td>{f.get('cvss',0)}</td><td>{esc(f.get('status',''))}</td>"
        f"<td>{'yes' if f.get('confirmed', True) else 'no'}</td></tr>"
        for f in finds
    ) or "<tr><td colspan=6 class=muted>no findings logged</td></tr>"

    strat_rows = "".join(
        f"<tr><td><code>{esc(n)}</code></td><td>{esc(c)}</td><td>{esc(note)}</td></tr>"
        for n, c, note in STRATEGIES
    )

    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>NEMESIS dashboard</title>
<style>
:root{{color-scheme:light dark}}
body{{font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;margin:0;padding:1.5rem;
 background:#0b0e14;color:#c8d3e0}}
h1{{font-size:1.2rem;margin:0 0 1rem}}h2{{font-size:.95rem;color:#7aa2f7;margin:1.5rem 0 .5rem}}
.stats{{display:flex;flex-wrap:wrap;gap:.75rem}}
.stat{{background:#131722;border:1px solid #222a3a;border-radius:8px;padding:.75rem 1rem;min-width:6rem}}
.stat .v{{font-size:1.5rem;font-weight:700}}.stat .l{{color:#6b7688;font-size:.8rem}}
.stat.hot .v{{color:#f7768e}}
table{{border-collapse:collapse;width:100%;margin:.25rem 0;font-size:.85rem;overflow-x:auto;display:block}}
td,th{{border:1px solid #222a3a;padding:.25rem .6rem;text-align:left;white-space:nowrap}}
th{{color:#6b7688;font-weight:600}}
code{{color:#9ece6a}}.muted{{color:#6b7688}}
.chart rect{{fill:#7aa2f7}}
.note{{color:#6b7688;font-size:.8rem;margin-top:2rem;border-top:1px solid #222a3a;padding-top:.75rem}}
</style></head><body>
<h1>⬡ NEMESIS — coverage-guided differential Wasm-GC/JIT fuzzer</h1>
<div class="stats">{stats}</div>
<h2>throughput (execs/sec per run)</h2>{_bars(thr)}
<h2>recent runs</h2>
<table><tr><th>time</th><th>cmd</th><th>modules</th><th>cfgs</th><th>div</th><th>crash</th><th>ex/s</th></tr>{run_rows}</table>
<h2>findings (evidence vault)</h2>
<table><tr><th>id</th><th>kind</th><th>exploitability</th><th>cvss</th><th>status</th><th>confirmed</th></tr>{find_rows}</table>
<h2>strategy registry ({len(STRATEGIES)})</h2>
<table><tr><th>strategy</th><th>class</th><th>trigger shape</th></tr>{strat_rows}</table>
<p class="note">Generated {esc(time.strftime('%Y-%m-%d %H:%M:%S'))} · finds + characterizes
bugs for disclosure; does not weaponize. Divergence/crash counts are real oracle output.</p>
</body></html>"""


def build_html():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(render())
    return OUT


def _main(argv):
    path = build_html()
    print(f"dashboard -> {path}")
    if argv and argv[0] == "serve":
        import http.server
        import socketserver
        port = int(argv[1]) if len(argv) > 1 else 8777
        os.chdir(os.path.dirname(OUT))

        class H(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *a):
                pass

        with socketserver.TCPServer(("127.0.0.1", port), H) as httpd:
            print(f"serving on http://127.0.0.1:{port}/  (ctrl-c to stop)")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
