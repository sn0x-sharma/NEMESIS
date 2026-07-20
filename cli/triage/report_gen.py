#!/usr/bin/env python3
"""report_gen.py — finding -> HackerOne/Bugzilla-ready markdown draft.

WHY: The last mile of triage is a clean disclosure. This turns a vault Finding (plus an
optional parsed ASan report) into a report skeleton with the fields a browser-vendor / VRP
submission expects: title, affected build, summary, deterministic-reproduction steps, PoC
pointers, exploitability evidence, CWE, and a *conservative* CVSS. It never claims more than
the evidence supports — a divergence is reported as a correctness/miscompilation defect, a
crash as a memory-safety issue, and severity is not inflated. It writes a report, not an
exploit.
"""
import os
from .vault import Finding

# Exploitability bucket -> (one-line impact statement, is memory-write).
_IMPACT = {
    "write-primitive": ("a controlled write primitive (attacker-influenced value to an "
                        "attacker-influenced address) — the strongest exploitability signal.", True),
    "controlled-write": ("a write to an apparently controllable address.", True),
    "oob-write": ("an out-of-bounds write.", True),
    "use-after-free": ("a use-after-free (dangling pointer reused).", True),
    "oob-read": ("an out-of-bounds read (memory-disclosure candidate).", False),
    "info-leak": ("an information leak from freed/adjacent memory.", False),
    "null-deref": ("a near-null dereference (denial-of-service class unless shown otherwise).", False),
    "miscompilation": ("a JIT miscompilation (wrong result for a deterministic program).", False),
    "unknown": ("an unclassified fault; see the crash evidence.", False),
}


def _cvss(f: Finding):
    if f.cvss and f.cvss_vector:
        return f.cvss, f.cvss_vector
    # Conservative fallback if the vault has no stored score.
    _, is_write = _IMPACT.get(f.exploitability, _IMPACT["unknown"])
    if f.kind == "divergence":
        return 5.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"
    if is_write:
        return 9.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
    if f.exploitability in ("oob-read", "info-leak"):
        return 7.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:L"
    return 6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"


def _render_informational(f: Finding) -> str:
    m = [f"# Wasm-GC test artifact `{f.crash_id}` — no anomaly reproduced\n",
         f"**Target:** {f.engine}  ",
         f"**Affected build/rev:** {f.affected_rev or '(tested build)'}  ",
         "**CVSS 3.1:** 0.0 (Informational)\n",
         "## Summary\n",
         "This module did **not** crash or diverge on the tested build — no vulnerability "
         "is demonstrated. It is a reproducible test artifact only. Re-run it against the "
         "target/nightly/older build (override the config binaries) before treating it as a "
         "finding. Do not submit this as-is.\n"]
    return "\n".join(m)


def render(f: Finding, asan=None) -> str:
    # Never dress up a non-reproduced artifact as a finding.
    if not f.confirmed and not asan:
        return _render_informational(f)
    # A parsed ASan report is itself evidence of a real crash; let it drive the class.
    if asan:
        f.kind = "crash"
        if f.exploitability in ("", "unknown"):
            f.exploitability = asan.exploitability
        if not f.cwe_candidate:
            f.cwe_candidate = asan.cwe
    impact, is_write = _IMPACT.get(f.exploitability, _IMPACT["unknown"])
    cvss, vector = _cvss(f)
    eng = {"v8": "V8 (Chrome/Chromium)", "spidermonkey": "SpiderMonkey (Firefox)",
           "jsc": "JavaScriptCore (Safari/WebKit)"}.get(f.engine, f.engine)

    if f.kind == "divergence":
        title = f"JIT miscompilation in {f.engine}: Wasm-GC result divergence across tiers"
    else:
        cls = (asan.bug_type if asan else f.exploitability)
        title = f"Memory-safety issue in {f.engine} Wasm-GC ({cls})"

    m = []
    m.append(f"# {title}\n")
    m.append(f"**Target:** {eng}  ")
    m.append(f"**Affected build/rev:** {f.affected_rev or '(fill in exact build id)'}  ")
    m.append(f"**Finding ID:** `{f.crash_id}`  ")
    if f.cwe_candidate:
        m.append(f"**CWE:** {f.cwe_candidate}  ")
    m.append(f"**CVSS 3.1:** {cvss} — `{vector}`\n")

    m.append("## Summary\n")
    m.append(f"NEMESIS identified {impact}\n")

    m.append("## Steps to reproduce\n")
    m.append("1. Use the affected build above.")
    if f.repro_html:
        m.append(f"2. Open the attached `repro.html` (self-contained; embeds the module).")
    if f.minimized_wasm:
        m.append(f"3. Or run headless: `node harness/run_wasm.js {os.path.basename(f.minimized_wasm)}`.")
    m.append("4. Observe the result below.\n")

    m.append("## Evidence\n")
    if asan:
        m.append("Sanitizer report (parsed):\n")
        m.append("```")
        m.append(f"bug type   : {asan.bug_type}  ({asan.cwe})")
        if asan.access:
            m.append(f"access     : {asan.access} of size {asan.access_size}")
        if asan.fault_addr is not None:
            m.append(f"fault addr : {hex(asan.fault_addr)}  ({asan.addr_char})")
        m.append(f"exploitability: {asan.exploitability}")
        for fr in asan.frames[:5]:
            m.append(f"  #{asan.frames.index(fr)} {fr}")
        m.append("```\n")
    else:
        m.append(f"Exploitability bucket: **{f.exploitability}**. "
                 "Attach a controlled-RIP register snapshot from an instrumented build to "
                 "strengthen the severity argument.\n")

    m.append("## Impact\n")
    if f.kind == "divergence":
        m.append("A JIT that returns a wrong value for a deterministic Wasm program is a "
                 "correctness defect and a common precursor to type-confusion memory "
                 "corruption. Severity is stated conservatively until a memory-safety "
                 "consequence is demonstrated.\n")
    elif is_write:
        m.append("Memory corruption reachable from a crafted web page, in the renderer "
                 "process. A write primitive is a direct path to code execution in the "
                 "engine's threat model.\n")
    else:
        m.append("Memory-safety violation reachable from a crafted web page. Impact stated "
                 "per the observed fault class; escalate only with further evidence.\n")

    m.append("\n---\n*Draft generated by NEMESIS (finds + characterizes; does not weaponize). "
             "Verify every field against the live target before submitting.*\n")
    return "\n".join(m)


def _main(argv):
    from .vault import Vault, _default_root
    if not argv:
        print("usage: report_gen <crash_id> [asan_report_file]")
        return 1
    v = Vault(_default_root())
    f = v.get(argv[0])
    if not f:
        print(f"no finding {argv[0]} in vault")
        return 1
    asan = None
    if len(argv) > 1 and os.path.exists(argv[1]):
        from .asan_parser import parse_asan
        asan = parse_asan(open(argv[1]).read())
    print(render(f, asan))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
