#!/usr/bin/env python3
"""NEMESIS command-line entrypoint (thin orchestration layer).

WHY: The hot work (IL, lifting, mutation, execution, differential) lives in the C++ core for
speed and portability; this Python layer builds the binary on demand, forwards the native
subcommands, and hosts the triage/reporting/safety helpers that are naturally Python (JSON
ledgers, text parsing, scope checks). Capabilities not yet wired print an honest status.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "build", "nemesis")

# Subcommands implemented natively in the C++ core (forwarded as-is).
NATIVE = {"selftest", "version", "gen", "mutate", "fuzz", "configs", "diff",
          "strategies", "minimize", "report", "help"}

# Capabilities still to be wired; honest status instead of fake success.
NOT_WIRED = {
    "coverage": "NEEDS-ENGINE: edge-coverage feedback needs an instrumented engine build",
}


def have(tool):
    from shutil import which
    return which(tool) is not None


def build(force=False):
    if os.path.exists(BIN) and not force:
        return True
    if have("make"):
        return subprocess.call(["make", "-C", ROOT]) == 0
    cxx = os.environ.get("CXX", "clang++" if have("clang++") else "g++")
    os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
    srcs = [os.path.join(ROOT, "core", "main.cpp"), os.path.join(ROOT, "core", "lifter", "lifter.cpp")]
    cmd = [cxx, "-std=c++17", "-O2", "-Wall", "-Wextra", "-I" + os.path.join(ROOT, "core")] + srcs + ["-o", BIN]
    print("[build]", " ".join(cmd))
    return subprocess.call(cmd) == 0


def run_bin(args):
    if not build():
        print("build failed", file=sys.stderr)
        return 2
    return subprocess.call([BIN] + args)


USAGE = """nemesis — coverage-guided differential Wasm-GC/JS-JIT fuzzer

native (C++ core):
  build                      compile the native core
  selftest                   IL -> lifter -> validator -> execute chain check
  gen [N] [seed]             generate N random Wasm-GC modules, validate on V8
  mutate [N] [seed]          mutate a base program, validate on V8
  fuzz [N] [seed] [t]        blackbox mutate+execute loop, save/dedup crashes
  configs                    list the 8 V8 JIT configs (v1..v8) and live status
  diff [N] [seed] [t]        differential across V8 configs; flag miscompiles
  strategies [seed] [t]      run each CVE-shaped strategy through the oracle
  report <module.wasm> [strategy] [cve]   package a finding pack

triage / reporting / safety (python):
  scope <add|check|list> [target]         authorization scope gate
  vault <list|show|ingest|status> ...     evidence vault / findings ledger
  asan <file>                             parse ASan output -> structured finding
  report-gen <crash_id> [asan_file]       finding -> HackerOne markdown draft
  cve <match|variant|patchgap|trend> ...  CVE pattern intelligence over cve_db.json
  dashboard [serve [port]]                render/serve the telemetry dashboard
"""


def main(argv):
    if not argv or argv[0] in ("help", "-h", "--help"):
        print(USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]

    if cmd == "build":
        return 0 if build(force=True) else 2
    if cmd in NATIVE:
        return run_bin([cmd] + rest)

    # Python triage/safety modules.
    if cmd == "scope":
        from cli.execution.scope import _main as m
        return m(rest)
    if cmd == "vault":
        from cli.triage.vault import _main as m
        return m(rest)
    if cmd == "asan":
        from cli.triage.asan_parser import _main as m
        return m(rest)
    if cmd == "report-gen":
        from cli.triage.report_gen import _main as m
        return m(rest)
    if cmd == "cve":
        from cli.triage.cve_intel import _main as m
        return m(rest)
    if cmd == "dashboard":
        from cli.dashboard import _main as m
        return m(rest)

    if cmd in NOT_WIRED:
        print(f"[NOT_WIRED] {cmd}: {NOT_WIRED[cmd]}")
        return 0
    print(f"unknown command: {cmd}\n")
    print(USAGE)
    return 1


if __name__ == "__main__":
    sys.path.insert(0, ROOT)
    sys.exit(main(sys.argv[1:]))
