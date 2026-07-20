# NEMESIS

**A coverage-oriented, differential fuzzer for WebAssembly-GC / JavaScript-JIT compilers.**
It generates typed Wasm-GC modules, runs them across multiple V8 JIT tiers, and flags any
module that produces a *different result under different compilers* — a JIT miscompilation.

> **Scope — read this first.** NEMESIS **finds, minimizes, and reports** compiler
> miscompilations and crashes. It is a research / bug-hunting tool for **authorized testing
> and responsible disclosure only**. It is **explicitly not an exploit framework**: it does
> not build exploit primitives, shellcode, or sandbox escapes, and it does not weaponize the
> bugs it finds. Output is a minimized repro + an honest severity assessment + a report draft.

## What it does (today)

- **Typed Wasm-GC IL** — structs, arrays, i31, references, rec-groups, subtyping, control
  flow, `call_indirect`/tables, tail-calls. Mutation happens on the typed IL, so generated
  modules stay valid instead of being random bytes.
- **Type-aware generator + mutators** — ~100% validator-valid modules.
- **8-config V8 differential oracle** — the same module is run under 8 V8 Wasm compiler
  configurations (Liftoff baseline → TurboFan → Turboshaft → tier-up → …). Wasm is
  deterministic, so if two tiers disagree on the result, that is a real miscompilation.
- **13 bug-class strategies** — hand-written trigger shapes for type-confusion, OOB,
  UAF-boundary, LICM bounds-check elision, OSR, GC write-barrier, `call_indirect`, tail-call,
  shape-mutation, and deopt classes.
- **CVE-biased directed hunt** — weights strategy selection by real-world CVE class frequency
  (from a 486-entry CVE database + NVD scraper).
- **Delta-debug minimizer**, blackbox crash detection, stack-hash dedup, an exploitability
  classifier, an ASan-output parser, an evidence vault, a scope-gate, a repro/report/CVSS
  pack generator, and a telemetry dashboard.

## What it does **not** do (yet) — kept honest

- **Only V8 is wired as a target today** (via a `node` shell). SpiderMonkey (Firefox) and
  JavaScriptCore (Safari) targets are designed-for but not yet implemented — see
  `targets/`.
- **No coverage-guided feedback** and **no ASan-in-loop triage** on a stock engine — both
  need an instrumented engine build. The interfaces exist and light up when you supply one.
  See [`docs/CAPABILITY-MATRIX.md`](docs/CAPABILITY-MATRIX.md) for the exact per-feature
  status — nothing is oversold; unimplemented paths say so at runtime.
- It is Wasm-GC/JIT focused. It does not fuzz the DOM, JS built-ins, or the browser UI.

## Install & build

Requirements: a C++17 compiler (`g++` or `clang++`), `make`, and **Node.js** (provides the
V8 target). No cmake/ninja needed.

```sh
git clone https://github.com/<you>/nemesis
cd nemesis
make                 # builds build/nemesis (the C++ core)
make selftest        # lifts sample IL -> wasm -> validates + executes on V8
```

## Quickstart: gen → diff → strategies → minimize → report

```sh
# 1. generate valid Wasm-GC modules and validate them on V8
$ ./build/nemesis gen 20 42
generated 20 modules (seed=42) -> build/gen/
V8 valid: 20/20

# 2. differential fuzz: run mutated modules across all 8 V8 tiers, flag disagreements
$ ./build/nemesis diff 200 7
summary: modules=200 configs=8 divergences=0 crashes=0
# 0 divergences on a *patched* V8 is expected and correct (the oracle is sound).

# 3. run the CVE-shaped bug strategies through the oracle
$ ./build/nemesis strategies
  jit_tierup_stress      CVE-2026-10702  valid=yes  agree(8 cfg): RES 216474736
  subtype_cast_matrix    CVE-2024-2887   valid=yes  agree(8 cfg): RES 60000
  ...

# 4. minimize a module to a minimal repro (sound; audit-gated)
$ ./build/nemesis minimize 7 subtype_cast_matrix
minimize subtype_cast_matrix (agree)
  22 -> 22 instrs,  111 -> 111 bytes,  29 oracle probes,  audit=PASS

# 5. package a confirmed finding -> repro.html + report.md + CVSS + CVE match
$ ./build/nemesis report path/to/module.wasm
finding pack -> build/findings/<id>/
```

Python-side workflow helpers (triage, CVE intel, dashboard):

```sh
python3 cli/nemesis.py cve trend          # CVE database distribution
python3 cli/nemesis.py cve patchgap       # cross-engine variant-hunting candidates
python3 cli/nemesis.py dashboard serve     # local telemetry dashboard
python3 cli/nemesis.py scope add example.com   # authorization scope gate
```

See [`docs/USAGE.md`](docs/USAGE.md) for the full command reference and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the pieces fit.

## Finding real bugs

On a **patched** engine the oracle correctly reports 0 divergences (verified: 0 false
positives across thousands of modules). To hunt live bugs, point the config binaries at an
**older / nightly / unpatched** V8 build (each config's binary is overridable), or supply an
instrumented (ASan / coverage) build to unlock the deeper triage paths.

## Responsible use

Only run NEMESIS against engines and targets you are **authorized** to test. Use the scope
gate. Report what you find through the vendor's security / bug-bounty process. See
[`SECURITY.md`](SECURITY.md). NEMESIS deliberately stops at *finding and characterizing*
bugs — turning a bug into an exploit is out of scope for this project.

## Prior art

NEMESIS builds on well-established ideas from the coverage-guided and structure-aware fuzzing
literature — mutating a **typed intermediate language** rather than raw bytes, an incremental
program builder, differential / N-version testing, and persistent-execution harnessing.

## License

[MIT](LICENSE) © 2026 sn0x. Contributions welcome — see
[`CONTRIBUTING.md`](CONTRIBUTING.md).
