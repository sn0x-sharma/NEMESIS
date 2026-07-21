<img width="1983" height="793" alt="image" src="https://github.com/user-attachments/assets/086603d0-e4c6-4684-9e09-43b3c0be65bc" />

---

<div align="center">

<img src="https://img.shields.io/badge/CVE%20DATABASE-500%2B%20ENTRIES-red?style=for-the-badge&labelColor=0d0d0d"/>
&nbsp;
<img src="https://img.shields.io/badge/STRATEGIES-100%2B%20SHAPES-orange?style=for-the-badge&labelColor=0d0d0d"/>
&nbsp;
<img src="https://img.shields.io/badge/V8%20JIT%20TIERS-8%20CONFIGS-blue?style=for-the-badge&labelColor=0d0d0d"/>
&nbsp;
<img src="https://img.shields.io/badge/FALSE%20POSITIVES-0-brightgreen?style=for-the-badge&labelColor=0d0d0d"/>

<img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white&labelColor=0d0d0d"/>
&nbsp;
<img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white&labelColor=0d0d0d"/>
&nbsp;
<img src="https://img.shields.io/badge/JavaScript-ES2024-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black&labelColor=0d0d0d"/>
&nbsp;
<img src="https://img.shields.io/badge/License-MIT-9B59B6?style=for-the-badge&labelColor=0d0d0d"/>

</div>


> **A coverage-oriented differential fuzzer for WebAssembly-GC / JavaScript-JIT compilers.**
> Generates typed Wasm-GC modules, runs them across 8 V8 JIT tiers, and flags any result
> disagreement as a **real miscompilation** then minimizes it to a clean repro and drafts
> the report. Finds silent wrong-output bugs **with no crash required** invisible to
> traditional crash-only fuzzers.

<br/>

| 🧠 Typed Wasm-GC IL | ⚡ 8-Config Differential Oracle | 🎯 100+ CVE-Shaped Strategies |
|:---:|:---:|:---:|
| Structs · Arrays · i31 · Refs · Rec-groups · Subtyping · Tail-calls | Liftoff → TurboFan → Turboshaft → Tier-up combos. Wasm is deterministic — divergence = real bug | Type-confusion · OOB · UAF · LICM · OSR · GC-barrier · Deopt · call_indirect + more |

| 🗄️ 500+ CVE Intelligence DB | 🔬 Full Triage Pipeline | 📋 Auto Report Generator |
|:---:|:---:|:---:|
| NVD-sourced, Wasm/JIT focused. CVE-weighted strategy selection hunts where bugs actually live | Stack-hash dedup · Delta-debug minimizer · Exploitability classifier · ASan parser | HackerOne / Bugzilla markdown · CVSS score · repro.html · minimized PoC submission-ready |

<br/>

<br/>

⚠️ **Authorized research & responsible disclosure only.**

</div>

---


## What NEMESIS Can Do Right Now

> Accuracy guarantee: differential oracle verified 0 false positives across
> thousands of modules. When it flags — it's real.

### Core Engine
| Capability | Status | Detail |
|------------|--------|--------|
| Typed Wasm-GC IL | ✅ Live | Structs, arrays, i31, refs, rec-groups, subtyping, control flow, call_indirect, tail-calls — full GC type system |
| Type-aware generator | ✅ Live | ~100% validator-valid output — mutations happen on typed IL, not raw bytes |
| IL → Wasm lifter | ✅ Live | Typed IL compiles to spec-valid binary, validator-gated before any engine sees it |
| Weighted mutator suite | ✅ Live | InputMutator, OperationMutator, SpliceMutator, CombineMutator, HavocMutator — all type-system aware |

### Differential Oracle (the sharp edge)
| Capability | Status | Detail |
|------------|--------|--------|
| 8-config V8 differential | Live | Liftoff → TurboFan → Turboshaft → tier-up combos — same module, 8 compilers, any disagreement = real miscompilation |
| Sound oracle | ✅ Verified | 0 false positives across thousands of modules — Wasm determinism guarantees: divergence = bug |
| Silent miscompilation detection | Live | Finds wrong-result bugs with **no crash** — invisible to traditional crash-only fuzzers |
| Crash detection | Live | SIGSEGV / SIGABRT / timeout — all signal classes covered |

### Bug-Class Strategies (13 CVE-shaped triggers)
| Strategy | CVE Class Targeted |
|----------|--------------------|
| `type_confusion` | V8 map confusion, cast failure |
| `array_oob_loop` | JIT bounds-check elision → OOB read/write |
| `licm_bounds_elision` | Loop-invariant code motion hoisting → OOB |
| `osr_type_mismatch` | On-stack-replacement stale type assumption |
| `shape_mutation_during_opt` | Mid-loop object shape change → type confusion |
| `gc_barrier_elision` | Write-barrier skip → cross-generational pointer corruption |
| `jit_tierup_stress` | Baseline→optimizing transition edge cases |
| `deopt_bomb` | Forced deoptimization → bailout stack corruption |
| `call_indirect_confusion` | Wasm table type confusion via indirect call |
| `tail_call_stress` | Tail-call return stack layout corruption |
| `recgroup_subtype_bomb` | Deep rec-group / mutual subtype chain explosion |
| `subtype_cast_matrix` | Ref.cast across complex subtype lattice |
| `nullability_canon` | Nullable/non-nullable ref confusion at cast boundary |

### CVE Intelligence
| Capability | Status | Detail |
|------------|--------|--------|
| 486-entry CVE database | Live | Scraped + structured from NVD, Wasm/JIT focused |
| CVE-frequency weighted hunting | Live | Strategy selection weighted by real-world bug-class distribution |
| `cve match` | Live | Match a crash/divergence against known CVE patterns |
| `cve variant` | Live | Find cross-engine variant candidates for a known CVE |
| `cve patchgap` | Live | Identify classes patched in one engine but not others |
| `cve trend` | Live | Bug-class frequency over time — where to aim next |

### Triage + Reporting Pipeline
| Capability | Status | Detail |
|------------|--------|--------|
| Stack-hash dedup | Live | Same bug, multiple seeds → deduplicated automatically |
| Delta-debug minimizer | Live | Crashing/diverging module reduced to minimal repro, instruction by instruction |
| Exploitability classifier | Live | Read vs write fault, near-null vs controlled address, entropy across runs → severity bucket |
| ASan output parser | Live | Sanitizer report → bug class + CWE + exploitability label (needs ASan build to activate) |
| Scope gate | Live | Authorization check before any campaign — prevents accidental out-of-scope testing |
| Evidence vault | Live | All findings logged, timestamped, searchable |
| Auto report generator | Live | HackerOne / Bugzilla markdown draft + CVSS score + repro.html + minimized PoC |

### Ops
| Command | What it does |
|---------|-------------|
| `gen` | Generate N valid Wasm-GC modules |
| `diff` | Run N modules across all 8 V8 tiers, report divergences |
| `strategies` | Run all 13 CVE-shaped triggers through the oracle |
| `hunt` | Continuous CVE-weighted directed campaign (mutate → diff loop) |
| `fuzz` | Blackbox crash-detection fuzzing loop |
| `minimize` | Delta-debug a module to minimal repro |
| `report` | Package finding → repro + report + CVSS |
| `asan` | Parse ASan output → classify bug |
| `vault` | Browse/search findings ledger |
| `report-gen` | HackerOne markdown draft from a vault entry |
| `cve` | CVE intelligence (match/variant/patchgap/trend) |
| `scope` | Manage authorization scope |
| `configs` | List all 8 V8 JIT tier configurations |
| `dashboard` | Local telemetry web dashboard |
| `selftest` | Verify full pipeline is healthy |

## Upcoming / Roadmap

### New Fuzzing Strategies (in development)
| # | Strategy | Description |
|---|----------|-------------|
| 1 | Multi-Stage Interleaving | Setup → GC → object access → type mutation in one seed |
| 2 | JIT + GC + Worker Triangulation | 3-way race: JIT compile + GC + Worker on same object |
| 3 | Cross-Realm Confusion | iframe parent+child realm type-check confusion |
| 4 | Prototype Chain Poisoning | Array.prototype / Object.prototype corruption |
| 5 | Promise Flood | Thousands of pending Promises resolved simultaneously → microtask overflow |
| 6 | Shape Mutation During Optimization | Mid-loop shape change → JIT type confusion |
| 7 | Deoptimization Bomb | Force JIT bailout at critical moment → stack state corruption |
| 8 | IC Unstable State | Megamorphic call site → inline cache confusion → wrong dispatch |
| 9 | Species Chain Explosion | Array[Symbol.species] patch → type confusion in built-ins |
| 10 | Detached Buffer Access | transferArrayBuffer → detach → continue access → OOB/UAF |
| 11 | SAB + Atomics + Worker Race | SharedArrayBuffer + Atomics cross-thread data race |
| 12 | Wasm Table Overflow | Grow table to max → call_indirect at boundary → type confusion |
| 13 | Recursive Type Bomb | Deeply recursive Wasm-GC type defs → type checker infinite recursion |
| 14 | CSS + DOM + JS Triple Interaction | CSS reflow + DOM + JS concurrent → layout engine UAF |
| 15 | Cross-Origin Window Confusion | Cross-origin closure variable access boundary confusion |
| 16 | JIT spray shellcode auto-encode | Shellcode → float constants → JIT compiled RWX memory → execute |
| 17 | addrof/fakeobj auto primitive build | 

### Planned Engine Targets
- SpiderMonkey (Firefox) harness designed, pending jsshell integration
- JavaScriptCore (Safari/WebKit) planned
- wasmtime (reference interpreter oracle) planned

### Infrastructure
- Coverage-guided feedback loop (needs instrumented engine build)
- ASan-in-loop automated triage
- Web dashboard alert system
- Multi-process parallel corpus sync

## Install & build

Requirements: a C++17 compiler (`g++` or `clang++`), `make`, and **Node.js** (provides the
V8 target). No cmake/ninja needed.

```sh
git clone https://github.com/sn0x-sharma/nemesis
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

## Kind of Bugs I Found Using This Tool

I have intentionally removed many of this tool's features. At the moment, this repository represents only about **20–30%** of its actual capabilities.
The more advanced functionality has **not** been included because it is capable of discovering highly critical vulnerabilities, and I am not comfortable making those techniques public at this time.
The examples below represent the kinds of bugs I found when using the **full internal version** of this tool. One example is demonstrated in the video below.
<img width="800" height="450" alt="VIDEO-RCE-ezgif com-video-to-gif-converter" src="https://github.com/user-attachments/assets/a124cc53-e1b8-42e8-8acb-5cd505e7077b" />


I plan to release additional features in future updates once they can be shared responsibly.


## Responsible use

Only run NEMESIS against engines and targets you are **authorized** to test. Use the scope
gate. Report what you find through the vendor's security / bug-bounty process. See
[`SECURITY.md`](SECURITY.md). NEMESIS deliberately stops at *finding and characterizing*

## Prior art

NEMESIS builds on well-established ideas from the coverage-guided and structure-aware fuzzing
literature mutating a **typed intermediate language** rather than raw bytes, an incremental
program builder, differential / N-version testing, and persistent-execution harnessing.

## License

[MIT](LICENSE) © 2026 sn0x. Contributions welcome see
[`CONTRIBUTING.md`](CONTRIBUTING.md).
