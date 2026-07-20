# Capability Matrix

Honest status of every NEMESIS capability on **this** machine (Kali x86_64, ~9.8 GB free
disk, 10 GB RAM, stock Node/V8, no SpiderMonkey/d8, no cmake/ninja/swift). Nothing is
faked: a capability marked `NOT_WIRED` prints that at runtime rather than pretending.

Legend: **LIVE** runs now · **LIVE\*** runs now if you install the named tool ·
**NOT_WIRED** interface exists, needs an engine build this box can't produce ·
**PHASE-N** scheduled for a later phase.

| Capability | Status | Blocker / note |
|---|---|---|
| Typed IL + Wasm lifter | LIVE | — |
| Module validation gate | LIVE | via node `WebAssembly.validate` (V8) |
| Sample selftest (IL→wasm→validate→execute) | LIVE | — |
| ProgramBuilder generator | LIVE | type-aware, ~100% valid on V8 |
| Mutation engine (op/local/const retype + havoc + splice) | LIVE | weighted, validity-biased |
| Blackbox crash detection (signal/exit/timeout) | LIVE | one-shot node target; `fuzz` cmd |
| Stack-hash crash dedup + exploitability classifier | LIVE | `triage/triage.hpp` |
| **Differential oracle across V8 configs (v1..v8)** | **LIVE** | 8 JIT tiers on one V8; `diff`/`configs` |
| **Tier matrix (V8 flag matrix)** | **LIVE** | Liftoff/TurboFan/Turboshaft/tier-up/unroll |
| Cross-*version* differential (v1..v8 = 8 releases) | LIVE\* | override each slot's binary path |
| Corpus store + energy scheduler | PHASE-4 | guided growth needs coverage |
| Delta-debug minimizer | PHASE-4 | — |
| Adversarial strategies (LICM-bait, OSR, RTT-alias, GC-boundary) | PHASE-4 | induce real tier divergence |
| REPRL persistent harness | PHASE-5 | ~1000x throughput; needs instrumented engine |
| Interpreter oracle (wasmtime/wasm3) | PHASE-5, LIVE\* | 3rd-party ground truth vs V8 |
| Adversarial strategies (LICM-bait, OSR, variance, RTT, GC-boundary, …) | PHASE-4 | — |
| CVE metadata DB (300+) + IL seeds (~40) | PHASE-4 | — |
| **Coverage-guided feedback** | **NOT_WIRED** | instrumented engine build (~30-50 GB disk, cmake/ninja) |
| **ASan/MSan/UBSan-in-loop triage** | **NOT_WIRED** | sanitizer engine build |
| Firefox-tab watchdog harness | NOT_WIRED | Firefox install + disk |
| SpiderMonkey / d8 targets | NOT_WIRED | engine binaries not on box |
| Telemetry + local dashboard | PHASE-5 | — |
| Draft report generator | PHASE-6 | — |
| Snapshot / fork-server execution | PHASE-8 | — |
| Concolic branch-flip, taint tracking, ML bucket classifier | PHASE-8+ | interface seams reserved |

## How to unblock the NOT_WIRED items

- **Coverage / ASan:** build an instrumented SpiderMonkey or V8 (recipes in
  `targets/spidermonkey/` and `targets/v8/`). Needs a machine with ~50 GB free disk,
  8 GB+ RAM, cmake/ninja (V8: depot_tools/gn). Point NEMESIS at the resulting binary; the
  `coverage/` SHM protocol and `triage/asan_runner` light up automatically.
- **Differential oracle (cheap, high value):** `apt install wasmtime` or drop a `wasm3`
  binary on PATH. No engine build required — this is the best bug-per-effort path on
  constrained hardware.
