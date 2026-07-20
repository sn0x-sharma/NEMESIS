# NEMESIS — Design Spec

**Date:** 2026-07-20
**Author:** sn0x
**Status:** Approved — implementation in progress (Phase 0)

## 1. What NEMESIS is

A coverage-guided, mutation-based, **differential** fuzzer for **WebAssembly-GC / JS-JIT**
bugs, aimed at browser 0-day discovery. A coverage-guided typed-IL fuzzer
specialized for Wasm-GC / JIT-tiering bugs and
extended with capabilities that generic coverage fuzzers lack:

- differential / N-version testing (engine-vs-engine, tier-vs-tier)
- interpreter-oracle correctness diffing (reference interpreter vs JIT — finds *silent
  wrong-value* bugs, not just crashes)
- ASan-in-loop auto-triage
- CVE-root-cause pattern seeding
- REPRL-style persistent execution
- exploitability-heuristic crash classification
- local telemetry dashboard
- NEMESIS finds and triages crashes/bugs. It write
exploits or weaponize crashes. Output = minimized repro + crash classification
(controlled/uncontrolled, read/write, near-null/arbitrary) + a draft report skeleton.

## 2. Environment reality (the box this is built on)

Kali x86_64, 9 cores, 10 GB RAM (~4 GB free), **9.8 GB free disk**, no cmake/ninja/swift,
no SpiderMonkey shell, no d8. Only JS engine present: **stock Node.js v22 / V8**
(`/usr/bin/js` is Node). `WebAssembly.validate()` via Node is available and is our
on-box module validator.

**Consequence:** building an *instrumented* or *ASan* SpiderMonkey/V8 (needed for true
coverage feedback and sanitizer triage) is **not possible on this box** — it needs
~30-50 GB disk, more RAM, depot_tools/cmake/ninja, and hours. Those capabilities are
**designed-in behind clean interfaces** and light up when an instrumented engine binary
is supplied (bigger disk, or a prebuilt engine). Nothing is faked: unwired paths print
`NOT_WIRED: needs instrumented engine`.

## 3. Language & architecture

- **C++17 hot core** (`core/`) — IL, lifter, mutators, corpus, exec, diff, coverage,
  triage. Cross-platform (Linux + Windows). Fast path. Built with `clang++`/`g++` via a
  plain `Makefile` (no cmake dependency); `CMakeLists.txt` provided for MSVC/Windows.
- **Thin Python CLI** (`cli/nemesis.py`) — orchestration, subcommand dispatch, report
  glue, dashboard. Shells to the C++ binary for hot work.

## 4. Directory layout

```
nemesis/
  Makefile  CMakeLists.txt
  README.md  docs/{ARCHITECTURE,CAPABILITY-MATRIX,USAGE,TIERS}.md  docs/specs/
  core/
    common/     platform.hpp (win+linux), leb128, rng (xoshiro256**), hash, bytes
    il/         typed Wasm-GC IL: ir, builder (ProgramBuilder), program
    lifter/     IL -> valid Wasm binary; validator (node WebAssembly.validate on box)
    mutation/   input/operation/splice/combine/havoc/type mutators (validator-gated)
    corpus/     store + energy scheduler + delta-debug minimizer
    coverage/   edge bitmap + SHM protocol (interface real; engine plugs later)
    exec/       target iface + REPRL persistent pipe + v8_node (now) + sm/firefox stubs
    diff/       differential runner + tier-matrix + wasmtime/wasm3 oracle
    triage/     stack-hash dedup + exploitability classifier + asan_runner iface
    strategies/ LICM-bait, OSR, variance-violation, RTT-alias, GC-boundary, write-barrier,
                exnref/try-table, tail-call, SIMD+GC, table/call_indirect, i31/stringref
    telemetry/  stats json (coverage-over-time, throughput, per-strategy yield)
  cli/nemesis.py  cli/dashboard/
  seeds/ cve_db.json (300+) · il/*.nemil (~40 root-cause) · tools/scrape_cves.py
  targets/{spidermonkey,v8,firefox}/README.md   # instrumented+ASan build recipes
  tests/  build/
```

## 5. Capability matrix (honest)

| Capability | This box now | Needs |
|---|---|---|
| IL + lifter + validator round-trip | LIVE | — |
| Mutation engine | LIVE | — |
| Corpus + scheduler + minimizer | LIVE | — |
| Blackbox crash detection vs node/V8 | LIVE | — |
| REPRL persistent harness | LIVE | — |
| Differential interpreter-oracle | LIVE* | wasmtime/wasm3 binary (*install) |
| CVE metadata DB + IL seeds | LIVE | — |
| Telemetry + dashboard | LIVE | — |
| Coverage-guided feedback | NOT_WIRED | instrumented engine build |
| ASan-in-loop triage | NOT_WIRED | ASan engine build |
| Firefox-tab watchdog harness | NOT_WIRED | Firefox + disk |
| Snapshot / fork fuzzing | PHASE-8 | later |

## 6. Tier → module mapping

All 14 tiers from the brief map to a module and carry a status tag (`LIVE` /
`NEEDS-ENGINE` / `PHASE-N`) in `docs/TIERS.md`. Nothing is dropped; everything is
honestly statused. Highlights: Tier-1 coverage=`coverage/` (NEEDS-ENGINE),
corpus+mutation=`corpus/`+`mutation/` (LIVE), differential=`diff/` (LIVE),
grammar-aware generator=`il/`+`strategies/` (LIVE). Tier-2 ASan=`triage/asan_runner`
(NEEDS-ENGINE), dedup+minimize=`triage/`+`corpus/minimizer` (LIVE). Tiers 3/5/7
generators=`strategies/`. Tier-9/13 fault-injection + rr + redzone = documented recipes
under `targets/` + `triage/` interfaces. Tier-10 concolic + Tier-11 spec-corpus +
Tier-12 ML scheduling = later phases with interface seams reserved now.

## 7. Phases (each leaves a runnable tool + is a commit)

- **P0** — skeleton, build system, `core/common` platform layer, IL data model, lifter,
  validator round-trip test, `nemesis selftest`. Compiles on Linux; MSVC path documented.
  *Acceptance:* `make` builds; `nemesis selftest` lifts sample IL programs to `.wasm` and
  each passes `WebAssembly.validate()` via node; exit 0.
- **P1** — full ProgramBuilder + Wasm-GC IL ops (struct/array/rec-group/ref/cast) +
  mutators (input/operation/splice/combine/havoc/type) + corpus + delta-debug minimizer.
  *Acceptance:* `nemesis gen`/`nemesis mutate` produce validator-valid modules; mutation
  round-trips stay valid ≥ configured rate; unit tests green.
- **P2** — REPRL persistent harness + `v8_node` target + blackbox crash loop + stack-hash
  dedup + exploitability classifier. *Acceptance:* `nemesis fuzz --mode blackbox` runs a
  timed loop vs node, logs execs/sec, dedups crashes.
- **P3** — differential runner + `wasmtime`/`wasm3` interpreter oracle + tier-matrix
  (flag matrix over node/V8). *Acceptance:* `nemesis diff` runs same IL on interpreter +
  V8, reports divergences (trap/return/timeout), zero false-positive on known-equal set.
- **P4** — `strategies/` generators (all tier 3/5/6/7 patterns) + CVE seed corpus +
  scheduler energy seeded from CVE patterns. *Acceptance:* each strategy independently
  toggleable + coverage/yield-measured; `nemesis seeds` loads cve_db + IL seeds.
- **P5** — coverage interface + SHM protocol + edge_map (validated against a fake feeder,
  ready for a real instrumented engine) + telemetry + dashboard.
  *Acceptance:* `nemesis fuzz --mode coverage` runs against fake feeder end-to-end;
  `nemesis dashboard` serves coverage-over-time.
- **P6** — triage/report polish (`report_gen`, `asan_runner` iface, snapshot stub) +
  `targets/` instrumented/ASan build docs + cross-platform build notes.

## 8. Non-negotiable engineering constraints

- Every phase leaves `nemesis` runnable + demonstrable. No big-bang breakage.
- Every generated module passes validation before hitting any target.
- Real code only: unwired features print honest `NOT_WIRED`, never fake success.
- Each new component: a unit test + a one-paragraph doc comment on *why* it exists.
- Deterministic RNG (seedable) so any run/crash is reproducible.

## 9. Out of scope

Exploit development, weaponization, ROP/heap-spray primitives. NEMESIS stops at
minimized-repro + classification + draft report.
