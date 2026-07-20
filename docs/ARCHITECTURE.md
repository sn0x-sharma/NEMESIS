# Architecture

```
                    ┌───────────────────────── cli/nemesis.py ─────────────────────────┐
                    │  subcommand dispatch · build-on-demand · honest NOT_WIRED status   │
                    └───────────────────────────────┬───────────────────────────────────┘
                                                     │ shells to
                                                     ▼
   seeds/cve_db.json ──► ┌────────────────── core/ (C++17 hot core) ──────────────────┐
   seeds/il/*.nemil      │                                                              │
                         │   il/  ──►  lifter/  ──►  [Wasm binary]  ──►  validator      │
                         │    ▲            (IL -> bytes)                (node/V8 gate)   │
                         │    │                                                         │
                         │  mutation/  ◄── corpus/ (store+scheduler+minimizer)          │
                         │    │                                                         │
                         │  strategies/ (LICM/OSR/variance/RTT/GC-boundary/exnref/...)  │
                         │                                                              │
                         │   exec/ (REPRL) ──► targets: v8_node | spidermonkey | firefox│
                         │      │                                                       │
                         │   coverage/ (edge bitmap + SHM) ◄── instrumented engine      │
                         │      │                                                       │
                         │   diff/ (interpreter oracle + tier matrix)                   │
                         │      │                                                       │
                         │   triage/ (dedup · classifier · asan_runner) ──► report      │
                         │   telemetry/ (coverage-over-time · throughput · yield)       │
                         └──────────────────────────────────────────────────────────────┘
```

## Data flow (one fuzzing iteration, target end state)

1. **Scheduler** (`corpus/`) picks a seed by energy score.
2. **Mutation** (`mutation/`) or a **strategy** (`strategies/`) transforms its typed IL.
3. **Validator** (`lifter/validator`) rejects anything invalid before it wastes a run.
4. **Lifter** (`lifter/`) encodes the IL to a Wasm binary.
5. **Exec** (`exec/` REPRL) runs it on the target engine without a process restart.
6. **Coverage** (`coverage/`) diffs the edge bitmap; novel edges → keep the seed.
7. **Diff** (`diff/`) cross-checks the result against a reference interpreter and other
   engines/tiers — catches *silent wrong-value* bugs, not just crashes.
8. **Triage** (`triage/`) dedups by stack hash, classifies exploitability, re-runs under
   ASan, and emits a draft report.

## Key design decisions

- **Typed IL, never raw bytes** — the prerequisite for safe structural mutation
  (the core typed-IL insight). See `core/il/ir.hpp`.
- **One encoder** — only the lifter knows the Wasm binary format; encoding bugs are found
  once, not per-probe.
- **Validation gate everywhere** — invalid modules never reach a target.
- **Honest capability boundaries** — features needing an instrumented engine expose a real
  interface and refuse loudly (`NOT_WIRED`) rather than faking success.
- **Deterministic PRNG** — seedable xoshiro256\*\* so every crash replays exactly.
- **Thin Python / fat C++** — orchestration in Python; the hot loop in portable C++17.
