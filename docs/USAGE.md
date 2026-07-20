# Usage

## Build

```sh
make            # -> build/nemesis   (g++ or clang++; no cmake needed)
make selftest   # build + lift sample IL -> wasm -> validate + execute on V8
make clean
```

No `make`? The Python CLI compiles the core on demand:

```sh
python3 cli/nemesis.py build
```

Node.js must be on `PATH` — it provides the V8 target used by everything below.

## Native commands (`build/nemesis <cmd>` or `python3 cli/nemesis.py <cmd>`)

| Command | What it does |
|---|---|
| `selftest` | Lift sample IL programs, validate + execute on V8 (chain sanity check) |
| `gen [N] [seed]` | Generate `N` random Wasm-GC modules, batch-validate on V8 |
| `mutate [N] [seed]` | Mutate a base program `N` times, report valid-mutant rate |
| `configs` | List the 8 V8 JIT configs (v1-liftoff … v8-ts-tierup) and which are runnable |
| `diff [N] [seed] [timeout]` | Differential fuzz: run `N` mutated modules across all V8 tiers; flag result divergences (miscompilations) + crashes |
| `strategies [seed] [timeout]` | Run each of the 13 CVE-shaped bug strategies through the oracle |
| `hunt [N] [seed] [timeout]` | CVE-biased directed campaign: pick a strategy weighted by CVE class frequency, mutate, run across tiers |
| `minimize [seed] [strategy] [timeout]` | Delta-debug a module to the minimal one preserving its cross-tier behavior (audit-gated) |
| `report <module.wasm> [strategy] [cve]` | Package a finding: `repro.html` + `report.md` + CVSS + CVE match under `build/findings/<id>/` |
| `version` / `help` | Version / help |

## Workflow commands (`python3 cli/nemesis.py <cmd>`)

| Command | What it does |
|---|---|
| `scope <add\|check\|list> [target]` | Authorization scope gate — refuse out-of-scope targets |
| `vault <list\|show\|ingest\|status> …` | Evidence vault / findings ledger (dedup by crash id) |
| `asan <file>` | Parse ASan output → structured finding (bug class, CWE, exploitability, stack-hash) |
| `report-gen <crash_id> [asan_file]` | Vault finding → HackerOne-ready markdown (honest severity) |
| `cve <match\|variant\|patchgap\|trend\|weights> …` | CVE-pattern intelligence over `seeds/cve_db.json` |
| `dashboard [serve [port]]` | Render / serve the local telemetry dashboard |

Anything not yet implemented prints an honest `NOT_WIRED` line — it never fakes a result.
Coverage-guided feedback and ASan-in-loop need an instrumented engine build (see
[CAPABILITY-MATRIX.md](CAPABILITY-MATRIX.md)).

## Typical session

```sh
make selftest                       # sanity
./build/nemesis strategies          # run the 13 bug-class triggers through the oracle
./build/nemesis hunt 200 1          # CVE-weighted directed differential campaign
./build/nemesis diff 500 1          # broad differential fuzz across the 8 V8 tiers
# on a divergence/crash, NEMESIS writes build/findings/<id>/ (repro.html + report.md + CVSS)
./build/nemesis minimize 1 subtype_cast_matrix   # shrink a repro

# workflow
python3 cli/nemesis.py cve trend
python3 cli/nemesis.py cve weights          # emit CVE class weights for `hunt`
python3 cli/nemesis.py dashboard serve       # http://127.0.0.1:8777
python3 cli/nemesis.py scope add example.com # authorization gate
```

## Hunting real bugs

On a **patched** engine the oracle correctly reports 0 divergences (it is sound — 0 false
positives). To find live bugs, override a config's binary to point at an **older / nightly /
unpatched** V8, or supply an instrumented (ASan / coverage) build to unlock deeper triage.
Each config's binary is set in `default_v8_configs()` in `core/exec/v8_node.hpp`.

## Reproducibility

Every run is driven by a seedable xoshiro256** PRNG. The same `seed` replays a run
bit-for-bit, so any finding is deterministically reproducible.
