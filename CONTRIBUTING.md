# Contributing to NEMESIS

Thanks for your interest. NEMESIS is a research tool for finding compiler miscompilations and
crashes in JS/Wasm engines, for **authorized testing and responsible disclosure**. Please
keep contributions aligned with that scope.

## Scope

**In scope:** IL/generator/mutator improvements, new bug-class strategies (trigger shapes),
new engine targets, triage/minimization/reporting quality, CVE-intel, docs, tests, CI.

**Out of scope (will not be merged):** exploit primitives (addrof/fakeobj/arbitrary R-W),
shellcode/JIT-spray encoders, sandbox-escape chains, or anything whose purpose is to
weaponize a bug rather than find/characterize it. NEMESIS finds and reports; it does not
weaponize. See [`SECURITY.md`](SECURITY.md).

## Dev workflow

```sh
make            # build the C++ core
make selftest   # sanity check (lifts sample IL, validates + executes on V8)
python3 tests/test_triage.py   # Python triage tests
```

- **Every generated module must validate** — new IL/strategy code must keep the validator
  gate green. If it emits invalid modules, it wastes the fuzzer's budget.
- **Keep it honest.** A capability that needs an instrumented engine must print an honest
  `NOT_WIRED` at runtime, never fake success. Update `docs/CAPABILITY-MATRIX.md`.
- **Deterministic RNG** — runs must be reproducible from a seed.
- Match the surrounding code's style; add a one-paragraph "why" doc comment on new modules.

## Adding a strategy

A strategy is a small generator in `core/strategies/strategies.hpp` that emits a valid module
shaped like a real bug root cause, registered in the catalogue with a `bug_class`. Verify it
validates + executes on V8 (`./build/nemesis strategies`) before submitting.

## Pull requests

- One logical change per PR. Include what you tested and the observed output.
- New behavior needs a test or a reproducible command in the PR description.
- CI (build + selftest) must pass.
