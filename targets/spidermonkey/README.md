# SpiderMonkey (Firefox) target

> **Status: not yet wired.** The SpiderMonkey execution target is on the roadmap but not
> implemented in the current release — NEMESIS's only wired target today is V8 (see
> `../v8/`). This document records how to obtain a SpiderMonkey shell so the target can be
> added, and so you're ready when it lands.

## Get a SpiderMonkey `js` shell (no full Firefox build needed)

Mozilla publishes a **prebuilt JS shell** for every Firefox build:

```sh
# nightly jsshell (Linux x86_64) — pick the channel/date you want:
#   https://ftp.mozilla.org/pub/firefox/nightly/latest-mozilla-central/
# look for: jsshell-linux-x86_64.zip
curl -LO https://ftp.mozilla.org/pub/firefox/nightly/latest-mozilla-central/jsshell-linux-x86_64.zip
unzip jsshell-linux-x86_64.zip -d ./sm
./sm/js --version         # confirm it's SpiderMonkey (has gczeal, wasmCompileMode, etc.)
```

The binary and archive placed here are git-ignored.

## Compiler configs (for the differential oracle, once the target is wired)

SpiderMonkey selects its Wasm compiler via `--wasm-compiler=`:

| config | flag | tier |
|---|---|---|
| sm-baseline | `--wasm-compiler=baseline` | RabaldrMonkey (baseline) |
| sm-optimizing | `--wasm-compiler=optimizing` | IonMonkey (optimizing) |
| sm-tierup | `--wasm-compiler=baseline+optimizing` | baseline → Ion tier-up |

The oracle would then flag `baseline` vs `Ion` disagreement (a SpiderMonkey miscompilation) —
and, with both V8 and SpiderMonkey present, **cross-engine** disagreement (a bug in whichever
one differs from the spec).

## Deeper yield

For crash triage, build/download an **ASan** jsshell (`--enable-address-sanitizer`); for
coverage-guided mode, a `sancov`-instrumented build. Both are larger and are the
"needs-instrumented-engine" tier in `docs/CAPABILITY-MATRIX.md`.
