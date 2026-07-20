# Examples

Small, labeled **sample output modules** — not build artifacts, not fuzzing finds. They exist
so you can see what a NEMESIS-produced Wasm-GC module looks like and confirm your build agrees
with the reference results below.

| file | what it is | exported `run()` result |
|---|---|---|
| `const42.wasm` | minimal module: `() -> i32 { i32.const 42 }` | `42` |
| `loop.wasm` | hot counting loop summing `0..9` | `45` |

Both are tiny (36 / 60 bytes) and **deterministic**, so every V8 tier must return the same
value. Verify against your build:

```sh
# validate + run under the node/V8 harness
node harness/run_wasm.js examples/const42.wasm      # -> RES 42
node harness/run_wasm.js examples/loop.wasm         # -> RES 45
```

If any tier returned something other than `RES 42` / `RES 45`, that would be a divergence —
i.e. a miscompilation. (On a correct engine, they agree — these samples are here to show the
"agree" baseline, not a bug.)

To generate your own modules: `./build/nemesis gen 10 <seed>` writes to `build/gen/`.
