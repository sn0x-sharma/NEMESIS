// run_wasm.js — NEMESIS node/V8 execution harness.
//
// WHY: The core drives this under many different V8 compiler configurations (v1..v8: the
// interpreter, Liftoff, TurboFan, Turboshaft, ...). Two jobs:
//   1. Force JIT tiering by calling the exported `run` in a hot loop, so miscompiles in the
//      optimizing tiers actually trigger.
//   2. Print a *canonical, comparable* result token so the C++ core can diff the outcome
//      across configs. Wasm is deterministic: the same module must produce the same result
//      under every tier, so any divergence in this token across configs is a real
//      JIT-correctness bug (not a crash — a *silent wrong value*, the highest-value class).
//
// Result token (last matching line of stdout is authoritative):
//   RES <value>   run() returned a value (i32 number / i64 BigInt printed in decimal)
//   RES void      run() returned nothing
//   TRAP          run() deterministically trapped (a comparable outcome, not a crash)
//   INVALID       module failed compile/link (validation gate should prevent this)
//   ERR           harness-level error (not an engine bug)
//
// Exit code contract (read by core/exec/v8_node.hpp):
//   0  produced a RES/TRAP token (see stdout for which)
//   2  INVALID module      3  file unreadable      4  unexpected harness error
//   >=128  killed by signal N (128+N): SIGSEGV/SIGABRT/... = real engine crash
'use strict';

const fs = require('fs');

// Enough to push a hot export through TurboFan/Turboshaft on V8. Minimization (which only
// preserves a value, not a tier-dependent divergence) overrides this low via env for speed.
const TIER_ITERS = parseInt(process.env.NEMESIS_TIER_ITERS, 10) || 20000;

function emit(tok) {
  // Single authoritative line; process.stdout.write avoids trailing-buffer loss on exit.
  process.stdout.write(tok + '\n');
}

async function main() {
  const modPath = process.argv[2];
  if (!modPath) { emit('ERR'); process.exit(3); }

  let bytes;
  try {
    bytes = fs.readFileSync(modPath);
  } catch (_e) {
    emit('ERR');
    process.exit(3);
  }

  let instance;
  try {
    const result = await WebAssembly.instantiate(bytes, {});
    instance = result.instance;
  } catch (e) {
    if (e instanceof WebAssembly.CompileError || e instanceof WebAssembly.LinkError) {
      emit('INVALID');
      process.exit(2);
    }
    if (e instanceof WebAssembly.RuntimeError) {
      emit('TRAP'); // start-function trap — a deterministic, comparable outcome
      process.exit(0);
    }
    emit('ERR');
    process.exit(4);
  }

  const run = instance.exports.run;
  if (typeof run !== 'function') {
    emit('RES void');
    process.exit(0);
  }

  // Warm up to force tier-up, tolerating traps (a trap is deterministic — same every call).
  let trapped = false;
  for (let i = 0; i < TIER_ITERS; i++) {
    try {
      run();
    } catch (_e) {
      trapped = true;
      break;
    }
  }
  if (trapped) {
    emit('TRAP');
    process.exit(0);
  }

  // Final hot call decides the reported value (post-optimization result).
  try {
    const v = run();
    emit(v === undefined ? 'RES void' : 'RES ' + String(v));
  } catch (_e) {
    emit('TRAP');
  }
  process.exit(0);
}

main().catch(() => { emit('ERR'); process.exit(4); });
