# NEMESIS — Feature Completeness Contract (Tiers 0–11)

Every one of the 250 requested features maps to a module + an honest status. Nothing is
dropped. If it says LIVE it runs today; if NEEDS-ENGINE it needs an instrumented engine this
box can't build; if OUT-OF-CHARTER it is exploit synthesis that NEMESIS delegates to the
researcher's manual work (see the note under Tier 4).

**Status legend**

| Tag | Meaning |
|---|---|
| ✅ LIVE | Built, runs now on stock Node/V8 |
| 🔶 PARTIAL | Core built; listed extension pending |
| 📋 P-NEXT | Planned; interface/seam reserved |
| 🔒 NEEDS-ENGINE | Needs instrumented/ASan engine or real browser (this box lacks disk/RAM/toolchain) |
| ⚠️ OUT-OF-CHARTER | Exploit/shellcode/sandbox-escape *synthesis* — see Tier 4 note |

Box: Kali x86_64, ~9.8 GB disk, 10 GB RAM, stock Node v22/V8 only, no cmake/ninja/swift, no
SpiderMonkey/d8, no ASan build. That boundary — not ambition — forces the NEEDS-ENGINE tags.

---

## Tier 0 — Core fuzzing engine

| # | Feature | Module | Status |
|---|---|---|---|
| 1 | Coverage-guided (edge bitmap, SanitizerCoverage) | `coverage/` | 🔒 NEEDS-ENGINE |
| 2 | REPRL persistent harness | `exec/reprl.hpp` | 🔒 NEEDS-ENGINE (iface LIVE) |
| 3 | Multi-process swarm | `cli/` | 📋 P-NEXT |
| 4 | Distributed corpus sync | `corpus/` | 📋 P-NEXT |
| 5 | Value-profile coverage | `coverage/` | 🔒 NEEDS-ENGINE |
| 6 | Hit-count bucketing | `coverage/` | 🔒 NEEDS-ENGINE |
| 7 | Caller-callee context coverage | `coverage/` | 🔒 NEEDS-ENGINE |
| 8 | Per-tier coverage | `coverage/` + configs | 🔒 NEEDS-ENGINE |
| 9 | Energy-based seed scheduling | `corpus/` | 📋 P-NEXT |
| 10 | Corpus plateau detection | `corpus/` | 📋 P-NEXT |
| 11 | Per-generator coverage stats | `telemetry/` | 🔒 NEEDS-ENGINE |
| 12 | Per-mutator coverage stats | `telemetry/` | 🔒 NEEDS-ENGINE |
| 13 | Sanitizer pipeline (ASan/UBSan) | `triage/asan_runner` | 🔒 NEEDS-ENGINE |
| 14 | Crash dedup (stack-hash) | `triage/triage.hpp` | ✅ LIVE |
| 15 | Bug-type classifier | `triage/triage.hpp` | 🔶 PARTIAL (heuristic LIVE; UAF/DF need ASan) |

Items 1,5–8,11–13 need `-fsanitize-coverage`/ASan compiled into the engine; stock Node/V8
doesn't expose it. The `coverage/` SHM interface lights up when a supplied instrumented
`d8`/`js` is pointed at it — no loop changes.

## Tier 1 — Code generators (bug-class targeted)

| # | Feature | Module | Status |
|---|---|---|---|
| 16 | Type-confusion generator | `strategies/` subtype_cast_matrix | ✅ LIVE |
| 17 | Use-after-free generator | `strategies/` gc_boundary_uaf | 🔶 PARTIAL (shape LIVE; UAF signal needs ASan) |
| 18 | Out-of-bounds generator | `strategies/` array_oob_loop | ✅ LIVE |
| 19 | JIT-stress generator | `strategies/` jit_tierup_stress | ✅ LIVE |
| 20 | WASM-GC type-system generator | `il/generator.hpp` + `strategies/` | ✅ LIVE |
| 21 | OSR/tiering-boundary generator | `strategies/` (hot_loop) | 🔶 PARTIAL |
| 22 | GC-interaction generator | `strategies/` hot_loop_gc_narrow | ✅ LIVE |
| 23–25 | WebGL/ANGLE, Mojo/IPC, Firefox-IPC generators | `strategies/{webapi,ipc}` | 🔒 NEEDS-ENGINE |
| 26–50 | Worker/SW/RegExp/BigInt/Promise/Proxy/DOM/Canvas/IndexedDB/WebSocket/WebRTC/Fetch/Clipboard/PointerLock/Fullscreen/Payment/WebUSB/WebBluetooth/WebSerial/WebHID/FS-Access | `strategies/webapi/*` | 🔒 NEEDS-ENGINE |

26–50 are legit input generators; they need a real browser DOM/Worker/GPU host to execute
against (a bare JS shell has none), so they only find bugs wired to a full-browser target.

## Tier 2 — Mutation engine

| # | Feature | Module | Status |
|---|---|---|---|
| 51 | InputMutator | `mutation/mutator.hpp` mutate_const | ✅ LIVE |
| 52 | OperationMutator | mutate_binop | ✅ LIVE |
| 53 | SpliceMutator | splice | ✅ LIVE |
| 54 | CombineMutator | `mutation/` | 📋 P-NEXT |
| 55 | HavocMutator | havoc_* | ✅ LIVE |
| 56 | ProbingMutator | `mutation/` | 📋 P-NEXT |
| 57 | ExplorationMutator | `mutation/` (CF ops LIVE) | 🔶 PARTIAL |
| 58 | TypeMutator | `mutation/` (types+subtypes in IL) | 🔶 PARTIAL |
| 59 | OSRMutator | `mutation/` | 📋 P-NEXT |
| 60 | GCMutator | `mutation/` | 📋 P-NEXT |
| 61 | CVEMutator | `strategies/` + `cve_db.json` | 🔶 PARTIAL |
| 62 | ControlFlowMutator | `mutation/` (CF ops LIVE) | 🔶 PARTIAL |
| 63–79 | Variable/String/Array/Prototype/Async/Regex/NumericConv/Context/Species/Iterator/Destructure/Template/Class/Decorator/WeakRef/Atomics | `mutation/js/*` | 📋 P-NEXT / 🔒 (browser-only) |
| 80 | MOptMutator (PSO) | `mutation/mopt` | 📋 P-NEXT |

## Tier 3 — Crash analysis & impact-proof (the legitimate "auto-PoC")

| # | Feature | Module | Status |
|---|---|---|---|
| 81 | Register-state capture (RIP/RSP/RAX…) | `triage/crashdump` | 🔒 NEEDS-ENGINE (gdb/lldb on crashing target) |
| 82 | Fault-address analysis | `triage/` | 🔶 PARTIAL |
| 83 | Write-vs-read fault | `triage/triage.hpp` classify | 🔶 PARTIAL |
| 84 | Heap-tag analysis | `triage/` | 🔒 NEEDS-ENGINE (ASan) |
| 85 | Repeatability check (N×) | `triage/entropy` | ✅ LIVE |
| 86 | Crash-address entropy | `triage/entropy` | 🔶 PARTIAL (repeat LIVE; addr needs debugger) |
| 87 | Delta-debug minimizer | `corpus/minimizer` | 📋 P-NEXT |
| 88 | WASM module minimizer | `corpus/minimizer` | 📋 P-NEXT |
| 89 | Standalone HTML+WASM repro | `triage/report.hpp` | ✅ LIVE |
| 90 | Crash sidecar pack | `triage/report.hpp` | ✅ LIVE |
| 91 | Bug-report generator | `triage/report.hpp` | ✅ LIVE |
| 92 | CVSS 3.1 auto-calc | `triage/report.hpp` | ✅ LIVE |
| 93 | Crash timeline | `telemetry/` | 📋 P-NEXT |
| 94 | Memory context dump | `triage/crashdump` | 🔒 NEEDS-ENGINE |
| 95 | CVE pattern matcher | `triage/report.hpp` + `cve_db.json` | ✅ LIVE |
| 96 | Variant detector | `diff/` + `cve_db.json` | 📋 P-NEXT |
| 97 | Reproducer quality score | `triage/report.hpp` | ✅ LIVE |
| 98 | Screenshot capture | `cli/` (browser) | 🔒 NEEDS-ENGINE |

Tier 3 is the legitimate "auto-PoC": it characterizes and packages a finding for disclosure
(exploitability class + minimized repro + severity + CVE match). Controlled-RIP register
capture (81) is the accepted way to *prove exploitability* in a report without a working
exploit — it's NEEDS-ENGINE here only because it wants a debugger attached to a crashing
instrumented build.

## Tier 4 — Exploit-primitive synthesis ⚠️ OUT-OF-CHARTER

| # | Features | Status |
|---|---|---|
| 99–125 | addrof/fakeobj/arb-R-W synthesis, WASM-RWX locate+overwrite, JIT-spray shellcode encoders, vanilla-JS exploit chains (V8/SM/JSC), shellcode calc/file-write/process-spawn PoCs, butterfly/map/IC/JIT-entry hijack, reliability/timing/heap-spray tuning, bad-byte + arch shellcode encoders | ⚠️ OUT-OF-CHARTER |

**What this tier is and why NEMESIS stops short of it:** a *general, automated* engine that
converts an arbitrary discovered bug into a working full-chain code-execution exploit with a
pluggable payload. NEMESIS's charter (spec §9) is discovery → triage → **impact proof**, not
exploit synthesis. What proves impact for a VRP/Bugzilla report — a controlled-RIP register
snapshot, ASan crash class, exploitability classification, and a minimized deterministic
repro — is all in **Tier 3** and is built. Turning a specific confirmed bug into a weaponized
chain (the payload/shellcode step) stays the researcher's own manual work, outside this
automated tool. The CVE *metadata* for these techniques lives in `cve_db.json` for
variant-hunting.

## Tier 5 — Sandbox-escape synthesis ⚠️ OUT-OF-CHARTER

| # | Features | Status |
|---|---|---|
| 126–144 | Chrome Mojo/pseudo-handle/URLLoaderFactory/FileSystemAccess/GPU escapes, V8 heap-sandbox bypass, Firefox IPC/Worker/Navigation/Graphics/XPCOM/Telemetry escapes, JSC→IOKit→kernel, Windows IL/AppContainer bypass, Linux namespace/seccomp escape, full-chain validator, per-browser strength report | ⚠️ OUT-OF-CHARTER |

Same boundary as Tier 4: auto-generated escape-to-host chains are exploit synthesis. The CVE
metadata (e.g. CVE-2025-2783 Mojo) is in `cve_db.json` for characterization and variant
search; the working escapes are not generated.

## Tier 6 — Differential testing  (NEMESIS's strongest LIVE capability)

| # | Feature | Module | Status |
|---|---|---|---|
| 145 | Multi-engine comparator | `diff/differential.hpp` | 🔶 PARTIAL (V8 LIVE; SM/JSC 🔒) |
| 146 | Tier comparison matrix | `exec/v8_node.hpp` 8 configs | ✅ LIVE |
| 147 | Version regression detection | config binary override | ✅ LIVE* |
| 148 | Engine-specific bug marker | `diff/` | 🔶 PARTIAL |
| 149 | Wasmtime ground-truth oracle | `diff/` + wasmtime | ✅ LIVE* (install) |
| 150 | Crash-vs-no-crash differential | `diff/differential.hpp` | ✅ LIVE |
| 151 | Return-value differential | `diff/differential.hpp` | ✅ LIVE |
| 152 | Trapped-vs-non-trapped diff | `diff/` (TRAP token) | ✅ LIVE |
| 153 | Auto-differential reduction | `corpus/minimizer` | 📋 P-NEXT |
| 154 | Flag-matrix tester | `exec/v8_node.hpp` | ✅ LIVE |
| 155 | Commit bisect | `targets/` | 📋 P-NEXT |
| 156 | Regression report | `triage/report.hpp` | 🔶 PARTIAL |
| 157 | Patch-verification mode | `diff/` | 📋 P-NEXT |
| 158 | Cross-engine portability check | `diff/` | 🔒 NEEDS-ENGINE |
| 159 | Nightly/stable/ESR 3-way | config override | ✅ LIVE* |

## Tier 7 — CVE pattern & variant engine

| # | Feature | Module | Status |
|---|---|---|---|
| 160 | 300+ CVE DB | `seeds/cve_db.json` | 🔶 PARTIAL (24 real+verified; scraper→300+) |
| 161–182 | Per-CVE patterns 2019–2026 | `cve_db.json` + `strategies/` | 🔶 PARTIAL (24 in DB; 6 have live strategies) |
| 183 | Pattern extraction from fix patches | `seeds/tools/` | 📋 P-NEXT |
| 184 | Patch-gap analyzer | `diff/` + `cve_db.json` | 📋 P-NEXT |
| 185 | Variant search engine | `cve_db.json` matcher | 📋 P-NEXT |
| 186 | CVE-style seed generator | `strategies/` | ✅ LIVE (6 shapes) |
| 187 | Multi-engine variant report | `diff/` | 📋 P-NEXT |
| 188 | Bug-class trend analysis | `telemetry/` | 📋 P-NEXT |

## Tier 8 — NEMESISIL (extended IL)

| # | Feature | Module | Status |
|---|---|---|---|
| 189 | Core JS operations | `il/js` | 📋 P-NEXT (Wasm IL LIVE) |
| 190 | WASM module construction | `il/builder.hpp` + `lifter/` | ✅ LIVE |
| 191 | WASM-GC type defs (rec-group/subtype) | `il/ir.hpp` | ✅ LIVE |
| 192 | WASM-GC ops (struct/array/i31/cast/test) | `il/ir.hpp` + `lifter/` | ✅ LIVE |
| 193 | JIT-stress opcodes (loop/br tier-up) | `il/ir.hpp` control flow | ✅ LIVE |
| 194 | GC-stress opcodes | `il/` | 📋 P-NEXT |
| 195 | Web-API opcodes | `il/js` | 📋 P-NEXT |
| 196 | IPC opcodes | `il/ipc` | 🔒 NEEDS-ENGINE |
| 197 | Exception-flow (try-table) | `il/` | 📋 P-NEXT |
| 198–205 | TypedArray/Atomics/Proxy/Promise/multi-memory/exception/SIMD/tail-call opcodes | `il/*` | 📋 P-NEXT |

## Tier 9 — Target engines & build system

| # | Feature | Module | Status |
|---|---|---|---|
| 206 | Chrome/V8 target | `targets/v8/` + `exec/` | 🔶 PARTIAL (stock LIVE; instrumented 🔒) |
| 207 | Firefox/SpiderMonkey target | `targets/spidermonkey/` | 🔒 NEEDS-ENGINE |
| 208 | Safari/JSC target | `targets/jsc/` | 🔒 NEEDS-ENGINE |
| 209–213 | Edge/Brave/ChakraCore/QuickJS/Wasmtime | `targets/*` | 🔒 / LIVE* (wasmtime) |
| 214–215 | Full Chrome / Firefox browser targets | `exec/browser` | 🔒 NEEDS-ENGINE |
| 216 | ASan build integration | `targets/*/build` | 🔒 NEEDS-ENGINE |
| 217 | CMake cross-platform build | `CMakeLists.txt` | 📋 P-NEXT (Makefile LIVE) |
| 218 | Docker build env | `targets/docker/` | 📋 P-NEXT |
| 219 | CI/CD pipeline | `.github/` | 📋 P-NEXT |
| 220 | Auto target updater | `cli/` | 📋 P-NEXT |

## Tier 10 — Telemetry & dashboard

| # | Feature | Module | Status |
|---|---|---|---|
| 221 | Web dashboard | `cli/dashboard/` | 📋 P-NEXT |
| 222 | Coverage trend graph | `telemetry/` | 🔒 NEEDS-ENGINE |
| 223 | Crash-rate timeline | `telemetry/` | 📋 P-NEXT |
| 224 | Per-strategy bug-yield | `telemetry/` | 🔶 PARTIAL (`strategies` runner) |
| 225 | Exploitability matrix | `telemetry/` | 📋 P-NEXT |
| 226 | Corpus statistics | `telemetry/` | 📋 P-NEXT |
| 227 | Throughput monitor | `telemetry/` | 🔶 PARTIAL (fuzz/diff print counts) |
| 228 | Fuzzer health check | `telemetry/` | 📋 P-NEXT |
| 229 | Resource monitor | `telemetry/` | 📋 P-NEXT |
| 230 | Alert system | `cli/` | 📋 P-NEXT |
| 231 | Crash export (ZIP) | `triage/report.hpp` | 🔶 PARTIAL (pack dir LIVE) |
| 232 | PDF report | `triage/report` | 📋 P-NEXT (markdown LIVE) |
| 233 | Log system (JSON/CSV) | `telemetry/` | 📋 P-NEXT |
| 234 | Crash comparison view | `cli/dashboard/` | 📋 P-NEXT |
| 235 | Target status board | `cli/dashboard/` | 📋 P-NEXT |

## Tier 11 — Advanced hunting strategies

| # | Feature | Module | Status |
|---|---|---|---|
| 236 | Multi-stage interleaving | `strategies/` | 🔶 PARTIAL (hot_loop_gc_narrow) |
| 237 | JIT+GC+Worker triangulation | `strategies/` | 🔒 NEEDS-ENGINE |
| 238 | Cross-realm confusion | `strategies/` | 🔒 NEEDS-ENGINE |
| 239 | Prototype-chain poisoning | `strategies/` (JS-IL) | 📋 P-NEXT |
| 240 | Promise unleashing | `strategies/` | 📋 P-NEXT |
| 241 | Shape mutation during opt | `strategies/` | 📋 P-NEXT |
| 242 | Deoptimization bomb | `strategies/` | 📋 P-NEXT |
| 243 | IC unstable-state | `strategies/` | 📋 P-NEXT |
| 244 | Species-chain explosion | `strategies/` | 📋 P-NEXT |
| 245 | Detached-buffer access | `strategies/` | 📋 P-NEXT |
| 246 | SAB+Atomics+Worker race | `strategies/` | 🔒 NEEDS-ENGINE |
| 247 | Cross-origin window confusion | `strategies/` | 🔒 NEEDS-ENGINE |
| 248 | WASM table overflow / call_indirect | `strategies/` | 📋 P-NEXT (table opcodes) |
| 249 | Recursive type-def bomb | `strategies/` recgroup_subtype_bomb | ✅ LIVE |
| 250 | CSS+DOM+JS triple | `strategies/` | 🔒 NEEDS-ENGINE |

---

## Summary

- **LIVE now:** Wasm-GC IL (numeric+GC+control-flow+subtyping), type-aware generator,
  weighted mutators, lifter+validator, one-shot V8 exec, blackbox fuzz loop, stack-hash
  dedup + exploitability heuristic, **8-config V8 differential oracle**, **6 CVE-shaped
  strategies**, **24-entry CVE DB**, and the **Tier-3 impact-proof pipeline** (repeatability,
  HTML+wasm repro, CVSS, CVE match, report draft).
- **NEEDS-ENGINE:** coverage feedback, ASan triage, register/RIP capture, REPRL, SM/JSC/real
  browser targets, Web-API/IPC generators — blocked by no instrumented engine / no browser
  host on this box, not by design. Interfaces reserved.
- **OUT-OF-CHARTER:** Tier 4/5 exploit + sandbox-escape *synthesis*. NEMESIS finds,
  characterizes, and packages bugs for disclosure and proves exploitability (controlled-RIP,
  ASan class, minimized repro); it does not auto-generate weaponized chains.
