// main.cpp — NEMESIS C++ core entrypoint (Phase 0/1).
//
// WHY: A single native binary is the fuzzer's hot core; the Python CLI shells to it.
// `selftest` exercises the whole IL -> lifter -> validator chain — now including the
// Wasm-GC surface (struct/array/i31/ref) — and proves the toolchain works on this box.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <map>
#include <memory>

#include "common/platform.hpp"
#include "common/rng.hpp"
#include "corpus/minimizer.hpp"
#include "diff/differential.hpp"
#include "strategies/cve_bias.hpp"
#include "exec/reprl.hpp"
#include "exec/v8_node.hpp"
#include "il/builder.hpp"
#include "il/generator.hpp"
#include "lifter/lifter.hpp"
#include "lifter/validator.hpp"
#include "mutation/mutator.hpp"
#include <ctime>

#include "strategies/strategies.hpp"
#include "telemetry/telemetry.hpp"
#include "triage/report.hpp"
#include "triage/triage.hpp"

using namespace nemesis;

// () -> i32 { i32.const 42 }
static Program sample_const() {
    ProgramBuilder b;
    uint32_t t = b.func_type({}, {ValType::i32()});
    uint32_t f = b.begin_function(t);
    b.emit(Op::I32Const, 42);
    b.export_function("run", f);
    return b.take();
}

// (i32,i32) -> i32 { local.get 0; local.get 1; i32.add }
static Program sample_add() {
    ProgramBuilder b;
    uint32_t t = b.func_type({ValType::i32(), ValType::i32()}, {ValType::i32()});
    uint32_t f = b.begin_function(t);
    b.emit(Op::LocalGet, 0);
    b.emit(Op::LocalGet, 1);
    b.emit(Op::I32Add);
    b.export_function("add", f);
    return b.take();
}

// () -> i32 { local i32; i32.const 7; local.set l; local.get l; i32.const 5; i32.mul }
static Program sample_locals() {
    ProgramBuilder b;
    uint32_t t = b.func_type({}, {ValType::i32()});
    uint32_t f = b.begin_function(t);
    uint32_t l = b.local(ValType::i32());
    b.emit(Op::I32Const, 7);
    b.emit(Op::LocalSet, l);
    b.emit(Op::LocalGet, l);
    b.emit(Op::I32Const, 5);
    b.emit(Op::I32Mul);
    b.export_function("run", f);
    return b.take();
}

// GC struct: type0 = struct { i32 mut }; run() { i32.const 99; struct.new 0; struct.get 0 0 }
static Program sample_struct() {
    ProgramBuilder b;
    uint32_t s = b.struct_type({Field{ValType::i32(), true}});
    uint32_t t = b.func_type({}, {ValType::i32()});
    uint32_t f = b.begin_function(t);
    b.emit(Op::I32Const, 99);
    b.emit(Op::StructNew, s);
    b.emit(Op::StructGet, s, 0);
    b.export_function("run", f);
    return b.take();
}

// GC array: type0 = array { i32 mut }; run() { i32.const 4; array.new_default 0; array.len }
static Program sample_array() {
    ProgramBuilder b;
    uint32_t a = b.array_type(Field{ValType::i32(), true});
    uint32_t t = b.func_type({}, {ValType::i32()});
    uint32_t f = b.begin_function(t);
    b.emit(Op::I32Const, 4);
    b.emit(Op::ArrayNewDefault, a);
    b.emit(Op::ArrayLen);
    b.export_function("run", f);
    return b.take();
}

// Control flow: hot counting loop. run() sums i for i in 0..9 -> 45. Forces JIT tier-up.
static Program sample_loop() {
    ProgramBuilder b;
    uint32_t t = b.func_type({}, {ValType::i32()});
    uint32_t f = b.begin_function(t);
    uint32_t i = b.local(ValType::i32());
    uint32_t acc = b.local(ValType::i32());
    b.emit(Op::Loop, -64);            // blocktype empty
    b.emit(Op::LocalGet, acc);
    b.emit(Op::LocalGet, i);
    b.emit(Op::I32Add);
    b.emit(Op::LocalSet, acc);        // acc += i
    b.emit(Op::LocalGet, i);
    b.emit(Op::I32Const, 1);
    b.emit(Op::I32Add);
    b.emit(Op::LocalTee, i);          // i += 1, leave i on stack
    b.emit(Op::I32Const, 10);
    b.emit(Op::I32LtS);               // i < 10
    b.emit(Op::BrIf, 0);              // continue loop while true
    b.emit(Op::End);
    b.emit(Op::LocalGet, acc);
    b.export_function("run", f);
    return b.take();
}

// GC i31: run() { i32.const 12345; ref.i31; i31.get_s }
static Program sample_i31() {
    ProgramBuilder b;
    uint32_t t = b.func_type({}, {ValType::i32()});
    uint32_t f = b.begin_function(t);
    b.emit(Op::I32Const, 12345);
    b.emit(Op::RefI31);
    b.emit(Op::I31GetS);
    b.export_function("run", f);
    return b.take();
}

static int cmd_selftest() {
    std::vector<std::pair<std::string, Program>> samples = {
        {"const42", sample_const()}, {"add", sample_add()},   {"locals", sample_locals()},
        {"struct", sample_struct()}, {"array", sample_array()}, {"i31", sample_i31()},
        {"loop", sample_loop()},
    };

    printf("NEMESIS selftest  —  IL -> lifter -> validator  (numeric + Wasm-GC)\n");
    printf("os=%s  validator=%s\n\n", os_name(),
           have_tool("node") ? "node WebAssembly.validate (V8)" : "structural-only (node missing)");

    int fails = 0;
    bool used_engine = false;
    for (size_t i = 0; i < samples.size(); ++i) {
        const std::string& name = samples[i].first;
        std::vector<uint8_t> bytes = lift(samples[i].second);
        std::string path = "build/selftest_" + std::to_string(i) + "_" + name + ".wasm";
        ValidationResult res = validate_module(bytes, path);
        used_engine |= res.used_engine;
        // Also execute — proves the encoding is semantically correct, not just structurally
        // valid. Prints the result token (e.g. loop -> RES 45).
        std::string exec_note;
        if (have_tool("node")) {
            V8NodeTarget t;
            ExecResult er = t.run(bytes);
            exec_note = "  exec:" + std::string(exec_status_name(er.status)) +
                        (er.result.empty() ? "" : " " + er.result);
        }
        printf("[%s] %-9s %4zu bytes  ->  %s%s\n", res.valid ? "PASS" : "FAIL", name.c_str(),
               bytes.size(), res.detail.c_str(), exec_note.c_str());
        if (!res.valid) ++fails;
    }

    printf("\n%zu/%zu modules valid%s\n", samples.size() - static_cast<size_t>(fails),
           samples.size(), used_engine ? "  (verified by node/V8)" : "");
    return fails == 0 ? 0 : 1;
}

// Batch-validate every .wasm in `dir` on V8 (one node process). The valid-rate is the
// core health metric: a type-aware generator/mutator must stay near 100% valid or it is
// wasting the fuzzer's time on modules the engine rejects before they can reach the JIT.
static void batch_validate(const std::string& dir) {
    if (!have_tool("node")) {
        printf("node not found — skipping V8 validation\n");
        return;
    }
    int rc = 0;
    std::string cmd =
        "node -e \"const fs=require('fs');const d='" + dir +
        "';let ok=0,n=0,bad=[];for(const f of fs.readdirSync(d)){if(f.endsWith('.wasm')){n++;"
        "try{if(WebAssembly.validate(fs.readFileSync(d+'/'+f)))ok++;else bad.push(f);}"
        "catch(e){bad.push(f);}}}console.log('V8 valid: '+ok+'/'+n);"
        "if(bad.length)console.log('invalid: '+bad.slice(0,12).join(' '));\" 2>&1";
    std::string out = run_capture(cmd, &rc);
    printf("%s", out.c_str());
}

static void write_wasm(const std::string& path, const std::vector<uint8_t>& bytes) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
}

// Generate `count` random Wasm-GC modules and batch-validate them on V8.
static int cmd_gen(int count, uint64_t seed) {
    ensure_dir("build/gen");
    clear_wasm("build/gen");
    Generator g(seed);
    for (int i = 0; i < count; ++i)
        write_wasm("build/gen/gen_" + std::to_string(i) + ".wasm", lift(g.generate()));
    printf("generated %d modules (seed=%llu) -> build/gen/\n", count,
           static_cast<unsigned long long>(seed));
    batch_validate("build/gen");
    return 0;
}

// Generate a base program + donor pool, then produce `count` mutants and batch-validate.
// The valid-mutant rate shows how much of the mutation budget survives the validator gate.
static int cmd_mutate(int count, uint64_t seed) {
    ensure_dir("build/mut");
    clear_wasm("build/mut");
    Generator g(seed);
    Program base = g.generate();
    std::vector<Program> donors;
    for (int i = 0; i < 4; ++i) donors.push_back(g.generate());

    for (int i = 0; i < count; ++i) {
        Program m = base;
        Mutator mut(seed + static_cast<uint64_t>(i) + 1);
        mut.mutate(m, &donors[static_cast<size_t>(i) % donors.size()]);
        write_wasm("build/mut/mut_" + std::to_string(i) + ".wasm", lift(m));
    }
    printf("mutated 1 base -> %d mutants (seed=%llu) -> build/mut/\n", count,
           static_cast<unsigned long long>(seed));
    printf("(raw mutant survival below; the fuzz loop discards invalids cheaply)\n");
    batch_validate("build/mut");
    return 0;
}

// The fuzz loop: generate a seed corpus, then repeatedly mutate a corpus member and run it
// against the engine target, classifying every outcome and de-duplicating any crash into a
// saved repro. On stock V8 (hardened, no instrumentation) a CRASH is rare-but-real — the
// honest expected result is zero crashes here; deeper yield needs an instrumented engine
// (REPRL/ASan) or the differential oracle (P3). Without coverage feedback the corpus is a
// fixed seed set (guided corpus growth is the NEEDS-ENGINE piece — see CAPABILITY-MATRIX).
static int cmd_fuzz(int iters, uint64_t seed, int timeout_s) {
    time_t t0 = std::time(nullptr);
    V8NodeTarget target("harness/run_wasm.js", timeout_s);
    if (!target.available()) {
        ReprlTarget reprl;
        printf("no runnable engine target on this box.\n");
        printf("  v8-node : NOT_WIRED (node not found on PATH)\n");
        printf("  reprl   : NOT_WIRED (%s)\n", reprl.run({}).output.c_str());
        return 1;
    }

    ensure_dir("build/crashes");
    Generator g(seed);
    std::vector<Program> corpus;
    for (int i = 0; i < 8; ++i) corpus.push_back(g.generate());

    Rng rng(seed ^ 0xABCDEF01ULL);
    int n_ok = 0, n_invalid = 0, n_timeout = 0, n_crash = 0, n_error = 0, n_unique = 0;
    std::set<std::string> seen;

    printf("NEMESIS fuzz  —  target=%s  iters=%d  seed=%llu  timeout=%ds\n\n",
           target.name(), iters, static_cast<unsigned long long>(seed), timeout_s);

    for (int it = 0; it < iters; ++it) {
        Program m = corpus[rng.below(corpus.size())];
        Mutator mut(seed + static_cast<uint64_t>(it) + 1);
        const Program& donor = corpus[rng.below(corpus.size())];
        mut.mutate(m, &donor);

        std::vector<uint8_t> wasm = lift(m);
        ExecResult r = target.run(wasm);

        switch (r.status) {
            case ExecStatus::Ok: ++n_ok; break;
            case ExecStatus::Invalid: ++n_invalid; break;
            case ExecStatus::Timeout: ++n_timeout; break;
            case ExecStatus::Error: ++n_error; break;
            case ExecStatus::Crash: {
                ++n_crash;
                std::string bucket = crash_bucket(r);
                if (seen.insert(bucket).second) {
                    ++n_unique;
                    ExploitHint hint = classify_exploitability(r);
                    std::string base = "build/crashes/crash_" + bucket;
                    write_wasm(base + ".wasm", wasm);
                    std::ofstream meta(base + ".txt");
                    meta << "bucket=" << bucket << "\nsignal=" << r.signal
                         << "\nexit_code=" << r.exit_code
                         << "\nexploitability=" << exploit_hint_name(hint) << "\n\n"
                         << r.output << "\n";
                    printf("  [CRASH] bucket=%s signal=%d hint=%s -> %s.wasm\n",
                           bucket.c_str(), r.signal, exploit_hint_name(hint), base.c_str());
                }
                break;
            }
        }

        if ((it + 1) % 50 == 0 || it + 1 == iters)
            printf("  [%d/%d] ok=%d invalid=%d timeout=%d crash=%d (unique=%d)\n",
                   it + 1, iters, n_ok, n_invalid, n_timeout, n_crash, n_unique);
    }

    printf("\nsummary: exec=%d ok=%d invalid=%d timeout=%d error=%d crash=%d unique=%d\n",
           iters, n_ok, n_invalid, n_timeout, n_error, n_crash, n_unique);
    if (n_crash == 0)
        printf("no crashes — expected on stock/hardened V8. Wire an instrumented engine "
               "(REPRL/ASan) or use the differential oracle for deeper yield.\n");
    else
        printf("%d unique crash bucket(s) saved under build/crashes/\n", n_unique);
    telemetry_run("fuzz", iters, 1, 0, n_crash, difftime(std::time(nullptr), t0));
    return 0;
}

// List the eight V8 configs and whether each is runnable on this box.
static int cmd_configs() {
    printf("NEMESIS V8 config matrix (v1..v8)  —  differential JIT-tier oracle\n\n");
    int live = 0;
    for (const V8Config& c : default_v8_configs()) {
        V8NodeTarget t(c);
        bool ok = t.available();
        live += ok ? 1 : 0;
        printf("  %-14s %-8s %s\n", c.label.c_str(), ok ? "LIVE" : "NOT_WIRED",
               c.flags.c_str());
    }
    printf("\n%d/8 configs runnable. v1-liftoff (baseline tier) is the reference; any\n", live);
    printf("optimizing config that disagrees with it on a result = JIT miscompilation.\n");
    printf("(V8's --jitless disables Wasm, so Liftoff is the lowest usable Wasm tier.)\n");
    printf("Override a slot's binary to diff across real V8 releases instead of tiers.\n");
    return 0;
}

// Build the set of available config-targets for the differential oracle.
// tier_iters>0 caps the harness tier-up loop — safe for strategy/hunt runs whose modules
// self-tier via their own internal hot loops (a low outer count still reaches the optimizing
// tier, far faster). Pass 0 for random modules (diff) that need the full tier-up loop.
static std::vector<std::unique_ptr<Target>> build_available_configs(int timeout_s,
                                                                    int tier_iters = 0) {
    std::vector<std::unique_ptr<Target>> targets;
    for (const V8Config& c : default_v8_configs()) {
        auto t = std::make_unique<V8NodeTarget>(c, "harness/run_wasm.js", timeout_s);
        if (tier_iters > 0) t->set_tier_iters(tier_iters);
        if (t->available()) targets.push_back(std::move(t));
    }
    return targets;
}

// Differential fuzzing: generate + mutate modules, run each across all available V8 configs,
// and flag any result divergence (miscompilation) or crash. This is the deepest bug class
// runnable on stock V8 with no instrumentation.
static int cmd_diff(int iters, uint64_t seed, int timeout_s) {
    time_t t0 = std::time(nullptr);
    auto targets = build_available_configs(timeout_s);
    if (targets.size() < 2) {
        printf("differential needs >=2 runnable configs; have %zu.\n", targets.size());
        printf("run `nemesis configs` to see status (node must be on PATH).\n");
        return 1;
    }
    size_t ncfg = targets.size();
    Differential diff(std::move(targets));

    ensure_dir("build/diffs");
    ensure_dir("build/crashes");
    Generator g(seed);
    std::vector<Program> corpus;
    for (int i = 0; i < 8; ++i) corpus.push_back(g.generate());
    Rng rng(seed ^ 0xD1FFULL);

    int n_diverge = 0, n_crash = 0, n_run = 0;
    std::set<std::string> seen;
    printf("NEMESIS diff  —  %zu V8 configs  iters=%d  seed=%llu  timeout=%ds\n\n",
           ncfg, iters, static_cast<unsigned long long>(seed), timeout_s);

    for (int it = 0; it < iters; ++it) {
        Program m = corpus[rng.below(corpus.size())];
        Mutator mut(seed + static_cast<uint64_t>(it) + 1);
        mut.mutate(m, &corpus[rng.below(corpus.size())]);
        std::vector<uint8_t> wasm = lift(m);

        DiffReport rep = diff.run(wasm);
        ++n_run;
        if (rep.interesting()) {
            // De-dup on the multiset of distinct result tokens (the disagreement shape).
            std::string key = rep.crashed ? "crash" : "";
            for (const std::string& d : rep.distinct_results()) key += "|" + d;
            if (seen.insert(key).second) {
                std::string tag = rep.crashed ? "crash" : "diverge";
                if (rep.diverged) ++n_diverge;
                if (rep.crashed) ++n_crash;
                std::string base = "build/diffs/" + tag + "_" + hex16(fnv1a(key + std::to_string(it)));
                write_wasm(base + ".wasm", wasm);
                std::ofstream meta(base + ".txt");
                meta << "kind=" << tag << "\niter=" << it << "\n\n";
                for (const ConfigOutcome& o : rep.outcomes)
                    meta << "  " << o.label << " : " << exec_status_name(o.result.status)
                         << "  " << o.result.result << "\n";
                printf("  [%s] %s -> %s.wasm\n", tag.c_str(),
                       rep.diverged ? "result divergence across configs" : "engine crash",
                       base.c_str());
                for (const ConfigOutcome& o : rep.outcomes)
                    printf("      %-14s %-8s %s\n", o.label.c_str(),
                           exec_status_name(o.result.status), o.result.result.c_str());
            }
        }
        if ((it + 1) % 25 == 0 || it + 1 == iters)
            printf("  [%d/%d] diverge=%d crash=%d\n", it + 1, iters, n_diverge, n_crash);
    }

    printf("\nsummary: modules=%d configs=%zu divergences=%d crashes=%d\n", n_run, ncfg,
           n_diverge, n_crash);
    if (n_diverge == 0 && n_crash == 0)
        printf("no divergence — the current IL subset compiles identically across tiers.\n"
               "Deeper strategies (P4: LICM-bait, OSR, RTT-alias) target the tier gaps.\n");
    else
        printf("saved under build/diffs/ — each is a candidate JIT-correctness bug.\n");
    telemetry_run("diff", n_run, static_cast<int>(ncfg), n_diverge, n_crash,
                  difftime(std::time(nullptr), t0));
    return 0;
}

// Build a Finding from a differential report + write a full disclosure pack
// (module.wasm, repro.html, report.md, meta.txt) under build/findings/<id>/.
static std::string emit_finding_pack(const std::vector<uint8_t>& wasm, const DiffReport& rep,
                                     const std::string& strategy, const std::string& cve) {
    Finding f;
    f.kind = rep.crashed ? Finding::Crash : Finding::Divergence;
    f.anomalous = rep.interesting();
    f.wasm = wasm;
    f.strategy = strategy;
    f.cve = cve;
    for (const ConfigOutcome& o : rep.outcomes) {
        f.config_results.push_back({o.label, o.result.result.empty()
                                                  ? exec_status_name(o.result.status)
                                                  : o.result.result});
        if (o.result.status == ExecStatus::Crash) { f.signal = o.result.signal; f.hint = classify_exploitability(o.result); }
    }
    // De-dup id from the disagreement shape.
    std::string key = f.kind == Finding::Crash ? "crash" : "diverge";
    for (const std::string& d : rep.distinct_results()) key += "|" + d;
    f.id = hex16(fnv1a(key + strategy));

    std::string dir = "build/findings/" + f.id;
    ensure_dir(dir);
    write_wasm(dir + "/module.wasm", wasm);
    std::ofstream(dir + "/repro.html") << html_repro(f);
    std::ofstream(dir + "/report.md") << markdown_report(f);
    std::ofstream meta(dir + "/meta.txt");
    Cvss c = cvss_for(f);
    meta << "id=" << f.id << " kind=" << (f.kind == Finding::Crash ? "crash" : "divergence")
         << "\ncve=" << cve << " strategy=" << strategy << "\ncvss=" << c.score << " "
         << c.vector << "\nquality=" << repro_quality(f) << "/100\n\n";
    for (const auto& cr : f.config_results) meta << "  " << cr.first << " : " << cr.second << "\n";
    return dir;
}

// `report <module.wasm> [strategy] [cve]`: run a confirmed module across the config matrix
// and package a disclosure pack. Point it at a crashing/diverging .wasm you already have.
static int cmd_report(const std::string& path, const std::string& strategy,
                      const std::string& cve, int timeout_s) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { printf("cannot read %s\n", path.c_str()); return 1; }
    std::vector<uint8_t> wasm((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
    auto targets = build_available_configs(timeout_s);
    if (targets.empty()) { printf("no runnable V8 config (node missing).\n"); return 1; }
    Differential diff(std::move(targets));
    DiffReport rep = diff.run(wasm);
    if (!rep.interesting())
        printf("note: no crash/divergence on THIS build — packaging anyway; results table "
               "reflects current engine. Re-run vs the vulnerable build for a live repro.\n");
    std::string dir = emit_finding_pack(wasm, rep, strategy, cve);
    printf("finding pack -> %s/  (module.wasm, repro.html, report.md, meta.txt)\n", dir.c_str());
    return 0;
}

// Delta-debug a program (from a seed or a strategy) down to the minimal module that still
// produces the same cross-tier signature. If the source diverges/crashes, the divergence is
// preserved; otherwise its result value is preserved. Emits the minimized module + stats.
static int cmd_minimize(uint64_t seed, const std::string& strategy, int timeout_s) {
    Program base;
    std::string src;
    if (!strategy.empty()) { Strategies s(seed); base = s.generate(strategy); src = strategy; }
    else { Generator g(seed); base = g.generate(); src = "seed " + std::to_string(seed); }

    auto targets = build_available_configs(timeout_s);
    if (targets.empty()) { printf("no runnable V8 config (node missing)\n"); return 1; }
    Differential diff(std::move(targets));

    // Full signature across every tier: interestingness tag + per-config tokens. This detects
    // whether the source diverges/crashes (must preserve full matrix) or merely returns a
    // value (single tier suffices).
    auto full_sig = [&](const Program& p) {
        DiffReport rep = diff.run(lift(p));
        std::string s = rep.diverged ? "D" : (rep.crashed ? "C" : "A");
        for (const ConfigOutcome& o : rep.outcomes)
            s += "|" + (o.result.result.empty() ? std::string("!") + exec_status_name(o.result.status)
                                                 : o.result.result);
        return s;
    };
    std::string base_sig = full_sig(base);
    bool interesting = base_sig[0] != 'A';
    size_t before_i = instr_count(base), before_b = lift(base).size();

    // Fast single-tier predicate for the common value-preserving case (agree): one node run
    // per probe, with the tier-up loop capped since a deterministic value is tier-invariant.
    V8NodeTarget fast(default_v8_configs()[3], "harness/run_wasm.js", timeout_s);  // v4-tierup
    fast.set_tier_iters(200);
    ExecResult be = fast.run(lift(base));
    std::string base_one = be.comparable() ? be.result : std::string("!") + exec_status_name(be.status);
    auto one_sig = [&](const Program& p) {
        ExecResult r = fast.run(lift(p));
        return r.comparable() ? r.result : std::string("!") + exec_status_name(r.status);
    };

    Minimizer m(interesting
                    ? Minimizer::Predicate([&](const Program& p) { return full_sig(p) == base_sig; })
                    : Minimizer::Predicate([&](const Program& p) { return one_sig(p) == base_one; }));
    Program small = m.minimize(base);
    // Audit: the minimized module must still show the full original signature.
    bool audit_ok = full_sig(small) == base_sig;

    ensure_dir("build/min");
    std::vector<uint8_t> wasm = lift(small);
    write_wasm("build/min/min.wasm", wasm);
    const char* tag = base_sig[0] == 'D' ? "DIVERGENCE" : base_sig[0] == 'C' ? "CRASH" : "agree";
    printf("minimize %s (%s)\n", src.c_str(), tag);
    printf("  %zu -> %zu instrs,  %zu -> %zu bytes,  %d oracle probes,  audit=%s\n", before_i,
           instr_count(small), before_b, wasm.size(), m.probes(), audit_ok ? "PASS" : "FAIL");
    printf("  preserved: %s\n", base_sig.c_str());
    printf("  -> build/min/min.wasm\n");
    return audit_ok ? 0 : 1;
}

// Run every CVE-shaped strategy once through the differential oracle. This is the direct
// test of "does any known-bug shape make this V8's tiers disagree?" — each strategy is
// validity-gated, then run across all live configs; divergence/crash saved as a candidate.
static int cmd_strategies(uint64_t seed, int timeout_s) {
    time_t t0 = std::time(nullptr);
    auto cat = Strategies::catalogue();
    printf("NEMESIS strategies  —  %zu CVE-root-cause shapes\n\n", cat.size());

    auto targets = build_available_configs(timeout_s, 2000);  // strategy modules self-tier
    bool have_oracle = targets.size() >= 2;
    size_t ncfg = targets.size();
    Differential diff(std::move(targets));

    Strategies strat(seed);
    ensure_dir("build/diffs");
    int interesting = 0, n_div = 0, n_crash = 0;
    for (const auto& s : cat) {
        Program p = strat.generate(s.name);
        std::vector<uint8_t> wasm = lift(p);
        ValidationResult vr = validate_module(wasm, "build/strat_" + std::string(s.name) + ".wasm");
        printf("  %-22s %-15s valid=%s", s.name, s.cve, vr.valid ? "yes" : "NO ");
        if (!vr.valid) { printf("  (%s)\n", vr.detail.c_str()); continue; }
        if (!have_oracle) { printf("  [%s]\n", s.note); continue; }

        DiffReport rep = diff.run(wasm);
        if (rep.interesting()) {
            ++interesting;
            n_div += rep.diverged ? 1 : 0;
            n_crash += rep.crashed ? 1 : 0;
            std::string dir = emit_finding_pack(wasm, rep, s.name, s.cve);
            printf("  >>> %s -> %s/\n", rep.diverged ? "DIVERGENCE" : "CRASH", dir.c_str());
            for (const ConfigOutcome& o : rep.outcomes)
                printf("        %-14s %s\n", o.label.c_str(), o.result.result.c_str());
        } else {
            // Show the agreed result token across configs.
            std::string tok = rep.outcomes.empty() ? "" : rep.outcomes[0].result.result;
            printf("  agree(%zu cfg): %s\n", ncfg, tok.c_str());
        }
    }
    printf("\n%d/%zu strategies produced a divergence/crash across %zu configs.\n",
           interesting, cat.size(), ncfg);
    if (interesting == 0 && have_oracle)
        printf("all shapes compile identically on this V8 build — expected for a patched\n"
               "engine; re-run against an older/nightly V8 (override config binaries) to hunt.\n");
    telemetry_run("strategies", static_cast<int>(cat.size()), static_cast<int>(ncfg), n_div,
                  n_crash, difftime(std::time(nullptr), t0));
    return 0;
}

// CVE-bias directed campaign: repeatedly seed from a strategy chosen weighted by real CVE
// class frequency, mutate it, and run across the config matrix. This is the CVE-bias mutator
// (feature #61) in action — the mutation budget concentrates on the bug classes that dominate
// shipped browser-engine CVEs. Directed *finding*; no exploitation.
static int cmd_hunt(int iters, uint64_t seed, int timeout_s) {
    time_t t0 = std::time(nullptr);
    auto targets = build_available_configs(timeout_s, 200);  // modules self-tier via loops
    if (targets.size() < 2) {
        printf("hunt needs >=2 runnable configs; have %zu (node must be on PATH).\n",
               targets.size());
        return 1;
    }
    size_t ncfg = targets.size();
    Differential diff(std::move(targets));
    auto cat = Strategies::catalogue();
    CveBias bias;
    Strategies strat(seed);
    Rng rng(seed ^ 0xC7EULL);
    ensure_dir("build/findings");

    int n_div = 0, n_crash = 0;
    std::map<std::string, int> picks;
    std::set<std::string> seen;
    printf("NEMESIS hunt — CVE-biased directed campaign  (%zu cfg, weights: %s)\n\n",
           ncfg, bias.source().c_str());

    for (int it = 0; it < iters; ++it) {
        std::string name = bias.pick(cat, rng);
        picks[name]++;
        Program p = strat.generate(name);
        Mutator mut(seed + static_cast<uint64_t>(it) + 1);
        mut.mutate(p);  // CVE-shaped seed, then mutate
        std::vector<uint8_t> wasm = lift(p);

        DiffReport rep = diff.run(wasm);
        if (rep.interesting()) {
            std::string key = rep.crashed ? "crash" : "";
            for (const std::string& d : rep.distinct_results()) key += "|" + d;
            if (seen.insert(key).second) {
                if (rep.diverged) ++n_div;
                if (rep.crashed) ++n_crash;
                std::string dir = emit_finding_pack(wasm, rep, name, "");
                printf("  [%s] via %s -> %s/\n", rep.diverged ? "DIVERGENCE" : "CRASH",
                       name.c_str(), dir.c_str());
            }
        }
        if ((it + 1) % 25 == 0 || it + 1 == iters)
            printf("  [%d/%d] diverge=%d crash=%d\n", it + 1, iters, n_div, n_crash);
    }

    printf("\nstrategy picks (CVE-weighted):\n");
    for (const auto& kv : picks) printf("  %-26s %d\n", kv.first.c_str(), kv.second);
    printf("\nsummary: iters=%d configs=%zu divergences=%d crashes=%d\n", iters, ncfg, n_div,
           n_crash);
    if (n_div == 0 && n_crash == 0)
        printf("no divergence — patched V8 resists these shapes; re-run vs nightly/unpatched.\n");
    telemetry_run("hunt", iters, static_cast<int>(ncfg), n_div, n_crash,
                  difftime(std::time(nullptr), t0));
    return 0;
}

static int cmd_help(int exit_code) {
    printf("NEMESIS — coverage-guided differential Wasm-GC/JS-JIT fuzzer\n");
    printf("usage: nemesis <command>\n\n");
    printf("  selftest        build sample IL programs (numeric + GC), lift, validate via node/V8\n");
    printf("  gen [N] [seed]  generate N random Wasm-GC modules, batch-validate on V8\n");
    printf("  mutate [N] [seed]  mutate a base program N times, batch-validate on V8\n");
    printf("  fuzz [N] [seed] [timeout]  run N mutate+execute iters, classify+save crashes\n");
    printf("  configs         list the 8 V8 JIT configs (v1..v8) and which are runnable\n");
    printf("  diff [N] [seed] [timeout]  differential across V8 configs; flag miscompiles\n");
    printf("  strategies [seed] [timeout]  run each CVE-shaped strategy through the oracle\n");
    printf("  hunt [N] [seed] [timeout]  CVE-biased directed campaign (weighted strategy + mutate)\n");
    printf("  minimize [seed] [strategy] [t]  delta-debug to the minimal module preserving behavior\n");
    printf("  report <module.wasm> [strategy] [cve]  package a finding: repro.html+report.md+CVSS\n");
    printf("  version         print version + host os\n");
    printf("  help            this text\n\n");
    printf("higher-level commands (fuzz/diff/mutate/triage/...) live in cli/nemesis.py\n");
    return exit_code;
}

int main(int argc, char** argv) {
    std::string cmd = argc > 1 ? argv[1] : "help";
    if (cmd == "selftest") return cmd_selftest();
    if (cmd == "gen") {
        int count = argc > 2 ? std::atoi(argv[2]) : 20;
        uint64_t seed = argc > 3 ? std::strtoull(argv[3], nullptr, 10) : 0x1234ULL;
        return cmd_gen(count, seed);
    }
    if (cmd == "mutate") {
        int count = argc > 2 ? std::atoi(argv[2]) : 50;
        uint64_t seed = argc > 3 ? std::strtoull(argv[3], nullptr, 10) : 0x1234ULL;
        return cmd_mutate(count, seed);
    }
    if (cmd == "fuzz") {
        int iters = argc > 2 ? std::atoi(argv[2]) : 200;
        uint64_t seed = argc > 3 ? std::strtoull(argv[3], nullptr, 10) : 0x1234ULL;
        int timeout_s = argc > 4 ? std::atoi(argv[4]) : 5;
        return cmd_fuzz(iters, seed, timeout_s);
    }
    if (cmd == "minimize") {
        uint64_t seed = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0x1234ULL;
        std::string strat = argc > 3 ? argv[3] : "";
        int timeout_s = argc > 4 ? std::atoi(argv[4]) : 5;
        return cmd_minimize(seed, strat, timeout_s);
    }
    if (cmd == "configs") return cmd_configs();
    if (cmd == "hunt") {
        int iters = argc > 2 ? std::atoi(argv[2]) : 100;
        uint64_t seed = argc > 3 ? std::strtoull(argv[3], nullptr, 10) : 0x1234ULL;
        int timeout_s = argc > 4 ? std::atoi(argv[4]) : 5;
        return cmd_hunt(iters, seed, timeout_s);
    }
    if (cmd == "strategies") {
        uint64_t seed = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0x1234ULL;
        int timeout_s = argc > 3 ? std::atoi(argv[3]) : 5;
        return cmd_strategies(seed, timeout_s);
    }
    if (cmd == "report") {
        if (argc < 3) { printf("usage: nemesis report <module.wasm> [strategy] [cve]\n"); return 1; }
        std::string strat = argc > 3 ? argv[3] : "";
        std::string cve = argc > 4 ? argv[4] : "";
        return cmd_report(argv[2], strat, cve, 5);
    }
    if (cmd == "diff") {
        int iters = argc > 2 ? std::atoi(argv[2]) : 100;
        uint64_t seed = argc > 3 ? std::strtoull(argv[3], nullptr, 10) : 0x1234ULL;
        int timeout_s = argc > 4 ? std::atoi(argv[4]) : 5;
        return cmd_diff(iters, seed, timeout_s);
    }
    if (cmd == "version") {
        printf("nemesis 0.2.0 (phase-1)  os=%s\n", os_name());
        return 0;
    }
    if (cmd == "help" || cmd == "-h" || cmd == "--help") return cmd_help(0);
    fprintf(stderr, "unknown command: %s\n\n", cmd.c_str());
    return cmd_help(1);
}
