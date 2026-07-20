// v8_node.hpp — V8/Node execution target, parameterized by compiler config (v1..v8).
//
// WHY: This is the target that actually runs on this box today. It writes the candidate
// module to a temp file, drives it through the node harness under a specific set of V8
// flags (a "config" = one JIT tier / compiler pipeline), and classifies the result. The
// same one installed V8 becomes N differentiable engines: the interpreter (--jitless) is a
// trusted oracle, and every optimizing config that returns a *different* value for the same
// module is a JIT miscompilation — a silent-wrong-value bug found with zero instrumentation.
//
// Each config carries an overridable binary path, so the eight slots can instead point at
// eight real V8/node *release* binaries for cross-version differential testing; whichever
// binaries are absent report available()==false honestly.
//
// A one-shot subprocess per run is slower than REPRL but portable and dependency-free.
#pragma once
#include <cstdio>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include "common/platform.hpp"
#include "exec/target.hpp"

namespace nemesis {

// One V8 execution configuration: a label, the node binary, and the V8 flags that select a
// compiler pipeline / tier.
struct V8Config {
    std::string label;   // e.g. "v1-interp"
    std::string binary;  // node/d8 binary (path or PATH name)
    std::string flags;   // space-separated V8 flags, e.g. "--jitless"
};

class V8NodeTarget : public Target {
public:
    explicit V8NodeTarget(std::string harness = "harness/run_wasm.js", int timeout_s = 5)
        : cfg_{"v8-node", "node", ""}, harness_(std::move(harness)), timeout_s_(timeout_s) {}

    V8NodeTarget(V8Config cfg, std::string harness = "harness/run_wasm.js", int timeout_s = 5)
        : cfg_(std::move(cfg)), harness_(std::move(harness)), timeout_s_(timeout_s) {}

    const char* name() const override { return cfg_.label.c_str(); }
    const V8Config& config() const { return cfg_; }

    // Fast mode: cap the harness tier-up loop (env NEMESIS_TIER_ITERS). Used by minimization,
    // which only needs to preserve a deterministic value, not trigger optimizing tiers.
    void set_tier_iters(int n) { tier_iters_ = n; }

    // Available if the config's binary resolves AND it accepts the config's flags (an
    // unknown flag makes V8 abort at startup — probed once, cached).
    bool available() const override {
        if (avail_ < 0) avail_ = probe() ? 1 : 0;
        return avail_ == 1;
    }

    ExecResult run(const std::vector<uint8_t>& wasm) override {
        ExecResult r;
        const std::string path = tmp_path();
        {
            std::ofstream f(path, std::ios::binary);
            if (!f) { r.status = ExecStatus::Error; return r; }
            f.write(reinterpret_cast<const char*>(wasm.data()),
                    static_cast<std::streamsize>(wasm.size()));
        }

        int rc = 0;
        std::string out = run_capture(build_cmd(path), &rc);
        std::remove(path.c_str());

        r.exit_code = rc;
        r.output = out;
        r.status = classify(rc, &r.signal);
        if (r.status == ExecStatus::Ok) r.result = parse_token(out);
        return r;
    }

private:
    // `node <flags> harness module`. On POSIX, `timeout` bounds a hung engine (rc 124).
    std::string build_cmd(const std::string& modpath) const {
        const std::string& bin = cfg_.binary;
        const std::string& fl = cfg_.flags;
        std::string env = tier_iters_ > 0
                              ? "NEMESIS_TIER_ITERS=" + std::to_string(tier_iters_) + " "
                              : "";
#if defined(NEMESIS_OS_WINDOWS)
        std::string pre = tier_iters_ > 0
                              ? "set NEMESIS_TIER_ITERS=" + std::to_string(tier_iters_) + " && "
                              : "";
        return pre + bin + (fl.empty() ? "" : " " + fl) + " \"" + harness_ + "\" \"" + modpath +
               "\" 2>&1";
#else
        return env + "timeout " + std::to_string(timeout_s_) + " " + bin +
               (fl.empty() ? "" : " " + fl) + " '" + harness_ + "' '" + modpath + "' 2>&1";
#endif
    }

    bool probe() const {
        if (!have_tool_or_path(cfg_.binary)) return false;
        // The flags must be accepted by this binary (unknown V8 flag => nonzero exit).
        std::string cmd = cfg_.binary + (cfg_.flags.empty() ? "" : " " + cfg_.flags) +
                          " -e 0 >/dev/null 2>&1";
#if defined(NEMESIS_OS_WINDOWS)
        cmd = cfg_.binary + (cfg_.flags.empty() ? "" : " " + cfg_.flags) + " -e 0 >NUL 2>NUL";
#endif
        return std::system(cmd.c_str()) == 0;
    }

    // A binary is usable if it's on PATH or is an existing file path.
    static bool have_tool_or_path(const std::string& bin) {
        if (have_tool(bin)) return true;
        std::ifstream f(bin);
        return f.good();
    }

    // Extract the last RES/TRAP/... token the harness printed.
    static std::string parse_token(const std::string& out) {
        static const char* toks[] = {"RES ", "TRAP", "INVALID", "ERR"};
        std::string found;
        size_t i = 0;
        while (i < out.size()) {
            size_t nl = out.find('\n', i);
            std::string line =
                out.substr(i, nl == std::string::npos ? std::string::npos : nl - i);
            for (const char* t : toks)
                if (line.rfind(t, 0) == 0) { found = line; break; }
            if (nl == std::string::npos) break;
            i = nl + 1;
        }
        return found;
    }

    static ExecStatus classify(int rc, int* signal) {
        *signal = 0;
        if (rc == 0) return ExecStatus::Ok;
        if (rc == 2) return ExecStatus::Invalid;
        if (rc == 124) return ExecStatus::Timeout;
        if (rc >= 128) {
            int sig = rc - 128;
            if (sig == 9) return ExecStatus::Timeout;  // SIGKILL — usually OOM/timeout kill
            *signal = sig;
            return ExecStatus::Crash;  // any fatal signal is a real fault
        }
        return ExecStatus::Error;  // rc 3/4 = harness plumbing; never inflate to a crash
    }

    std::string tmp_path() const {
        static uint64_t ctr = 0;
        return temp_dir() + "nemesis_exec_" + std::to_string(++ctr) + ".wasm";
    }

    V8Config cfg_;
    std::string harness_;
    int timeout_s_;
    int tier_iters_ = 0;  // 0 = harness default (20000); >0 caps it (fast/minimize mode)
    mutable int avail_ = -1;
};

// The eight V8 Wasm configurations (v1..v8). Ordered from least- to most-optimized so v1
// (baseline Liftoff) is the trusted reference tier — note V8's --jitless disables Wasm
// entirely, so the lowest *usable* Wasm tier is Liftoff, not a pure interpreter. All share
// the one installed node by default; override binary per slot for cross-version differential.
// Unsupported flags on a given build => that slot reports NOT_WIRED.
inline std::vector<V8Config> default_v8_configs(const std::string& binary = "node") {
    return {
        {"v1-liftoff",     binary, "--liftoff --no-wasm-tier-up"},
        {"v2-turbofan",    binary, "--no-liftoff --no-turboshaft-wasm"},
        {"v3-turboshaft",  binary, "--no-liftoff --turboshaft-wasm"},
        {"v4-tierup",      binary, "--liftoff --wasm-tier-up"},
        {"v5-eager",       binary, "--no-wasm-lazy-compilation --liftoff --wasm-tier-up"},
        {"v6-unroll",      binary, "--no-liftoff --wasm-loop-unrolling"},
        {"v7-genwrap",     binary, "--no-liftoff --no-wasm-generic-wrapper"},
        {"v8-ts-tierup",   binary, "--liftoff --wasm-tier-up --turboshaft-wasm"},
    };
}

}  // namespace nemesis
