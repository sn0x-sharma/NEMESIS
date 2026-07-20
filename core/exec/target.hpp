// target.hpp — execution target interface + outcome classification.
//
// WHY: The fuzz loop must run a candidate module against *some* engine and learn one of a
// small set of outcomes, without caring how the engine is driven. This interface is that
// boundary: a one-shot subprocess target (V8NodeTarget) plugs in now; a persistent REPRL
// target (needs an instrumented engine) plugs in later behind the same Result type. The
// loop, dedup, and classifier code never change when the engine does.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace nemesis {

// The outcome of executing one module. `CRASH` is the only class that represents a real
// engine bug; TRAP/OK are normal, INVALID means the validation gate leaked.
enum class ExecStatus : uint8_t {
    Ok,       // ran (or trapped) cleanly — no bug
    Invalid,  // engine rejected the module (validation gate should prevent this)
    Timeout,  // execution exceeded the wall-clock budget (possible infinite-loop/livelock)
    Crash,    // process killed by a fatal signal — a real memory-safety / engine bug
    Error,    // harness/plumbing failure (could not spawn, etc.) — not a target bug
};

struct ExecResult {
    ExecStatus status = ExecStatus::Error;
    int exit_code = -1;   // raw decoded exit code (>=128 => killed by signal exit_code-128)
    int signal = 0;       // fatal signal number if status==Crash, else 0
    std::string output;   // captured stderr/stdout (feeds the triage stack-hash)
    std::string result;   // canonical comparable token: "RES <v>" / "TRAP" (for diffing)

    bool is_bug() const { return status == ExecStatus::Crash; }
    // Two OK executions are comparable for divergence only if both produced a token.
    bool comparable() const { return status == ExecStatus::Ok && !result.empty(); }
};

inline const char* exec_status_name(ExecStatus s) {
    switch (s) {
        case ExecStatus::Ok: return "OK";
        case ExecStatus::Invalid: return "INVALID";
        case ExecStatus::Timeout: return "TIMEOUT";
        case ExecStatus::Crash: return "CRASH";
        case ExecStatus::Error: return "ERROR";
    }
    return "?";
}

// Abstract engine target. Implementations run one Wasm module and classify the outcome.
class Target {
public:
    virtual ~Target() = default;

    // Human-readable name for logs/telemetry (e.g. "v8-node", "reprl-spidermonkey").
    virtual const char* name() const = 0;

    // True if this target can actually execute on the current box. A NOT_WIRED target
    // (needs an instrumented engine build absent here) returns false and the CLI reports
    // it honestly instead of pretending to fuzz.
    virtual bool available() const = 0;

    // Execute one module (raw Wasm bytes) and return its classified outcome.
    virtual ExecResult run(const std::vector<uint8_t>& wasm) = 0;
};

}  // namespace nemesis
