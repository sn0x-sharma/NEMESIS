// differential.hpp — cross-config differential oracle (the silent-wrong-value finder).
//
// WHY: A crash is only the loud subset of JIT bugs. The dangerous, high-value class is a
// *miscompilation*: an optimizing tier computes a different result than the interpreter for
// the same deterministic Wasm module. Those never crash — they silently return the wrong
// value, which in a real engine is a type-confusion / OOB primitive. Wasm semantics are
// deterministic, so the oracle is simple and sound: run one module under every available V8
// config (v1..v8) and if two configs disagree on the result token, that is a real bug.
//
// v1 (--jitless interpreter) is the trusted reference; a disagreement between it and any
// optimizing config is the strongest signal, but any config-vs-config disagreement counts.
#pragma once
#include <memory>
#include <string>
#include <vector>

#include "exec/target.hpp"

namespace nemesis {

struct ConfigOutcome {
    std::string label;
    ExecResult result;
};

struct DiffReport {
    bool diverged = false;   // >=2 configs produced different comparable result tokens
    bool crashed = false;    // >=1 config crashed
    std::vector<ConfigOutcome> outcomes;

    // Distinct comparable result tokens seen (for reporting the disagreement set).
    std::vector<std::string> distinct_results() const {
        std::vector<std::string> out;
        for (const auto& o : outcomes) {
            if (!o.result.comparable()) continue;
            bool seen = false;
            for (const auto& e : out) if (e == o.result.result) { seen = true; break; }
            if (!seen) out.push_back(o.result.result);
        }
        return out;
    }

    bool interesting() const { return diverged || crashed; }
};

// Holds the set of available config-targets and runs a module across all of them.
class Differential {
public:
    // Takes ownership of the available targets; callers filter with available() first.
    explicit Differential(std::vector<std::unique_ptr<Target>> targets)
        : targets_(std::move(targets)) {}

    size_t config_count() const { return targets_.size(); }

    DiffReport run(const std::vector<uint8_t>& wasm) {
        DiffReport rep;
        std::string first_token;
        bool have_first = false;
        for (auto& t : targets_) {
            ExecResult r = t->run(wasm);
            if (r.status == ExecStatus::Crash) rep.crashed = true;
            if (r.comparable()) {
                if (!have_first) { first_token = r.result; have_first = true; }
                else if (r.result != first_token) rep.diverged = true;
            }
            rep.outcomes.push_back({t->name(), std::move(r)});
        }
        return rep;
    }

private:
    std::vector<std::unique_ptr<Target>> targets_;
};

}  // namespace nemesis
