// reprl.hpp — REPRL (persistent read-eval-print-reset loop) target — NOT_WIRED here.
//
// WHY: One-shot subprocess execution (V8NodeTarget) pays full process-startup cost per
// module — hundreds of executions/sec at best. REPRL keeps a single instrumented engine
// process alive and feeds it modules over a control-fd pair with a per-execution state
// reset, reaching ~10^4-10^5 exec/sec. That throughput is what makes coverage-guided
// fuzzing productive.
//
// HONEST STATUS: REPRL requires an engine built with the REPRL entrypoint (a Fuzzilli-
// patched SpiderMonkey/V8 or equivalent). No such build exists on this box, so this target
// reports available()==false and run() returns ExecStatus::Error. The interface is real so
// that supplying an instrumented engine later is a drop-in — no loop/triage changes.
#pragma once
#include <string>
#include <vector>

#include "exec/target.hpp"

namespace nemesis {

class ReprlTarget : public Target {
public:
    explicit ReprlTarget(std::string engine_path = "") : engine_(std::move(engine_path)) {}

    const char* name() const override { return "reprl"; }

    // Needs an instrumented engine binary that speaks the REPRL protocol; none here.
    bool available() const override { return false; }

    ExecResult run(const std::vector<uint8_t>&) override {
        ExecResult r;
        r.status = ExecStatus::Error;
        r.output = "NOT_WIRED: REPRL needs an instrumented engine build (see docs/CAPABILITY-MATRIX.md)";
        return r;
    }

private:
    std::string engine_;
};

}  // namespace nemesis
