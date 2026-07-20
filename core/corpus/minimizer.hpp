// minimizer.hpp — delta-debug an IL program while a predicate stays true.
//
// WHY: A raw diverging/crashing module found by fuzzing is large and noisy. A report needs
// the *minimal* module that still triggers the behavior — it isolates the root cause and is
// what a vendor triager can act on. This is ddmin over the typed IL: repeatedly try to delete
// an instruction / local / type definition / shrink a constant, and keep the deletion only if
// a caller-supplied predicate still holds (e.g. "still validates and still diverges across
// tiers"). Deletions that break the stack fail the predicate (which revalidates) and are
// reverted, so minimization stays sound without understanding each op.
#pragma once
#include <functional>
#include <utility>

#include "il/ir.hpp"

namespace nemesis {

class Minimizer {
public:
    // Predicate: true iff `prog` still exhibits the property being preserved. It MUST include
    // validation, so unsound deletions are rejected automatically.
    using Predicate = std::function<bool(const Program&)>;

    explicit Minimizer(Predicate pred, int max_passes = 8)
        : pred_(std::move(pred)), max_passes_(max_passes) {}

    int probes() const { return probes_; }

    // Returns the minimized program. If the predicate does not hold at entry, returns the
    // input unchanged (nothing to minimize against).
    Program minimize(Program prog) {
        if (!holds(prog)) return prog;
        for (int pass = 0; pass < max_passes_; ++pass) {
            bool changed = false;
            changed |= drop_instructions(prog);
            changed |= drop_locals(prog);
            changed |= drop_types(prog);
            changed |= shrink_consts(prog);
            if (!changed) break;  // fixpoint
        }
        return prog;
    }

private:
    bool holds(const Program& p) { ++probes_; return pred_(p); }

    // Try deleting each instruction (back to front so indices stay valid), keep if predicate
    // still holds. Back-to-front also tends to strip trailing dead code first.
    bool drop_instructions(Program& p) {
        bool changed = false;
        for (auto& f : p.funcs) {
            for (size_t i = f.body.size(); i-- > 0;) {
                if (f.body.size() <= 1) break;
                Instr saved = f.body[i];
                f.body.erase(f.body.begin() + i);
                if (holds(p)) changed = true;
                else f.body.insert(f.body.begin() + i, saved);  // revert
            }
        }
        return changed;
    }

    // Drop a declared local if nothing references it after removal (predicate re-checks).
    bool drop_locals(Program& p) {
        bool changed = false;
        for (auto& f : p.funcs) {
            for (size_t li = f.locals.size(); li-- > 0;) {
                ValType saved = f.locals[li];
                f.locals.erase(f.locals.begin() + li);
                if (holds(p)) changed = true;
                else f.locals.insert(f.locals.begin() + li, saved);
            }
        }
        return changed;
    }

    // Drop a trailing type definition if unused (predicate/validation catches references).
    bool drop_types(Program& p) {
        bool changed = false;
        for (size_t ti = p.types.size(); ti-- > 0;) {
            if (p.types.size() <= 1) break;
            // Only safe to drop the last type without reindexing; ddmin from the tail.
            if (ti != p.types.size() - 1) continue;
            TypeDef saved = p.types[ti];
            p.types.pop_back();
            if (holds(p)) { changed = true; }
            else { p.types.push_back(saved); }
        }
        return changed;
    }

    // Canonicalize constants toward 0 (smaller, clearer repros) when it preserves behavior.
    bool shrink_consts(Program& p) {
        bool changed = false;
        for (auto& f : p.funcs) {
            for (auto& in : f.body) {
                if ((in.op == Op::I32Const || in.op == Op::I64Const) && in.imm != 0) {
                    int64_t saved = in.imm;
                    in.imm = 0;
                    if (holds(p)) changed = true;
                    else in.imm = saved;
                }
            }
        }
        return changed;
    }

    Predicate pred_;
    int max_passes_;
    int probes_ = 0;
};

// Count instructions across all functions — the headline size metric for a repro.
inline size_t instr_count(const Program& p) {
    size_t n = 0;
    for (const auto& f : p.funcs) n += f.body.size();
    return n;
}

}  // namespace nemesis
