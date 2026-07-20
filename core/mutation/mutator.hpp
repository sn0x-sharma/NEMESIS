// mutator.hpp — IL mutation engine (structured-IL, validity-gated).
//
// WHY: A corpus-driven fuzzer must *evolve* existing interesting programs, not regenerate
// random ones each time — that's how it drills into a code path once coverage finds it.
// Mutating typed IL (not raw bytes) keeps most mutants structurally sane; the caller then
// re-validates every mutant against the engine and keeps only the valid ones (the
// "validator-gated mutation" the spec requires). This module implements the core
// structured-IL mutator family: OperationMutator (retype constants/ops/local-indices — validity-
// preserving), HavocMutator (insert/delete/duplicate instructions — gated), and
// SpliceMutator (graft an instruction run from a donor program — gated).
#pragma once
#include <algorithm>
#include <vector>

#include "common/rng.hpp"
#include "il/ir.hpp"

namespace nemesis {

class Mutator {
public:
    explicit Mutator(uint64_t seed) : rng_(seed) {}

    // Apply 1-3 random mutations to `p`. `donor` (optional) enables splicing.
    void mutate(Program& p, const Program* donor = nullptr) {
        if (p.funcs.empty()) return;
        int k = 1 + static_cast<int>(rng_.below(3));
        for (int i = 0; i < k; ++i) apply_one(p, donor);
    }

private:
    // Weighted selection: validity-preserving mutators (const/binop/local) dominate so the
    // mutant stays valid ~most of the time, while the stack-breaking structural mutators
    // (insert/delete/splice) still fire often enough to explore new shapes. Production
    // structured-IL fuzzers tune this ratio the same way — cheap valid mutants > raw havoc.
    void apply_one(Program& p, const Program* donor) {
        bool have_donor = donor && !donor->funcs.empty();
        // Cumulative weights: const 3, binop 2, local 2, insert 1, delete 1, splice 1.
        int total = have_donor ? 10 : 9;
        uint64_t r = rng_.below(total);
        if (r < 3)       mutate_const(p);
        else if (r < 5)  mutate_binop(p);
        else if (r < 7)  mutate_local(p);
        else if (r < 8)  havoc_insert(p);
        else if (r < 9)  havoc_delete(p);
        else             splice(p, *donor);
    }

    Function& rand_func(Program& p) { return p.funcs[rng_.below(p.funcs.size())]; }

    // Retarget a constant's value (validity-preserving).
    void mutate_const(Program& p) {
        Function& f = rand_func(p);
        std::vector<size_t> idx;
        for (size_t i = 0; i < f.body.size(); ++i) {
            Op o = f.body[i].op;
            if (o == Op::I32Const || o == Op::I64Const) idx.push_back(i);
        }
        if (idx.empty()) return;
        Instr& in = f.body[idx[rng_.below(idx.size())]];
        if (in.op == Op::I32Const) {
            static const int64_t boundary[] = {0, -1, 1, 0x7FFFFFFF, (int64_t)0x80000000, 255};
            in.imm = rng_.chance(0.6) ? boundary[rng_.below(6)] : rng_.next_i32();
        } else {
            in.imm = static_cast<int64_t>(rng_.next());
        }
    }

    // Swap one i32 binop for another of the same arity (validity-preserving).
    void mutate_binop(Program& p) {
        static const Op binops[] = {Op::I32Add, Op::I32Sub, Op::I32Mul,
                                    Op::I32And, Op::I32Or,  Op::I32Xor};
        Function& f = rand_func(p);
        std::vector<size_t> idx;
        for (size_t i = 0; i < f.body.size(); ++i)
            for (Op b : binops)
                if (f.body[i].op == b) { idx.push_back(i); break; }
        if (idx.empty()) return;
        f.body[idx[rng_.below(idx.size())]].op = binops[rng_.below(6)];
    }

    // Repoint a local.get/set/tee to another local *of the same type* (validity-preserving).
    void mutate_local(Program& p) {
        Function& f = rand_func(p);
        std::vector<ValType> ltypes = local_types(p, f);
        std::vector<size_t> idx;
        for (size_t i = 0; i < f.body.size(); ++i) {
            Op o = f.body[i].op;
            if (o == Op::LocalGet || o == Op::LocalSet || o == Op::LocalTee) idx.push_back(i);
        }
        if (idx.empty() || ltypes.empty()) return;
        Instr& in = f.body[idx[rng_.below(idx.size())]];
        if (in.imm < 0 || static_cast<size_t>(in.imm) >= ltypes.size()) return;
        const ValType& want = ltypes[in.imm];
        std::vector<int> same;
        for (size_t i = 0; i < ltypes.size(); ++i)
            if (ltypes[i] == want) same.push_back((int)i);
        if (!same.empty()) in.imm = same[rng_.below(same.size())];
    }

    // Insert a Nop (safe) or duplicate an instruction (gated by revalidation).
    void havoc_insert(Program& p) {
        Function& f = rand_func(p);
        size_t pos = rng_.below(f.body.size() + 1);
        if (rng_.chance(0.5) || f.body.empty())
            f.body.insert(f.body.begin() + pos, Instr(Op::Nop));
        else
            f.body.insert(f.body.begin() + pos, f.body[rng_.below(f.body.size())]);
    }

    // Delete a random instruction (gated by revalidation — often underflows the stack).
    void havoc_delete(Program& p) {
        Function& f = rand_func(p);
        if (f.body.empty()) return;
        f.body.erase(f.body.begin() + rng_.below(f.body.size()));
    }

    // Graft a contiguous instruction run from a donor function (gated by revalidation).
    void splice(Program& p, const Program& donor) {
        if (donor.funcs.empty()) return;
        const Function& src = donor.funcs[rng_.below(donor.funcs.size())];
        if (src.body.size() < 2) return;
        Function& dst = rand_func(p);
        size_t a = rng_.below(src.body.size());
        size_t len = 1 + rng_.below(std::min<size_t>(4, src.body.size() - a));
        size_t at = rng_.below(dst.body.size() + 1);
        dst.body.insert(dst.body.begin() + at, src.body.begin() + a, src.body.begin() + a + len);
    }

    std::vector<ValType> local_types(const Program& p, const Function& f) const {
        std::vector<ValType> out = p.types[f.type_index].func.params;
        out.insert(out.end(), f.locals.begin(), f.locals.end());
        return out;
    }

    Rng rng_;
};

}  // namespace nemesis
