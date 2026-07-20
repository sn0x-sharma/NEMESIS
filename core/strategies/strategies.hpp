// strategies.hpp — CVE-root-cause-shaped program generators (the divergence inducers).
//
// WHY: The random generator explores broadly but rarely lands on the precise shape that
// makes an optimizing JIT tier disagree with the baseline. Each strategy here is a small,
// deterministic generator that emits a program shaped like the root cause of a real,
// documented Wasm-GC / JIT bug (see seeds/cve_db.json). Fed through the differential oracle
// (v1-liftoff vs v2..v8), a strategy that reproduces a live miscompilation shows up as a
// result-token divergence — a silent-wrong-value bug — with no instrumentation.
//
// These generate *test inputs* that trigger engine bugs; they are not exploits. Every
// strategy is validity-gated by the caller (only valid modules reach the oracle).
//
// Naming maps 1:1 to cve_db.json `nemesis_strategy` fields so a divergence can be attributed
// back to the CVE family it resembles.
#pragma once
#include <string>
#include <vector>

#include "common/rng.hpp"
#include "il/builder.hpp"
#include "il/ir.hpp"

namespace nemesis {

class Strategies {
public:
    explicit Strategies(uint64_t seed) : rng_(seed) {}

    struct Named {
        const char* name;
        const char* cve;
        const char* note;
        const char* bug_class;  // maps to cve_db.json bug_class for CVE-frequency weighting
    };

    // Catalogue — kept in sync with cve_db.json nemesis_strategy fields. bug_class ties each
    // strategy to a CVE class so the CVE-bias scheduler can weight it by real-world frequency.
    static std::vector<Named> catalogue() {
        return {
            {"jit_tierup_stress", "CVE-2026-10702", "hot loop + type-specialized arithmetic; baseline vs optimizing", "miscompile"},
            {"hot_loop_gc_narrow", "CVE-2025-0291", "gc ref through single-block loop; Turboshaft type narrowing", "miscompile"},
            {"nullability_canon", "CVE-2025-5959", "ref types differing only in nullability; canonicalization", "type-confusion"},
            {"subtype_cast_matrix", "CVE-2024-2887", "struct subtype chain + ref.cast/ref.test across it", "type-confusion"},
            {"recgroup_subtype_bomb", "CVE-2024-6100", "deep rec-group subtype chain; isorecursive validator", "type-confusion"},
            {"array_oob_loop", "CVE-2026-11645", "array index driven by loop induction var near length bound", "oob"},
            {"call_indirect_confusion", "class#5", "hot call_indirect through a funcref table; target-type speculation", "type-confusion"},
            {"licm_bounds_elision", "class#2", "loop-invariant array index; LICM hoists the bounds check", "oob"},
            {"osr_type_mismatch", "class#3", "long loop (OSR entry) with a ref that transitions null->non-null mid-loop", "type-confusion"},
            {"gc_barrier_elision", "class#4", "hot old<-young ref store into a struct field; write-barrier surface", "uaf"},
            {"shape_mutation_during_opt", "class#1", "ref alternates between two subtypes mid-loop; ref.test speculation", "type-confusion"},
            {"deopt_bomb", "misc", "hot loop with a mid-run phase change (array path -> struct path)", "miscompile"},
            {"tail_call_stress", "class#5", "return_call (tail call) carrying the loop result into a helper", "type-confusion"},
        };
    }

    // Dispatch by name. Returns a valid-by-construction module for that strategy.
    Program generate(const std::string& name) {
        if (name == "jit_tierup_stress") return jit_tierup_stress();
        if (name == "hot_loop_gc_narrow") return hot_loop_gc_narrow();
        if (name == "nullability_canon") return nullability_canon();
        if (name == "subtype_cast_matrix") return subtype_cast_matrix();
        if (name == "recgroup_subtype_bomb") return recgroup_subtype_bomb();
        if (name == "array_oob_loop") return array_oob_loop();
        if (name == "call_indirect_confusion") return call_indirect_confusion();
        if (name == "licm_bounds_elision") return licm_bounds_elision();
        if (name == "osr_type_mismatch") return osr_type_mismatch();
        if (name == "gc_barrier_elision") return gc_barrier_elision();
        if (name == "shape_mutation_during_opt") return shape_mutation_during_opt();
        if (name == "deopt_bomb") return deopt_bomb();
        if (name == "tail_call_stress") return tail_call_stress();
        return jit_tierup_stress();
    }

private:
    // Blocktype "empty" immediate (SLEB -64 == 0x40).
    static constexpr int64_t kEmptyBT = -64;

    // A hot counting loop wrapper: runs `body` N times with induction var `i`. Caller emits
    // the loop body (must be stack-neutral). Forces the export through JIT tier-up.
    // Layout: local i, then: loop { body; i = i+1; if i<N br 0 } .
    void hot_loop(ProgramBuilder& b, uint32_t i, int64_t n,
                  const std::vector<Instr>& body) {
        b.emit(Op::I32Const, 0);
        b.emit(Op::LocalSet, i);
        b.emit(Op::Loop, kEmptyBT);
        for (const Instr& in : body) b.emit(in.op, in.imm, in.imm2);
        b.emit(Op::LocalGet, i);
        b.emit(Op::I32Const, 1);
        b.emit(Op::I32Add);
        b.emit(Op::LocalTee, i);
        b.emit(Op::I32Const, n);
        b.emit(Op::I32LtS);
        b.emit(Op::BrIf, 0);
        b.emit(Op::End);
    }

    // CVE-2026-10702 family: a hot loop doing type-specialized i32 arithmetic that the
    // optimizing tier will specialize; accumulate into acc, return acc.
    Program jit_tierup_stress() {
        ProgramBuilder b;
        uint32_t t = b.func_type({}, {ValType::i32()});
        uint32_t f = b.begin_function(t);
        uint32_t i = b.local(ValType::i32());
        uint32_t acc = b.local(ValType::i32());
        std::vector<Instr> body = {
            Instr(Op::LocalGet, acc), Instr(Op::LocalGet, i), Instr(Op::LocalGet, i),
            Instr(Op::I32Mul), Instr(Op::I32Add), Instr(Op::LocalSet, acc),  // acc += i*i
        };
        hot_loop(b, i, 100000, body);
        b.emit(Op::LocalGet, acc);
        b.export_function("run", f);
        return b.take();
    }

    // CVE-2025-0291 family: allocate a gc struct, carry a ref to it through a single-block
    // hot loop, then read a field. The single-block loop back-edge is what Turboshaft's
    // type analysis mis-narrowed. Return the field value.
    Program hot_loop_gc_narrow() {
        ProgramBuilder b;
        uint32_t s = b.struct_type({Field{ValType::i32(), true}});
        uint32_t t = b.func_type({}, {ValType::i32()});
        uint32_t f = b.begin_function(t);
        uint32_t i = b.local(ValType::i32());
        uint32_t r = b.local(ValType::ref(s, /*nullable=*/true));
        // r = struct.new(7)
        b.emit(Op::I32Const, 7);
        b.emit(Op::StructNew, s);
        b.emit(Op::LocalSet, r);
        // single-block hot loop that re-reads/re-stores the field each iter
        std::vector<Instr> body = {
            Instr(Op::LocalGet, r), Instr(Op::LocalGet, r), Instr(Op::StructGet, (int64_t)s, 0),
            Instr(Op::I32Const, 1), Instr(Op::I32Add), Instr(Op::StructSet, (int64_t)s, 0),
        };
        hot_loop(b, i, 50000, body);
        b.emit(Op::LocalGet, r);
        b.emit(Op::StructGet, s, 0);
        b.export_function("run", f);
        return b.take();
    }

    // CVE-2025-5959 family: two array types identical except element nullability; a value of
    // the nullable-elem type flows where the non-null-elem type is expected. Canonicalization
    // that ignores nullability treats them as equal. Return array length as an observable.
    Program nullability_canon() {
        ProgramBuilder b;
        // elem type: (ref null $s) vs (ref $s) — same $s, different nullability.
        uint32_t s = b.struct_type({Field{ValType::i32(), true}});
        uint32_t arr_nullable = b.array_type(Field{ValType::ref(s, true), true});
        uint32_t arr_nonnull = b.array_type(Field{ValType::ref(s, false), true});
        uint32_t t = b.func_type({}, {ValType::i32()});
        uint32_t f = b.begin_function(t);
        uint32_t i = b.local(ValType::i32());
        uint32_t a = b.local(ValType::ref(arr_nullable, true));
        // a = array.new_default $arr_nullable, len 4  (elements are null refs)
        b.emit(Op::I32Const, 4);
        b.emit(Op::ArrayNewDefault, arr_nullable);
        b.emit(Op::LocalSet, a);
        std::vector<Instr> body = {
            // ref.cast the nullable-elem array to the non-null-elem array type in a hot loop
            Instr(Op::LocalGet, a), Instr(Op::RefCast, (int64_t)arr_nonnull, /*nullable*/1),
            Instr(Op::ArrayLen), Instr(Op::Drop),
        };
        hot_loop(b, i, 20000, body);
        b.emit(Op::LocalGet, a);
        b.emit(Op::ArrayLen);
        b.export_function("run", f);
        return b.take();
    }

    // CVE-2024-2887 family: a struct subtype chain A <: B <: C, allocate the most-derived,
    // then ref.cast/ref.test up and down the chain inside a hot loop. Cast confusion across
    // the chain is the bug shape. Return an i32 from ref.test results.
    Program subtype_cast_matrix() {
        ProgramBuilder b;
        uint32_t a = b.struct_type({Field{ValType::i32(), true}}, -1, /*final=*/false);       // base
        uint32_t bb = b.struct_type({Field{ValType::i32(), true}, Field{ValType::i32(), true}},
                                    (int32_t)a, false);                                       // A <: base
        uint32_t c = b.struct_type({Field{ValType::i32(), true}, Field{ValType::i32(), true},
                                    Field{ValType::i32(), true}}, (int32_t)bb, true);         // B <: A
        uint32_t t = b.func_type({}, {ValType::i32()});
        uint32_t f = b.begin_function(t);
        uint32_t i = b.local(ValType::i32());
        uint32_t acc = b.local(ValType::i32());
        uint32_t r = b.local(ValType::ref(a, true));  // static type = base
        // r = struct.new_default $c  (most-derived)
        b.emit(Op::StructNewDefault, c);
        b.emit(Op::LocalSet, r);
        std::vector<Instr> body = {
            // acc += ref.test $r as $c ; acc += ref.test $r as $bb
            Instr(Op::LocalGet, acc),
            Instr(Op::LocalGet, r), Instr(Op::RefTest, (int64_t)c, 0),
            Instr(Op::I32Add),
            Instr(Op::LocalGet, r), Instr(Op::RefTest, (int64_t)bb, 0),
            Instr(Op::I32Add), Instr(Op::LocalSet, acc),
        };
        hot_loop(b, i, 30000, body);
        b.emit(Op::LocalGet, acc);
        b.export_function("run", f);
        return b.take();
    }

    // CVE-2024-6100 family: deep subtype chain to stress the isorecursive type validator +
    // optimizer type propagation. Depth is the knob. Return depth-derived observable.
    Program recgroup_subtype_bomb() {
        ProgramBuilder b;
        int depth = 8 + static_cast<int>(rng_.below(24));  // 8..31 deep
        std::vector<Field> fields = {Field{ValType::i32(), true}};
        int32_t prev = -1;
        uint32_t last = 0;
        for (int d = 0; d < depth; ++d) {
            bool final = (d == depth - 1);
            last = b.struct_type(fields, prev, final);
            prev = static_cast<int32_t>(last);
            fields.push_back(Field{ValType::i32(), true});  // each level adds a field
        }
        uint32_t t = b.func_type({}, {ValType::i32()});
        uint32_t f = b.begin_function(t);
        uint32_t r = b.local(ValType::ref(last, true));
        b.emit(Op::StructNewDefault, last);
        b.emit(Op::LocalSet, r);
        b.emit(Op::LocalGet, r);
        b.emit(Op::RefTest, (int64_t)last, 0);  // observable: 1
        b.export_function("run", f);
        return b.take();
    }

    // CVE-2026-11645 family: array indexed by a loop induction variable whose bound the
    // optimizer must range-analyze against the array length. Off-by-one range reasoning is
    // the OOB shape. Stays in-bounds by construction (valid module); the oracle catches a
    // tier that computes a different sum.
    Program array_oob_loop() {
        ProgramBuilder b;
        uint32_t arr = b.array_type(Field{ValType::i32(), true});
        uint32_t t = b.func_type({}, {ValType::i32()});
        uint32_t f = b.begin_function(t);
        uint32_t i = b.local(ValType::i32());
        uint32_t acc = b.local(ValType::i32());
        uint32_t a = b.local(ValType::ref(arr, true));
        b.emit(Op::I32Const, 64);
        b.emit(Op::ArrayNewDefault, arr);
        b.emit(Op::LocalSet, a);
        std::vector<Instr> body = {
            // acc += array.get a[i & 63]  (masked in-bounds; range analysis stress)
            Instr(Op::LocalGet, acc),
            Instr(Op::LocalGet, a),
            Instr(Op::LocalGet, i), Instr(Op::I32Const, 63), Instr(Op::I32And),
            Instr(Op::ArrayGet, (int64_t)arr),
            Instr(Op::I32Add), Instr(Op::LocalSet, acc),
        };
        hot_loop(b, i, 64, body);
        b.emit(Op::LocalGet, acc);
        b.export_function("run", f);
        return b.take();
    }

    // Priority class #5: call_indirect target-type speculation. Four same-signature leaf
    // functions live in a funcref table; a hot loop indirect-calls a table slot chosen by the
    // induction variable. The optimizing tier speculates the indirect target/type — the
    // surface where target-type confusion miscompiles live. Same signature => valid, no trap,
    // so the loop actually tiers up. Return the accumulated sum.
    Program call_indirect_confusion() {
        ProgramBuilder b;
        uint32_t sig = b.func_type({}, {ValType::i32()});
        uint32_t f0 = b.begin_function(sig); b.emit(Op::I32Const, 10);
        uint32_t f1 = b.begin_function(sig); b.emit(Op::I32Const, 20);
        uint32_t f2 = b.begin_function(sig); b.emit(Op::I32Const, 30);
        uint32_t f3 = b.begin_function(sig); b.emit(Op::I32Const, 40);
        uint32_t main = b.begin_function(sig);
        uint32_t i = b.local(ValType::i32());
        uint32_t acc = b.local(ValType::i32());
        b.set_table({f0, f1, f2, f3});
        std::vector<Instr> body = {
            Instr(Op::LocalGet, acc),
            Instr(Op::LocalGet, i), Instr(Op::I32Const, 3), Instr(Op::I32And),  // idx 0..3
            Instr(Op::CallIndirect, (int64_t)sig, 0),
            Instr(Op::I32Add), Instr(Op::LocalSet, acc),
        };
        hot_loop(b, i, 40000, body);
        b.emit(Op::LocalGet, acc);
        b.export_function("run", main);
        return b.take();
    }

    // Priority class #2: LICM bounds-check elision. A hot loop reads array[idx] where idx is
    // loop-invariant (set once before the loop). The optimizer proves the bounds check is
    // loop-invariant and hoists it out of the loop (LICM); a wrong range analysis there is an
    // OOB. In-bounds by construction (idx masked), so it stays valid; the oracle catches a
    // tier that computes a different sum. Return the accumulated value.
    Program licm_bounds_elision() {
        ProgramBuilder b;
        uint32_t arr = b.array_type(Field{ValType::i32(), true});
        uint32_t t = b.func_type({}, {ValType::i32()});
        uint32_t f = b.begin_function(t);
        uint32_t i = b.local(ValType::i32());
        uint32_t acc = b.local(ValType::i32());
        uint32_t idx = b.local(ValType::i32());
        uint32_t a = b.local(ValType::ref(arr, true));
        b.emit(Op::I32Const, 16);
        b.emit(Op::ArrayNewDefault, arr);
        b.emit(Op::LocalSet, a);
        // idx = 15 & 7 = 7 (in-bounds, but the optimizer must range-analyze to know that)
        b.emit(Op::I32Const, 15);
        b.emit(Op::I32Const, 7);
        b.emit(Op::I32And);
        b.emit(Op::LocalSet, idx);
        std::vector<Instr> body = {
            Instr(Op::LocalGet, acc),
            Instr(Op::LocalGet, a), Instr(Op::LocalGet, idx), Instr(Op::ArrayGet, (int64_t)arr),
            Instr(Op::I32Add), Instr(Op::LocalSet, acc),
        };
        hot_loop(b, i, 100000, body);
        b.emit(Op::LocalGet, acc);
        b.export_function("run", f);
        return b.take();
    }

    // Priority class #3: OSR mid-loop type/value transition. A very long loop (forces OSR:
    // the JIT swaps in optimized code while the loop is running) holds a nullable ref that
    // starts null and becomes non-null on the first iteration. OSR entry captures the loop
    // state; wrong speculation about the ref across the OSR boundary is the bug shape. Return
    // the accumulated field value.
    Program osr_type_mismatch() {
        ProgramBuilder b;
        uint32_t s = b.struct_type({Field{ValType::i32(), true}});
        uint32_t t = b.func_type({}, {ValType::i32()});
        uint32_t f = b.begin_function(t);
        uint32_t i = b.local(ValType::i32());
        uint32_t acc = b.local(ValType::i32());
        uint32_t r = b.local(ValType::ref(s, true));  // starts null
        std::vector<Instr> body = {
            // if (r == null) r = struct.new(5); else acc += r.f
            Instr(Op::LocalGet, r), Instr(Op::RefIsNull),
            Instr(Op::If, -64),
            Instr(Op::I32Const, 5), Instr(Op::StructNew, (int64_t)s), Instr(Op::LocalSet, r),
            Instr(Op::Else),
            Instr(Op::LocalGet, acc), Instr(Op::LocalGet, r), Instr(Op::StructGet, (int64_t)s, 0),
            Instr(Op::I32Add), Instr(Op::LocalSet, acc),
            Instr(Op::End),
        };
        hot_loop(b, i, 200000, body);
        b.emit(Op::LocalGet, acc);
        b.export_function("run", f);
        return b.take();
    }

    // Priority class #4: GC write-barrier elision. A long-lived (old) outer struct gets a
    // freshly allocated (young) inner struct stored into its ref field every iteration. That
    // old<-young store requires a GC write barrier; an optimizer that elides it lets a minor
    // GC miss the reference (UAF). Allocating each iteration also drives GC. Return the sum of
    // the stored field values read back.
    Program gc_barrier_elision() {
        ProgramBuilder b;
        uint32_t inner = b.struct_type({Field{ValType::i32(), true}});
        uint32_t outer = b.struct_type({Field{ValType::ref(inner, true), true}});
        uint32_t t = b.func_type({}, {ValType::i32()});
        uint32_t f = b.begin_function(t);
        uint32_t i = b.local(ValType::i32());
        uint32_t acc = b.local(ValType::i32());
        uint32_t o = b.local(ValType::ref(outer, true));
        b.emit(Op::StructNewDefault, outer);  // outer{ field = null }
        b.emit(Op::LocalSet, o);
        std::vector<Instr> body = {
            // o.field = struct.new inner(i)   (old <- young ref store: write barrier)
            Instr(Op::LocalGet, o),
            Instr(Op::LocalGet, i), Instr(Op::StructNew, (int64_t)inner),
            Instr(Op::StructSet, (int64_t)outer, 0),
            // acc += o.field.f
            Instr(Op::LocalGet, acc),
            Instr(Op::LocalGet, o), Instr(Op::StructGet, (int64_t)outer, 0),
            Instr(Op::StructGet, (int64_t)inner, 0),
            Instr(Op::I32Add), Instr(Op::LocalSet, acc),
        };
        hot_loop(b, i, 50000, body);
        b.emit(Op::LocalGet, acc);
        b.export_function("run", f);
        return b.take();
    }

    // Priority class #1: type-confusion via shape mutation during optimization. A ref local
    // alternates between two subtypes (A and B<:A) each iteration, then ref.test targets the
    // more-derived type. The optimizing tier speculates a stable "shape"; the per-iteration
    // shape churn is where a mis-speculated type check confuses A and B. Return the test count.
    Program shape_mutation_during_opt() {
        ProgramBuilder b;
        uint32_t a = b.struct_type({Field{ValType::i32(), true}}, -1, /*final=*/false);
        uint32_t bb = b.struct_type({Field{ValType::i32(), true}, Field{ValType::i32(), true}},
                                    (int32_t)a, true);  // B <: A
        uint32_t t = b.func_type({}, {ValType::i32()});
        uint32_t f = b.begin_function(t);
        uint32_t i = b.local(ValType::i32());
        uint32_t acc = b.local(ValType::i32());
        uint32_t r = b.local(ValType::ref(a, true));  // static type = A
        std::vector<Instr> body = {
            Instr(Op::LocalGet, i), Instr(Op::I32Const, 1), Instr(Op::I32And),
            Instr(Op::If, -64),
            Instr(Op::StructNewDefault, (int64_t)bb), Instr(Op::LocalSet, r),   // r = B
            Instr(Op::Else),
            Instr(Op::StructNewDefault, (int64_t)a), Instr(Op::LocalSet, r),    // r = A
            Instr(Op::End),
            Instr(Op::LocalGet, acc),
            Instr(Op::LocalGet, r), Instr(Op::RefTest, (int64_t)bb, 0),          // test as B
            Instr(Op::I32Add), Instr(Op::LocalSet, acc),
        };
        hot_loop(b, i, 60000, body);
        b.emit(Op::LocalGet, acc);
        b.export_function("run", f);
        return b.take();
    }

    // A deoptimization analogue for Wasm: a hot loop whose work changes phase partway through
    // (array-indexing path for the first half, struct-field path for the second). The
    // optimizer specializes for the first phase; the mid-run switch invalidates those
    // assumptions — the boundary where phase-change miscompiles surface. Return the sum.
    Program deopt_bomb() {
        ProgramBuilder b;
        uint32_t arr = b.array_type(Field{ValType::i32(), true});
        uint32_t s = b.struct_type({Field{ValType::i32(), true}});
        uint32_t t = b.func_type({}, {ValType::i32()});
        uint32_t f = b.begin_function(t);
        uint32_t i = b.local(ValType::i32());
        uint32_t acc = b.local(ValType::i32());
        uint32_t aa = b.local(ValType::ref(arr, true));
        uint32_t r = b.local(ValType::ref(s, true));
        b.emit(Op::I32Const, 16); b.emit(Op::ArrayNewDefault, arr); b.emit(Op::LocalSet, aa);
        b.emit(Op::I32Const, 7); b.emit(Op::StructNew, s); b.emit(Op::LocalSet, r);
        std::vector<Instr> body = {
            Instr(Op::LocalGet, i), Instr(Op::I32Const, 100000), Instr(Op::I32LtS),
            Instr(Op::If, -64),
            Instr(Op::LocalGet, acc), Instr(Op::LocalGet, aa),
            Instr(Op::LocalGet, i), Instr(Op::I32Const, 15), Instr(Op::I32And),
            Instr(Op::ArrayGet, (int64_t)arr), Instr(Op::I32Add), Instr(Op::LocalSet, acc),
            Instr(Op::Else),
            Instr(Op::LocalGet, acc), Instr(Op::LocalGet, r), Instr(Op::StructGet, (int64_t)s, 0),
            Instr(Op::I32Add), Instr(Op::LocalSet, acc),
            Instr(Op::End),
        };
        hot_loop(b, i, 200000, body);
        b.emit(Op::LocalGet, acc);
        b.export_function("run", f);
        return b.take();
    }

    // Priority class #5 (tail-call form): build an accumulator in a hot loop, then return_call
    // a helper carrying that value. Tail calls reuse the current frame, so the JIT's
    // tail-call lowering + argument handling is the surface. Helper doubles the value; the
    // return_call's result becomes run()'s result. Return helper(acc).
    Program tail_call_stress() {
        ProgramBuilder b;
        uint32_t unary = b.func_type({ValType::i32()}, {ValType::i32()});  // (i32)->i32
        uint32_t nullary = b.func_type({}, {ValType::i32()});              // ()->i32
        uint32_t helper = b.begin_function(unary);
        b.emit(Op::LocalGet, 0); b.emit(Op::I32Const, 2); b.emit(Op::I32Mul);  // acc*2
        uint32_t run = b.begin_function(nullary);
        uint32_t i = b.local(ValType::i32());
        uint32_t acc = b.local(ValType::i32());
        std::vector<Instr> body = {
            Instr(Op::LocalGet, acc), Instr(Op::LocalGet, i), Instr(Op::I32Add),
            Instr(Op::LocalSet, acc),
        };
        hot_loop(b, i, 40000, body);
        b.emit(Op::LocalGet, acc);
        b.emit(Op::ReturnCall, helper);  // tail-call helper(acc); its result is run()'s result
        b.export_function("run", run);
        return b.take();
    }

    Rng rng_;
};

}  // namespace nemesis
