// generator.hpp — type-aware random IL program generator.
//
// WHY: A random *byte* generator produces invalid modules ~always; a random *instruction*
// generator produces type-invalid stacks ~always. The only way to generate deep,
// validator-valid Wasm-GC programs at volume is to generate typed *expression trees*:
// each recursive call emits exactly one value of a requested type, so the operand stack
// is correct by construction. This is how a typed-IL builder stays semantically
// valid. The generator first defines a random rec-group of struct/array types, then emits
// an exported `run() -> i32` whose body is a typed expression over those types — deep
// enough to stress the JIT's type reasoning, always valid enough to reach it.
#pragma once
#include <cstdint>
#include <vector>

#include "common/rng.hpp"
#include "il/builder.hpp"
#include "il/ir.hpp"

namespace nemesis {

class Generator {
public:
    struct Config {
        int max_types = 5;   // upper bound on struct/array defs
        int max_locals = 4;
        int max_depth = 5;   // expression tree depth
    };

    explicit Generator(uint64_t seed) : rng_(seed) {}

    Program generate() { return generate(Config()); }

    Program generate(Config cfg) {
        pb_ = ProgramBuilder();
        structs_.clear();
        arrays_.clear();
        locals_.clear();

        int ntypes = 1 + static_cast<int>(rng_.below(cfg.max_types));
        for (int i = 0; i < ntypes; ++i) {
            if (rng_.chance(0.5)) def_struct();
            else def_array();
        }

        uint32_t ft = pb_.func_type({}, {ValType::i32()});
        uint32_t fn = pb_.begin_function(ft);

        int nlocals = static_cast<int>(rng_.below(cfg.max_locals + 1));
        for (int i = 0; i < nlocals; ++i) {
            ValType lt = rand_local_type();
            locals_.push_back(lt);
            pb_.local(lt);
        }

        // A few "statements" that set locals (dataflow), then the final i32 result.
        int stmts = static_cast<int>(rng_.below(3));
        for (int i = 0; i < stmts; ++i) emit_local_set(cfg.max_depth - 1);

        gen_value(ValType::i32(), cfg.max_depth);
        pb_.export_function("run", fn);
        return pb_.take();
    }

private:
    struct StructInfo { uint32_t index; std::vector<ValType> fields; };
    struct ArrayInfo { uint32_t index; ValType elem; };

    // ---- type definition -------------------------------------------------------
    void def_struct() {
        int nf = 1 + static_cast<int>(rng_.below(3));
        std::vector<Field> fs;
        std::vector<ValType> fts;
        for (int i = 0; i < nf; ++i) {
            ValType t = rand_field_type();
            fs.push_back(Field{t, rng_.chance(0.7)});
            fts.push_back(t);
        }
        structs_.push_back({pb_.struct_type(fs), fts});
    }
    void def_array() {
        ValType t = rand_field_type();
        arrays_.push_back({pb_.array_type(Field{t, true}), t});
    }

    // Field/element types: numeric-biased, sometimes a nullable ref to a defined type
    // (nullable keeps struct.new_default / array.new_default valid — defaultable).
    ValType rand_field_type() {
        uint32_t r = rng_.below(10);
        if (r < 6) return ValType::i32();
        if (r < 8) return ValType::i64();
        uint32_t total = structs_.size() + arrays_.size();
        if (total == 0) return ValType::i32();
        uint32_t pick = rng_.below(total);
        uint32_t idx = pick < structs_.size() ? structs_[pick].index
                                              : arrays_[pick - structs_.size()].index;
        return ValType::ref(idx, true);
    }

    // Locals must be defaultable: numeric or nullable ref.
    ValType rand_local_type() {
        uint32_t r = rng_.below(10);
        if (r < 6) return ValType::i32();
        if (r < 8) return ValType::i64();
        uint32_t total = structs_.size() + arrays_.size();
        if (total > 0 && rng_.chance(0.6)) {
            uint32_t pick = rng_.below(total);
            uint32_t idx = pick < structs_.size() ? structs_[pick].index
                                                  : arrays_[pick - structs_.size()].index;
            return ValType::ref(idx, true);
        }
        return ValType::absref(ht::kAny, true);
    }

    void emit_local_set(int depth) {
        if (locals_.empty()) return;
        uint32_t li = rng_.below(locals_.size());
        gen_value(locals_[li], depth < 1 ? 1 : depth);
        pb_.emit(Op::LocalSet, li);
    }

    // ---- typed value generation ------------------------------------------------
    void gen_value(const ValType& want, int depth) {
        if (want.is_num()) {
            if (want.num == 0x7F) return gen_i32(depth);
            if (want.num == 0x7E) return gen_i64(depth);
            // f32/f64/v128 aren't produced as field/local types in P1; emit a const.
            pb_.emit(want.num == 0x7D ? Op::F32Const : Op::F64Const, 0);
            return;
        }
        gen_ref(want, depth);
    }

    void gen_i32(int depth) {
        int choice = static_cast<int>(rng_.below(depth <= 0 ? 2 : 8));
        switch (choice) {
            case 0: pb_.emit(Op::I32Const, rand_i32()); return;
            case 1: {
                int li = local_of_num(0x7F);
                if (li >= 0) { pb_.emit(Op::LocalGet, li); return; }
                pb_.emit(Op::I32Const, rand_i32());
                return;
            }
            case 2: case 3: {  // binop
                gen_i32(depth - 1);
                gen_i32(depth - 1);
                static const Op ops[] = {Op::I32Add, Op::I32Sub, Op::I32Mul,
                                         Op::I32And, Op::I32Or,  Op::I32Xor};
                pb_.emit(ops[rng_.below(6)]);
                return;
            }
            case 4: {  // i31 roundtrip
                gen_i32(depth - 1);
                pb_.emit(Op::RefI31);
                pb_.emit(Op::I31GetS);
                return;
            }
            case 5: {  // array.len
                if (!arrays_.empty()) {
                    gen_arrayref(rng_.below(arrays_.size()), depth - 1);
                    pb_.emit(Op::ArrayLen);
                    return;
                }
                pb_.emit(Op::I32Const, rand_i32());
                return;
            }
            case 6: {  // struct.get of an i32 field
                int si = struct_with_i32_field();
                if (si >= 0) {
                    int fi = i32_field_index(structs_[si]);
                    gen_structref(si, depth - 1);
                    pb_.emit(Op::StructGet, structs_[si].index, fi);
                    return;
                }
                pb_.emit(Op::I32Const, rand_i32());
                return;
            }
            default: {  // array.get of an i32-element array
                int ai = array_with_i32_elem();
                if (ai >= 0) {
                    gen_arrayref(ai, depth - 1);
                    gen_i32(depth - 1);  // index (may trap OOB at runtime — acceptable)
                    pb_.emit(Op::ArrayGet, arrays_[ai].index);
                    return;
                }
                pb_.emit(Op::I32Const, rand_i32());
                return;
            }
        }
    }

    void gen_i64(int depth) {
        if (depth <= 0 || rng_.chance(0.6)) {
            int li = local_of_num(0x7E);
            if (li >= 0 && rng_.chance(0.5)) { pb_.emit(Op::LocalGet, li); return; }
            pb_.emit(Op::I64Const, static_cast<int64_t>(rng_.next()));
            return;
        }
        gen_i64(depth - 1);
        gen_i64(depth - 1);
        pb_.emit(Op::I64Add);
    }

    void gen_ref(const ValType& want, int depth) {
        if (!want.ht_concrete) {
            // abstract: i31/any/eq can be produced by ref.i31; else null.
            if ((want.ht_abs == ht::kI31 || want.ht_abs == ht::kAny || want.ht_abs == ht::kEq) &&
                depth > 0 && rng_.chance(0.7)) {
                gen_i32(depth - 1);
                pb_.emit(Op::RefI31);
                return;
            }
            pb_.emit(Op::RefNull, want.ht_abs);
            return;
        }
        // concrete: struct or array
        int si = find_struct(want.ht_index);
        int ai = find_array(want.ht_index);
        if (depth <= 0 || rng_.chance(0.15)) {
            pb_.emit(Op::RefNull, static_cast<int64_t>(want.ht_index));
            return;
        }
        if (si >= 0) return gen_structref(si, depth);
        if (ai >= 0) return gen_arrayref(ai, depth);
        pb_.emit(Op::RefNull, static_cast<int64_t>(want.ht_index));
    }

    void gen_structref(int si, int depth) {
        const StructInfo& s = structs_[si];
        int li = local_of_ref(s.index);
        uint32_t mode = rng_.below(4);
        if (mode == 0 && li >= 0) { pb_.emit(Op::LocalGet, li); return; }
        if (mode == 1) { pb_.emit(Op::StructNewDefault, s.index); return; }
        // struct.new: push each field value in order, then allocate.
        for (const ValType& f : s.fields) gen_value(f, depth - 1);
        pb_.emit(Op::StructNew, s.index);
    }

    void gen_arrayref(int ai, int depth) {
        const ArrayInfo& a = arrays_[ai];
        int li = local_of_ref(a.index);
        uint32_t mode = rng_.below(4);
        if (mode == 0 && li >= 0) { pb_.emit(Op::LocalGet, li); return; }
        if (mode == 1) {  // array.new_default (len)
            gen_i32_small(depth - 1);
            pb_.emit(Op::ArrayNewDefault, a.index);
            return;
        }
        // array.new_fixed with a small count
        int count = static_cast<int>(rng_.below(4));
        for (int i = 0; i < count; ++i) gen_value(a.elem, depth - 1);
        pb_.emit(Op::ArrayNewFixed, a.index, count);
    }

    // ---- small helpers ---------------------------------------------------------
    void gen_i32_small(int) { pb_.emit(Op::I32Const, static_cast<int64_t>(rng_.below(8))); }
    int32_t rand_i32() {
        // bias toward boundary values that stress JIT range analysis.
        switch (rng_.below(8)) {
            case 0: return 0;
            case 1: return -1;
            case 2: return 1;
            case 3: return 0x7FFFFFFF;
            case 4: return static_cast<int32_t>(0x80000000);
            case 5: return static_cast<int32_t>(rng_.below(256));
            default: return rng_.next_i32();
        }
    }

    int local_of_num(uint8_t num) const {
        std::vector<int> hits;
        for (size_t i = 0; i < locals_.size(); ++i)
            if (locals_[i].is_num() && locals_[i].num == num) hits.push_back((int)i);
        if (hits.empty()) return -1;
        return hits[rng_.below(hits.size())];
    }
    int local_of_ref(uint32_t type_index) const {
        std::vector<int> hits;
        for (size_t i = 0; i < locals_.size(); ++i)
            if (locals_[i].is_ref() && locals_[i].ht_concrete && locals_[i].ht_index == type_index)
                hits.push_back((int)i);
        if (hits.empty()) return -1;
        return hits[rng_.below(hits.size())];
    }
    int find_struct(uint32_t type_index) const {
        for (size_t i = 0; i < structs_.size(); ++i)
            if (structs_[i].index == type_index) return (int)i;
        return -1;
    }
    int find_array(uint32_t type_index) const {
        for (size_t i = 0; i < arrays_.size(); ++i)
            if (arrays_[i].index == type_index) return (int)i;
        return -1;
    }
    int struct_with_i32_field() const {
        std::vector<int> hits;
        for (size_t i = 0; i < structs_.size(); ++i)
            if (i32_field_index(structs_[i]) >= 0) hits.push_back((int)i);
        if (hits.empty()) return -1;
        return hits[rng_.below(hits.size())];
    }
    int array_with_i32_elem() const {
        std::vector<int> hits;
        for (size_t i = 0; i < arrays_.size(); ++i)
            if (arrays_[i].elem.is_num() && arrays_[i].elem.num == 0x7F) hits.push_back((int)i);
        if (hits.empty()) return -1;
        return hits[rng_.below(hits.size())];
    }
    static int i32_field_index(const StructInfo& s) {
        for (size_t i = 0; i < s.fields.size(); ++i)
            if (s.fields[i].is_num() && s.fields[i].num == 0x7F) return (int)i;
        return -1;
    }

    mutable Rng rng_;
    ProgramBuilder pb_;
    std::vector<StructInfo> structs_;
    std::vector<ArrayInfo> arrays_;
    std::vector<ValType> locals_;
};

}  // namespace nemesis
