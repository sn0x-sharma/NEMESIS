// builder.hpp — ProgramBuilder: incremental IL construction (Wasm-GC capable).
//
// WHY: Incremental typed-IL builder. Generators (P1 random generator, P4 strategies)
// and mutators build programs through typed emit methods rather than pushing raw structs,
// so construction can stay type-correct. This exposes the type-table operations
// (func/struct/array), function bodies, locals, and the GC instruction emitters.
#pragma once
#include <string>
#include <vector>

#include "il/ir.hpp"

namespace nemesis {

class ProgramBuilder {
public:
    // --- type table ---------------------------------------------------------------
    uint32_t func_type(std::vector<ValType> params, std::vector<ValType> results) {
        TypeDef t;
        t.kind = TypeDef::Func;
        t.func = FuncType{std::move(params), std::move(results)};
        return add_type(std::move(t));
    }
    // super_index<0 => a plain final struct; >=0 => a `sub` of that supertype. A struct
    // subtype must include all its supertype's fields (in order) then its own, per Wasm-GC.
    uint32_t struct_type(std::vector<Field> fields, int32_t super_index = -1,
                         bool is_final = true) {
        TypeDef t;
        t.kind = TypeDef::Struct;
        t.fields = std::move(fields);
        t.super_index = super_index;
        t.is_final = is_final;
        // A type that others subtype must itself be non-final.
        if (super_index >= 0 && !prog_.types.empty())
            prog_.types[super_index].is_final = false;
        return add_type(std::move(t));
    }
    uint32_t array_type(Field elem, int32_t super_index = -1, bool is_final = true) {
        TypeDef t;
        t.kind = TypeDef::Array;
        t.elem = elem;
        t.super_index = super_index;
        t.is_final = is_final;
        if (super_index >= 0 && !prog_.types.empty())
            prog_.types[super_index].is_final = false;
        return add_type(std::move(t));
    }

    // --- functions ----------------------------------------------------------------
    uint32_t begin_function(uint32_t type_index) {
        Function f;
        f.type_index = type_index;
        prog_.funcs.push_back(std::move(f));
        cur_ = static_cast<int>(prog_.funcs.size()) - 1;
        return static_cast<uint32_t>(cur_);
    }
    uint32_t local(ValType t) {
        Function& f = current();
        f.locals.push_back(t);
        uint32_t params = static_cast<uint32_t>(prog_.types[f.type_index].func.params.size());
        return params + static_cast<uint32_t>(f.locals.size()) - 1;
    }
    void emit(Op op, int64_t imm = 0, int64_t imm2 = 0) {
        current().body.emplace_back(op, imm, imm2);
    }
    // Install a funcref table populated with `funcs` (by function index), enabling
    // call_indirect against those slots.
    void set_table(std::vector<uint32_t> funcs) { prog_.table_funcs = std::move(funcs); }

    void export_function(const std::string& name, uint32_t func_index) {
        prog_.exports.push_back(Export{name, func_index});
    }

    const Program& build() const { return prog_; }
    Program take() { return std::move(prog_); }

private:
    uint32_t add_type(TypeDef t) {
        prog_.types.push_back(std::move(t));
        return static_cast<uint32_t>(prog_.types.size() - 1);
    }
    Function& current() { return prog_.funcs.at(static_cast<size_t>(cur_)); }

    Program prog_;
    int cur_ = -1;
};

}  // namespace nemesis
