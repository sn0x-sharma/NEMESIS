// ir.hpp — NEMESIS typed IL data model (Wasm-GC capable).
//
// WHY: Programs are represented as *typed operations over a typed heap graph*, not raw
// opcode bytes (the typed-IL insight). A byte flip on Wasm bytecode almost always
// yields an invalid module; a typed IL lets generators and mutators reason about
// value/heap types and stay validator-valid. This header models the Wasm-GC type graph
// (numeric + reference value types, struct/array/func type definitions, rec-groups) and
// the instruction set the lifter encodes. It intentionally covers the GC surface where
// the interesting JIT bugs live (struct/array allocation + field access, ref.cast/test,
// i31) while staying small enough to reason about.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace nemesis {

// Abstract heap type codes, encoded as their negative SLEB128 values (e.g. `any` is the
// single byte 0x6E which is SLEB(-18)). Concrete heap types use a non-negative type index.
namespace ht {
constexpr int32_t kNoFunc = -13;    // 0x73
constexpr int32_t kNoExtern = -14;  // 0x72
constexpr int32_t kNone = -15;      // 0x71
constexpr int32_t kFunc = -16;      // 0x70
constexpr int32_t kExtern = -17;    // 0x6F
constexpr int32_t kAny = -18;       // 0x6E
constexpr int32_t kEq = -19;        // 0x6D
constexpr int32_t kI31 = -20;       // 0x6C
constexpr int32_t kStruct = -21;    // 0x6B
constexpr int32_t kArray = -22;     // 0x6A
}  // namespace ht

// A Wasm value type: either numeric (i32/i64/f32/f64/v128) or a reference type
// `(ref null? <heaptype>)` where the heap type is abstract (ht::*) or a concrete index.
struct ValType {
    enum Kind : uint8_t { Num, Ref } kind = Num;
    uint8_t num = 0x7F;         // Num: wasm numeric byte
    bool nullable = true;       // Ref: nullable?
    bool ht_concrete = false;   // Ref: concrete type index vs abstract code
    int32_t ht_abs = ht::kAny;  // Ref & abstract: SLEB heap-type value
    uint32_t ht_index = 0;      // Ref & concrete: type index

    static ValType i32() { return num_(0x7F); }
    static ValType i64() { return num_(0x7E); }
    static ValType f32() { return num_(0x7D); }
    static ValType f64() { return num_(0x7C); }
    static ValType v128() { return num_(0x7B); }
    static ValType ref(uint32_t index, bool nullable = true) {
        ValType v;
        v.kind = Ref;
        v.ht_concrete = true;
        v.ht_index = index;
        v.nullable = nullable;
        return v;
    }
    static ValType absref(int32_t abs, bool nullable = true) {
        ValType v;
        v.kind = Ref;
        v.ht_concrete = false;
        v.ht_abs = abs;
        v.nullable = nullable;
        return v;
    }

    bool is_num() const { return kind == Num; }
    bool is_ref() const { return kind == Ref; }

    bool operator==(const ValType& o) const {
        if (kind != o.kind) return false;
        if (kind == Num) return num == o.num;
        if (nullable != o.nullable || ht_concrete != o.ht_concrete) return false;
        return ht_concrete ? ht_index == o.ht_index : ht_abs == o.ht_abs;
    }

private:
    static ValType num_(uint8_t b) {
        ValType v;
        v.kind = Num;
        v.num = b;
        return v;
    }
};

struct FuncType {
    std::vector<ValType> params;
    std::vector<ValType> results;
    bool operator==(const FuncType& o) const {
        return params == o.params && results == o.results;
    }
};

// A struct/array field: a storage type plus mutability. (Packed i8/i16 storage is a P4
// extension; P1 uses full value types.)
struct Field {
    ValType type;
    bool mut = true;
};

// A type definition: function, struct, or array. All defined types of a program that
// contains any GC type are emitted inside a single rec-group so struct<->array mutual
// references are possible (a fertile source of rec-group encoding + JIT bugs).
struct TypeDef {
    enum Kind : uint8_t { Func, Struct, Array } kind = Func;
    FuncType func;               // Func
    std::vector<Field> fields;   // Struct
    Field elem;                  // Array
    // Wasm-GC subtyping: if super_index >= 0 the def is emitted as a `sub` type declaring
    // that supertype; is_final=false lets other types further subtype it. Subtype chains +
    // ref.cast across them are the exact shape of several WASM-GC type-confusion CVEs.
    int32_t super_index = -1;
    bool is_final = true;
};

// IL operations. Each is semantic (carries typed immediates), not a raw byte.
enum class Op : uint16_t {
    Nop,
    // numeric
    I32Const, I64Const, F32Const, F64Const,
    LocalGet, LocalSet, LocalTee,
    I32Add, I32Sub, I32Mul, I32And, I32Or, I32Xor,
    I64Add,
    // comparisons (i32 result) — loop conditions + type-specialized branches
    I32Eqz, I32Eq, I32Ne, I32LtS, I32GtS, I32LeS, I32GeS,
    // control flow — hot loops force JIT tier-up; imm = blocktype (Block/Loop/If) or
    // label depth (Br/BrIf). blocktype -64 (0x40) = empty.
    Block, Loop, If, Else, End, Br, BrIf,
    Call,             // imm = function index
    CallIndirect,     // imm = type index, imm2 = table index  (consumes i32 table slot)
    ReturnCall,       // imm = function index  (tail call)
    ReturnCallIndirect, // imm = type index, imm2 = table index  (tail call)
    Drop, Return,
    // reference / GC  (imm = type index or heaptype; imm2 = field index / count / nullable)
    RefNull,          // imm = heaptype (abs<0 or concrete index)
    RefIsNull,
    StructNew,        // imm = type index
    StructNewDefault, // imm = type index
    StructGet,        // imm = type index, imm2 = field index
    StructSet,        // imm = type index, imm2 = field index
    ArrayNewDefault,  // imm = type index                (consumes i32 len)
    ArrayNewFixed,    // imm = type index, imm2 = count  (consumes `count` elems)
    ArrayGet,         // imm = type index                (consumes arrayref, i32 idx)
    ArrayLen,         // consumes arrayref -> i32
    RefI31,           // i32 -> i31ref
    I31GetS,          // i31ref -> i32
    RefCast,          // imm = heaptype, imm2 = nullable
    RefTest,          // imm = heaptype, imm2 = nullable
};

struct Instr {
    Op op;
    int64_t imm = 0;
    int64_t imm2 = 0;
    explicit Instr(Op o, int64_t a = 0, int64_t b = 0) : op(o), imm(a), imm2(b) {}
};

struct Function {
    uint32_t type_index = 0;
    std::vector<ValType> locals;
    std::vector<Instr> body;
};

struct Export {
    std::string name;
    uint32_t func_index = 0;
};

struct Program {
    std::vector<TypeDef> types;
    std::vector<Function> funcs;
    std::vector<Export> exports;
    // If non-empty: a funcref table of this size, populated (active element segment at
    // offset 0) with these function indices. Enables call_indirect — the surface for
    // call_indirect target type-confusion JIT bugs.
    std::vector<uint32_t> table_funcs;

    bool has_gc_types() const {
        for (const TypeDef& t : types)
            if (t.kind != TypeDef::Func) return true;
        return false;
    }
};

}  // namespace nemesis
