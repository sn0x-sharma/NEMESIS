// lifter.cpp — see lifter.hpp for the "why".
//
// Encodes the IL into a Wasm binary. The GC surface (reference value types, rec-group
// type section, struct/array/i31 and ref.cast/test instructions) is the reason NEMESIS
// exists, so those encodings live here and are exercised by the selftest against V8.
#include "lifter/lifter.hpp"

#include <utility>

#include "common/bytes.hpp"

namespace nemesis {

enum SectionId : uint8_t {
    SEC_TYPE = 1,
    SEC_FUNCTION = 3,
    SEC_TABLE = 4,
    SEC_EXPORT = 7,
    SEC_ELEMENT = 9,
    SEC_CODE = 10,
};

// GC / reference opcode constants.
enum : uint8_t {
    OP_REF_NULL = 0xD0,
    OP_REF_IS_NULL = 0xD1,
    OP_GC_PREFIX = 0xFB,
};
// 0xFB sub-opcodes.
enum : uint8_t {
    GC_STRUCT_NEW = 0,
    GC_STRUCT_NEW_DEFAULT = 1,
    GC_STRUCT_GET = 2,
    GC_STRUCT_SET = 5,
    GC_ARRAY_NEW_DEFAULT = 7,
    GC_ARRAY_NEW_FIXED = 8,
    GC_ARRAY_GET = 11,
    GC_ARRAY_LEN = 15,
    GC_REF_TEST = 20,
    GC_REF_TEST_NULL = 21,
    GC_REF_CAST = 22,
    GC_REF_CAST_NULL = 23,
    GC_REF_I31 = 28,
    GC_I31_GET_S = 29,
};

// A heap type as SLEB128: concrete -> non-negative index; abstract -> its negative code.
static void emit_heaptype_concrete(ByteBuf& b, int64_t index) { b.sleb(index); }
static void emit_heaptype(ByteBuf& b, int64_t ht_value) { b.sleb(ht_value); }

static void emit_valtype(ByteBuf& b, const ValType& v) {
    if (v.is_num()) {
        b.u8(v.num);
        return;
    }
    // Reference type long form: 0x64 (ref ht) or 0x63 (ref null ht), then heaptype.
    b.u8(v.nullable ? 0x63 : 0x64);
    if (v.ht_concrete)
        emit_heaptype_concrete(b, static_cast<int64_t>(v.ht_index));
    else
        emit_heaptype(b, v.ht_abs);
}

static void emit_field(ByteBuf& b, const Field& f) {
    emit_valtype(b, f.type);
    b.u8(f.mut ? 0x01 : 0x00);
}

// Emit one type definition's composite type (bare comptype == final subtype, no supers).
static void emit_comptype(ByteBuf& b, const TypeDef& t) {
    // Wrap in a sub-type declaration when this def has a supertype or is explicitly
    // non-final: 0x50 = sub (non-final), 0x4F = sub final, then a vec of supertype indices.
    if (t.super_index >= 0 || !t.is_final) {
        b.u8(t.is_final ? 0x4F : 0x50);
        if (t.super_index >= 0) { b.uleb(1); b.uleb((uint64_t)t.super_index); }
        else b.uleb(0);
    }
    switch (t.kind) {
        case TypeDef::Func:
            b.u8(0x60);
            b.uleb(t.func.params.size());
            for (const ValType& p : t.func.params) emit_valtype(b, p);
            b.uleb(t.func.results.size());
            for (const ValType& r : t.func.results) emit_valtype(b, r);
            break;
        case TypeDef::Struct:
            b.u8(0x5F);
            b.uleb(t.fields.size());
            for (const Field& f : t.fields) emit_field(b, f);
            break;
        case TypeDef::Array:
            b.u8(0x5E);
            emit_field(b, t.elem);
            break;
    }
}

static void emit_instr(ByteBuf& b, const Instr& in) {
    switch (in.op) {
        case Op::Nop: b.u8(0x01); break;
        case Op::I32Const: b.u8(0x41); b.sleb(in.imm); break;
        case Op::I64Const: b.u8(0x42); b.sleb(in.imm); break;
        case Op::F32Const: {
            b.u8(0x43);
            uint32_t v = static_cast<uint32_t>(in.imm);
            for (int i = 0; i < 4; ++i) b.u8((v >> (8 * i)) & 0xFF);
            break;
        }
        case Op::F64Const: {
            b.u8(0x44);
            uint64_t v = static_cast<uint64_t>(in.imm);
            for (int i = 0; i < 8; ++i) b.u8((v >> (8 * i)) & 0xFF);
            break;
        }
        case Op::LocalGet: b.u8(0x20); b.uleb(static_cast<uint64_t>(in.imm)); break;
        case Op::LocalSet: b.u8(0x21); b.uleb(static_cast<uint64_t>(in.imm)); break;
        case Op::LocalTee: b.u8(0x22); b.uleb(static_cast<uint64_t>(in.imm)); break;
        case Op::I32Add: b.u8(0x6A); break;
        case Op::I32Sub: b.u8(0x6B); break;
        case Op::I32Mul: b.u8(0x6C); break;
        case Op::I32And: b.u8(0x71); break;
        case Op::I32Or: b.u8(0x72); break;
        case Op::I32Xor: b.u8(0x73); break;
        case Op::I64Add: b.u8(0x7C); break;
        // comparisons
        case Op::I32Eqz: b.u8(0x45); break;
        case Op::I32Eq: b.u8(0x46); break;
        case Op::I32Ne: b.u8(0x47); break;
        case Op::I32LtS: b.u8(0x48); break;
        case Op::I32GtS: b.u8(0x4A); break;
        case Op::I32LeS: b.u8(0x4C); break;
        case Op::I32GeS: b.u8(0x4E); break;
        // control flow (imm = blocktype for Block/Loop/If; label depth for Br/BrIf)
        case Op::Block: b.u8(0x02); b.sleb(in.imm); break;
        case Op::Loop: b.u8(0x03); b.sleb(in.imm); break;
        case Op::If: b.u8(0x04); b.sleb(in.imm); break;
        case Op::Else: b.u8(0x05); break;
        case Op::End: b.u8(0x0B); break;
        case Op::Br: b.u8(0x0C); b.uleb((uint64_t)in.imm); break;
        case Op::BrIf: b.u8(0x0D); b.uleb((uint64_t)in.imm); break;
        case Op::Call: b.u8(0x10); b.uleb((uint64_t)in.imm); break;
        case Op::CallIndirect: b.u8(0x11); b.uleb((uint64_t)in.imm); b.uleb((uint64_t)in.imm2); break;
        case Op::ReturnCall: b.u8(0x12); b.uleb((uint64_t)in.imm); break;
        case Op::ReturnCallIndirect: b.u8(0x13); b.uleb((uint64_t)in.imm); b.uleb((uint64_t)in.imm2); break;
        case Op::Drop: b.u8(0x1A); break;
        case Op::Return: b.u8(0x0F); break;

        case Op::RefNull: b.u8(OP_REF_NULL); emit_heaptype(b, in.imm); break;
        case Op::RefIsNull: b.u8(OP_REF_IS_NULL); break;
        case Op::StructNew: b.u8(OP_GC_PREFIX); b.uleb(GC_STRUCT_NEW); b.uleb((uint64_t)in.imm); break;
        case Op::StructNewDefault: b.u8(OP_GC_PREFIX); b.uleb(GC_STRUCT_NEW_DEFAULT); b.uleb((uint64_t)in.imm); break;
        case Op::StructGet: b.u8(OP_GC_PREFIX); b.uleb(GC_STRUCT_GET); b.uleb((uint64_t)in.imm); b.uleb((uint64_t)in.imm2); break;
        case Op::StructSet: b.u8(OP_GC_PREFIX); b.uleb(GC_STRUCT_SET); b.uleb((uint64_t)in.imm); b.uleb((uint64_t)in.imm2); break;
        case Op::ArrayNewDefault: b.u8(OP_GC_PREFIX); b.uleb(GC_ARRAY_NEW_DEFAULT); b.uleb((uint64_t)in.imm); break;
        case Op::ArrayNewFixed: b.u8(OP_GC_PREFIX); b.uleb(GC_ARRAY_NEW_FIXED); b.uleb((uint64_t)in.imm); b.uleb((uint64_t)in.imm2); break;
        case Op::ArrayGet: b.u8(OP_GC_PREFIX); b.uleb(GC_ARRAY_GET); b.uleb((uint64_t)in.imm); break;
        case Op::ArrayLen: b.u8(OP_GC_PREFIX); b.uleb(GC_ARRAY_LEN); break;
        case Op::RefI31: b.u8(OP_GC_PREFIX); b.uleb(GC_REF_I31); break;
        case Op::I31GetS: b.u8(OP_GC_PREFIX); b.uleb(GC_I31_GET_S); break;
        case Op::RefCast:
            b.u8(OP_GC_PREFIX);
            b.uleb(in.imm2 ? GC_REF_CAST_NULL : GC_REF_CAST);
            emit_heaptype(b, in.imm);
            break;
        case Op::RefTest:
            b.u8(OP_GC_PREFIX);
            b.uleb(in.imm2 ? GC_REF_TEST_NULL : GC_REF_TEST);
            emit_heaptype(b, in.imm);
            break;
    }
}

static void emit_section(ByteBuf& out, uint8_t id, const ByteBuf& payload) {
    if (payload.empty()) return;
    out.u8(id);
    out.uleb(payload.size());
    out.raw(payload.data);
}

std::vector<uint8_t> lift(const Program& program) {
    ByteBuf out;
    const uint8_t header[8] = {0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00};
    out.raw(header, 8);

    // Type section. If any GC type is present, wrap ALL defs in one rec-group (0x4E)
    // so struct<->array mutual references validate; otherwise use flat singleton defs.
    ByteBuf types;
    if (program.has_gc_types()) {
        types.uleb(1);           // one rectype entry: the rec group
        types.u8(0x4E);          // rec
        types.uleb(program.types.size());
        for (const TypeDef& t : program.types) emit_comptype(types, t);
    } else {
        types.uleb(program.types.size());
        for (const TypeDef& t : program.types) emit_comptype(types, t);
    }
    emit_section(out, SEC_TYPE, types);

    ByteBuf funcs;
    funcs.uleb(program.funcs.size());
    for (const Function& f : program.funcs) funcs.uleb(f.type_index);
    emit_section(out, SEC_FUNCTION, funcs);

    // Table section (id 4): one funcref table sized to hold the element segment.
    if (!program.table_funcs.empty()) {
        ByteBuf table;
        table.uleb(1);                              // one table
        table.u8(0x70);                             // funcref elemtype
        table.u8(0x00);                             // limits: min only
        table.uleb(program.table_funcs.size());     // min == count
        emit_section(out, SEC_TABLE, table);
    }

    ByteBuf exports;
    exports.uleb(program.exports.size());
    for (const Export& e : program.exports) {
        exports.name(e.name);
        exports.u8(0x00);
        exports.uleb(e.func_index);
    }
    emit_section(out, SEC_EXPORT, exports);

    // Element section (id 9): active segment filling table 0 from offset 0 with func indices.
    if (!program.table_funcs.empty()) {
        ByteBuf elem;
        elem.uleb(1);                               // one segment
        elem.u8(0x00);                              // flags 0: active, table 0, funcref
        elem.u8(0x41); elem.sleb(0); elem.u8(0x0B); // offset expr: i32.const 0; end
        elem.uleb(program.table_funcs.size());
        for (uint32_t fi : program.table_funcs) elem.uleb(fi);
        emit_section(out, SEC_ELEMENT, elem);
    }

    ByteBuf code;
    code.uleb(program.funcs.size());
    for (const Function& f : program.funcs) {
        ByteBuf body;
        std::vector<std::pair<uint32_t, ValType>> groups;
        for (const ValType& lt : f.locals) {
            if (!groups.empty() && groups.back().second == lt)
                groups.back().first++;
            else
                groups.emplace_back(1u, lt);
        }
        body.uleb(groups.size());
        for (const auto& g : groups) {
            body.uleb(g.first);
            emit_valtype(body, g.second);
        }
        for (const Instr& in : f.body) emit_instr(body, in);
        body.u8(0x0B);

        code.uleb(body.size());
        code.raw(body.data);
    }
    emit_section(out, SEC_CODE, code);

    return out.data;
}

}  // namespace nemesis
