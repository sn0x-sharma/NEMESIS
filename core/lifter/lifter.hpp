// lifter.hpp — IL program -> Wasm binary encoder.
//
// WHY: This replaces hand-rolled per-probe bytecode emission with a single, tested
// IL->binary path. Every generator and mutator produces IL; exactly one component
// (the lifter) knows the Wasm binary format, so encoding bugs are found once, here,
// instead of scattered across probe code. P0 encodes the type/function/export/code
// sections for the numeric IL subset; P1 extends it with the GC type section
// (rec-groups, struct/array), globals, tables, and memory.
#pragma once
#include <cstdint>
#include <vector>

#include "il/ir.hpp"

namespace nemesis {

// Encode a complete IL program into a Wasm module binary.
std::vector<uint8_t> lift(const Program& program);

}  // namespace nemesis
