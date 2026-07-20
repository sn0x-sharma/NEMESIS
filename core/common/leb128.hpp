// leb128.hpp — LEB128 / SLEB128 variable-length integer encoders.
//
// WHY: Wasm binary format encodes every count, index, size, and integer literal as
// LEB128 (unsigned) or SLEB128 (signed). The lifter cannot emit a single valid module
// without these, so they live in `common/` as the lowest-level shared primitive.
#pragma once
#include <cstdint>
#include <vector>

namespace nemesis {

// Unsigned LEB128.
inline void encode_uleb(uint64_t value, std::vector<uint8_t>& out) {
    do {
        uint8_t byte = value & 0x7F;
        value >>= 7;
        if (value != 0) byte |= 0x80;
        out.push_back(byte);
    } while (value != 0);
}

// Signed LEB128 (two's complement, sign-extended terminating byte).
inline void encode_sleb(int64_t value, std::vector<uint8_t>& out) {
    bool more = true;
    while (more) {
        uint8_t byte = value & 0x7F;
        value >>= 7;  // arithmetic shift (sign-extends)
        bool sign_bit_set = (byte & 0x40) != 0;
        if ((value == 0 && !sign_bit_set) || (value == -1 && sign_bit_set)) {
            more = false;
        } else {
            byte |= 0x80;
        }
        out.push_back(byte);
    }
}

}  // namespace nemesis
