// bytes.hpp — ByteBuf: a growable byte buffer with Wasm-oriented helpers.
//
// WHY: The lifter builds a module by appending bytes, LEB-encoded integers, length-
// prefixed vectors, and nested sections. Centralizing that here keeps the lifter's
// encoding logic declarative and free of manual index bookkeeping.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "common/leb128.hpp"

namespace nemesis {

struct ByteBuf {
    std::vector<uint8_t> data;

    void u8(uint8_t b) { data.push_back(b); }
    void uleb(uint64_t v) { encode_uleb(v, data); }
    void sleb(int64_t v) { encode_sleb(v, data); }
    void raw(const std::vector<uint8_t>& v) { data.insert(data.end(), v.begin(), v.end()); }
    void raw(const uint8_t* p, size_t n) { data.insert(data.end(), p, p + n); }

    // A Wasm "name" / byte vector: uleb length prefix then raw bytes.
    void name(const std::string& s) {
        uleb(s.size());
        data.insert(data.end(), s.begin(), s.end());
    }

    size_t size() const { return data.size(); }
    bool empty() const { return data.empty(); }
};

}  // namespace nemesis
