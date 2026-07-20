// triage.hpp — crash de-duplication + first-pass exploitability classification.
//
// WHY: A fuzzer that runs long enough re-discovers the same bug thousands of times. Triage
// collapses duplicates to one bucket and attaches a coarse exploitability signal so a human
// looks at distinct, ranked bugs — not a flood. Two pieces:
//
//   1. crash_bucket() — a stable key derived from the fatal signal + the most specific
//      engine-emitted lines (assertion text, "Fatal error", sanitizer summary, top frames).
//      Same root cause -> same key, so the corpus keeps one repro per bug.
//
//   2. classify_exploitability() — a heuristic verdict from the crash text: a controlled
//      write / sanitizer heap-write is ranked above a null-dereference read. This is a
//      *triage hint*, never a proof; the tool finds and ranks, it does not weaponize.
//
// The heuristic is engine-agnostic (matches SpiderMonkey/V8/ASan phrasings) so the same
// triage works once an instrumented target is wired in.
#pragma once
#include <cstdint>
#include <string>

#include "exec/target.hpp"

namespace nemesis {

// FNV-1a — small, stable, dependency-free. Used to fold a bucket string into a short hex id.
inline uint64_t fnv1a(const std::string& s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

inline std::string hex16(uint64_t h) {
    static const char* d = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 15; i >= 0; --i) { out[i] = d[h & 0xF]; h >>= 4; }
    return out;
}

// Lines whose presence pins a crash to a root cause. First match wins, in priority order.
inline bool line_is_signature(const std::string& line) {
    static const char* keys[] = {
        "AddressSanitizer", "SUMMARY: ", "ERROR: ", "Assertion", "assertion",
        "MOZ_CRASH", "Fatal error", "segfault", "SIGSEGV", "SIGABRT",
        "#0 ", "#1 ", "#2 ", "RangeError", "abort",
    };
    for (const char* k : keys)
        if (line.find(k) != std::string::npos) return true;
    return false;
}

// Build a de-dup key: fatal signal + up to the first few signature lines of the output.
inline std::string crash_bucket(const ExecResult& r) {
    std::string key = "sig" + std::to_string(r.signal) + "|";
    int taken = 0;
    size_t i = 0;
    while (i < r.output.size() && taken < 3) {
        size_t nl = r.output.find('\n', i);
        std::string line = r.output.substr(i, nl == std::string::npos ? std::string::npos : nl - i);
        if (line_is_signature(line)) { key += line + "|"; ++taken; }
        if (nl == std::string::npos) break;
        i = nl + 1;
    }
    return hex16(fnv1a(key));
}

// Coarse, honest exploitability tiers. Ordering encodes triage priority, not a CVSS score.
enum class ExploitHint : uint8_t {
    Unknown = 0,
    NullDeref,       // near-null read/write — usually low value
    UncontrolledOob, // out-of-bounds at an address the input does not obviously control
    ControlledWrite, // write primitive / sanitizer heap-write — highest triage priority
};

inline const char* exploit_hint_name(ExploitHint h) {
    switch (h) {
        case ExploitHint::ControlledWrite: return "controlled-write";
        case ExploitHint::UncontrolledOob: return "uncontrolled-oob";
        case ExploitHint::NullDeref: return "null-deref";
        case ExploitHint::Unknown: return "unknown";
    }
    return "unknown";
}

inline ExploitHint classify_exploitability(const ExecResult& r) {
    const std::string& o = r.output;
    auto has = [&](const char* s) { return o.find(s) != std::string::npos; };

    if (has("WRITE of size") || has("heap-buffer-overflow") || has("write to")) {
        // A sanitizer-reported write is the strongest available signal.
        if (has("WRITE") || has("write")) return ExploitHint::ControlledWrite;
    }
    if (has("SEGV on unknown address 0x000000000") || has("null") || has("0x00000000")) {
        return ExploitHint::NullDeref;
    }
    if (has("heap-buffer-overflow") || has("READ of size") || has("out of bounds") ||
        has("OOB")) {
        return ExploitHint::UncontrolledOob;
    }
    if (r.signal == 6) return ExploitHint::UncontrolledOob;  // SIGABRT: assertion/guard hit
    if (r.signal == 11) return ExploitHint::NullDeref;       // bare SIGSEGV, no detail
    return ExploitHint::Unknown;
}

}  // namespace nemesis
