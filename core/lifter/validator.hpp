// validator.hpp — module validation gate.
//
// WHY: A non-negotiable engineering constraint: every generated module must be validated
// before it is sent to any target — invalid-module noise wastes fuzzing time and
// pollutes crash triage. On this box the ground-truth validator is V8's
// `WebAssembly.validate()` reached through node. When node is absent we fall back to a
// structural pre-check (magic/version) and say so honestly. P1 will additionally gate
// every mutation through this path.
#pragma once
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "common/platform.hpp"

namespace nemesis {

struct ValidationResult {
    bool valid = false;
    std::string detail;
    bool used_engine = false;  // true if a real engine (node/V8) validated it
};

inline bool structural_ok(const std::vector<uint8_t>& m, std::string& why) {
    if (m.size() < 8) { why = "too short"; return false; }
    if (!(m[0] == 0x00 && m[1] == 0x61 && m[2] == 0x73 && m[3] == 0x6D)) {
        why = "bad magic";
        return false;
    }
    if (!(m[4] == 0x01 && m[5] == 0x00 && m[6] == 0x00 && m[7] == 0x00)) {
        why = "bad version";
        return false;
    }
    return true;
}

// Validate a module. Writes it to `tmp_path` (also handy as a repro artifact) and, when
// node is available, runs V8's WebAssembly.validate over it.
inline ValidationResult validate_module(const std::vector<uint8_t>& module,
                                        const std::string& tmp_path) {
    std::string why;
    if (!structural_ok(module, why)) return {false, "structural: " + why, false};

    {
        std::ofstream f(tmp_path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(module.data()),
                static_cast<std::streamsize>(module.size()));
    }

    if (have_tool("node")) {
        std::string cmd =
            "node -e \"const fs=require('fs');"
            "process.exit(WebAssembly.validate(fs.readFileSync(process.argv[1]))?0:1)\" " +
            tmp_path + " 2>&1";
        int rc = 0;
        run_capture(cmd, &rc);
        return {rc == 0,
                rc == 0 ? "node WebAssembly.validate: OK" : "node WebAssembly.validate: REJECTED",
                true};
    }
    return {true, "structural-only (node not found)", false};
}

}  // namespace nemesis
