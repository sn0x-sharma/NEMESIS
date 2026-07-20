// cve_bias.hpp — CVE-frequency-weighted strategy scheduler (feature #61, CVEMutator).
//
// WHY: Not every bug class is equally fertile. The CVE database records how often each class
// actually occurs in shipped browser-engine bugs (type-confusion >> oob > uaf > miscompile).
// This scheduler biases which strategy the fuzz loop seeds from toward those high-frequency
// classes — directed fuzzing that spends the mutation budget where real bugs historically
// cluster. It reads a weights file (build/cve_weights.txt, one "<class> <count>" per line,
// emitted by `nemesis cve weights` from the live DB); if absent it falls back to a built-in
// distribution mirroring the current DB. Learning from CVE data, applied to *finding* bugs.
#pragma once
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/rng.hpp"
#include "strategies/strategies.hpp"

namespace nemesis {

class CveBias {
public:
    // Load class weights from the DB-derived file, else use the built-in fallback.
    explicit CveBias(const std::string& weights_path = "build/cve_weights.txt") {
        if (!load(weights_path)) {
            // Fallback mirrors the current cve_db.json distribution (counts).
            weights_ = {{"type-confusion", 125}, {"oob", 82}, {"uaf", 48},
                        {"miscompile", 6}, {"sandbox-escape", 1}};
            source_ = "built-in (cve_db distribution)";
        }
    }

    const std::string& source() const { return source_; }

    // Weight of one strategy = its class's CVE frequency (min 1 so every strategy can fire).
    double weight_of(const Strategies::Named& s) const {
        auto it = weights_.find(s.bug_class ? s.bug_class : "");
        return it != weights_.end() ? static_cast<double>(it->second) : 1.0;
    }

    // Pick a strategy name weighted by CVE class frequency.
    std::string pick(const std::vector<Strategies::Named>& cat, Rng& rng) const {
        double total = 0;
        for (const auto& s : cat) total += weight_of(s);
        double r = (static_cast<double>(rng.next()) / static_cast<double>(UINT64_MAX)) * total;
        for (const auto& s : cat) {
            r -= weight_of(s);
            if (r <= 0) return s.name;
        }
        return cat.empty() ? "" : cat.back().name;
    }

private:
    bool load(const std::string& path) {
        std::ifstream f(path);
        if (!f) return false;
        std::string cls;
        long cnt;
        bool any = false;
        while (f >> cls >> cnt) { weights_[cls] = cnt; any = true; }
        if (any) source_ = path;
        return any;
    }

    std::unordered_map<std::string, long> weights_;
    std::string source_;
};

}  // namespace nemesis
