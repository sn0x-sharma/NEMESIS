// rng.hpp — xoshiro256** deterministic PRNG.
//
// WHY: A fuzzer must be reproducible — given the same seed, the same programs and
// mutations must result, so any crash can be replayed exactly. std::mt19937 is slow in
// the hot loop; xoshiro256** is tiny, fast, and has good statistical quality. Seedable
// so `--seed` reproduces a run bit-for-bit.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace nemesis {

class Rng {
public:
    explicit Rng(uint64_t seed = 0x9E3779B97F4A7C15ULL) { reseed(seed); }

    void reseed(uint64_t seed) {
        // SplitMix64 to spread a single seed across the 256-bit state.
        for (auto& s : s_) {
            seed += 0x9E3779B97F4A7C15ULL;
            uint64_t z = seed;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
            s = z ^ (z >> 31);
        }
    }

    uint64_t next() {
        const uint64_t result = rotl(s_[1] * 5, 7) * 9;
        const uint64_t t = s_[1] << 17;
        s_[2] ^= s_[0];
        s_[3] ^= s_[1];
        s_[1] ^= s_[2];
        s_[0] ^= s_[3];
        s_[2] ^= t;
        s_[3] = rotl(s_[3], 45);
        return result;
    }

    uint32_t next_u32() { return static_cast<uint32_t>(next() >> 32); }

    // Uniform in [0, n). Returns 0 for n == 0.
    uint64_t below(uint64_t n) { return n == 0 ? 0 : next() % n; }

    // True with probability p (0..1).
    bool chance(double p) { return (next() >> 11) * (1.0 / 9007199254740992.0) < p; }

    // Pick a random element index; caller guarantees non-empty.
    template <typename T>
    const T& pick(const std::vector<T>& v) { return v[below(v.size())]; }

    int32_t next_i32() { return static_cast<int32_t>(next_u32()); }

private:
    static uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
    uint64_t s_[4];
};

}  // namespace nemesis
