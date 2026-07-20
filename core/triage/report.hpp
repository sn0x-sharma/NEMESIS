// report.hpp — finding → disclosure pack (the legitimate "auto-PoC").
//
// WHY: A finding is only useful if it can be reported. This packages a crash or a
// differential divergence into what a VRP/Bugzilla submission needs: a standalone repro
// (double-click HTML that re-triggers it), an honest severity (CVSS 3.1), a CVE-variant
// attribution, a reproducer-quality score, and a markdown report skeleton. It proves
// *impact* and *reproducibility* — it does NOT synthesize an exploit or shellcode. Severity
// is computed conservatively: a differential divergence is a confirmed miscompilation but
// not, by itself, proven memory-unsafe, so it is not auto-rated as critical RCE.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "exec/target.hpp"
#include "triage/triage.hpp"

namespace nemesis {

struct Finding {
    enum Kind : uint8_t { Crash, Divergence } kind = Divergence;
    std::string id;                 // bucket hash
    std::vector<uint8_t> wasm;
    std::string strategy;           // originating strategy name, if any
    std::string cve;                // attributed CVE family, if any
    int signal = 0;                 // fatal signal (Crash)
    ExploitHint hint = ExploitHint::Unknown;
    std::vector<std::pair<std::string, std::string>> config_results;  // label -> token
    bool deterministic = true;
    int repeat_runs = 0;
    // True only if a crash or a genuine cross-config divergence was actually observed. When
    // false (e.g. `report` run against an already-patched build), the pack must say so and
    // never assert a miscompilation that did not happen.
    bool anomalous = true;
};

// One-decimal CVSS score, no float noise.
inline std::string score_str(double s) {
    char b[8];
    std::snprintf(b, sizeof(b), "%.1f", s);
    return b;
}

// --- base64 (for embedding the wasm in a standalone HTML repro) ---------------------------
inline std::string base64(const std::vector<uint8_t>& in) {
    static const char* T =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        uint32_t n = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out += T[(n >> 18) & 63]; out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];  out += T[n & 63];
    }
    if (i < in.size()) {
        uint32_t n = in[i] << 16;
        if (i + 1 < in.size()) n |= in[i + 1] << 8;
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += (i + 1 < in.size()) ? T[(n >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}

// --- honest CVSS 3.1 ----------------------------------------------------------------------
// Browser memory-safety RCE reachable from a web page: AV:N/AC:L/PR:N/UI:R. A controlled
// write in the renderer with heap-sandbox implications is Scope:Changed, C/I/A:High -> ~9.6.
// A differential miscompilation not yet shown memory-unsafe is rated conservatively.
struct Cvss {
    std::string vector;
    double score = 0.0;
    const char* rating = "None";
};

inline Cvss cvss_for(const Finding& f) {
    Cvss c;
    if (!f.anomalous) {
        c.vector = "n/a (no anomaly reproduced on tested build)";
        c.score = 0.0; c.rating = "Informational";
        return c;
    }
    if (f.kind == Finding::Crash) {
        switch (f.hint) {
            case ExploitHint::ControlledWrite:
                c.vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H";
                c.score = 9.6; c.rating = "Critical"; break;
            case ExploitHint::UncontrolledOob:
                c.vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H";
                c.score = 7.6; c.rating = "High"; break;
            case ExploitHint::NullDeref:
            default:
                c.vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H";
                c.score = 6.5; c.rating = "Medium"; break;  // DoS-class until shown otherwise
        }
    } else {
        // Divergence = confirmed JIT correctness bug; memory-safety impact not yet proven.
        c.vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L";
        c.score = 5.0; c.rating = "Medium (miscompilation; exploitability TBD)";
    }
    return c;
}

// --- reproducer quality (0-100): deterministic + minimal-ish + self-contained ------------
inline int repro_quality(const Finding& f) {
    if (!f.anomalous) return 0;                   // nothing to reproduce
    int q = 40;                                   // self-contained HTML always
    if (f.deterministic) q += 35;                 // reproduces every run
    if (f.wasm.size() < 300) q += 15;             // small module
    else if (f.wasm.size() < 1200) q += 8;
    if (!f.cve.empty()) q += 10;                  // matches a known family
    return q > 100 ? 100 : q;
}

// --- standalone HTML repro ----------------------------------------------------------------
// Double-clickable: embeds the module as base64, instantiates it, drives run() through a
// tier-up loop, and prints the observed result. For a divergence it lists the per-config
// expected tokens so a reviewer sees the disagreement without our toolchain.
inline std::string html_repro(const Finding& f) {
    std::string kind = !f.anomalous ? "test artifact (no anomaly on tested build)"
                       : f.kind == Finding::Crash ? "crash"
                                                  : "differential divergence";
    std::string rows;
    for (const auto& cr : f.config_results)
        rows += "      <tr><td>" + cr.first + "</td><td>" + cr.second + "</td></tr>\n";

    std::string html;
    html += "<!doctype html><html><head><meta charset=utf-8>\n";
    html += "<title>NEMESIS repro " + f.id + "</title>\n";
    html += "<style>body{font:14px monospace;margin:2rem;max-width:70rem}"
            "table{border-collapse:collapse}td,th{border:1px solid #888;padding:2px 8px}"
            "</style></head><body>\n";
    html += "<h2>NEMESIS finding " + f.id + " — " + kind + "</h2>\n";
    if (!f.cve.empty()) html += "<p>Resembles: <b>" + f.cve + "</b>";
    if (!f.strategy.empty()) html += " (strategy <code>" + f.strategy + "</code>)";
    html += "</p>\n";
    if (!f.config_results.empty()) {
        html += "<p>Per-config results observed by NEMESIS (a disagreement is the bug):</p>\n";
        html += "<table><tr><th>V8 config</th><th>result</th></tr>\n" + rows + "</table>\n";
    }
    html += "<p>Live result in <i>this</i> browser:</p>\n<pre id=out>running…</pre>\n";
    html += "<script>\n";
    html += "const B64=\"" + base64(f.wasm) + "\";\n";
    html += "function b2u(b){const s=atob(b),a=new Uint8Array(s.length);"
            "for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return a;}\n";
    html += "(async()=>{const o=document.getElementById('out');try{\n";
    html += "  const {instance}=await WebAssembly.instantiate(b2u(B64),{});\n";
    html += "  const run=instance.exports.run; let v;\n";
    html += "  for(let i=0;i<100000;i++){try{v=run();}catch(e){v='TRAP';break;}}\n";
    html += "  o.textContent='run() => '+v+'\\n(compare against the table above)';\n";
    html += "}catch(e){o.textContent='error: '+e;}})();\n";
    html += "</script></body></html>\n";
    return html;
}

// --- markdown report skeleton -------------------------------------------------------------
inline std::string markdown_report(const Finding& f) {
    Cvss c = cvss_for(f);
    std::string title;
    if (!f.anomalous)
        title = "Wasm-GC module — no anomaly reproduced on tested V8 build";
    else if (f.kind == Finding::Crash)
        title = "Memory-safety crash in V8 Wasm-GC (" + std::string(exploit_hint_name(f.hint)) + ")";
    else
        title = "JIT miscompilation: Wasm-GC result divergence across V8 tiers";

    std::string m;
    m += "# " + title + "\n\n";
    m += "**Finding ID:** " + f.id + "  \n";
    m += "**Component:** V8 / WebAssembly-GC  \n";
    if (!f.cve.empty()) m += "**Resembles:** " + f.cve + "  \n";
    if (!f.strategy.empty()) m += "**NEMESIS strategy:** `" + f.strategy + "`  \n";
    m += "**CVSS 3.1:** " + score_str(c.score) + " (" + c.rating + ")  \n";
    m += "`" + c.vector + "`  \n";
    m += "**Reproducer quality:** " + std::to_string(repro_quality(f)) + "/100  \n";
    m += "**Deterministic:** " + std::string(f.deterministic ? "yes" : "no") +
         (f.repeat_runs ? " (" + std::to_string(f.repeat_runs) + " runs)" : "") + "  \n\n";

    m += "## Summary\n\n";
    if (!f.anomalous) {
        std::string tok = f.config_results.empty() ? "" : f.config_results[0].second;
        m += "No crash or cross-tier divergence was reproduced on the tested V8 build — all "
             "configurations agreed (`" + tok + "`). This build appears **not vulnerable** to "
             "the tested shape; re-run against the target/nightly/older build (override the "
             "config binaries) to reproduce. Full per-config table:\n\n";
        for (const auto& cr : f.config_results)
            m += "- `" + cr.first + "` => `" + cr.second + "`\n";
        m += "\n";
    } else if (f.kind == Finding::Crash) {
        m += "The attached Wasm-GC module crashes V8 with a fatal signal (" +
             std::to_string(f.signal) + "). Fault class (heuristic): " +
             exploit_hint_name(f.hint) + ".\n\n";
    } else {
        m += "The attached Wasm-GC module is deterministic per the Wasm spec, yet V8 "
             "produced **different results under different compiler tiers** — a "
             "miscompilation. Observed:\n\n";
        for (const auto& cr : f.config_results)
            m += "- `" + cr.first + "` => `" + cr.second + "`\n";
        m += "\nThe baseline (Liftoff) result is the reference; any optimizing tier that "
             "disagrees has mis-optimized.\n\n";
    }

    m += "## Reproduction\n\n";
    m += "1. Open `repro.html` in the affected browser build, **or**\n";
    m += "2. `node harness/run_wasm.js module.wasm` under each config in `meta.txt`.\n\n";
    m += "## Impact\n\n";
    if (!f.anomalous)
        m += "None demonstrated on this build. This pack is a reproducible test artifact for "
             "the tested shape; it becomes a finding only if a target build diverges or "
             "crashes.\n";
    else if (f.kind == Finding::Crash)
        m += "Memory-safety violation reachable from a crafted web page (renderer). "
             "Exploitability signal: " + std::string(exploit_hint_name(f.hint)) +
             ". Attach a controlled-RIP register snapshot (needs an instrumented build) to "
             "raise severity.\n";
    else
        m += "A JIT that returns a wrong value for a deterministic program is a correctness "
             "defect and a frequent precursor to type-confusion memory corruption. Impact is "
             "reported conservatively until a memory-safety consequence is demonstrated.\n";
    m += "\n---\n*Generated by NEMESIS. Finds + characterizes; does not weaponize.*\n";
    return m;
}

}  // namespace nemesis
