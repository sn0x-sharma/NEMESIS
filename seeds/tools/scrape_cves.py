#!/usr/bin/env python3
"""scrape_cves.py — grow seeds/cve_db.json with REAL CVE data (Tier 7, feature #160/#183).

WHY: The differential/variant engine is only as good as its CVE corpus. This grows the DB two
ways, both with REAL data — nothing is fabricated:

  seed   — merge a curated batch of well-known, verifiable browser-engine memory-safety / JIT
           CVEs (V8 / SpiderMonkey / JavaScriptCore) shipped in this file. Offline.
  nvd    — fetch more from the NVD 2.0 API by browser-engine keywords and merge them. Needs
           internet; run it to push the corpus past 300 with real, source-linked entries.

Every entry carries an nvd.nist.gov detail URL so it is independently verifiable. Curated
entries use class-level bug_class + a brief component note (no invented specifics); the `nvd`
fetch fills bug_class/description straight from NVD.

Usage:
  python3 seeds/tools/scrape_cves.py seed
  python3 seeds/tools/scrape_cves.py nvd --max 400
  python3 seeds/tools/scrape_cves.py stats
"""
import json
import os
import sys

DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cve_db.json")


def _e(cid, engine, bug_class, itw, component, strat=None):
    return {
        "id": cid, "engine": engine, "component": component, "bug_class": bug_class,
        "tier": "optimizing", "in_the_wild": itw, "cvss": None,
        "trigger_shape": component, "nemesis_strategy": strat,
        "source": f"https://nvd.nist.gov/vuln/detail/{cid}",
    }


# Curated, verifiable browser-engine memory-safety / JIT CVEs (public, well documented).
# bug_class kept at class level; specifics deliberately not invented.
CURATED = [
    # --- V8 / Chrome ---
    _e("CVE-2016-1646", "v8", "oob", False, "V8 array OOB", "array_oob_loop"),
    _e("CVE-2017-5030", "v8", "oob", False, "V8 memory corruption in the parser/JIT"),
    _e("CVE-2018-17463", "v8", "type-confusion", False, "V8 Turbofan Object.create type confusion", "map_transition_confusion"),
    _e("CVE-2019-5782", "v8", "oob", False, "V8 Turbofan incorrect range/bounds (OOB)", "range_analysis_confusion"),
    _e("CVE-2019-13764", "v8", "type-confusion", False, "V8 type confusion"),
    _e("CVE-2020-6418", "v8", "type-confusion", True, "V8 type confusion in Turbofan (ITW)", "map_transition_confusion"),
    _e("CVE-2020-16009", "v8", "type-confusion", True, "V8 inline-cache/type confusion (ITW)"),
    _e("CVE-2021-21148", "v8", "heap-oob", True, "V8 heap buffer overflow (ITW)"),
    _e("CVE-2021-30551", "v8", "type-confusion", True, "V8 type confusion (ITW)"),
    _e("CVE-2021-30632", "v8", "oob", True, "V8 out-of-bounds write (ITW)"),
    _e("CVE-2021-37975", "v8", "uaf", True, "V8 use-after-free (ITW)", "gc_boundary_uaf"),
    _e("CVE-2021-38003", "v8", "miscompile", True, "V8 inappropriate implementation / JIT (ITW)", "jit_tierup_stress"),
    _e("CVE-2022-1096", "v8", "type-confusion", True, "V8 type confusion (ITW)"),
    _e("CVE-2022-1364", "v8", "type-confusion", True, "V8 type confusion (ITW)"),
    _e("CVE-2022-3723", "v8", "type-confusion", True, "V8 type confusion (ITW)"),
    _e("CVE-2022-4262", "v8", "type-confusion", True, "V8 type confusion (ITW)"),
    _e("CVE-2023-2033", "v8", "type-confusion", True, "V8 type confusion (ITW)"),
    _e("CVE-2023-3079", "v8", "type-confusion", True, "V8 type confusion (ITW)"),
    _e("CVE-2023-4762", "v8", "type-confusion", True, "V8 type confusion (ITW)"),
    _e("CVE-2024-0519", "v8", "oob", True, "V8 out-of-bounds memory access (ITW)", "array_oob_loop"),
    _e("CVE-2024-4947", "v8", "type-confusion", True, "V8 type confusion (ITW)"),
    _e("CVE-2024-5274", "v8", "type-confusion", True, "V8 type confusion (ITW)"),
    # --- SpiderMonkey / Firefox ---
    _e("CVE-2018-12386", "spidermonkey", "type-confusion", True, "IonMonkey type confusion (ITW)"),
    _e("CVE-2019-9810", "spidermonkey", "oob", False, "IonMonkey Array.prototype.slice bounds (OOB)", "range_analysis_confusion"),
    _e("CVE-2019-11707", "spidermonkey", "type-confusion", True, "Array/type confusion (ITW)"),
    _e("CVE-2020-6383", "spidermonkey", "type-confusion", False, "type confusion in the JS engine"),
    _e("CVE-2020-15656", "spidermonkey", "type-confusion", False, "JIT type confusion"),
    _e("CVE-2024-9680", "spidermonkey", "uaf", True, "Firefox animation-timeline use-after-free (ITW)", "gc_boundary_uaf"),
    # --- JavaScriptCore / WebKit / Safari ---
    _e("CVE-2016-4622", "jsc", "oob", False, "JSC out-of-bounds (Array)", "array_oob_loop"),
    _e("CVE-2019-8506", "jsc", "type-confusion", False, "JSC type confusion"),
    _e("CVE-2021-30858", "jsc", "uaf", True, "WebKit use-after-free (ITW)", "gc_boundary_uaf"),
    _e("CVE-2022-22620", "jsc", "uaf", True, "WebKit use-after-free (ITW)", "gc_boundary_uaf"),
    _e("CVE-2022-42856", "jsc", "type-confusion", True, "WebKit type confusion (ITW)"),
    _e("CVE-2023-28204", "jsc", "oob", True, "WebKit out-of-bounds read (ITW)"),
    _e("CVE-2023-42916", "jsc", "oob", True, "WebKit out-of-bounds read (ITW)"),
    _e("CVE-2024-23222", "jsc", "type-confusion", True, "WebKit type confusion (ITW)"),
    _e("CVE-2024-44308", "jsc", "type-confusion", True, "JSC/WebKit type confusion (ITW)"),
]


def load():
    with open(DB) as fh:
        return json.load(fh)


def save(db):
    with open(DB, "w") as fh:
        json.dump(db, fh, indent=2)


def merge(db, entries):
    have = {c["id"] for c in db["cves"]}
    added = 0
    for e in entries:
        if e["id"] not in have:
            db["cves"].append(e)
            have.add(e["id"])
            added += 1
    return added


def cmd_seed():
    db = load()
    n = merge(db, CURATED)
    save(db)
    print(f"seeded {n} curated CVEs; DB now {len(db['cves'])} entries")


def cmd_nvd(max_n):
    try:
        import urllib.error
        import urllib.request
    except ImportError:
        print("no urllib available")
        return 1
    kws = ["V8 type confusion", "V8 out of bounds", "SpiderMonkey", "IonMonkey",
           "JavaScriptCore", "WebKit type confusion", "WebAssembly memory",
           "WebKit use after free", "TurboFan", "Chrome V8 use after free",
           "Firefox memory safety", "WebAssembly type", "V8 heap"]
    import time
    db = load()
    total = 0
    for ki, kw in enumerate(kws):
        url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
               + urllib.parse.quote(kw) + "&resultsPerPage=100")
        # NVD without an API key allows ~5 requests / 30s; space requests and back off on 429.
        if ki:
            time.sleep(6)
        data = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(url, timeout=30) as r:
                    data = json.load(r)
                break
            except urllib.error.HTTPError as ex:
                if ex.code == 429 and attempt < 2:
                    time.sleep(25)  # wait out the rate-limit window
                    continue
                print(f"  [{kw}] fetch failed: {ex}")
                break
            except Exception as ex:  # noqa: BLE001 — best-effort network fetch
                print(f"  [{kw}] fetch failed: {ex}")
                break
        if data is None:
            continue
        batch = []
        for v in data.get("vulnerabilities", []):
            c = v.get("cve", {})
            cid = c.get("id")
            if not cid:
                continue
            desc = ""
            for d in c.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:200]
                    break
            eng = ("v8" if "V8" in desc else "spidermonkey" if "SpiderMonkey" in desc
                   or "IonMonkey" in desc else "jsc" if "WebKit" in desc
                   or "JavaScriptCore" in desc else "unknown")
            bc = ("type-confusion" if "type confusion" in desc.lower()
                  else "uaf" if "use after free" in desc.lower()
                  else "oob" if "out of bounds" in desc.lower() else "unknown")
            batch.append({"id": cid, "engine": eng, "component": desc, "bug_class": bc,
                          "tier": "optimizing", "in_the_wild": False, "cvss": None,
                          "trigger_shape": desc, "nemesis_strategy": None,
                          "source": f"https://nvd.nist.gov/vuln/detail/{cid}"})
        added = merge(db, batch)
        total += added
        print(f"  [{kw}] +{added}")
        if len(db["cves"]) >= max_n:
            break
    save(db)
    print(f"nvd fetch added {total}; DB now {len(db['cves'])} entries")


def cmd_stats():
    db = load()
    print(f"DB: {len(db['cves'])} entries")


def main(argv):
    if not argv or argv[0] == "seed":
        return cmd_seed()
    if argv[0] == "nvd":
        max_n = 400
        if "--max" in argv:
            max_n = int(argv[argv.index("--max") + 1])
        return cmd_nvd(max_n)
    if argv[0] == "stats":
        return cmd_stats()
    print("usage: scrape_cves.py <seed|nvd [--max N]|stats>")
    return 1


if __name__ == "__main__":
    import urllib.parse  # noqa: F401 — used in cmd_nvd
    sys.exit(main(sys.argv[1:]))
