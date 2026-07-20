#!/usr/bin/env python3
"""cve_intel.py — CVE pattern intelligence over seeds/cve_db.json (Tier 7).

WHY: A crash/divergence is more actionable when tied to prior art. This reads the structured
CVE database and answers four workflow questions:
  match     — which known CVE families match a bug class (+ engine)? (finding -> prior art)
  variant   — same bug class in OTHER engines? (cross-engine variant hunting)
  patchgap  — a class fixed in one engine but present in others? (candidate unfixed variants)
  trend     — bug-class + per-engine distribution (where to point generators)

It reasons over metadata + trigger shapes only. It does not fetch exploits or the internet.
"""
import json
import os
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB = os.path.join(ROOT, "seeds", "cve_db.json")


def load_db():
    with open(DB) as fh:
        return json.load(fh).get("cves", [])


def match(bug_class=None, engine=None):
    rows = load_db()
    out = []
    for c in rows:
        if bug_class and bug_class.lower() not in c.get("bug_class", "").lower():
            continue
        if engine and engine.lower() != c.get("engine", "").lower():
            continue
        out.append(c)
    return out


def variants(cve_id):
    rows = load_db()
    target = next((c for c in rows if c["id"] == cve_id), None)
    if not target:
        return None, []
    bc = target.get("bug_class")
    comp = target.get("component", "")
    out = [c for c in rows if c["id"] != cve_id and c.get("bug_class") == bc]
    # rank same-component/similar first
    out.sort(key=lambda c: (c.get("engine") == target.get("engine"),
                            _kw_overlap(c.get("component", ""), comp)), reverse=True)
    return target, out


def _kw_overlap(a, b):
    wa = set(a.lower().replace("(", " ").replace(")", " ").split())
    wb = set(b.lower().replace("(", " ").replace(")", " ").split())
    return len(wa & wb)


def patch_gap():
    """Bug classes present in >1 engine → the same root cause may be unfixed in an engine
    where it hasn't been reported. Heuristic candidate list for cross-engine variant hunting."""
    rows = load_db()
    by_class = {}
    for c in rows:
        by_class.setdefault(c.get("bug_class"), set()).add(c.get("engine"))
    gaps = []
    all_engines = {"v8", "spidermonkey", "jsc"}
    for bc, engines in by_class.items():
        missing = all_engines - engines
        if engines & all_engines and missing:
            gaps.append((bc, sorted(engines), sorted(missing)))
    return gaps


def trend():
    rows = load_db()
    return {
        "total": len(rows),
        "by_class": Counter(c.get("bug_class") for c in rows).most_common(),
        "by_engine": Counter(c.get("engine") for c in rows).most_common(),
        "in_the_wild": sum(1 for c in rows if c.get("in_the_wild")),
        "with_strategy": sum(1 for c in rows if c.get("nemesis_strategy")),
    }


def _fmt(c):
    itw = " [ITW]" if c.get("in_the_wild") else ""
    strat = f"  strategy={c['nemesis_strategy']}" if c.get("nemesis_strategy") else ""
    return (f"  {c['id']:<16} {c.get('engine',''):<12} {c.get('bug_class',''):<15}"
            f"{itw}{strat}\n      {c.get('component','')}")


def write_weights(path):
    """Emit '<bug_class> <count>' lines from the live DB — the CVE-bias scheduler reads this
    to weight strategy selection by real-world class frequency."""
    t = trend()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        for cls, cnt in t["by_class"]:
            if cls and cls != "unknown":
                fh.write(f"{cls} {cnt}\n")
    return t["by_class"]


def _main(argv):
    if not argv:
        print("usage: cve <match [class] [engine] | variant <id> | patchgap | trend | weights>")
        return 1
    cmd = argv[0]
    if cmd == "weights":
        path = os.path.join(ROOT, "build", "cve_weights.txt")
        rows = write_weights(path)
        print(f"wrote {path}")
        for cls, cnt in rows:
            if cls and cls != "unknown":
                print(f"  {cls:<16} {cnt}")
        return 0
    if cmd == "match":
        bc = argv[1] if len(argv) > 1 else None
        eng = argv[2] if len(argv) > 2 else None
        rows = match(bc, eng)
        print(f"{len(rows)} CVE(s) matching class={bc} engine={eng}:")
        for c in rows:
            print(_fmt(c))
        return 0
    if cmd == "variant" and len(argv) > 1:
        target, out = variants(argv[1])
        if not target:
            print(f"{argv[1]} not in DB")
            return 1
        print(f"{target['id']} is {target['bug_class']} in {target['engine']}.")
        print(f"{len(out)} same-class variant candidate(s) (other engines ranked first):")
        for c in out:
            print(_fmt(c))
        return 0
    if cmd == "patchgap":
        gaps = patch_gap()
        print(f"{len(gaps)} bug class(es) with cross-engine patch-gap candidates:")
        for bc, have, missing in gaps:
            print(f"  {bc:<16} seen in {have} — hunt the same shape in: {missing}")
        return 0
    if cmd == "trend":
        t = trend()
        print(f"CVE DB: {t['total']} entries  ({t['in_the_wild']} in-the-wild, "
              f"{t['with_strategy']} with a live NEMESIS strategy)")
        print("by bug class:")
        for k, v in t["by_class"]:
            print(f"  {k:<16} {v}")
        print("by engine:")
        for k, v in t["by_engine"]:
            print(f"  {k:<14} {v}")
        return 0
    print("usage: cve <match [class] [engine] | variant <id> | patchgap | trend>")
    return 1


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
