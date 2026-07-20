#!/usr/bin/env python3
"""vault.py — evidence vault / findings ledger.

WHY: A researcher who finds many bugs needs one durable, structured record of each — not a
pile of loose files. The vault stores one entry per unique finding (keyed by stack-hash), with
the fields a disclosure needs: engine + affected revision, the minimized module, the ASan
report, an exploitability bucket, a CWE candidate, a CVSS estimate, and a workflow status
(draft -> triaged -> submitted). It de-dups by crash_id so the same bug is recorded once.

It stores evidence and metadata for reporting; it does not execute or exploit anything.
"""
import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

VALID_STATUS = ("draft", "triaged", "submitted", "resolved", "duplicate")
VALID_BUCKETS = ("write-primitive", "controlled-write", "oob-write", "oob-read",
                 "info-leak", "use-after-free", "null-deref", "miscompilation", "unknown")


@dataclass
class Finding:
    crash_id: str                                   # stack-hash (dedup key)
    kind: str = "crash"                             # crash | divergence
    engine: str = "v8"
    affected_rev: str = ""                          # build id / version / git rev
    exploitability: str = "unknown"                # one of VALID_BUCKETS
    cwe_candidate: str = ""
    cvss: float = 0.0
    cvss_vector: str = ""
    confirmed: bool = True                         # False = no anomaly reproduced (informational)
    status: str = "draft"                          # one of VALID_STATUS
    minimized_wasm: str = ""                        # path
    asan_report: str = ""                           # path
    repro_html: str = ""                            # path
    report_md: str = ""                             # path
    notes: str = ""
    created: float = field(default_factory=lambda: time.time())
    updated: float = field(default_factory=lambda: time.time())


class Vault:
    def __init__(self, root):
        self.root = root
        self.index_path = os.path.join(root, "findings.json")
        os.makedirs(root, exist_ok=True)
        self._items = {}
        if os.path.exists(self.index_path):
            with open(self.index_path) as fh:
                for d in json.load(fh):
                    self._items[d["crash_id"]] = Finding(**d)

    def _flush(self):
        with open(self.index_path, "w") as fh:
            json.dump([asdict(f) for f in self._items.values()], fh, indent=2)

    def add(self, f: Finding) -> bool:
        """Insert if new (by crash_id). Returns True if newly added, False if duplicate."""
        if f.status not in VALID_STATUS:
            raise ValueError(f"bad status {f.status}")
        if f.crash_id in self._items:
            return False
        self._items[f.crash_id] = f
        self._flush()
        return True

    def get(self, crash_id) -> Optional[Finding]:
        return self._items.get(crash_id)

    def update_status(self, crash_id, status):
        if status not in VALID_STATUS:
            raise ValueError(f"bad status {status}")
        f = self._items[crash_id]
        f.status = status
        f.updated = time.time()
        self._flush()

    def list(self, status=None):
        vs = self._items.values()
        return [f for f in vs if status is None or f.status == status]

    # Ingest a build/findings/<id>/ pack produced by the C++ `report` command.
    def ingest_pack(self, pack_dir) -> Optional[Finding]:
        meta = os.path.join(pack_dir, "meta.txt")
        if not os.path.exists(meta):
            return None
        kv = {}
        for line in open(meta):
            line = line.strip()
            if "=" in line and " " not in line.split("=", 1)[0]:
                for tok in line.split():
                    if "=" in tok:
                        k, v = tok.split("=", 1)
                        kv[k] = v
        cid = kv.get("id") or os.path.basename(pack_dir.rstrip("/"))
        cvss = float(kv.get("cvss", 0) or 0)
        # Grab a real CVSS vector token if the pack recorded one (non-anomalous packs don't).
        vector = ""
        for line in open(meta):
            i = line.find("CVSS:3.1/")
            if i >= 0:
                vector = line[i:].split()[0].strip()
                break
        f = Finding(
            crash_id=cid,
            kind=kv.get("kind", "divergence"),
            cvss=cvss,
            cvss_vector=vector,
            confirmed=cvss > 0,           # cvss 0.0 == no anomaly reproduced on tested build
            exploitability=kv.get("exploitability", "unknown"),
            minimized_wasm=os.path.join(pack_dir, "module.wasm"),
            repro_html=os.path.join(pack_dir, "repro.html"),
            report_md=os.path.join(pack_dir, "report.md"),
        )
        self.add(f)
        return f


def _default_root():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, "build", "vault")


def _main(argv):
    v = Vault(_default_root())
    if not argv or argv[0] == "list":
        status = argv[1] if len(argv) > 1 else None
        rows = v.list(status)
        print(f"{len(rows)} finding(s):")
        for f in rows:
            print(f"  {f.crash_id}  {f.kind:10} {f.status:9} cvss={f.cvss:<4} "
                  f"{f.exploitability}  {f.affected_rev}")
        return 0
    if argv[0] == "show" and len(argv) > 1:
        f = v.get(argv[1])
        print(json.dumps(asdict(f), indent=2) if f else "not found")
        return 0 if f else 1
    if argv[0] == "ingest" and len(argv) > 1:
        f = v.ingest_pack(argv[1])
        print(f"ingested {f.crash_id}" if f else "no meta.txt in pack")
        return 0 if f else 1
    if argv[0] == "status" and len(argv) > 2:
        v.update_status(argv[1], argv[2])
        print(f"{argv[1]} -> {argv[2]}")
        return 0
    print("usage: vault <list [status]|show <id>|ingest <pack_dir>|status <id> <status>>")
    return 1


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
