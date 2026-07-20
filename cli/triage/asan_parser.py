#!/usr/bin/env python3
"""asan_parser.py — AddressSanitizer / sanitizer output -> structured exploitability finding.

WHY: When NEMESIS is pointed at an ASan-instrumented engine build (NEEDS-ENGINE on this box,
but the parser is engine-independent), a crash prints a sanitizer report. This turns that
free-text into a structured finding a human can rank: bug class, access direction, fault
address character, a stack-hash for dedup, and a CWE candidate. It characterizes a crash for
disclosure — it does not build an exploit.

Pure/text-only so it is unit-testable without a live target.
"""
import hashlib
import re
from dataclasses import dataclass, field
from typing import List, Optional

# Sanitizer bug-type token -> (canonical bug class, CWE, exploitability bias).
# Bias: "write" faults are higher-value than "read"; UAF/OOB-write are the top classes.
_BUG_MAP = {
    "heap-use-after-free": ("use-after-free", "CWE-416", "high"),
    "heap-buffer-overflow": ("heap-oob", "CWE-122", "high"),
    "stack-buffer-overflow": ("stack-oob", "CWE-121", "high"),
    "global-buffer-overflow": ("global-oob", "CWE-787", "medium"),
    "stack-use-after-return": ("use-after-return", "CWE-562", "high"),
    "stack-use-after-scope": ("use-after-scope", "CWE-562", "high"),
    "double-free": ("double-free", "CWE-415", "high"),
    "use-after-poison": ("use-after-poison", "CWE-416", "high"),
    "SEGV": ("segv", "CWE-476", "unknown"),
    "attempting-free-on-address": ("bad-free", "CWE-590", "medium"),
    "negative-size-param": ("negative-size", "CWE-1284", "medium"),
    "dynamic-stack-buffer-overflow": ("dyn-stack-oob", "CWE-121", "high"),
}


@dataclass
class AsanFinding:
    bug_type: str = "unknown"            # canonical class
    cwe: str = ""                        # CWE candidate
    access: str = ""                     # READ | WRITE | ""
    access_size: int = 0                 # bytes
    fault_addr: Optional[int] = None     # faulting address (int) if present
    addr_char: str = "unknown"           # near-null | low | heap | high/arbitrary
    exploitability: str = "unknown"      # write-primitive | oob-read | null-deref | ...
    frames: List[str] = field(default_factory=list)   # top symbolized frames
    stack_hash: str = ""                 # dedup key from top frames + bug type
    summary_line: str = ""               # the SUMMARY: line if present

    def to_dict(self):
        return {
            "bug_type": self.bug_type, "cwe": self.cwe, "access": self.access,
            "access_size": self.access_size, "fault_addr": self.fault_addr,
            "addr_char": self.addr_char, "exploitability": self.exploitability,
            "frames": self.frames, "stack_hash": self.stack_hash,
            "summary_line": self.summary_line,
        }


def _addr_character(addr: Optional[int]) -> str:
    if addr is None:
        return "unknown"
    if addr < 0x1000:
        return "near-null"            # low value: usually a DoS-class null deref
    if addr < 0x10000:
        return "low"
    if 0x500000000000 <= addr <= 0x700000000000:
        return "heap"                 # typical linux heap/ASan shadow range
    return "high/arbitrary"           # candidate for controlled address


def _exploitability(bug_type: str, access: str, addr_char: str) -> str:
    if access == "WRITE" and bug_type in ("use-after-free", "heap-oob", "double-free"):
        return "write-primitive"      # highest triage priority
    if access == "WRITE":
        return "controlled-write?" if addr_char == "high/arbitrary" else "oob-write"
    if access == "READ":
        return "info-leak" if bug_type == "use-after-free" else "oob-read"
    if addr_char == "near-null":
        return "null-deref"           # low value
    return "unknown"


def parse_asan(text: str) -> AsanFinding:
    f = AsanFinding()

    # Bug type: "ERROR: AddressSanitizer: <type> on address ..." or SUMMARY line.
    m = re.search(r"AddressSanitizer:\s*([a-zA-Z0-9\-]+)", text)
    if not m:
        m = re.search(r"SUMMARY:\s*\w+Sanitizer:\s*([a-zA-Z0-9\-]+)", text)
    raw_type = m.group(1) if m else ""
    if raw_type in _BUG_MAP:
        f.bug_type, f.cwe, _ = _BUG_MAP[raw_type]
    elif raw_type:
        f.bug_type = raw_type

    # Access direction + size: "READ of size 8 at 0x..." / "WRITE of size 4 ...".
    m = re.search(r"(READ|WRITE) of size (\d+)", text)
    if m:
        f.access = m.group(1)
        f.access_size = int(m.group(2))

    # Fault address: first "on address 0x..." or "at 0x...".
    m = re.search(r"(?:on address|at)\s+(0x[0-9a-fA-F]+)", text)
    if m:
        f.fault_addr = int(m.group(1), 16)
    f.addr_char = _addr_character(f.fault_addr)
    f.exploitability = _exploitability(f.bug_type, f.access, f.addr_char)

    # SUMMARY line, if present.
    m = re.search(r"^SUMMARY:.*$", text, re.MULTILINE)
    if m:
        f.summary_line = m.group(0).strip()

    # Top stack frames: "#0 0x... in symbol file:line".
    for fr in re.findall(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(.+)", text):
        f.frames.append(fr.strip())
        if len(f.frames) >= 6:
            break

    # Stack-hash: bug type + normalized top-3 frame symbols (drop addresses/line numbers).
    norm = [re.sub(r"0x[0-9a-fA-F]+|:\d+", "", fr).strip() for fr in f.frames[:3]]
    f.stack_hash = hashlib.sha1(("|".join([f.bug_type] + norm)).encode()).hexdigest()[:16]
    return f


def _main(argv):
    import sys
    data = open(argv[0]).read() if argv else sys.stdin.read()
    import json
    print(json.dumps(parse_asan(data).to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
