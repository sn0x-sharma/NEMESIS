#!/usr/bin/env python3
"""Smoke tests for the Python triage/safety modules. Plain asserts, no pytest dependency.

Run: python3 tests/test_triage.py   (exit 0 = pass)
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from cli.triage.asan_parser import parse_asan            # noqa: E402
from cli.triage.vault import Vault, Finding              # noqa: E402
from cli.triage.report_gen import render                 # noqa: E402
from cli.execution.scope import Scope                    # noqa: E402

ASAN_UAF = """==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x0
WRITE of size 8 at 0x602000000010 thread T0
    #0 0x55 in v8::internal::wasm::StructSet() src/wasm/foo.cc:120
    #1 0x66 in v8::internal::Compiler::Run() src/compiler/bar.cc:88
SUMMARY: AddressSanitizer: heap-use-after-free src/wasm/foo.cc:120
"""


def test_asan():
    f = parse_asan(ASAN_UAF)
    assert f.bug_type == "use-after-free", f.bug_type
    assert f.cwe == "CWE-416"
    assert f.access == "WRITE" and f.access_size == 8
    assert f.exploitability == "write-primitive", f.exploitability
    assert len(f.stack_hash) == 16
    # deterministic hash
    assert parse_asan(ASAN_UAF).stack_hash == f.stack_hash


def test_asan_null_deref():
    txt = "AddressSanitizer: SEGV on unknown address 0x000000000000\nREAD of size 4 at 0x0\n"
    f = parse_asan(txt)
    assert f.addr_char == "near-null", f.addr_char
    assert f.exploitability in ("null-deref", "oob-read")


def test_scope():
    sc = Scope(hosts=["*.target.com", "app.example.org"])
    assert sc.allows("./build/nemesis")                  # local file
    assert sc.allows("https://api.target.com/x.wasm")    # wildcard
    assert sc.allows("app.example.org")                  # exact
    assert not sc.allows("https://evil.com/x.wasm")      # not listed
    try:
        sc.require("https://evil.com/x.wasm")
        raise AssertionError("require should have refused out-of-scope")
    except PermissionError:
        pass


def test_vault_and_report():
    with tempfile.TemporaryDirectory() as d:
        v = Vault(d)
        f = Finding(crash_id="deadbeef00000001", kind="crash", engine="v8",
                    affected_rev="V8 14.2.0", exploitability="write-primitive",
                    cwe_candidate="CWE-416", cvss=9.6,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
                    confirmed=True, status="draft")
        assert v.add(f) is True
        assert v.add(f) is False          # dedup
        v.update_status("deadbeef00000001", "submitted")
        assert v.get("deadbeef00000001").status == "submitted"
        assert len(v.list(status="submitted")) == 1

        md = render(f)
        assert "9.6" in md and "CWE-416" in md and "write primitive" in md.lower()

        # non-confirmed artifact must render informational, never a severity claim
        art = Finding(crash_id="0000000000000002", kind="divergence", cvss=0.0,
                      confirmed=False)
        info = render(art)
        assert "no anomaly" in info.lower() and "0.0" in info
        assert "9.6" not in info


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"{len(tests)}/{len(tests)} triage tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
