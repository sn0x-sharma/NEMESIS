#!/usr/bin/env python3
"""scope.py — authorization scope gate.

WHY: A fuzzer/triage tool must only ever operate against targets its operator is authorized
to test. This gate is the single chokepoint: every target (an engine binary, a local module,
or — if a browser/URL target is ever wired — a host) is checked against an explicit allow-list
before any execution. Default-deny for remote hosts; localhost and local files are allowed by
default because the primary use is testing local engine builds. Out-of-scope => refuse.

This is a safety control, kept deliberately simple and auditable.
"""
import fnmatch
import ipaddress
import json
import os
from urllib.parse import urlparse

DEFAULT_SCOPE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    ".nemesis-scope.json",
)

# Always-allowed local targets (testing your own engine build on your own machine).
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", ""}


class Scope:
    def __init__(self, hosts=None, allow_local=True):
        self.hosts = list(hosts or [])       # exact or fnmatch patterns, e.g. "*.example.com"
        self.allow_local = allow_local

    # --- persistence ---------------------------------------------------------------------
    @classmethod
    def load(cls, path=DEFAULT_SCOPE_FILE):
        if not os.path.exists(path):
            return cls()
        with open(path) as fh:
            d = json.load(fh)
        return cls(hosts=d.get("hosts", []), allow_local=d.get("allow_local", True))

    def save(self, path=DEFAULT_SCOPE_FILE):
        with open(path, "w") as fh:
            json.dump({"hosts": self.hosts, "allow_local": self.allow_local}, fh, indent=2)

    def add(self, entry):
        if entry not in self.hosts:
            self.hosts.append(entry)

    # --- the gate ------------------------------------------------------------------------
    def _host_of(self, target):
        # A bare engine binary or local .wasm path is a local file target.
        if os.path.sep in target and "://" not in target:
            return None  # local path
        if "://" in target:
            return (urlparse(target).hostname or "").lower()
        return target.lower()  # bare host

    def is_local(self, target):
        if os.path.sep in target and "://" not in target and "//" not in target:
            return True  # filesystem path
        host = self._host_of(target)
        if host in _LOCAL_HOSTS:
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def allows(self, target):
        """True iff `target` is authorized. Local files/hosts pass when allow_local."""
        if self.is_local(target):
            return self.allow_local
        host = self._host_of(target)
        if host is None:
            return self.allow_local
        for pat in self.hosts:
            if host == pat.lower() or fnmatch.fnmatch(host, pat.lower()):
                return True
        return False

    def require(self, target):
        """Raise if the target is out of scope. Call before any execution against it."""
        if not self.allows(target):
            raise PermissionError(
                f"target '{target}' is OUT OF SCOPE. Add it to {DEFAULT_SCOPE_FILE} "
                f"(nemesis scope add <host>) only if you are authorized to test it."
            )


def _main(argv):
    import sys
    if not argv:
        print("usage: scope <add|check|list> [target]")
        return 1
    cmd = argv[0]
    sc = Scope.load()
    if cmd == "list":
        print(f"allow_local={sc.allow_local}")
        for h in sc.hosts:
            print(f"  {h}")
        return 0
    if cmd == "add" and len(argv) > 1:
        sc.add(argv[1]); sc.save()
        print(f"added to scope: {argv[1]}")
        return 0
    if cmd == "check" and len(argv) > 1:
        ok = sc.allows(argv[1])
        print(f"{'IN-SCOPE' if ok else 'OUT-OF-SCOPE'}: {argv[1]}")
        return 0 if ok else 3
    print("usage: scope <add|check|list> [target]")
    return 1


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))
