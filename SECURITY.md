# Security Policy

NEMESIS is a tool for **finding** compiler miscompilations and crashes in JS/Wasm engines. It
is intended for authorized security testing and **responsible disclosure**. This policy
covers two distinct things.

## 1. Vulnerabilities you find *using* NEMESIS (bugs in an engine)

If you use NEMESIS to find a real bug in V8, SpiderMonkey, JavaScriptCore, or any other
engine or product:

- **Report it to that vendor's security / bug-bounty program**, not here. Examples:
  - V8 / Chrome — the Chrome Vulnerability Reward Program
  - Firefox / SpiderMonkey — Mozilla's security bug process
  - Safari / WebKit / JavaScriptCore — Apple Security
- Follow **coordinated disclosure**: give the vendor time to fix before publishing details.
- Only test engines and targets you are **authorized** to test. Use the built-in scope gate
  (`nemesis scope`). Do not run NEMESIS against systems or services you do not own or lack
  permission to test.
- NEMESIS produces a minimized repro + severity assessment + report draft to make responsible
  disclosure easier. Please use them.

## 2. A vulnerability in NEMESIS itself (this codebase)

If you find a security issue in NEMESIS's own code (e.g. a way the tool could be abused, a
memory-safety bug in the C++ core, an unsafe file/command handling path):

- **Do not open a public issue.** Report it privately via GitHub Security Advisories
  ("Report a vulnerability") on this repository, or to the maintainer.
- Include a description, affected version/commit, and a reproduction if possible.
- We aim to acknowledge within a few days and to fix and disclose in coordination with you.

## Not in scope

NEMESIS does not build exploits, shellcode, or sandbox escapes, and requests to add such
capabilities are out of scope for this project. The goal is finding and reporting bugs, not
weaponizing them.
