# Security Policy

NEMESIS is a tool for **finding** compiler miscompilations and crashes in JS/Wasm engines. It
is intended for authorized security testing and **responsible disclosure**. This policy
covers two distinct things.

## 1. Vulnerabilities you find *using* NEMESIS (bugs in an engine)

If you use NEMESIS to find a real bug in V8, SpiderMonkey, JavaScriptCore, or any other
engine or product:

- **Report it to that vendor's security / bug-bounty program**, not here. Examples:
  - V8 / Chrome the Chrome Vulnerability Reward Program
  - Firefox / SpiderMonkey — Mozilla's security bug process
  - Safari / WebKit / JavaScriptCore Apple Security
- Follow **coordinated disclosure**: give the vendor time to fix before publishing details.
- Only test engines and targets you are **authorized** to test. Use the built-in scope gate
  (`nemesis scope`). Do not run NEMESIS against systems or services you do not own or lack
  permission to test.
- NEMESIS produces a minimized repro + severity assessment + report draft to make responsible
  disclosure easier. Please use them.
