---
name: Bug report
about: A problem with NEMESIS itself (the tool), not a bug found using it
title: "[bug] "
labels: bug
---

<!--
  IMPORTANT: If you found a vulnerability in an ENGINE (V8/SpiderMonkey/JSC) using NEMESIS,
  do NOT report it here — report it to that vendor's security program (see SECURITY.md).
  This template is for problems with NEMESIS's own code/behavior.
-->

**What happened**
A clear description of the bug in the tool.

**To reproduce**
Exact command(s) and seed:
```
./build/nemesis ...
```

**Expected vs actual**
What you expected, and what you got (paste output).

**Environment**
- OS:
- Compiler (`g++ --version` / `clang++ --version`):
- Node version (`node --version`):
- NEMESIS commit (`git rev-parse --short HEAD`):
