# V8 target

NEMESIS drives V8 through a JavaScript shell. This directory documents how to obtain one — it
does **not** vendor engine binaries (they are large and their licensing/versioning is best
handled by fetching from the vendor).

## Quick path: stock Node.js (what NEMESIS uses out of the box)

Any recent **Node.js** provides V8. Nothing to place here — if `node` is on your `PATH`,
`nemesis diff` / `strategies` / `hunt` work immediately, running the 8 V8 compiler configs via
the `--<v8-flag>` options Node forwards to V8.

```sh
node --version   # V8 is embedded; that's the default target
```

## Deeper path: a standalone `d8` (V8's own shell)

`d8` gives you the newest V8 and finer flag control. Build it with `depot_tools` + `gn`/`ninja`
(this needs ~30–50 GB disk and is not required for the default flow):

```sh
# https://v8.dev/docs/build
fetch v8 && cd v8
gn gen out/x64.release --args='is_debug=false'
ninja -C out/x64.release d8
# then point a config's binary at out/x64.release/d8 (see below)
```

For real bug-hunting yield, build an **older / nightly / ASan** V8 and point the configs at it.

## Pointing configs at a specific binary

Each of the 8 configs (`v1-liftoff` … `v8-ts-tierup`) has an overridable binary. In
`core/exec/v8_node.hpp`, `default_v8_configs(binary)` takes the shell path; supply a different
build there (or two different builds across slots) to do **cross-version** differential
testing — a new divergence between an old and a new build is a regression window.

> Downloaded binaries placed in this directory are git-ignored (`js`, `d8`, `*.zip`, etc.).
