# OCPlayground

`ocplay` — a console (CLI) emulator for [OpenComputers](https://github.com/MightyPirates/OpenComputers).
It boots the real OpenComputers Lua machine (`machine.lua` + `bios.lua` + OpenOS) and renders the
in-game screen to the terminal with full color support.

```
ocplay ./computer.yaml test.lua
```

## Installation

### Ubuntu / Linux (prebuilt)

```sh
curl -fsSL https://raw.githubusercontent.com/MagicBOTAlex/OCPlayground/master/install.sh | bash
```

The installer downloads the latest released build into `~/.local/share/ocplay`
and symlinks `~/.local/bin/ocplay`. Options: `--version <tag>` and
`--prefix <dir>`.

Prebuilt `x86_64-unknown-linux-gnu` tarballs (with `.sha256` checksums) are
attached to [releases](https://github.com/MagicBOTAlex/OCPlayground/releases).
Every push to `master` refreshes the rolling `latest` release; `v*` tags create
versioned releases. The workflow builds on Ubuntu 22.04 so the binary runs on
22.04 and newer.

Update an installed build in place:

```sh
ocplay --upgrade
```

`--upgrade` downloads the latest release and replaces both the binary and its
bundled system files. Nix-managed installs refuse it (Nix owns the store paths);
use `nix profile upgrade ocplay` there instead.

### Nix (flakes)

```sh
nix profile install .#ocplay     # install / upgrade
nix profile remove ocplay        # remove
```

Or run/build it without installing:

```sh
nix run .#ocplay -- --help
nix build .#ocplay
```

The Nix package bundles the vendored OpenOS and points `OCPLAY_SYSTEM` at it, so
the installed binary works from anywhere.

## Decisions

These choices were made up front and drive the implementation:

| Topic | Decision |
| --- | --- |
| Language / runtime | **Rust + `mlua`** with bundled **Lua 5.4** |
| Fidelity | Run the **actual** OpenComputers system Lua (vendored), not a reimplementation |
| Components | Start with **core** only, but design around a component trait + registry so more can be injected later |
| Script mode | Default is **silent** (non-interactive); `--interactive` opts into the live shell |
| Config | Schema is **designed here** (see below) |

### What "core" means

The minimum needed to boot OpenOS, run scripts, and reproduce in-game behavior:

- `eeprom` — serves the BIOS and boot address
- `screen` — text buffer with 1/4/8-bit color, resolution, viewport, palette, and touch/pointer signals
- `gpu` — bind, colors, palette, depth, resolution, viewport, `set`/`copy`/`fill`/`get`
- `keyboard` — `key_down`/`key_up`/`clipboard` with OpenComputers key codes
- `filesystem` — `open`/`read`/`write`/`seek`/`close`, listing, metadata; RO OpenOS root + RW mounts
- `computer` — `beep`, `getDeviceInfo`, `getProgramLocations`, users
- `internet` — HTTP(S) `request` with a streaming handle (`read`/`response`/`finishConnect`/`close`) and raw TCP `connect` sockets

Redstone, modems, robots and other cards are **unplanned** (see [Status](#status)); they can still be
added through the same component registry.

## Architecture

```
src/
  main.rs               # CLI (clap)
  config.rs             # serde_yaml schema
  machine/mod.rs        # Lua init, resume loop, signal queue, sleep scheduler
  machine/host_api.rs   # component/computer/system/unicode/os globals
  components/mod.rs     # Component trait + Registry (DI seam)
  components/…          # eeprom, screen, gpu, keyboard, filesystem, computer, internet
  color.rs              # PackedColor, palettes, depth conversion, wcwidth
  term/mod.rs           # alternate screen, ANSI rendering, key + mouse input
  run.rs                # script injection + silent/interactive modes
  tests/e2e.rs          # end-to-end tests against the compiled binary
assets/system/          # vendored machine.lua, bios.lua, loot/openos/
```

- The host runs `machine.lua` as a Lua thread and interprets yields like OpenComputers does:
  a `number` is a requested sleep (interruptible by signals), a `boolean` is shutdown/reboot,
  and a `function` is a host callback that is invoked and resumed with its result.
- Most component methods are **direct**; the few that aren't (e.g. `internet.request`) use the
  host-callback path above. HTTP runs on a background thread so the screen keeps updating while a
  request is in flight.
- Terminal output is produced by rendering the `gpu`/`screen` text buffer, not by parsing guest ANSI.
- In interactive mode the terminal mouse is captured and converted into OpenComputers screen
  `touch`/`drag`/`drop`/`scroll` signals, matching the in-game 1-based (or high-precision) coordinates.

## Configuration (`computer.yaml`)

```yaml
name: my-computer

# KiB of RAM available to the Lua machine.
memory: 512

cpu:
  tier: 2

gpu:
  # Maximum color depth: 1 -> 1-bit, 2 -> 4-bit, 3 -> 8-bit.
  tier: 3
  screen:
    width: 80
    height: 25
    maxDepth: 8

eeprom:
  # "builtin" uses the vendored OpenComputers BIOS, otherwise a path to a .lua file.
  bios: builtin
  # "auto" picks the first bootable filesystem, otherwise a filesystem label.
  boot: auto

filesystems:
  # "builtin" serves a session copy of the vendored OpenOS; otherwise a host directory.
  - label: openos
    path: builtin
    mount: /
    readonly: false
  - label: data
    path: ./data
    mount: /home
    readonly: false

components:
  keyboard: true
  # Capture the terminal mouse and deliver it to the screen as touch signals
  # (interactive mode only).
  mouse: true

internet:
  # Canonical names are enableHttp/enableTcp; `enabled` and `tcp` are aliases.
  # Both default to true, matching OpenComputers.
  enabled: true        # alias for enableHttp
  tcp: true            # alias for enableTcp
  # HTTP request timeout in seconds; 0 = no timeout.
  timeout: 30
  # First matching rule wins; no match denies access. The defaults deny
  # private/bogon addresses, so loopback is blocked unless allowed here.
  filteringRules:
    - removeme
    - deny private
    - deny bogon
    - allow default
  # Concurrent HTTP requests plus TCP sockets per card.
  maxTcpConnections: 4
  # Maximum bytes returned by one read call (OC's key is filesystem.maxReadBuffer).
  maxReadBuffer: 2048
  userAgent: opencomputers/ocplay

run:
  script: test.lua
  timeout: 0
  interactive: false
  # Seconds to keep the final screen visible after the machine stops.
  terminateDelay: 5
```

CLI overrides:

```
ocplay [--interactive | --silent] [--timeout N] [--upgrade | --llm] <computer.yaml> [script.lua] [args...]
```

- **silent** (default): no stdin; run the script, render while it goes, exit when it finishes or times out.
- **`--interactive`**: run the script, then hand control to the live OpenOS shell.
- **`[args...]`**: extra arguments are passed to the script as varargs, exactly like an OpenOS
  program run from the shell — read them with `local args, options = require("shell").parse(...)`
  or `local args = {...}`.
- **`--upgrade`**: update to the latest release and exit (not for Nix installs).
- **`--llm`**: print an extremely detailed usage reference and exit (no config needed).

## Usage

```sh
# Boot OpenOS, run a script, then exit (non-interactive)
cargo run -- examples/computer.yaml examples/test.lua

# Drop into the live OpenOS shell after the script
cargo run -- --interactive examples/computer.yaml examples/test.lua

# Interactive mouse/touch demo (click/drag to paint, right-click or any key to quit)
cargo run -- --interactive examples/computer.yaml examples/mouse.lua

# Stop after 30 seconds
cargo run -- --timeout 30 examples/computer.yaml examples/test.lua

# Pass arguments to the script (available as `...`)
cargo run -- examples/computer.yaml examples/test.lua "test"
```

The script is copied into the emulated filesystem and executed once OpenOS has
booted. In non-interactive mode the computer shuts down when the script finishes;
in `--interactive` mode it then drops into the shell. When stdout is not a
terminal the final screen is printed as plain text, which is convenient for CI.
In interactive mode **Ctrl+C force-quits ocplay**; use Ctrl+Alt+C to interrupt the
running OpenOS program. If `--interactive` is requested without a usable terminal,
ocplay warns and runs non-interactively instead of hanging.

## Status

Implemented and working end-to-end:

- Real OpenOS boots and runs (vendored `machine.lua` / BIOS / OpenOS).
- `screen` + `gpu` with 1/4/8-bit color, palette, resolution and viewport.
- ANSI truecolor terminal rendering (via `ratatui`), wide-character aware.
- Terminal mouse input delivered as screen `touch`/`drag`/`drop`/`scroll` signals,
  including high-precision mode coordinates (demo: `examples/mouse.lua`).
- `keyboard` with OpenComputers scancodes, modifiers and Ctrl+Alt+C interrupts.
- `filesystem` backed by a session copy of OpenOS plus configured mounts.
- `eeprom`, `computer` and the machine host API (`component`, `computer`,
  `system`, `unicode`, `os`).
- `internet` card: HTTP/HTTPS `request` (GET/POST/custom method, headers, POST
  bodies) with OpenComputers' streaming handle semantics, run on a worker thread.
  Raw TCP through `component.internet.connect` (and the OpenOS
  `internet.socket`/`internet.open` wrappers), OC-style address filtering,
  per-card connection limits and `internet_ready` signals.
- Script autostart through OpenOS's own `rc` mechanism.

### Internet card

`enableHttp`/`enableTcp` (aliases: `enabled`/`tcp`) are independent. The card is
always present; a disabled protocol returns its own error. TCP defaults to
enabled like OpenComputers. Existing configs still parse: `enabled` controls
HTTP only, so set both `enabled: false` and `tcp: false` to disable both (or
deny everything with `filteringRules`). `component.internet.connect`
accepts `host:port`, `host` plus an explicit port, `scheme://host:port` and
bracketed IPv6 (`[::1]:port` or `[::1]` plus a port). An embedded port wins over
the explicit argument. Bare IPv6 literals are rejected, matching OC's `checkUri`.

The returned handle exposes `finishConnect`, `read`, `write`, `close` and `id`:

- `finishConnect():boolean` returns `false` while connecting and `true` once
  connected. A failed connect returns `false` once, then `nil, "connection lost"`;
  after `close()` it returns `nil, "connection lost"`.
- `read([n])` is non-blocking and reads at most `maxReadBuffer` bytes. It returns
  `""` while connecting or when no data is available, plain `nil` at EOF, and
  `nil, "connection lost"` after close or a hard error.
- `write(data):number` returns the accepted byte count, `0` while connecting or
  when the send buffer is full, and `nil, reason` after close or a hard error.
  The OpenOS stream wrappers busy-spin on `0`; they do not poll `finishConnect`,
  so `write` only returns `0` for connecting/backpressure, never for a dead socket.
- `close()` is idempotent, `id()` is stable, and `internet_ready <id>` is emitted
  when a connected socket becomes readable (repeated after reads drain data).

`filteringRules` follows OpenComputers: rules are evaluated first-to-last, the
first match wins, and no match denies access. Supported filters are `all`,
`default`, `private`, `bogon`, `ipv4`, `ipv6`, `ipv4-embedded-ipv6`,
`ip:<addr>[/cidr]` and `domain:<name>` (domains resolve once at config load).
`removeme` is ignored. Invalid rules disable all internet access. HTTP and TCP
are both filtered, and IPv4 addresses embedded in IPv6 (including NAT64) are
checked too.

**The default rules deny loopback and private addresses.** Local tests and
OCShell-style agents must add a rule such as:

```yaml
internet:
  filteringRules:
    - allow ip:127.0.0.1/8
    - deny private
    - deny bogon
    - allow default
```

or simply `- allow all` in a trusted test environment. `maxTcpConnections`
(default 4) counts HTTP request handles plus TCP sockets per card and is shared
between them; closing or failing a handle frees a slot. Sockets are closed when
the machine stops or reboots.

TCP is deliberately raw: there is no TLS, proxy support, or OC connection
ownership accounting. `internet.timeout` still applies to HTTP only; TCP
connects are bounded by a fixed 10 second handshake timeout.

### Tests

```sh
cargo test        # unit tests + end-to-end tests that boot OpenOS
```

Unit tests cover config parsing, URL validation, TCP address parsing, filtering
rules, connection accounting, the mouse→signal mapping and screen signal
emission. The end-to-end tests run the compiled binary against a temporary
computer: booting and running a script, an HTTP GET against a local server, a TCP
echo round trip (dot-call methods, EOF, prompt write-after-close failure), the
TCP-disabled error path, the shared connection limit, default loopback denial,
`internet_ready`, and the missing-root-filesystem error.

### Unplanned

The following are explicitly **not planned** for now (they may be contributed
through the component registry). Everything below is a known gap:

- **Components**: `modem` / `tunnel`, `data` (crypto/compress), `drive`,
  `redstone` (+ bundled / wireless / signaller), `robot`, `drone`, `tablet`,
  `server` (RPC), `geolyzer`, `motion_sensor`, `transposer`, `trading`, `sign`,
  `navigation`, `piston`, `leash`, `database`, `experience`, `generator`,
  `crafting`, `debug`, and all upgrades.
- **Internet**: proxies, OC's asynchronous `http_response` signals, TLS for TCP
  sockets, and OC's per-computer connection ownership checks.
- **GPU**: VRAM buffers (`allocateBuffer`, `freeBuffer`, `bitblt`, active
  buffer, buffer memory reporting).
- **Filesystem**: OpenComputers-style `userdata` file handles (we use integer
  tokens), symlinks, and accurate space accounting.
- **Host fidelity**: the `userdata` host API and persistence (`save`/`load`,
  NBT disk images), enforced memory limits, execution-time interrupts for
  runaway scripts, sandboxed bytecode, and alternate architectures (LuaJ / 5.2 / 5.3).
- **Front-end**: screen resize handling, the in-game `font.hex` bitmap font,
  audio (`computer.beep`), and multi-screen support.
- **Other**: save/load of machine state and CI.

## Notes

- `font.hex` (~4.7 MB) is **not** vendored: ANSI rendering uses the host font, not the in-game bitmap font.
