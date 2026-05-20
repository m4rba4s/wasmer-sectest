# Wasmer Hostile-Guest Security Harness

Rust security harness for Wasmer host imports. The tool runs a deterministic
corpus of hostile WebAssembly guests against a hardened Rust host, records every
guest-host ABI decision, and can present the same evidence as a live terminal
cockpit, defensive adversary-emulation campaign, text output, Markdown, JSON,
or SARIF.

This is intentionally more than a slide demo: the TUI is only a presentation
layer over the same runner, policy, ABI checks, telemetry, and report generation
used by the CLI.

Continuous integration runs the harness on Ubuntu and macOS, plus Debian and
Arch Linux containers for extra portability coverage.

## Why This Exists

Wasmer gives the host a WebAssembly sandbox boundary, but a powerful or careless
host import can reintroduce memory-safety, capability, and resource-exhaustion
bugs. This harness treats every guest-controlled pointer, length, alignment,
string, and import call as malicious input.

The goal is to demonstrate and test host-side controls:

- validate guest linear-memory ranges before reads;
- reject `ptr + len` overflow in the 32-bit Wasm address space;
- audit module memory limits before instantiation (Static Analysis);
- enforce alignment contracts for structured ABI reads;
- parse packet headers only after the outer range is safe;
- treat capability strings as exact length-delimited UTF-8 grants;
- cap host allocations before `Vec` reserve or other host allocation work;
- run the corpus through Cranelift or Singlepass backends;
- track cooperative import-level fuel for CPU-abuse cases;
- run risky guests under an out-of-process supervisor with timeout/kill
  semantics;
- reject unmetered static-audit fixtures before a host-thread hang is possible;
- reacquire fresh `MemoryView` state after guest execution can grow memory.

## Quick Start

Interactive security console:

```bash
git clone https://github.com/m4rba4s/wasmer-sectest.git
cd wasmer-sectest/
make menu

```

Inside the menu, use a number or alias such as `t`, `i`, `ops`, `c`, `e`, or `l`.
Invalid input stays in the menu with a notice instead of exiting. Press Enter to
redraw or return after a run, and type `q` to close the application. Menu runs are recorded under
`target/security-sessions/`; the console can show recent session history,
preview the latest JSON evidence file, explain one case, open a charts
dashboard, or export an interview bundle.

Live interview cockpit:

```bash
./run-tui.sh
```

Equivalent direct command:

```bash
cargo run --release -- --interview --tui
```

## WASI Network Honeypot Demo

The network interception demo compiles a tiny Rust WASI guest, runs it inside
the Wasmer host, and proves that a public HTTP request is handled entirely by
the host sandbox. The guest asks for
`jsonplaceholder.typicode.com:80/users/1`; the host resolver returns a
synthetic `203.0.113.0/24` address, captures the request payload, blocks real
egress, and injects a deterministic HTTP 200 JSON response.

```bash
make wasi-network-demo
```

The integration test asserts both sides of the boundary: host telemetry must
contain resolve/connect/payload/mock-response events, and guest stdout must
contain the mocked JSON body. Fresh-machine installs provision the Rust
`wasm32-wasip1` target automatically.

## Policy File

By default the harness uses a strict built-in policy:

```text
max_packet_len=4096 max_cap_string=256 max_alloc=65536 fuel=256 max_memory_pages=16 require_tick_import=true supervisor_timeout_ms=250
allowed_paths=["/sandbox/allowed.txt"]
```

For tool-style runs, the same values can be supplied explicitly:

```toml
max_packet_len = 4096
max_cap_string_len = 256
max_alloc = 65536
initial_fuel = 256
max_memory_pages = 16
require_tick_import = true
supervisor_timeout_ms = 250
allowed_paths = ["/sandbox/allowed.txt"]
```

Run it with:

```bash
cargo run --release -- --policy policy.example.toml --profile all
```
