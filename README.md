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

Install from GitHub without cloning first:

```bash
curl -fsSL https://raw.githubusercontent.com/m4rba4s/wasmer-sectest/main/scripts/install.sh | bash -s -- --check
```

Install the release binary into a local directory:

```bash
curl -fsSL file://$PWD/scripts/install.sh | bash -s -- --source-dir "$PWD" --install-dir "$PWD/target/install-bin"
```

The installer provisions the build dependencies it can manage on the current
platform, then bootstraps `rustup` so `cargo`, `rustfmt`, and `clippy` are
available before the build starts. On macOS, Homebrew is used when present; if
Homebrew is missing, install Xcode Command Line Tools first.

Non-animated interview output:

```bash
cargo run --release -- --interview --no-color
```

Defensive adversary-emulation campaign:

```bash
cargo run --release -- --campaign --no-color
```

Run with an explicit policy file:

```bash
cargo run --release -- --policy policy.example.toml --interview --no-color
```

Run an external corpus directory:

```bash
cargo run --release -- --corpus examples/external-corpus --no-color
```

Single hostile case:

```bash
cargo run --release -- --case ptr_len_overflow
```

List cases:

```bash
cargo run -- --list
```

Generate evidence reports:

```bash
cargo run --release -- --profile interview --format markdown --report target/interview-report.md
cargo run --release -- --profile campaign --format markdown --report target/adversary-campaign.md
cargo run --release -- --profile resource --format json --report target/resource-report.json
cargo run --release -- --profile all --format sarif --report target/wasmer-harness.sarif
```

Stress run:

```bash
cargo run --release -- --repeat 1000 --summary-only --no-color
```

Process-supervised timeout proof:

```bash
cargo run --release -- --case non_cooperative_loop --isolate process --timeout-ms 100 --no-color
```

## Build And Compilation Model

There are two compilation paths in the project.

The Rust host is compiled by Cargo into a native binary:

```bash
cargo build --release
```

The hostile guests live as readable WAT files in `guests/`. At runtime, the
binary converts each WAT guest to Wasm bytes with the `wat` crate, then passes
those bytes into Wasmer:

```text
guests/*.wat -> wat::parse_str -> wasm bytes -> wasmer::Module -> wasmer::Instance -> run()
```

The crate currently pins `wasmer = 6.1.0` and supports the Cranelift and
Singlepass backends through Wasmer's Rust API:

```bash
cargo run --release -- --profile all --backend cranelift --summary-only --no-color
cargo run --release -- --profile all --backend singlepass --summary-only --no-color
```

Release mode is used for the live demo so compile/run timings are
representative and the TUI does not feel sluggish.

To inspect the generated guest modules separately:

```bash
cargo run --release -- --emit-wasm-dir target/guests-wasm
```

If the `wasmer` CLI is installed, this optional matrix checks whether the
emitted guests compile through CLI backends such as Cranelift, Singlepass, and
LLVM:

```bash
./scripts/wasmer-cli-matrix.sh
```

The matrix is intentionally separate from the core Rust harness. The core tool
needs only the Rust dependencies in `Cargo.toml`; the CLI matrix is extra
evidence when the local machine has the Wasmer CLI available.

## Architecture

- `src/main.rs`: CLI entrypoint, profile selection, report routing, TUI mode.
- `src/corpus.rs`: external `.wat`/`.wasm` corpus loading and manifest parsing.
- `src/runner.rs`: Wasmer store/module/instance setup and host import wiring.
- `src/session.rs`: recorded run history and JSON evidence sessions.
- `src/supervisor.rs`: process worker, timeout, kill, and worker-protocol
  evidence for non-cooperative guests.
- `src/abi.rs`: packet parser, guest range validation, ABI error mapping.
- `src/policy.rs`: packet/string/allocation/fuel/memory limits, required CPU
  budget import, capability allow-list, and optional policy file parsing.
- `src/telemetry.rs`: import events, gates, timing, memory snapshots.
- `src/report.rs`: text, Markdown, JSON, SARIF, and adversary-emulation evidence output.
- `src/tui.rs`: live terminal cockpit that replays real telemetry gates.
- `guests/*.wat`: hostile and positive-control WebAssembly guests.
- `docs/threat-model.md`: security assumptions and non-goals.
- `docs/abi-contract.md`: guest-host packet and capability ABI contract.
- `docs/interview-runbook.md`: short narrative for the interview.
- `SECURITY.md`: supported security surface and reporting boundaries.
- `.github/workflows/ci.yml`: reproducible verification workflow.
- `policy.example.toml`: explicit policy config matching the default policy.
- `examples/external-corpus/`: small external corpus with metadata manifest.

## Profiles

```bash
cargo run --release -- --profile all
cargo run --release -- --profile interview
cargo run --release -- --profile campaign
cargo run --release -- --profile abi
cargo run --release -- --profile memory
cargo run --release -- --profile capability
cargo run --release -- --profile resource
```

The campaign profile is a safe APT-style adversary-emulation chain. It models
operator pressure against a Wasmer host boundary with stages such as ABI
contract drift, payload integrity abuse, guest pointer confusion, capability
escalation, resource pressure, and containment validation. Each case carries a
stage, TTP tag, detection signal, and defensive control in the terminal and
saved reports. It does not implement persistence, stealth, exfiltration, or any
real target interaction.

The interview profile is curated for a 7-10 minute technical walkthrough:

1. `good_packet`: positive control.
2. `ptr_len_overflow`: checked arithmetic before memory access.
3. `invalid_align_param`: strict ABI contracts.
4. `out_of_bounds`: current memory size bounds check.
5. `body_len_mismatch` and `checksum_mismatch`: nested packet validation.
6. `capability_escape`, `capability_allowed`, `null_byte_capability`: exact
   length-delimited capability grants with a positive control.
7. `excessive_alloc`: host allocation cap.
8. `cpu_metered_loop`: cooperative import fuel.
9. `non_cooperative_loop`: static audit refuses an infinite loop fixture before
   execution; process isolation proves timeout/kill behavior.
10. `excessive_memory`: module memory limits are audited before instantiation.
11. `zero_length_packet`: empty ranges do not bypass fixed-header parsing.
12. `memory_grow_probe`: memory growth and fresh view reacquisition.

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

The parser is deliberately small and strict: unknown keys fail fast, and
capabilities are exact strings. That keeps policy drift visible during security
reviews.

## External Corpus

`--corpus DIR` turns the harness into an audit runner for modules outside the
built-in demo corpus. The loader scans recursively for `.wat` and `.wasm` files.
If `DIR/corpus.toml` exists, it supplies expected return codes and metadata:

```toml
[[case]]
file = "external_overflow.wat"
name = "external_ptr_len_overflow"
expected = "ERR_BOUNDS"
category = "external-memory"
severity = "critical"
description = "external WAT guest wraps ptr + len"
control = "checked_add catches overflow for external corpus modules"
```

Without a manifest entry, a module defaults to `expected = "OK"` and
`category = "external"`. That keeps ad hoc smoke tests easy while still
allowing CI-grade expected outcomes when a corpus is curated.

The default policy requires a `host.tick` import for in-process execution. For
external modules without that cooperative CPU-budget hook, either declare
`expected = "ERR_BUDGET"` in the manifest or run with an explicit policy that
sets `require_tick_import = false`.

For audit-only fixtures that must not execute in-process, set
`kind = "static_audit"` in `corpus.toml`.

When process isolation is enabled with `--isolate process`, the parent harness
spawns a worker process, waits up to `supervisor_timeout_ms` or `--timeout-ms`,
and kills the worker on timeout. A killed worker reports `ERR_TIMEOUT` with
`host.supervisor.process` evidence.

Single external case:

```bash
cargo run --release -- --corpus examples/external-corpus --case external_ptr_len_overflow --no-color
```

## Interview Positioning

The concise pitch:

> I built a small Wasmer host-import security harness. It treats Wasm guests as
> malicious inputs, runs a hostile guest corpus, validates host-side ABI and
> capability boundaries, and emits reproducible evidence. The TUI is just the
> live view over the same telemetry.

What to emphasize for a tech lead:

- The boundary is explicit: the guest can control linear memory and import
  arguments; the host owns validation and policy.
- The code separates concerns: ABI parsing, policy, execution, telemetry, and
  presentation are separate modules.
- Security limits and capability grants can be loaded from an explicit policy
  file instead of being hidden in the runner.
- External `.wat` and `.wasm` corpora can be loaded without changing the binary.
- Positive controls are included, so the harness proves that valid behavior
  still works.
- Every denial has evidence: gate name, import, pointer/length/alignment,
  memory size, return code, and timing.
- The non-cooperative loop can be shown two ways: static audit in the normal
  interview profile, and real timeout/kill evidence with `--isolate process`.
- CI output is clean by default: SARIF emits alerts only when the corpus
  regresses from expected behavior.
- The limitations are stated honestly: this is not a Wasmer escape, and
  arbitrary non-cooperative loops still need runtime metering, process
  isolation, or the strict `require_tick_import` guard.

## Toward A Full Tool

The repository now has the shape of a small audit tool:

- reusable case corpus;
- external corpus loader;
- deterministic runner;
- policy object;
- optional policy config file;
- structured telemetry;
- machine-readable JSON and SARIF reports;
- out-of-process supervisor for timeout/kill semantics;
- live presentation layer;
- tests that assert the hostile corpus still matches expected outcomes;
- CI workflow that checks formatting, tests, release execution, report
  generation, policy mode, and the Singlepass backend.

The next production steps are straightforward:

- add richer external corpus manifests with remediation text and tags;
- enrich SARIF with custom external corpora and remediation metadata;
- add Wasmer runtime metering as a second line of defense for non-cooperative
  CPU loops;
- support WASI capability scenarios;
- add corpus minimization and regression labels;
- run the harness in CI across multiple Wasmer crate versions when an upgrade
  matrix is needed.

## Verification

```bash
cargo fmt
cargo test
cargo run --release -- --profile all --summary-only --no-color
cargo run --release -- --profile all --backend singlepass --summary-only --no-color
cargo run --release -- --case non_cooperative_loop --isolate process --timeout-ms 100 --no-color
cargo run --release -- --policy policy.example.toml --interview --no-color
cargo run --release -- --corpus examples/external-corpus --no-color
cargo run --release -- --interview --no-color
cargo run --release -- --interview --tui
cargo run --release -- --profile all --format sarif --report target/wasmer-harness.sarif
```

Expected result for the full built-in corpus:

```text
summary: 24/24 passed, 0 failed
```

Expected result for the curated interview profile:

```text
summary: 15/15 passed, 0 failed
```
