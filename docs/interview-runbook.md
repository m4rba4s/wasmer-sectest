# Interview Runbook

## One-Minute Setup

Interactive security console:

```bash
cargo run --release -- --menu
```

Use the numbered choices, press Enter to return to the menu after a run, and
type `q` when the demo is finished. The console records menu runs in
`target/security-sessions/`, can replay recent session evidence, explain a
single boundary case, and export `target/demo-bundle/` for interview material.

```bash
./run-tui.sh
```

Fallback without animation:

```bash
cargo run --release -- --interview --no-color
```

Evidence artifact:

```bash
cargo run --release -- --profile interview --format markdown --report target/interview-report.md
cargo run --release -- --profile all --format sarif --report target/wasmer-harness.sarif
```

Process-supervisor proof:

```bash
cargo run --release -- --case non_cooperative_loop --isolate process --timeout-ms 100 --no-color
```

Explicit policy run:

```bash
cargo run --release -- --policy policy.example.toml --interview --no-color
```

External corpus run:

```bash
cargo run --release -- --corpus examples/external-corpus --no-color
```

## Story

This is a Wasmer host-import security harness. It treats a WebAssembly guest as
malicious input and validates host-side ABI boundaries before any privileged
host action happens. The terminal UI is the live presentation layer over the
same telemetry that powers text, Markdown, and JSON reports.

Short pitch:

> I wanted to show that I understand the sandbox boundary from the host side.
> The guest is untrusted, but the import implementation is my code, so I built a
> harness that attacks that boundary and records exactly which gate stopped each
> case.

## Compilation Explanation

The host is a normal Rust binary:

```bash
cargo build --release
```

The guests are WAT source files checked into `guests/`. The binary compiles them
at runtime with the `wat` crate and then hands the resulting Wasm bytes to
Wasmer:

```text
WAT source -> wasm bytes -> Wasmer Module -> Instance -> guest run() -> host imports
```

That design keeps the hostile corpus readable in the repo while still using the
real Wasmer Rust API during execution.

The default policy can also be loaded from `policy.example.toml`. This shows the
tool boundary clearly: guest corpus, host ABI, and host policy are separate
inputs. The default policy also caps module memory pages and requires the
`host.tick` CPU-budget import before a module can execute in-process.

For the non-cooperative fixture, the CLI can switch from static audit to a real
supervised run. The parent process spawns a worker, waits for the configured
timeout, kills the worker if it keeps looping, and reports `ERR_TIMEOUT` through
the same evidence pipeline.

External corpus mode loads `.wat` and `.wasm` files from a directory. A
`corpus.toml` manifest can attach expected return codes and case metadata, so the
same runner can be used for curated demos and CI-style regression corpora.

## Live Flow

1. `good_packet`: positive control. A valid packet crosses the boundary.
2. `ptr_len_overflow`: `ptr + len` wraps the 32-bit address space and fails at
   `checked_add`.
3. `out_of_bounds`: arithmetic succeeds, but the checked end offset exceeds the
   current `MemoryView`.
4. `zero_length_packet`: an empty range can pass the outer range gates, but it
   fails the fixed packet header gate.
5. `body_len_mismatch` and `checksum_mismatch`: nested packet fields are
   validated after the outer range is safe to read.
6. `capability_escape`, `capability_allowed`, and `null_byte_capability`: host
   capabilities are exact length-delimited grants, with a positive control for
   the allowed path.
7. `excessive_alloc`: allocation policy is checked before host allocation.
8. `cpu_metered_loop`: cooperative import fuel stops host-driven CPU abuse.
9. `non_cooperative_loop`: the static audit path refuses a known infinite-loop
   fixture without executing it; `--isolate process` demonstrates timeout/kill
   behavior.
10. `excessive_memory`: module memory declarations are denied before
   instantiation.
11. `memory_grow_probe`: guest memory growth is visible in telemetry, and host
   code reacquires a fresh view instead of holding stale linear-memory state.

## Honest Limits

- This is a host-import hardening demo, not a Wasmer escape.
- Import fuel demonstrates cooperative metering, and the process supervisor
  demonstrates timeout/kill containment for a non-cooperative loop. Arbitrary
  external infinite loops still need runtime metering, strict
  `require_tick_import`, or supervised process isolation.
- The corpus is intentionally local and deterministic so it can be rerun during
  an interview.

## Tech Lead Angle

- The architecture separates runner, ABI validation, policy, telemetry, reports,
  recorded sessions, and presentation.
- Host security limits can be provided as an explicit policy file, so the demo
  is not tied to hidden constants.
- External corpora can be tested without recompiling the harness.
- Positive controls show that the host still accepts valid inputs.
- Negative controls are mapped to specific security gates, not just generic
  failures.
- SARIF stays clean when the expected hostile corpus passes; it creates a
  CI/security-dashboard alert only when a control regresses.
- Remaining expansion areas are richer external-corpus metadata, runtime
  metering as another defense layer, WASI capability cases, and CI across
  Wasmer crate versions.
