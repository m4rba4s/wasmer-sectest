# Security Policy

This project is a defensive Wasmer host-import hardening harness. It is not a
Wasmer escape, exploit framework, or target scanner.

## Supported Surface

- Built-in hostile guest corpus under `guests/`
- External `.wat` / `.wasm` corpora loaded through `--corpus`
- Policy limits in `policy.example.toml`
- Text, Markdown, JSON, SARIF, campaign, and TUI evidence output

## Reporting A Control Regression

A control regression is any case where a hostile guest no longer returns its
expected code, a static audit fixture executes when it should not, or a report
omits the denial evidence needed to understand the boundary failure.

Useful evidence:

```bash
cargo test
cargo run --release -- --campaign --summary-only --no-color
cargo run --release -- --profile all --summary-only --no-color
cargo run --release -- --profile all --format sarif --report target/wasmer-harness.sarif
```

## Boundaries

The harness validates host-side ABI, capability, allocation, memory, and
cooperative CPU-budget controls. The process supervisor can contain a
non-cooperative guest with timeout/kill semantics and reports `ERR_TIMEOUT`.
Runtime metering remains useful as an additional defense layer for arbitrary
external modules.

The adversary-emulation campaign is defensive and local. It maps sandbox abuse
attempts to stages, TTP tags, detections, and controls, but it does not include
persistence, stealth, credential access, exfiltration, command-and-control, or
third-party target interaction.
