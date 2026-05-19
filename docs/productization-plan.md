# Productization Plan

## Current Shape

The repository is already structured like a small security tool:

- corpus: hostile WAT guests in `guests/`;
- external corpus loader: recursive `.wat`/`.wasm` loading with optional
  `corpus.toml` metadata;
- runner: deterministic Wasmer execution in `src/runner.rs`;
- policy: limits, capability allow-list, and optional policy file parsing in
  `src/policy.rs`;
- static audit: memory declarations and unmetered CPU-risk fixtures are denied
  before instantiation or execution;
- process supervisor: risky guests can run in a worker process with
  timeout/kill containment and `ERR_TIMEOUT` evidence;
- ABI: low-level range and packet validation in `src/abi.rs`;
- evidence: import telemetry and memory snapshots in `src/telemetry.rs`;
- outputs: text, Markdown, JSON, SARIF, campaign, and TUI views;
- adversary emulation: curated campaign profile with stage, TTP, detection, and
  control metadata for each case;
- CI: format, unit tests, release corpus execution, policy mode, reports, and
  Singlepass backend smoke coverage;
- regression test: the whole hostile corpus must match expected results.

## Serious Tool Milestones

1. External corpus input

   `--corpus DIR` now runs all `.wat`/`.wasm` files from that directory. Keep
   built-in cases as regression fixtures and use `corpus.toml` when expected
   outcomes must be stable in CI.

2. Policy config

   Packet, string, allocation, fuel, memory, CPU-budget, and capability
   settings can now be loaded from a strict TOML-like file:

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

   The next step is named profiles and per-import settings.

3. CI-native reporting

   SARIF output now exists for corpus regressions. The next step is to enrich it
   with external corpus remediation text, tags, and stable rule help URIs so
   findings can show up cleanly in GitHub code scanning or security dashboards.

4. Threat-informed campaign mode

   `--campaign` now runs a safe adversary-emulation chain over the same Wasmer
   harness. It should stay defensive: no persistence, stealth, credential
   access, exfiltration, or real target interaction. The next step is to allow
   external corpus manifests to provide stage, TTP, and detection fields.

5. Runtime CPU metering

   The current `tick` import demonstrates cooperative fuel, the static audit
   fixture proves the runner will not execute a known unmetered infinite loop
   in-process, and the process supervisor proves timeout/kill containment. A
   production tool should also exercise Wasmer metering as a second line of
   defense.

6. WASI capability scenarios

   Add cases around preopened directories, inherited environment variables,
   stdio, clock/random access, and network-facing host functions.

7. Version/backend matrix

   CI now runs the core harness and Singlepass backend. Keep the local CLI
   matrix as a convenience, and add a pinned Wasmer-version matrix when the
   project starts validating upgrades.

## Interview Framing

This is a credible internal security harness because it is deterministic,
produces evidence artifacts, has a clear threat model, refuses unsafe static
fixtures before execution, and keeps host-import hardening separate from
presentation code. The campaign profile adds a threat-informed story for
security leads without turning the project into an offensive tool. It can also
run external corpora without recompiling the harness.
