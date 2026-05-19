# Threat Model

## Assets

- Host process memory and Rust safety invariants.
- Host filesystem, environment, and future network capabilities.
- Host CPU and allocation budget.
- Correct ABI interpretation across the guest-host boundary.

## Attacker

- A fully malicious WebAssembly guest.
- Controls all bytes in linear memory.
- Controls `i32` pointer, length, and alignment arguments passed to imports.
- Can pass wrapped addresses such as `0xfffffff0`.
- Can grow linear memory between host observations.
- Can repeatedly call host imports to consume CPU or allocations.
- Can omit cooperative host imports and try to run forever inside guest code.
- Can send empty ranges, oversized lengths, invalid UTF-8, and embedded NUL
  bytes through host string and packet ABIs.

## Security Posture

- Default deny for capabilities. The demo allows only `/sandbox/allowed.txt`.
- No host filesystem read is performed by the demo capability import.
- Every guest range goes through `checked_add`, alignment, max-length, and bounds gates.
- The host reacquires a fresh `MemoryView` after guest execution that may grow memory.
- Capability strings are length-delimited UTF-8 and compared as exact grants.
- Module memory declarations are audited before instantiation.
- CPU defense is demonstrated as import-level fuel.
- The built-in non-cooperative infinite-loop fixture is static-audit-only and
  is never executed in-process.
- Process isolation can run a risky guest under a supervised worker, enforce a
  timeout, kill the child, and report `ERR_TIMEOUT`.
- Arbitrary external non-cooperative loops still require compiler/runtime
  metering, a strict `require_tick_import` policy, or supervised process
  isolation.

## Non-Goals

- Kernel exploitation.
- Escaping Wasmer itself.
- Attacking third-party targets or real services.
- Weaponized exploit chains.
