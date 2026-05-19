##Wasmer Hostile-Guest Security Harness

Rust security harness for Wasmer host imports. The tool runs a deterministic corpus of hostile WebAssembly guests against a hardened Rust host, records every guest-host ABI decision, and can present the same evidence as a live terminal cockpit, text output, Markdown, JSON, or SARIF.

This is intentionally more than a slide demo: the TUI is only a presentation layer over the same runner, policy, ABI checks, telemetry, and report generation used by the CLI.
