#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

out_dir="target/guest-wasm"
matrix_dir="target/wasmer-cli-matrix"
mkdir -p "$out_dir" "$matrix_dir"

cargo run --quiet --offline -- --emit-wasm-dir "$out_dir" >/dev/null

printf 'backend,case,status,artifact\n'
for backend in cranelift singlepass llvm; do
  for wasm in "$out_dir"/*.wasm; do
    case_name="$(basename "$wasm" .wasm)"
    artifact="$matrix_dir/${case_name}-${backend}.wasmu"
    if wasmer compile "--$backend" -o "$artifact" "$wasm" >/dev/null 2>&1; then
      printf '%s,%s,ok,%s\n' "$backend" "$case_name" "$artifact"
    else
      printf '%s,%s,fail,%s\n' "$backend" "$case_name" "$artifact"
    fi
  done
done
