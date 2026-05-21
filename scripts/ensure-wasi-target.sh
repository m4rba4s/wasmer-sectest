#!/usr/bin/env bash
set -euo pipefail

target="${1:-wasm32-wasip1}"
rustc_bin="${RUSTC:-rustc}"

if ! command -v "${rustc_bin}" >/dev/null 2>&1; then
  echo "error: rustc is required before building WASI guests" >&2
  exit 1
fi

target_libdir="$("${rustc_bin}" --print target-libdir --target "${target}" 2>/dev/null || true)"
if [[ -n "${target_libdir}" ]] && compgen -G "${target_libdir}/libstd-*.rlib" >/dev/null; then
  exit 0
fi

if ! command -v rustup >/dev/null 2>&1; then
  cat >&2 <<EOF
error: Rust stdlib for ${target} is not installed.

Install it with:
  rustup target add ${target}

If this Rust toolchain was not installed through rustup, install the matching
WASI stdlib package for your distribution/toolchain before rerunning make.
EOF
  exit 1
fi

echo "installing Rust target ${target}"
rustup target add "${target}"
