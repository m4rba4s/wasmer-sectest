#!/usr/bin/env bash
set -euo pipefail

target="${1:-wasm32-wasip1}"
toolchain="${WASMER_SECTEST_RUST_TOOLCHAIN:-stable}"

has_target_std() {
  local target_libdir
  target_libdir="$("$@" --print target-libdir --target "${target}" 2>/dev/null || true)"
  [[ -n "${target_libdir}" ]] && compgen -G "${target_libdir}/libstd-*.rlib" >/dev/null
}

if ! command -v rustup >/dev/null 2>&1; then
  rustc_bin="${RUSTC:-rustc}"
  if ! command -v "${rustc_bin}" >/dev/null 2>&1; then
    echo "error: rustc is required before building WASI guests" >&2
    exit 1
  fi

  if has_target_std "${rustc_bin}"; then
    exit 0
  fi

  cat >&2 <<EOF
error: Rust stdlib for ${target} is not installed.

Install rustup and then run:
  rustup target add --toolchain ${toolchain} ${target}

If this Rust toolchain was not installed through rustup, install the matching
WASI stdlib package for your distribution/toolchain before rerunning make.
EOF
  exit 1
fi

if ! rustup run "${toolchain}" rustc -V >/dev/null 2>&1; then
  echo "installing Rust toolchain ${toolchain}"
  rustup toolchain install "${toolchain}" --profile minimal
fi

if has_target_std rustup run "${toolchain}" rustc; then
  exit 0
fi

echo "installing Rust target ${target} for ${toolchain}"
if ! rustup target add --toolchain "${toolchain}" "${target}"; then
  cat >&2 <<EOF
error: failed to install Rust stdlib for ${target} on ${toolchain}.

If rustup reported "Permission denied", the selected toolchain directory under
RUSTUP_HOME is not writable by the current user. Fix that ownership or choose a
writable toolchain with:
  make RUST_TOOLCHAIN=<toolchain> wasi-network-demo
EOF
  exit 1
fi

if ! has_target_std rustup run "${toolchain}" rustc; then
  echo "error: Rust stdlib for ${target} is still unavailable on ${toolchain}" >&2
  exit 1
fi
