#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install.sh [--source-dir DIR] [--install-dir DIR] [--repo-url URL] [--ref REF] [--check]

Options:
  --source-dir DIR   repository root to build from
  --install-dir DIR  install destination for the release binary
                     (default: ~/.local/bin)
  --repo-url URL     git repository to clone when --source-dir is not set
                     (default: https://github.com/m4rba4s/wasmer-sectest.git)
  --ref REF          git ref to clone when --source-dir is not set
                     (default: main)
  --check            run dependency bootstrap, build, and test checks without installing
  -h, --help         show this help
EOF
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  elif have_cmd sudo; then
    sudo "$@"
  else
    echo "missing sudo; rerun as root or install the dependency manually: $*" >&2
    exit 1
  fi
}

install_linux_deps() {
  local package_manager="${1}"
  case "$package_manager" in
    apt)
      run_root apt-get update
      DEBIAN_FRONTEND=noninteractive run_root apt-get install -y \
        build-essential ca-certificates curl git pkg-config
      ;;
    dnf)
      run_root dnf install -y \
        ca-certificates curl gcc gcc-c++ git make pkgconf-pkg-config
      ;;
    pacman)
      run_root pacman -Sy --noconfirm --needed \
        base-devel ca-certificates curl git pkgconf
      ;;
    zypper)
      run_root zypper --non-interactive install \
        ca-certificates curl gcc gcc-c++ git make pkg-config
      ;;
    *)
      echo "unsupported Linux package manager: $package_manager" >&2
      exit 1
      ;;
  esac
}

linux_needs_packages() {
  if ! have_cmd git || ! have_cmd curl || ! have_cmd pkg-config; then
    return 0
  fi

  if ! have_cmd make; then
    return 0
  fi

  if ! have_cmd cc && ! have_cmd gcc && ! have_cmd clang; then
    return 0
  fi

  return 1
}

ensure_system_dependencies() {
  local os
  os="$(uname -s)"

  if [[ "$os" == "Linux" ]]; then
    if linux_needs_packages; then
      if have_cmd apt-get; then
        install_linux_deps apt
      elif have_cmd dnf; then
        install_linux_deps dnf
      elif have_cmd pacman; then
        install_linux_deps pacman
      elif have_cmd zypper; then
        install_linux_deps zypper
      else
        echo "no supported Linux package manager found (apt-get, dnf, pacman, zypper)" >&2
        exit 1
      fi
    fi
  elif [[ "$os" == "Darwin" ]]; then
    if ! have_cmd git || ! have_cmd curl || ! have_cmd pkg-config; then
      if have_cmd brew; then
        brew install ca-certificates curl git pkg-config
      else
        if ! xcode-select -p >/dev/null 2>&1; then
          echo "Xcode Command Line Tools are missing. Install them with: xcode-select --install" >&2
          exit 1
        fi
        echo "Homebrew is not installed; using existing Apple toolchain and skipping package installs"
      fi
    fi
  else
    echo "unsupported operating system: $os" >&2
    exit 1
  fi
}

ensure_rust_toolchain() {
  local cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
  local rustup_home="${RUSTUP_HOME:-${HOME}/.rustup}"
  export CARGO_HOME="${cargo_home}"
  export RUSTUP_HOME="${rustup_home}"

  if ! have_cmd rustup; then
    echo "installing Rust toolchain via rustup"
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "${TMPDIR:-/tmp}/rustup-init.sh"
    CARGO_HOME="${CARGO_HOME}" RUSTUP_HOME="${RUSTUP_HOME}" \
      sh "${TMPDIR:-/tmp}/rustup-init.sh" -y --profile minimal --default-toolchain stable
  fi

  export PATH="${CARGO_HOME}/bin:${PATH}"
  if ! rustup toolchain list | grep -q '^stable'; then
    rustup toolchain install stable >/dev/null
  fi

  if ! rustup component list --installed | grep -q '^rustfmt-'; then
    rustup component add rustfmt >/dev/null
  fi

  if ! rustup component list --installed | grep -q '^clippy-'; then
    rustup component add clippy >/dev/null
  fi

  if ! rustup target list --installed | grep -q '^wasm32-wasip1$'; then
    rustup target add wasm32-wasip1 >/dev/null
  fi
}

source_dir=""
install_dir="${HOME}/.local/bin"
repo_url="https://github.com/m4rba4s/wasmer-sectest.git"
ref="main"
check_only=false
cleanup_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-dir)
      source_dir="${2:-}"
      shift 2
      ;;
    --install-dir)
      install_dir="${2:-}"
      shift 2
      ;;
    --repo-url)
      repo_url="${2:-}"
      shift 2
      ;;
    --ref)
      ref="${2:-}"
      shift 2
      ;;
    --check)
      check_only=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "$source_dir" ]]; then
  if [[ ! -f "$source_dir/Cargo.toml" ]]; then
    echo "source-dir does not look like the repository root: $source_dir" >&2
    exit 2
  fi
else
  cleanup_dir="$(mktemp -d)"
  trap 'rm -rf "$cleanup_dir"' EXIT
  source_dir="$cleanup_dir/wasmer-sectest"
  git clone --depth 1 --branch "$ref" "$repo_url" "$source_dir"
fi

ensure_system_dependencies
ensure_rust_toolchain

cd "$source_dir"

echo "install source: $source_dir"

cargo +stable fmt --check
cargo +stable test
cargo +stable clippy -- -D warnings
cargo +stable build --release

printf 'q\n' | cargo +stable run --release -- --menu --no-color >/dev/null

if [[ "$check_only" == true ]]; then
  echo "install check complete"
  exit 0
fi

mkdir -p "$install_dir"
cp target/release/wasmer-demo "$install_dir/wasmer-demo"
chmod 0755 "$install_dir/wasmer-demo"
echo "installed: $install_dir/wasmer-demo"
