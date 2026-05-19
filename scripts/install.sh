#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install.sh [--source-dir DIR] [--install-dir DIR] [--check]

Options:
  --source-dir DIR   repository root to build from (default: current directory)
  --install-dir DIR  install destination for the release binary
                     (default: ~/.local/bin)
  --check            run build and test checks without installing
  -h, --help         show this help
EOF
}

source_dir="$(pwd)"
install_dir="${HOME}/.local/bin"
check_only=false

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

if [[ ! -f "$source_dir/Cargo.toml" ]]; then
  echo "source-dir does not look like the repository root: $source_dir" >&2
  exit 2
fi

cd "$source_dir"

echo "install source: $source_dir"

cargo fmt --check
cargo test
cargo clippy -- -D warnings
cargo build --release

printf 'q\n' | cargo run --release -- --menu --no-color >/dev/null

if [[ "$check_only" == true ]]; then
  echo "install check complete"
  exit 0
fi

mkdir -p "$install_dir"
cp target/release/wasmer-demo "$install_dir/wasmer-demo"
chmod 0755 "$install_dir/wasmer-demo"
echo "installed: $install_dir/wasmer-demo"
