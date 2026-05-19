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
  --check            run build and test checks without installing
  -h, --help         show this help
EOF
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
