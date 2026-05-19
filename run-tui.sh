#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

printf '\033]0;Wasmer Security Harness\007'
trap 'printf "\033[0m\033[?25h\n"' EXIT
if [[ -t 1 ]]; then
  clear
fi
echo "Starting Wasmer hostile-guest security harness..."
echo "Stop: Ctrl+C"
sleep 0.8

cargo run --quiet --release -- --interview --tui
