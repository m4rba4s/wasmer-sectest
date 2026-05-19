#!/usr/bin/env bash
set -euo pipefail

# Script to demonstrate WASI POSIX networking inside Wasmer
# It compiles a simple Rust TCP server and TCP client to WebAssembly
# and runs them in separate terminals using Wasmer.

echo "[*] Building WASI socket examples..."
cd examples/sockets
cargo build --target wasm32-wasip1 --release
cd ../..

SERVER_WASM="examples/sockets/target/wasm32-wasip1/release/server.wasm"
CLIENT_WASM="examples/sockets/target/wasm32-wasip1/release/client.wasm"

echo "[*] Launching Wasmer socket demonstration..."

if command -v tmux >/dev/null 2>&1; then
    echo "[*] Using tmux to split the terminal..."
    # Start a new tmux session in detached mode
    tmux new-session -d -s wasmer-sockets -n demo "echo '== WASM SERVER ==' && wasmer run --net $SERVER_WASM; read -p 'Press enter to exit'"
    # Split window horizontally for the client
    tmux split-window -h "echo '== WASM CLIENT ==' && sleep 2 && wasmer run --net $CLIENT_WASM && echo '' && read -p 'Press enter to exit'"
    # Attach to the session
    tmux attach-session -t wasmer-sockets
elif command -v x-terminal-emulator >/dev/null 2>&1; then
    echo "[*] Opening separate terminal emulator windows..."
    x-terminal-emulator -e bash -c "echo '== WASM SERVER ==' && wasmer run --net $SERVER_WASM; read -p 'Press enter to exit'" &
    sleep 2
    x-terminal-emulator -e bash -c "echo '== WASM CLIENT ==' && wasmer run --net $CLIENT_WASM; read -p 'Press enter to exit'" &
else
    echo "[*] No tmux or terminal emulator found. Running in the same terminal using background jobs."
    echo "-----------------------------------"
    echo "== WASM SERVER =="
    wasmer run --net "$SERVER_WASM" &
    SERVER_PID=$!
    
    sleep 2
    echo "-----------------------------------"
    echo "== WASM CLIENT =="
    wasmer run --net "$CLIENT_WASM"
    
    sleep 1
    kill $SERVER_PID || true
fi
