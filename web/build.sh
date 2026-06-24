#!/usr/bin/env bash
# Build the browser demo: compile the engine to WASM and stage the runtime +
# rules so web/ can be served as a static site.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

echo "building web/ch.wasm ..."
GOOS=js GOARCH=wasm go build -o web/ch.wasm ./cmd/wasm

echo "staging Go wasm runtime ..."
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/wasm_exec.js

echo "staging rules + lexicons ..."
mkdir -p web/config/lexicons
cp config/rules.json web/config/rules.json
cp config/lexicons/*.txt web/config/lexicons/

echo
echo "done. Serve it (a server is required — fetch()+wasm don't work over file://):"
echo "    (cd web && python3 -m http.server 8080)"
echo "then open http://localhost:8080/"
