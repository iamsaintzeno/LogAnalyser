#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"

if [ ! -d node_modules ]; then npm ci; fi
if [ ! -d frontend/node_modules ]; then npm ci --prefix frontend; fi
npm run build
npm run preview --prefix frontend -- --host 127.0.0.1 --port 4173 --strictPort &
preview_pid=$!
trap 'kill "$preview_pid" 2>/dev/null || true' EXIT INT TERM
sleep 1
if command -v open >/dev/null 2>&1; then open http://127.0.0.1:4173
elif command -v xdg-open >/dev/null 2>&1; then xdg-open http://127.0.0.1:4173
fi
wait "$preview_pid"
