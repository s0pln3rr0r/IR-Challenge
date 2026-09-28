#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$ROOT/runtime/capture.pid" ]]; then
  sudo kill -INT "$(cat "$ROOT/runtime/capture.pid")" 2>/dev/null || true
  rm -f "$ROOT/runtime/capture.pid"
fi
echo "[+] capture stopped"
