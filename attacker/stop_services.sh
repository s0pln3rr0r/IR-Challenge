#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for svc in http dns websocket; do
  pidf="$ROOT/runtime/${svc}.pid"
  if [[ -f "$pidf" ]]; then
    kill "$(cat "$pidf")" 2>/dev/null || true
    rm -f "$pidf"
    echo "[+] Stopped $svc service"
  fi
done
echo "[+] All services stopped"