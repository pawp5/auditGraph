#!/usr/bin/env bash
# Fallback for machines without Docker: runs a real FalkorDB server (redis-server +
# FalkorDB module) from the `falkordblite` pip package, on the same port as docker-compose.
# Usage: pip install falkordblite && ./scripts/falkordb_nodocker.sh
set -euo pipefail
BIN=$(python3 -c "import redislite,os;print(os.path.join(os.path.dirname(redislite.__file__),'bin'))")
PORT=${FALKORDB_PORT:-6380}
mkdir -p .falkordb
setsid nohup "$BIN/redis-server" --port "$PORT" --loadmodule "$BIN/falkordb.so" \
  --dir "$(pwd)/.falkordb" --logfile "$(pwd)/.falkordb/server.log" >/dev/null 2>&1 &
for _ in $(seq 1 20); do
  if "$BIN/redis-cli" -p "$PORT" ping >/dev/null 2>&1; then echo "FalkorDB running on port $PORT (data in .falkordb/)"; exit 0; fi
  sleep 0.5
done
echo "FalkorDB did not start; see .falkordb/server.log" >&2; exit 1
