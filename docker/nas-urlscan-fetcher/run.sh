#!/usr/bin/env bash
# DSM Task Scheduler invokes this script every 15 min.
#
# `docker run --name phish-urlscan-fetcher` acts as a concurrency lock: if the
# previous tick is still in flight, the new docker run fails immediately
# ("name in use") and DSM logs the skip — naturally preventing tick overlap.
#
# Robust to being invoked by:
#   - DSM Task Scheduler (typically as root; $HOME = /root)
#   - jxlu manually (sudo); $HOME may or may not be preserved
# All paths absolute, no $HOME / $PATH assumptions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST_DATA_DIR="/var/services/homes/jxlu/data/phishing/urlscan_results"
DOCKER_BIN="/usr/local/bin/docker"
# OS-level hard kill: container's in-process HARD_BUDGET_SEC only stops
# scheduling new work; if asyncio loop deadlocks (observed once: futex_wait
# for 6h+, holding the --name lock and blocking every subsequent DSM tick)
# the process won't exit. `timeout` SIGTERMs at 900s, SIGKILLs 30s later;
# `--rm` then frees the container name so the next 15-min tick can proceed.
HARD_KILL_SEC=900

cd "$SCRIPT_DIR"

exec timeout --kill-after=30 "$HARD_KILL_SEC" "$DOCKER_BIN" run --rm \
  --name phish-urlscan-fetcher \
  --user 1026:100 \
  --env-file "$SCRIPT_DIR/.env" \
  -v "${HOST_DATA_DIR}:/data" \
  phish-urlscan-fetcher:latest
