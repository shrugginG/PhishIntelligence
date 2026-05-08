#!/usr/bin/env bash
# DSM Task Scheduler invokes this every 30 min:
#   /var/services/.../phishing_virustotal_fetcher/run.sh
#
# `--name phishing_virustotal_fetcher` acts as a concurrency lock: if the
# previous tick is still in flight, the new docker run fails immediately
# ("name in use") and DSM logs the skip. Combined with HARD_BUDGET_SEC inside
# the container and the OS-level `timeout` wrapper outside, ticks cannot
# overlap, deadlock, or stack indefinitely.
#
# Robust to being invoked by:
#   - DSM Task Scheduler (typically as root; $HOME = /root)
#   - jxlu manually (sudo); $HOME may or may not be preserved
# All paths absolute, no $HOME / $PATH assumptions.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_BIN="/usr/local/bin/docker"
IMAGE="phishing_virustotal_fetcher:latest"
# OS-level hard kill: container's in-process HARD_BUDGET_SEC (default 720s)
# only stops scheduling new work; an asyncio deadlock would leave the process
# alive holding the --name lock. `timeout` SIGTERMs at 900s, SIGKILLs 30s
# later; `--rm` then frees the container name for the next 30-min tick.
HARD_KILL_SEC=900

cd "$SCRIPT_DIR"

exec timeout --kill-after=30 "$HARD_KILL_SEC" "$DOCKER_BIN" run --rm \
  --name phishing_virustotal_fetcher \
  --user 1026:100 \
  --env-file "$SCRIPT_DIR/.env" \
  "$IMAGE"
