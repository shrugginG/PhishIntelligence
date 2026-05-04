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

cd "$SCRIPT_DIR"

exec "$DOCKER_BIN" run --rm \
  --name phish-urlscan-fetcher \
  --user 1026:100 \
  --env-file "$SCRIPT_DIR/.env" \
  -v "${HOST_DATA_DIR}:/data" \
  phish-urlscan-fetcher:latest
