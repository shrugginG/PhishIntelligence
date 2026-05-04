#!/usr/bin/env bash
# DSM Task Scheduler invokes this script every 15 min.
#
# `docker run --name phish-urlscan-fetcher` acts as a concurrency lock: if the
# previous tick is still in flight, the new docker run fails immediately
# ("name in use") and DSM logs the skip — naturally preventing tick overlap.

set -euo pipefail
cd "$(dirname "$0")"

exec docker run --rm \
  --name phish-urlscan-fetcher \
  --user 1026:100 \
  --env-file .env \
  -v "$HOME/data/phishing/urlscan_results:/data" \
  phish-urlscan-fetcher:latest
