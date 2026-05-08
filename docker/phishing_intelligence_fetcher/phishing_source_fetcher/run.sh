#!/usr/bin/env bash
# DSM Task Scheduler invokes this script for each raw source, e.g.:
#   /var/services/.../phishing_source_fetcher/run.sh phishtank
#   /var/services/.../phishing_source_fetcher/run.sh openphish_academic
#
# `--name phishing_source_fetcher_<action>` is a per-source concurrency lock:
# if the previous tick of THIS source is still in flight, the new docker run
# fails immediately ("name in use") and DSM logs the skip. Different sources
# do NOT block each other (different --name → independent locks).
#
# Robust to being invoked by:
#   - DSM Task Scheduler (typically as root; $HOME = /root)
#   - jxlu manually (sudo); $HOME may or may not be preserved
# All paths absolute, no $HOME / $PATH assumptions.
#
# OS-level hard kill = 600s. Source fetchers normally finish in <60s; phishstats
# multi-page pull at 20 req/min is the slowest (typically ~300s). 600s gives 2×
# safety margin and aligns with the cron interval headroom.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_BIN="/usr/local/bin/docker"
IMAGE="phishing_source_fetcher:latest"
HARD_KILL_SEC=600

ACTION="${1:-}"
if [[ -z "$ACTION" ]]; then
  cat <<EOF >&2
Usage: $0 <action> [args...]
  source actions: phishtank | openphish_academic | openphish_community | ecrimex | phishstats
  manual actions: bootstrap [--targets ...] | reset WIPE-ALL
EOF
  exit 2
fi
shift

# reset is destructive (TRUNCATEs all 8 phishing tables). The Python script
# itself does no confirmation — the GH workflow YAML used to do that, so we
# replicate the same gate at this wrapper layer.
if [[ "$ACTION" == "reset" && "${1:-}" != "WIPE-ALL" ]]; then
  cat <<EOF >&2
FATAL: 'reset' will TRUNCATE all 8 phishing tables (raw_* + phishing_urls +
       vt_url_reports + urlscan_url_scans). This is irreversible.

To confirm, run: $0 reset WIPE-ALL
EOF
  exit 2
fi

cd "$SCRIPT_DIR"

exec timeout --kill-after=30 "$HARD_KILL_SEC" "$DOCKER_BIN" run --rm \
  --name "phishing_source_fetcher_${ACTION}" \
  --user 1026:100 \
  --env-file "$SCRIPT_DIR/.env" \
  "$IMAGE" \
  "$ACTION" "$@"
