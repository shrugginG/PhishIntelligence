#!/usr/bin/env bash
# DSM Task Scheduler invokes this script for each reference source, e.g.:
#   /var/services/.../reference_list_fetcher/run.sh v2fly
#
# `--name reference_list_fetcher_<action>` is a per-source concurrency lock: if
# the previous tick of THIS source is still in flight, the new docker run fails
# immediately ("name in use") and DSM logs the skip.
#
# All paths absolute, no $HOME / $PATH assumptions (DSM runs as root; $HOME=/root).
#
# OS-level hard kill = 600s. The v2fly sync downloads a few-MB tarball, parses
# ~37k rules and UPSERTs them — normally <60s. 600s gives ample margin.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_BIN="/usr/local/bin/docker"
IMAGE="reference_list_fetcher:latest"
HARD_KILL_SEC=600

ACTION="${1:-}"
if [[ -z "$ACTION" ]]; then
  cat <<EOF >&2
Usage: $0 <action> [args...]
  source actions: v2fly
  manual actions: reset WIPE-REFERENCE
EOF
  exit 2
fi
shift

# reset is destructive (TRUNCATEs the reference.v2fly_* tables). The Python
# script does no confirmation; gate it here like the phishing reset.
if [[ "$ACTION" == "reset" && "${1:-}" != "WIPE-REFERENCE" ]]; then
  cat <<EOF >&2
FATAL: 'reset' will TRUNCATE the reference.v2fly_* tables. This is irreversible.

To confirm, run: $0 reset WIPE-REFERENCE
EOF
  exit 2
fi

cd "$SCRIPT_DIR"

exec timeout --kill-after=30 "$HARD_KILL_SEC" "$DOCKER_BIN" run --rm \
  --name "reference_list_fetcher_${ACTION}" \
  --user 1026:100 \
  --env-file "$SCRIPT_DIR/.env" \
  "$IMAGE" \
  "$ACTION" "$@"
