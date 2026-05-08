#!/usr/bin/env bash
# In-container dispatcher. Parses the first arg and delegates to the right
# Python module. Forwards remaining args to bootstrap/reset (which accept CLI flags).

set -euo pipefail

ACTION="${1:-}"
shift || true

case "$ACTION" in
  phishtank|openphish_academic|openphish_community|ecrimex|phishstats)
    exec uv run python -m "src.sources.${ACTION}"
    ;;
  bootstrap)
    exec uv run python -m src.bootstrap "$@"
    ;;
  reset)
    exec uv run python -m src.reset "$@"
    ;;
  "")
    cat <<EOF >&2
Usage: <action> [args...]
  Source actions: phishtank | openphish_academic | openphish_community | ecrimex | phishstats
  Manual actions: bootstrap [--targets ...] | reset
EOF
    exit 2
    ;;
  *)
    echo "Unknown action: $ACTION" >&2
    echo "Valid: phishtank, openphish_academic, openphish_community, ecrimex, phishstats, bootstrap, reset" >&2
    exit 2
    ;;
esac
