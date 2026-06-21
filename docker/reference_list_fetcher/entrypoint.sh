#!/usr/bin/env bash
# In-container dispatcher for the reference list fetcher. Parses the first arg
# and delegates to the right Python module. Forwards remaining args to reset.

set -euo pipefail

ACTION="${1:-}"
shift || true

case "$ACTION" in
  v2fly)
    exec uv run python -m src.sources.reference.v2fly_domain_list
    ;;
  tranco)
    exec uv run python -m src.sources.reference.tranco
    ;;
  reset)
    exec uv run python -m src.sources.reference.reset "$@"
    ;;
  "")
    cat <<EOF >&2
Usage: <action> [args...]
  Source actions: v2fly | tranco
  Manual actions: reset
EOF
    exit 2
    ;;
  *)
    echo "Unknown action: $ACTION" >&2
    echo "Valid: v2fly, tranco, reset" >&2
    exit 2
    ;;
esac
