"""Bootstrap orchestrator: pull latest N items from each source, mark as stale.

Triggered by `.github/workflows/bootstrap.yml` (manual workflow_dispatch only).
Locally: `uv run python -m src.bootstrap --sources all --phishtank-size 10 ...`

For each source:
  - call <source>.bootstrap_fetch(size)
  - on exception: log + mark source as failed; other sources keep running

After all sources run, optionally UPDATE phishing_urls SET crawl_status='stale'
for rows ingested during this bootstrap (so the future Web Agent doesn't fire
on possibly-already-dead phishes).
"""

from __future__ import annotations

import argparse
import importlib
import sys
import traceback
from datetime import datetime, timezone

from src.shared.db import get_connection

SOURCES: list[str] = [
    "phishtank",
    "openphish_academic",
    "openphish_community",
    "ecrimex",
    "phishstats",
]


def _parse_size(s: str) -> int | None:
    if s.lower() == "all":
        return None
    n = int(s)
    if n <= 0:
        raise ValueError(f"size must be positive, got {n}")
    return n


def _parse_sources(s: str) -> list[str]:
    if s.lower() == "all":
        return SOURCES
    requested = [x.strip() for x in s.split(",") if x.strip()]
    unknown = [x for x in requested if x not in SOURCES]
    if unknown:
        raise SystemExit(f"Unknown sources: {unknown}. Valid: {SOURCES}")
    return requested


def _run_one(source: str, size: int | None) -> tuple[str, int | str]:
    """Returns ('ok', n_affected) or ('failed', error_message)."""
    try:
        module = importlib.import_module(f"src.sources.{source}")
        affected = module.bootstrap_fetch(size=size)
        return ("ok", affected)
    except Exception as e:
        traceback.print_exc()
        return ("failed", str(e))


def _mark_stale_since(start_ts: datetime) -> int:
    """Mark all phishing_urls rows ingested at/after start_ts as 'stale'.

    Only touches rows that are still 'pending' — never overrides a status the
    client has explicitly changed.
    """
    sql = """
        UPDATE phishing_urls
        SET crawl_status = 'stale'
        WHERE ingested_at >= %s AND crawl_status = 'pending'
    """
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(sql, (start_ts,))
        return cur.rowcount


def main() -> None:
    ap = argparse.ArgumentParser(description="Bootstrap phishing intelligence tables")
    ap.add_argument("--sources", default="all",
                    help="Comma-separated source names, or 'all'")
    ap.add_argument("--phishtank-size",            default="100")
    ap.add_argument("--openphish-academic-size",   default="100")
    ap.add_argument("--openphish-community-size",  default="100")
    ap.add_argument("--ecrimex-size",              default="100")
    ap.add_argument("--phishstats-size",           default="100")
    ap.add_argument("--mark-stale", dest="mark_stale",
                    action=argparse.BooleanOptionalAction, default=True)
    args = ap.parse_args()

    sources_to_run = _parse_sources(args.sources)
    sizes = {s: _parse_size(getattr(args, f"{s}_size")) for s in SOURCES}

    bootstrap_start = datetime.now(timezone.utc)
    print(f"=== Bootstrap started at {bootstrap_start.isoformat()} ===")
    print(f"Sources: {sources_to_run}")
    print(f"Sizes:   {sizes}\n")

    results: dict[str, tuple[str, int | str]] = {}
    for source in sources_to_run:
        size = sizes[source]
        print(f"--- {source} (size={'all' if size is None else size}) ---")
        results[source] = _run_one(source, size)
        status, info = results[source]
        print(f"    → {status}: {info}\n")

    if args.mark_stale:
        n = _mark_stale_since(bootstrap_start)
        print(f"--- Marked {n} phishing_urls rows as 'stale' ---\n")
    else:
        print("--- mark_stale disabled, skipping ---\n")

    print("=== Summary ===")
    for s in sources_to_run:
        status, info = results[s]
        print(f"  {s:30}  {status:8}  {info}")

    if any(v[0] == "failed" for v in results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
