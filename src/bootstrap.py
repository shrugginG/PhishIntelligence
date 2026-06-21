"""Bootstrap orchestrator: pull latest N items from each chosen target, mark as stale.

Triggered by `.github/workflows/bootstrap.yml` (manual workflow_dispatch only).
Locally: `uv run python -m src.bootstrap --targets all --phishtank-size 10 ...`

Targets fall in two flavors:
  - Source targets (raw_* fetchers): hit external HTTP, bounded by --<src>-size
  - Derived-table targets (vt, urlscan): internal SQL only, no size

For each target:
  - call <target>.bootstrap_fetch(size=...) — vt/urlscan accept but ignore size
  - on exception: log + mark target as failed; other targets keep running

After all targets run, optionally UPDATE phishing_urls SET crawl_status='stale',
vt_url_reports SET fetch_status='stale', urlscan_url_scans SET fetch_status='stale'
for rows ingested during this bootstrap window — keeps all three tables aligned
and prevents Web Agent / VT fetcher / urlscan fetcher from acting on
possibly-already-dead historical phishes.
"""

from __future__ import annotations

import argparse
import importlib
import sys
import traceback
from datetime import datetime, timezone

from src.shared.db import get_connection

SOURCE_TARGETS: list[str] = [
    "phishtank",
    "openphish_academic",
    "openphish_community",
    "ecrimex",
    "phishstats",
]

ALL_TARGETS: list[str] = SOURCE_TARGETS + ["vt", "urlscan"]


def _parse_size(s: str) -> int | None:
    if s.lower() == "all":
        return None
    n = int(s)
    if n <= 0:
        raise ValueError(f"size must be positive, got {n}")
    return n


def _parse_targets(s: str) -> list[str]:
    if s.lower() == "all":
        return ALL_TARGETS
    requested = [x.strip() for x in s.split(",") if x.strip()]
    unknown = [x for x in requested if x not in ALL_TARGETS]
    if unknown:
        raise SystemExit(f"Unknown targets: {unknown}. Valid: {ALL_TARGETS}")
    return requested


def _run_one(target: str, size: int | None) -> tuple[str, int | str]:
    """Returns ('ok', n_affected) or ('failed', error_message)."""
    try:
        module = importlib.import_module(f"src.sources.phishing.{target}")
        affected = module.bootstrap_fetch(size=size)
        return ("ok", affected)
    except Exception as e:
        traceback.print_exc()
        return ("failed", str(e))


def _mark_stale_since(start_ts: datetime) -> tuple[int, int, int]:
    """Mark rows ingested at/after start_ts as stale, across three tables.

    phishing_urls:     crawl_status pending → stale
    vt_url_reports:    fetch_status pending → stale
    urlscan_url_scans: fetch_status pending → stale

    Only touches rows still in 'pending' state, never overrides a status
    something else already changed.

    Returns (n_phishing_urls, n_vt_url_reports, n_urlscan_url_scans).
    """
    sql_phish = """
        UPDATE phishing_urls
        SET crawl_status = 'stale'
        WHERE ingested_at >= %s AND crawl_status = 'pending'
    """
    sql_vt = """
        UPDATE vt_url_reports
        SET fetch_status = 'stale'
        WHERE ingested_at >= %s AND fetch_status = 'pending'
    """
    sql_urlscan = """
        UPDATE urlscan_url_scans
        SET fetch_status = 'stale'
        WHERE ingested_at >= %s AND fetch_status = 'pending'
    """
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute(sql_phish, (start_ts,))
        n_phish = cur.rowcount
        cur.execute(sql_vt, (start_ts,))
        n_vt = cur.rowcount
        cur.execute(sql_urlscan, (start_ts,))
        n_urlscan = cur.rowcount
        return (n_phish, n_vt, n_urlscan)


def main() -> None:
    ap = argparse.ArgumentParser(description="Bootstrap phishing intelligence tables")
    ap.add_argument("--targets", default="all",
                    help=f"Comma-separated target names, or 'all'. Valid: {ALL_TARGETS}")
    ap.add_argument("--phishtank-size",            default="100")
    ap.add_argument("--openphish-academic-size",   default="100")
    ap.add_argument("--openphish-community-size",  default="100")
    ap.add_argument("--ecrimex-size",              default="100")
    ap.add_argument("--phishstats-size",           default="100")
    ap.add_argument("--mark-stale", dest="mark_stale",
                    action=argparse.BooleanOptionalAction, default=True)
    args = ap.parse_args()

    targets_to_run = _parse_targets(args.targets)
    sizes = {s: _parse_size(getattr(args, f"{s}_size")) for s in SOURCE_TARGETS}

    bootstrap_start = datetime.now(timezone.utc)
    print(f"=== Bootstrap started at {bootstrap_start.isoformat()} ===")
    print(f"Targets: {targets_to_run}")
    print(f"Sizes:   {sizes}\n")

    results: dict[str, tuple[str, int | str]] = {}
    for target in targets_to_run:
        size = sizes.get(target)  # vt → None
        size_label = "all" if size is None else size
        print(f"--- {target} (size={size_label}) ---")
        results[target] = _run_one(target, size)
        status, info = results[target]
        print(f"    → {status}: {info}\n")

    if args.mark_stale:
        n_phish, n_vt, n_urlscan = _mark_stale_since(bootstrap_start)
        print(f"--- Marked stale: phishing_urls={n_phish}, vt_url_reports={n_vt}, "
              f"urlscan_url_scans={n_urlscan} ---\n")
    else:
        print("--- mark_stale disabled, skipping ---\n")

    print("=== Summary ===")
    for t in targets_to_run:
        status, info = results[t]
        print(f"  {t:30}  {status:8}  {info}")

    if any(v[0] == "failed" for v in results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
