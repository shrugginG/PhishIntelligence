"""Reset the reference-schema tables (v2fly + tranco).

Scoped to the `reference` schema ONLY — does NOT touch the phishing pipeline
(that's `src/reset.py`). The user-facing safety check (typing 'WIPE-REFERENCE')
lives in docker/reference_list_fetcher/run.sh; by the time this script runs the
wrapper has already validated it.

NOTE: this TRUNCATEs DB tables only. The cold archives in the `tranco-archive`
and `crux-top-archive` Storage buckets are NOT cleared (same caveat as the
urlscan results bucket) — delete those objects separately if a full wipe is
intended.

Behavior:
  1. Print row count of every target table BEFORE truncate (audit log)
  2. TRUNCATE all tables in one statement (atomic)
  3. Print row counts AFTER (should all be 0)
"""

from src.shared.db import get_connection

TABLES = [
    "reference.v2fly_domain_rules",
    "reference.v2fly_list_includes",
    "reference.v2fly_sync_runs",
    "reference.tranco_top1m",
    "reference.tranco_archive",
    "reference.crux_top1m",
    "reference.crux_archive",
]


def _print_counts(cur, header: str) -> None:
    print(f"--- {header} ---")
    for t in TABLES:
        cur.execute(f"SELECT count(*) FROM {t}")
        (n,) = cur.fetchone()
        print(f"  {t}: {n} rows")


def main() -> None:
    with get_connection() as conn:
        with conn.cursor() as cur:
            _print_counts(cur, "BEFORE")

            print(f"\n--- TRUNCATE {len(TABLES)} tables ---")
            cur.execute(f"TRUNCATE {', '.join(TABLES)} RESTART IDENTITY")

            print()
            _print_counts(cur, "AFTER")


if __name__ == "__main__":
    main()
