"""VirusTotal URL reports — bootstrap module.

Unlike the 5 raw_* fetchers, vt is an *internal* derivation target:
  - No external HTTP/API calls during bootstrap
  - No source-end size to bound (always full set-based)
  - Idempotent via INSERT ... ON CONFLICT DO NOTHING

bootstrap_fetch() registers every existing phishing_urls row in vt_url_reports
with the default fetch_status='pending'. The orchestrator's --mark-stale flag
then sweeps any newly-pending vt rows from this bootstrap run to 'stale',
keeping vt rows aligned with phishing_urls' own 'stale' semantics.

The routine fetcher (TBD) will be added in a future module addition; this file
intentionally exposes only bootstrap_fetch for now.
"""

from __future__ import annotations

from src.shared.db import get_connection


def bootstrap_fetch(size: int | None = None) -> int:
    """Register every phishing_urls row in vt_url_reports.

    The size parameter is accepted for orchestrator signature compatibility
    but ignored — vt bootstrap is always set-based over the full phishing_urls.
    Status assignment ('pending' vs 'stale') is handled by the orchestrator's
    --mark-stale sweep, not here.

    Returns the number of rows actually inserted (excluding ON CONFLICT skips).
    """
    if size is not None:
        print(f"  Note: size={size} ignored — vt bootstrap is set-based")

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM phishing_urls")
        (n_phish,) = cur.fetchone()
        cur.execute("SELECT count(*) FROM vt_url_reports")
        (n_vt_before,) = cur.fetchone()

        cur.execute("""
            INSERT INTO vt_url_reports (url_sha256)
            SELECT url_sha256 FROM phishing_urls
            ON CONFLICT (url_sha256) DO NOTHING
        """)
        affected = cur.rowcount

        print(f"  phishing_urls: {n_phish} rows")
        print(f"  vt_url_reports before: {n_vt_before}")
        print(f"  newly registered:      {affected}")
        return affected


if __name__ == "__main__":
    affected = bootstrap_fetch()
    print(f"\n=== bootstrap_fetch done: {affected} new rows ===")
