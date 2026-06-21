"""urlscan.io URL scans — bootstrap (routine_fetch lives outside, on NAS).

bootstrap_fetch: idempotent INSERT INTO urlscan_url_scans SELECT FROM phishing_urls
                 — registers every existing phishing_urls row as a default scan
                 row in urlscan_url_scans. Status assignment ('pending' vs 'stale')
                 is handled by the orchestrator's --mark-stale sweep, not here.

Unlike vt, urlscan's routine fetcher does NOT run in GitHub Actions — it runs on
the home NAS and writes results to local disk (NAS is the canonical store; only
orchestration state lives in Supabase). This module therefore only owns the
bootstrap path; routine_fetch is intentionally absent.
"""

from __future__ import annotations

from src.shared.db import get_connection


def bootstrap_fetch(size: int | None = None) -> int:
    """Register every phishing_urls row in urlscan_url_scans as a default scan.

    The size parameter is accepted for orchestrator signature compatibility but
    ignored — urlscan bootstrap is always set-based over the full phishing_urls.

    The partial unique index `urlscan_url_scans_default_uniq` on (url_sha256)
    WHERE scan_purpose='default' is what `ON CONFLICT` targets; rows with other
    purposes (none in v1) are unaffected.

    Returns the number of rows actually inserted (excluding ON CONFLICT skips).
    """
    if size is not None:
        print(f"  Note: size={size} ignored — urlscan bootstrap is set-based")

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM phishing_urls")
        (n_phish,) = cur.fetchone()
        cur.execute("SELECT count(*) FROM urlscan_url_scans")
        (n_urlscan_before,) = cur.fetchone()

        cur.execute("""
            INSERT INTO urlscan_url_scans (url_sha256)
            SELECT url_sha256 FROM phishing_urls
            ON CONFLICT (url_sha256) WHERE scan_purpose = 'default'
            DO NOTHING
        """)
        affected = cur.rowcount

        print(f"  phishing_urls: {n_phish} rows")
        print(f"  urlscan_url_scans before: {n_urlscan_before}")
        print(f"  newly registered:         {affected}")
        return affected
