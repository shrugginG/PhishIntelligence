"""phishunt.io fetcher (OBSERVATION mode).

Source: https://phishunt.io/feed.json — a flat JSON array of the currently
"active" suspicious phishing set (~330-523 entries), no auth, refreshed hourly.

Unlike the other 5 sources this is NOT an append-only event stream but a
rolling, re-checked active set. So there is no incremental anchor (the API's
`since` filters on `date`, which is refreshed to "now" on every hourly batch
and is therefore useless for incrementality). Strategy: pull the full set every
tick and UPSERT on phishunt's stable per-entry `uuid`.

raw_phishunt has NO propagation trigger into phishing_urls — writes here stay
isolated. bootstrap_fetch and routine_fetch are identical (full-set UPSERT);
both entrypoints exist only to match the other sources' convention.
"""

from __future__ import annotations

import hashlib
import json

import httpx

from src.shared.db import get_connection

FEED_URL = "https://phishunt.io/feed.json"


def _fetch() -> list[dict]:
    """Pull the full active set. feed.json is a bare array (no wrapper)."""
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        resp = client.get(FEED_URL)
        resp.raise_for_status()
        data = resp.json()
    # feed.json is a flat array; defensively unwrap if shape ever changes
    records = data if isinstance(data, list) else data.get("results", [])
    print(f"  Fetched {len(records)} active entries from feed.json")
    return records


def _norm_ip(v):
    return v if v not in (None, "") else None


def _upsert(records: list[dict]) -> int:
    if not records:
        return 0

    rows = []
    for r in records:
        url = r["url"]
        url_sha256 = hashlib.sha256(url.encode()).hexdigest()
        rows.append(
            (
                r["uuid"],
                url,
                url_sha256,
                r.get("domain"),
                r.get("company"),
                _norm_ip(r.get("ip")),
                r.get("country"),
                r.get("asn"),
                r.get("org"),
                r.get("cert"),
                r.get("malicious_google"),
                r.get("malicious_openphish"),
                r.get("malicious_phishtank"),
                r.get("malicious_tweetfeed"),
                r.get("malicious_urlscan"),
                r.get("first_seen"),
                r.get("date"),
                json.dumps(r, ensure_ascii=False),
            )
        )

    # UPSERT on uuid: refresh re-check fields + observation instruments.
    # first_seen / url / url_sha256 / ingested_at stay frozen at first capture.
    sql = """
        INSERT INTO raw_phishunt (
            uuid, url, url_sha256, domain, company,
            ip, country, asn, org, cert,
            malicious_google, malicious_openphish, malicious_phishtank,
            malicious_tweetfeed, malicious_urlscan,
            first_seen, source_date, raw_payload
        ) VALUES (
            %s, %s, %s, %s, %s,
            %s::inet, %s, %s, %s, %s,
            %s, %s, %s,
            %s, %s,
            %s::timestamptz, %s::timestamptz, %s::jsonb
        )
        ON CONFLICT (uuid) DO UPDATE SET
            source_date         = EXCLUDED.source_date,
            ip                  = EXCLUDED.ip,
            country             = EXCLUDED.country,
            asn                 = EXCLUDED.asn,
            org                 = EXCLUDED.org,
            cert                = EXCLUDED.cert,
            malicious_google    = EXCLUDED.malicious_google,
            malicious_openphish = EXCLUDED.malicious_openphish,
            malicious_phishtank = EXCLUDED.malicious_phishtank,
            malicious_tweetfeed = EXCLUDED.malicious_tweetfeed,
            malicious_urlscan   = EXCLUDED.malicious_urlscan,
            raw_payload         = EXCLUDED.raw_payload,
            last_seen_at        = now(),
            fetch_count         = raw_phishunt.fetch_count + 1
    """

    with get_connection() as conn, conn.cursor() as cur:
        cur.executemany(sql, rows)
        # rowcount over executemany is unreliable across drivers for the
        # split insert/update; report the batch size we attempted instead.
        return len(rows)


def routine_fetch() -> int:
    """Pull the full active set and UPSERT. New entries insert; re-checked
    entries update (bumping last_seen_at / fetch_count)."""
    records = _fetch()
    affected = _upsert(records)
    print(f"  Upserted {affected} entries")
    return affected


def bootstrap_fetch(size: int | None = None) -> int:
    """Identical to routine_fetch for phishunt (the feed is the full active
    set). `size` accepted for signature parity; slices the pull if provided."""
    records = _fetch()
    if size is not None:
        records = records[:size]
    affected = _upsert(records)
    print(f"  Upserted {affected} entries")
    return affected


if __name__ == "__main__":
    affected = routine_fetch()
    print(f"\n=== phishunt routine_fetch done: {affected} entries ===")
