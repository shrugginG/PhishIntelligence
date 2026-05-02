"""PhishStats fetcher.

Source: public REST API at `https://api.phishstats.info/api/phishing`.
No auth required; rate-limited to 20 req/min.

Source `hash` field has been verified == sha256(url), so we reuse it as
url_sha256 directly (defensive recompute on missing).

This source has the richest schema (45 columns).
"""

from __future__ import annotations

import hashlib
import json
import time

import httpx

from src.shared.db import get_connection

API_URL = "https://api.phishstats.info/api/phishing"
PAGE_SIZE = 100         # API max per page
MAX_PAGES_SAFETY = 100
INTER_PAGE_DELAY = 3.0  # 20 req/min ≈ 3s/req; conservative pause between pages


def _fetch(size: int | None) -> list[dict]:
    records: list[dict] = []
    with httpx.Client(timeout=60) as client:
        for page in range(1, MAX_PAGES_SAFETY + 1):
            need = PAGE_SIZE if size is None else min(PAGE_SIZE, size - len(records))
            if need <= 0:
                break

            resp = client.get(
                API_URL,
                params={"_p": page, "_size": need, "_sort": "-id"},
            )
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break

            records.extend(batch)
            print(f"  page {page} → {len(batch)} records (total {len(records)})")

            if size is not None and len(records) >= size:
                records = records[:size]
                break

            time.sleep(INTER_PAGE_DELAY)

    return records


def _upsert(records: list[dict]) -> int:
    if not records:
        return 0

    rows = []
    for r in records:
        # PhishStats `hash` field is sha256(url); fall back defensively
        url_sha256 = r.get("hash") or hashlib.sha256(r["url"].encode()).hexdigest()
        rows.append(
            (
                r["id"],
                r["url"],
                url_sha256,
                r.get("redirect_url"),
                r.get("ip"),
                r.get("bgp"),
                r.get("asn"),
                r.get("isp"),
                r.get("ports"),
                r.get("http_code"),
                r.get("http_server"),
                r.get("os"),
                r.get("technology"),
                r.get("countrycode"),
                r.get("countryname"),
                r.get("regioncode"),
                r.get("regionname"),
                r.get("city"),
                r.get("zipcode"),
                float(r["latitude"]) if r.get("latitude") not in (None, "") else None,
                float(r["longitude"]) if r.get("longitude") not in (None, "") else None,
                r.get("host"),
                r.get("domain"),
                r.get("tld"),
                r.get("title"),
                r.get("ssl_issuer"),
                r.get("ssl_subject"),
                r.get("ssl_fingerprint"),
                r.get("score"),
                r.get("google_safebrowsing"),
                r.get("virus_total"),
                r.get("abuse_ch_malware"),
                r.get("vulns"),
                r.get("tags"),
                r.get("abuse_contact"),
                r.get("screenshot"),
                r.get("domain_registered_n_days_ago"),
                r.get("rank_host"),
                r.get("rank_domain"),
                r.get("n_times_seen_ip"),
                r.get("n_times_seen_host"),
                r.get("n_times_seen_domain"),
                r["date"],
                r.get("date_update"),
                json.dumps(r, ensure_ascii=False),
            )
        )

    sql = """
        INSERT INTO raw_phishstats (
            id, url, url_sha256, redirect_url,
            ip, bgp, asn, isp, ports,
            http_code, http_server, os, technology,
            country_code, country_name, region_code, region_name,
            city, zipcode, latitude, longitude,
            host, domain, tld, title,
            ssl_issuer, ssl_subject, ssl_fingerprint,
            score, google_safebrowsing, virus_total, abuse_ch_malware,
            vulns, tags, abuse_contact, screenshot,
            domain_registered_n_days_ago,
            rank_host, rank_domain,
            n_times_seen_ip, n_times_seen_host, n_times_seen_domain,
            discovered_at, updated_at,
            raw_payload
        ) VALUES (
            %s, %s, %s, %s,
            %s::inet, %s::cidr, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s,
            %s, %s,
            %s, %s, %s,
            %s::timestamptz, %s::timestamptz,
            %s::jsonb
        )
        ON CONFLICT (id) DO NOTHING
    """

    with get_connection() as conn, conn.cursor() as cur:
        cur.executemany(sql, rows)
        return cur.rowcount


def bootstrap_fetch(size: int | None) -> int:
    records = _fetch(size)
    print(f"  Fetched {len(records)} records")
    affected = _upsert(records)
    print(f"  Upsert affected {affected} rows")
    return affected
