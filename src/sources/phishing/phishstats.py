"""PhishStats fetcher.

Source: public REST API at `https://api.phishstats.info/api/phishing`.
No auth required; rate-limited to 20 req/min.

Source `hash` field has been verified == sha256(url), so we reuse it as
url_sha256 directly (defensive recompute on missing).

This source has the richest schema (45 columns).

Incremental resilience (2026-07): the routine now UPSERTs **per page** and
handles HTTP 429 with backoff. Records are `_sort=-id` (newest first), so each
page that lands advances `MAX(id)` toward the current head. This guarantees the
anchor makes forward progress even if a later page 429s or the OS-level timeout
kills the process mid-run — avoiding the old "fetch-all-then-insert" trap where
a single 429 discarded the whole batch and the anchor never moved (stale anchor
→ every run needs >9 pages → page-10 429 → 0 rows → permanently stuck).
"""

from __future__ import annotations

import hashlib
import json
import time

import httpx

from src.shared.db import get_connection

API_URL = "https://api.phishstats.info/api/phishing"
PAGE_SIZE = 100          # API max per page
MAX_PAGES_SAFETY = 100
INTER_PAGE_DELAY = 4.0   # keep strictly under the 20 req/min limit (3s == the limit)
MAX_429_RETRIES = 5      # per-page backoff attempts before giving up (partial progress)
BACKOFF_BASE = 5.0       # initial 429 backoff seconds (doubles, capped)
BACKOFF_CAP = 60.0


def _get_page(client: httpx.Client, page: int, size: int) -> list[dict] | None:
    """GET one API page, sorted id desc.

    Returns the parsed batch (possibly empty) on success. Returns ``None`` if the
    request keeps returning HTTP 429 past ``MAX_429_RETRIES`` — the caller should
    then stop paging and keep whatever earlier pages already landed. Non-429 HTTP
    errors still raise (genuine failures we want to surface).
    """
    delay = BACKOFF_BASE
    for attempt in range(1, MAX_429_RETRIES + 1):
        resp = client.get(
            API_URL,
            params={"_p": page, "_size": size, "_sort": "-id"},
        )
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            wait = float(retry_after) if (retry_after or "").isdigit() else delay
            print(f"  page {page}: 429, backoff {wait:.0f}s "
                  f"(attempt {attempt}/{MAX_429_RETRIES})")
            time.sleep(wait)
            delay = min(delay * 2, BACKOFF_CAP)
            continue
        resp.raise_for_status()
        return resp.json()

    print(f"  page {page}: still 429 after {MAX_429_RETRIES} retries — "
          f"stopping with partial progress")
    return None


def _scrub_null_bytes(obj):
    """Recursively replace \\x00 (null byte) in any string. PG rejects null
    bytes in TEXT and JSONB (JSONB explicitly disallows \\u0000 escape).
    PhishStats' page_text field can contain raw binary from scraped pages.
    """
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, dict):
        return {k: _scrub_null_bytes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub_null_bytes(v) for v in obj]
    return obj


def _rows_from_records(records: list[dict]) -> list[tuple]:
    # Defensive: PhishStats records may contain null bytes (esp. in page_text);
    # PG JSONB and TEXT can't represent them.
    records = [_scrub_null_bytes(r) for r in records]

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
    return rows


_INSERT_SQL = """
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


def _upsert(records: list[dict]) -> int:
    if not records:
        return 0
    rows = _rows_from_records(records)
    with get_connection() as conn, conn.cursor() as cur:
        cur.executemany(_INSERT_SQL, rows)
        return cur.rowcount


def bootstrap_fetch(size: int | None) -> int:
    """Bounded fetch (no anchor). Pages up to `size`, UPSERTing per page so
    progress survives a mid-run 429 / timeout.
    """
    total = 0
    fetched = 0
    with httpx.Client(timeout=60) as client:
        for page in range(1, MAX_PAGES_SAFETY + 1):
            need = PAGE_SIZE if size is None else min(PAGE_SIZE, size - fetched)
            if need <= 0:
                break

            batch = _get_page(client, page, need)
            if batch is None:      # 429 exhausted → keep partial progress
                break
            if not batch:
                break

            fetched += len(batch)
            affected = _upsert(batch)
            total += affected
            print(f"  page {page}: {len(batch)} fetched, {affected} inserted "
                  f"(total {total})")

            if size is not None and fetched >= size:
                break
            time.sleep(INTER_PAGE_DELAY)

    print(f"  Insert affected {total} rows")
    return total


def _get_anchor() -> int:
    """Returns MAX(id) from raw_phishstats, or 0 if empty."""
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COALESCE(MAX(id), 0) FROM raw_phishstats")
        return cur.fetchone()[0]


def routine_fetch() -> int:
    """Incremental fetch: paginate API for id > anchor, UPSERTing **per page**.

    Because rows are newest-first, each landed page pushes `MAX(id)` forward, so
    the anchor advances even if a later page 429s or the process is killed. Stops
    on: a page containing any record <= anchor (subsequent pages are older),
    an empty page, or 429 exhaustion (partial progress preserved).
    """
    anchor = _get_anchor()
    print(f"  Anchor: id > {anchor}")

    total = 0
    last_page = 0
    with httpx.Client(timeout=60) as client:
        for page in range(1, MAX_PAGES_SAFETY + 1):
            last_page = page
            batch = _get_page(client, page, PAGE_SIZE)
            if batch is None:      # 429 exhausted → keep what already landed
                break
            if not batch:
                break

            new_in_batch = [r for r in batch if r["id"] > anchor]
            affected = _upsert(new_in_batch)
            total += affected
            print(f"  page {page}: {len(batch)} fetched, "
                  f"{len(new_in_batch)} > anchor, {affected} inserted")

            # Short-circuit: any record <= anchor means subsequent pages are older
            if len(new_in_batch) < len(batch):
                break

            time.sleep(INTER_PAGE_DELAY)

    print(f"  Total inserted over {last_page} page(s): {total}")
    return total


if __name__ == "__main__":
    affected = routine_fetch()
    print(f"\n=== routine_fetch done: {affected} rows ===")
