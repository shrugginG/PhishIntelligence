"""OpenPhish Community fetcher.

Source: public `https://openphish.com/feed.txt` (302 → GitHub raw).
URL-only. Fixed 300-row sliding window, 12h refresh cycle.
No credentials required.
"""

from __future__ import annotations

import hashlib

import httpx

from src.shared.db import get_connection

URL = "https://openphish.com/feed.txt"
UA = "PhishIntelligence/1.0"


def _fetch_feed() -> list[str]:
    print(f"  Fetching {URL}")
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        resp = client.get(URL, headers={"User-Agent": UA})
        resp.raise_for_status()
        urls = [line for line in resp.text.splitlines() if line.strip()]
    print(f"  Got {len(urls)} URLs")
    return urls


def _upsert(urls: list[str]) -> int:
    if not urls:
        return 0
    rows = [
        (hashlib.sha256(u.encode()).hexdigest(), u)
        for u in urls
    ]
    sql = """
        INSERT INTO raw_openphish_community (url_sha256, url)
        VALUES (%s, %s)
        ON CONFLICT (url_sha256) DO NOTHING
    """
    with get_connection() as conn, conn.cursor() as cur:
        cur.executemany(sql, rows)
        return cur.rowcount


def bootstrap_fetch(size: int | None) -> int:
    urls = _fetch_feed()
    # feed.txt is desc by recency (verified empirically)
    selected = urls if size is None else urls[:size]
    print(f"  Selected top {len(selected)}")
    affected = _upsert(selected)
    print(f"  Upsert affected {affected} rows")
    return affected
