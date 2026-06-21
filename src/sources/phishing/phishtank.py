"""PhishTank fetcher.

Source: bulk JSON dump from `data.phishtank.com`. Always pulls the full dump,
sorts by phish_id desc, takes top N. Works with INSERT ... ON CONFLICT DO NOTHING.

Env: PHISHTANK_TOKEN (API key embedded in URL path)
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os

import httpx

from src.shared.db import get_connection

UA = "phishtank/PhishIntelligence"


def _bulk_url() -> str:
    token = os.environ["PHISHTANK_TOKEN"]
    return f"https://data.phishtank.com/data/{token}/online-valid.json.gz"


def _fetch_dump() -> list[dict]:
    url = _bulk_url()
    print(f"  Downloading bulk dump (~3 MB gz)…")
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        resp = client.get(url, headers={"User-Agent": UA})
        resp.raise_for_status()
        records = json.loads(gzip.decompress(resp.content))
    print(f"  Got {len(records)} records")
    return records


def _select_latest(records: list[dict], size: int | None) -> list[dict]:
    # PhishTank dump is roughly desc by phish_id but not strictly monotonic.
    # Sort defensively before slicing.
    sorted_recs = sorted(records, key=lambda r: r["phish_id"], reverse=True)
    return sorted_recs if size is None else sorted_recs[:size]


def _upsert(records: list[dict]) -> int:
    if not records:
        return 0

    rows = [
        (
            r["phish_id"],
            r["url"],
            hashlib.sha256(r["url"].encode()).hexdigest(),
            r["submission_time"],
            r["verification_time"],
            r.get("target"),
            json.dumps(r.get("details", []), ensure_ascii=False),
            json.dumps(r, ensure_ascii=False),
        )
        for r in records
    ]

    sql = """
        INSERT INTO raw_phishtank
            (phish_id, url, url_sha256, submission_time, verification_time,
             target, details, raw_payload)
        VALUES (%s, %s, %s, %s::timestamptz, %s::timestamptz,
                %s, %s::jsonb, %s::jsonb)
        ON CONFLICT (phish_id) DO NOTHING
    """

    with get_connection() as conn, conn.cursor() as cur:
        cur.executemany(sql, rows)
        return cur.rowcount


def bootstrap_fetch(size: int | None) -> int:
    records = _fetch_dump()
    selected = _select_latest(records, size)
    print(f"  Selected top {len(selected)} by phish_id desc")
    affected = _upsert(selected)
    print(f"  Upsert affected {affected} rows")
    return affected


def _get_anchor() -> int:
    """Returns the largest phish_id we already have, or 0 if raw_phishtank is empty."""
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COALESCE(MAX(phish_id), 0) FROM raw_phishtank")
        return cur.fetchone()[0]


def routine_fetch() -> int:
    """Incremental fetch: pull the bulk dump, keep only entries with
    phish_id > current MAX, upsert. Application-layer filter on phish_id
    (NOT short-circuit) because PhishTank dump is not strictly monotonic
    by phish_id — see CLAUDE.md / design docs for rationale.
    """
    anchor = _get_anchor()
    print(f"  Anchor: phish_id > {anchor}")
    records = _fetch_dump()
    new = [r for r in records if r["phish_id"] > anchor]
    print(f"  New entries beyond anchor: {len(new)} (out of {len(records)} dump rows)")
    affected = _upsert(new)
    print(f"  Upsert affected {affected} rows")
    return affected


if __name__ == "__main__":
    affected = routine_fetch()
    print(f"\n=== routine_fetch done: {affected} new rows ===")
