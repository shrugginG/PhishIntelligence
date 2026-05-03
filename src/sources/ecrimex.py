"""eCrimeX (APWG) fetcher.

Source: REST API at `https://ecrimex.net/api/v1/phish?page=N&limit=N` with
`Authorization: Bearer <token>`. Default sort is id desc (newest first).

Design choice: raw_ecrimex stores a **first-observation snapshot only**. We do
NOT track source-side updates (is_active flips, submission_count growth, etc.).
Aliveness is determined by Web Agent at crawl time; raw_payload still preserves
the source's status/submissionCount at ingestion for forensic analysis.

This means INSERT path is the only path. ON CONFLICT DO NOTHING.

Env: ECRIMEX_TOKEN
"""

from __future__ import annotations

import hashlib
import json
import os

import httpx

from src.shared.db import get_connection

API_URL = "https://ecrimex.net/api/v1/phish"
PAGE_LIMIT = 100      # API per-page cap we use
MAX_PAGES_SAFETY = 100  # absolute upper bound across all bootstrap modes


def _fetch(size: int | None) -> list[dict]:
    token = os.environ["ECRIMEX_TOKEN"]
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    records: list[dict] = []
    with httpx.Client(timeout=60) as client:
        for page in range(1, MAX_PAGES_SAFETY + 1):
            need = PAGE_LIMIT if size is None else min(PAGE_LIMIT, size - len(records))
            if need <= 0:
                break

            resp = client.get(
                API_URL,
                headers=headers,
                params={"page": page, "limit": need},
            )
            resp.raise_for_status()
            batch = resp.json().get("data", [])
            if not batch:
                break

            records.extend(batch)
            print(f"  page {page} → {len(batch)} records (total {len(records)})")

            if size is not None and len(records) >= size:
                records = records[:size]
                break

    return records


def _upsert(records: list[dict]) -> int:
    if not records:
        return 0

    rows = []
    for r in records:
        url = r["url"]
        # discoveredAt is string-epoch in actual responses; createdAt is int
        disc = int(r["discoveredAt"]) if isinstance(r["discoveredAt"], str) else r["discoveredAt"]
        rows.append(
            (
                r["id"],
                url,
                hashlib.sha256(url.encode()).hexdigest(),
                r["brand"],
                r["confidence"],
                r.get("ip", []),
                r.get("asn", []),
                r.get("tld"),
                disc,
                r["createdAt"],
                json.dumps(r, ensure_ascii=False),
            )
        )

    sql = """
        INSERT INTO raw_ecrimex
            (phish_id, url, url_sha256,
             brand, confidence,
             ip, asn, tld,
             discovered_at, created_at,
             raw_payload)
        VALUES (%s, %s, %s,
                %s, %s,
                %s::inet[], %s::integer[], %s,
                to_timestamp(%s::numeric), to_timestamp(%s::numeric),
                %s::jsonb)
        ON CONFLICT (phish_id) DO NOTHING
    """

    with get_connection() as conn, conn.cursor() as cur:
        cur.executemany(sql, rows)
        return cur.rowcount


def bootstrap_fetch(size: int | None) -> int:
    records = _fetch(size)
    print(f"  Fetched {len(records)} records")
    affected = _upsert(records)
    print(f"  Insert affected {affected} rows")
    return affected


def _get_anchor() -> int:
    """Returns MAX(phish_id) from raw_ecrimex, or 0 if empty."""
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT COALESCE(MAX(phish_id), 0) FROM raw_ecrimex")
        return cur.fetchone()[0]


def routine_fetch() -> int:
    """Incremental fetch: paginate eCrimeX API for phish_id > anchor.

    eCrimeX returns by id desc. Short-circuit IS safe: once a page contains any
    record with id <= anchor, all subsequent pages are entirely older records.
    """
    anchor = _get_anchor()
    print(f"  Anchor: phish_id > {anchor}")

    token = os.environ["ECRIMEX_TOKEN"]
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    new_records: list[dict] = []
    last_page = 0
    with httpx.Client(timeout=60) as client:
        for page in range(1, MAX_PAGES_SAFETY + 1):
            last_page = page
            resp = client.get(
                API_URL,
                headers=headers,
                params={"page": page, "limit": PAGE_LIMIT},
            )
            resp.raise_for_status()
            batch = resp.json().get("data", [])
            if not batch:
                break

            new_in_batch = [r for r in batch if r["id"] > anchor]
            new_records.extend(new_in_batch)
            print(f"  page {page}: {len(batch)} fetched, {len(new_in_batch)} > anchor")

            # Short-circuit: if this page had any rows ≤ anchor, all subsequent pages
            # contain only even older records (eCrimeX is strict id desc).
            if len(new_in_batch) < len(batch):
                break

    print(f"  Total new records over {last_page} page(s): {len(new_records)}")
    affected = _upsert(new_records)
    print(f"  Insert affected {affected} rows")
    return affected


if __name__ == "__main__":
    affected = routine_fetch()
    print(f"\n=== routine_fetch done: {affected} rows ===")
