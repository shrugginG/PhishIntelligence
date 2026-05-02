"""eCrimeX (APWG) fetcher.

Source: REST API at `https://ecrimex.net/api/v1/phish?page=N&limit=N` with
`Authorization: Bearer <token>`. Default sort is id desc (newest first).

Bootstrap pulls latest N via paginated calls (up to 100 per page).
On UPSERT we only overwrite when source-side `updatedAt` is newer
(captures active→inactive status flips).

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
        # discoveredAt is string-epoch in actual responses; createdAt/updatedAt are int
        disc = int(r["discoveredAt"]) if isinstance(r["discoveredAt"], str) else r["discoveredAt"]
        rows.append(
            (
                r["id"],
                url,
                hashlib.sha256(url.encode()).hexdigest(),
                r["brand"],
                r["confidence"],
                r["status"] == "active",
                r.get("ip", []),
                r.get("asn", []),
                r.get("tld"),
                r.get("metadata", {}).get("submissionCount"),
                disc,
                r["createdAt"],
                r["updatedAt"],
                json.dumps(r, ensure_ascii=False),
            )
        )

    sql = """
        INSERT INTO raw_ecrimex
            (phish_id, url, url_sha256,
             brand, confidence, is_active,
             ip, asn, tld, submission_count,
             discovered_at, created_at, updated_at,
             raw_payload)
        VALUES (%s, %s, %s,
                %s, %s, %s,
                %s::inet[], %s::integer[], %s, %s,
                to_timestamp(%s::numeric), to_timestamp(%s::numeric), to_timestamp(%s::numeric),
                %s::jsonb)
        ON CONFLICT (phish_id) DO UPDATE SET
            is_active        = EXCLUDED.is_active,
            updated_at       = EXCLUDED.updated_at,
            submission_count = EXCLUDED.submission_count,
            raw_payload      = EXCLUDED.raw_payload
        WHERE raw_ecrimex.updated_at < EXCLUDED.updated_at
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
