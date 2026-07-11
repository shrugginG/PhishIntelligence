"""Tranco top-1M fetcher (Strategy A: current-mirror hot table + cold Storage archive).

Source: https://tranco-list.eu/ — research-oriented, manipulation-hardened top
sites ranking, updated daily by 0:00 UTC. We use the permanent daily URLs:
  default (pay-level domains):  /top-1m.csv.zip               + /top-1m-id
  with subdomains:              /top-1m-incl-subdomains.csv.zip + /top-1m-id?subdomains=true
Each zip holds a single `rank,domain` CSV with 1,000,000 rows.

Two layers (history is NOT kept in Postgres):
  HOT  reference.tranco_top1m   — current-only mirror, BOTH granularities (the
       `subdomains` flag). Refreshed via TRUNCATE+COPY → the whole table IS the
       latest list; no `current` flag, no historical rows, zero bloat.
  COLD bucket `tranco-archive`  — each day's raw .csv.zip, immutable, keyed by
       date+list_id. Lossless history, re-importable on demand.
  reference.tranco_archive      — tiny manifest (one row per archived day/granularity).

Idempotency = Tranco permanent list_id. If both granularities' current list_ids
are already in tranco_archive, the run is a no-op (Tranco updates once/day; we
may tick 3x/day).

Storage writes need SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY (Kong gateway +
service role), same as the urlscan fetcher. bootstrap_fetch == routine_fetch
(Strategy A only has "today"; historical backfill would be a separate job).
"""

from __future__ import annotations

import hashlib
import io
import os
import zipfile
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx

from src.shared.db import get_connection

BASE = "https://tranco-list.eu"
STORAGE_BUCKET = os.environ.get("TRANCO_STORAGE_BUCKET", "tranco-archive")

# (subdomains, id_endpoint, zip_endpoint, object_prefix)
GRANULARITIES = [
    (False, "/top-1m-id",                 "/top-1m.csv.zip",                 "top-1m"),
    (True,  "/top-1m-id?subdomains=true", "/top-1m-incl-subdomains.csv.zip", "top-1m-incl-subdomains"),
]


# ────────────────────────────── Storage helpers ──────────────────────────────
def _supabase_url() -> str:
    v = os.environ.get("SUPABASE_URL")
    if not v:
        raise RuntimeError(
            "SUPABASE_URL not set (Kong gateway; self-host = http://192.168.1.21:8000)"
        )
    return v.rstrip("/")


def _service_key() -> str:
    v = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not v:
        raise RuntimeError(
            "SUPABASE_SERVICE_ROLE_KEY not set (required to write the tranco-archive bucket)"
        )
    return v


def _storage_put(client: httpx.Client, object_path: str, zip_bytes: bytes) -> None:
    """PUT raw zip bytes to Supabase Storage with x-upsert=true (idempotent overwrite)."""
    key = _service_key()
    url = f"{_supabase_url()}/storage/v1/object/{STORAGE_BUCKET}/{object_path}"
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/zip",
        "x-upsert": "true",
    }
    r = client.post(url, headers=headers, content=zip_bytes)
    r.raise_for_status()


# ────────────────────────────── Fetch + parse ──────────────────────────────
def _get_list_id(client: httpx.Client, endpoint: str) -> str:
    r = client.get(BASE + endpoint)
    r.raise_for_status()
    return r.text.strip()


def _download_zip(client: httpx.Client, endpoint: str):
    """Return (zip_bytes, last_modified: datetime|None)."""
    r = client.get(BASE + endpoint)
    r.raise_for_status()
    lm = r.headers.get("Last-Modified")
    last_modified = parsedate_to_datetime(lm) if lm else None
    return r.content, last_modified


def _parse_zip(zip_bytes: bytes, subdomains: bool):
    """Yield-list of (subdomains, domain, rank) from the inner `rank,domain` CSV."""
    rows = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        name = z.namelist()[0]  # single member, e.g. top-1m.csv
        with z.open(name) as f:
            for raw in io.TextIOWrapper(f, encoding="utf-8"):
                line = raw.strip()
                if not line:
                    continue
                rank_s, _, domain = line.partition(",")
                if not domain:
                    continue
                rows.append((subdomains, domain, int(rank_s)))
    return rows


# ────────────────────────────── Orchestration ──────────────────────────────
def routine_fetch() -> int:
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        # 1. resolve current list_ids for both granularities
        resolved = []
        for subdomains, id_ep, zip_ep, prefix in GRANULARITIES:
            list_id = _get_list_id(client, id_ep)
            resolved.append((subdomains, zip_ep, prefix, list_id))
            print(f"  {prefix}: list_id={list_id}")

        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT list_id FROM reference.tranco_archive")
            archived = {r[0] for r in cur.fetchall()}

            if all(list_id in archived for _, _, _, list_id in resolved):
                print("  both granularities already archived; no upstream update (no-op)")
                return 0

            # 2. at least one granularity is new → fetch+parse BOTH (the hot-table
            #    TRUNCATE+COPY rewrites both, so we need both granularities' rows)
            all_rows: list[tuple] = []
            for subdomains, zip_ep, prefix, list_id in resolved:
                zip_bytes, last_modified = _download_zip(client, zip_ep)
                rows = _parse_zip(zip_bytes, subdomains)
                all_rows.extend(rows)
                print(f"  {prefix}: {len(rows)} rows, last_modified={last_modified}")

                if list_id not in archived:
                    sha = hashlib.sha256(zip_bytes).hexdigest()
                    list_date = (last_modified or datetime.now(timezone.utc)).date()
                    object_path = f"{prefix}/{list_date.isoformat()}__{list_id}.csv.zip"
                    _storage_put(client, object_path, zip_bytes)
                    cur.execute(
                        """INSERT INTO reference.tranco_archive
                             (list_id, list_date, subdomains, row_count, sha256,
                              object_path, last_modified)
                           VALUES (%s, %s, %s, %s, %s, %s, %s)
                           ON CONFLICT (list_id) DO NOTHING""",
                        (list_id, list_date, subdomains, len(rows), sha,
                         object_path, last_modified),
                    )
                    print(f"  archived → {object_path} (sha {sha[:12]}…)")

            # 3. refresh hot table: atomic TRUNCATE + COPY both granularities.
            #    Same txn as the manifest inserts → all-or-nothing; readers see the
            #    old list until COMMIT.
            cur.execute("TRUNCATE reference.tranco_top1m")
            with cur.copy(
                "COPY reference.tranco_top1m (subdomains, domain, rank) FROM STDIN"
            ) as cp:
                for row in all_rows:
                    cp.write_row(row)
            print(f"  hot table refreshed: {len(all_rows)} rows (both granularities)")

    return len(all_rows)


def bootstrap_fetch(size: int | None = None) -> int:
    """Strategy A has only 'today'; bootstrap == routine. `size` for signature parity."""
    return routine_fetch()


if __name__ == "__main__":
    n = routine_fetch()
    print(f"\n=== tranco routine_fetch done: {n} rows ===")
