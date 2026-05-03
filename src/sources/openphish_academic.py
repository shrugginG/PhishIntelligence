"""OpenPhish Academic fetcher.

Source: private GitHub repo `openphish/academic` containing `archive.tar.gz`
(30-day rolling JSON archive) and `feed.csv` (24h CSV). Bootstrap uses the
30-day JSON archive (null-faithful). Source occasionally refreshes per-URL
metadata, so writes use UPSERT (DO UPDATE).

Env: OPENPHISH_GITHUB_USER, OPENPHISH_GITHUB_PAT
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from datetime import datetime

from src.shared.db import get_connection

REPO = "github.com/openphish/academic"
ARCHIVE_NAME = "phishing_feed_30_days"


def _clone_repo() -> str:
    user = os.environ["OPENPHISH_GITHUB_USER"]
    pat = os.environ["OPENPHISH_GITHUB_PAT"]
    tmp = tempfile.mkdtemp(prefix="openphish-academic-")
    print(f"  Cloning {REPO}…")
    subprocess.run(
        ["git", "clone", "--depth", "1", f"https://{user}:{pat}@{REPO}", tmp],
        check=True,
        capture_output=True,
    )
    return tmp


def _read_archive(repo_path: str) -> list[dict]:
    archive = os.path.join(repo_path, "archive.tar.gz")
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf.getmembers():
            if member.name.endswith(ARCHIVE_NAME):
                f = tf.extractfile(member)
                if f is None:
                    raise RuntimeError(f"could not extract {member.name}")
                return json.load(f)
    raise RuntimeError(f"{ARCHIVE_NAME} not found inside archive.tar.gz")


def _upsert(records: list[dict]) -> int:
    if not records:
        return 0

    rows = [
        (
            hashlib.sha256(r["url"].encode()).hexdigest(),
            r["url"],
            r.get("brand"),
            r.get("ip"),
            r.get("asn"),
            r.get("asn_name"),
            r.get("country_code"),
            r.get("country_name"),
            r.get("tld"),
            r.get("isotime"),
            r.get("family_id"),
            r.get("host"),
            r.get("page_language"),
            r.get("ssl_cert_issued_by"),
            r.get("ssl_cert_issued_to"),
            r.get("ssl_cert_serial"),
            r.get("is_spear", False),
            r.get("sector"),
            json.dumps(r, ensure_ascii=False),
        )
        for r in records
    ]

    sql = """
        INSERT INTO raw_openphish_academic
            (url_sha256, url, brand, ip, asn, asn_name,
             country_code, country_name, tld, discover_time,
             family_id, host, page_language,
             ssl_cert_issued_by, ssl_cert_issued_to, ssl_cert_serial,
             is_spear, sector, raw_payload)
        VALUES (%s, %s, %s, %s::inet, %s, %s,
                %s, %s, %s, %s::timestamptz,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s::jsonb)
        ON CONFLICT (url_sha256) DO UPDATE SET
            brand              = EXCLUDED.brand,
            ip                 = EXCLUDED.ip,
            asn                = EXCLUDED.asn,
            asn_name           = EXCLUDED.asn_name,
            country_code       = EXCLUDED.country_code,
            country_name       = EXCLUDED.country_name,
            tld                = EXCLUDED.tld,
            discover_time      = EXCLUDED.discover_time,
            family_id          = EXCLUDED.family_id,
            host               = EXCLUDED.host,
            page_language      = EXCLUDED.page_language,
            ssl_cert_issued_by = EXCLUDED.ssl_cert_issued_by,
            ssl_cert_issued_to = EXCLUDED.ssl_cert_issued_to,
            ssl_cert_serial    = EXCLUDED.ssl_cert_serial,
            is_spear           = EXCLUDED.is_spear,
            sector             = EXCLUDED.sector,
            raw_payload        = EXCLUDED.raw_payload
    """

    with get_connection() as conn, conn.cursor() as cur:
        cur.executemany(sql, rows)
        return cur.rowcount


def bootstrap_fetch(size: int | None) -> int:
    repo_path = _clone_repo()
    try:
        records = _read_archive(repo_path)
        print(f"  Got {len(records)} records from 30-day archive (already desc by isotime)")
        selected = records if size is None else records[:size]
        print(f"  Selected top {len(selected)}")
        affected = _upsert(selected)
        print(f"  Upsert affected {affected} rows")
        return affected
    finally:
        shutil.rmtree(repo_path, ignore_errors=True)


def _read_feed_csv(repo_path: str) -> list[dict]:
    """Read feed.csv (24h rolling, CSV format), normalize empty strings to None,
    parse `is_spear` to bool. CSV cannot distinguish null from empty string;
    we collapse both to None for consistency with JSON archive parsing.
    """
    csv_path = os.path.join(repo_path, "feed.csv")

    def _norm(v: str | None) -> str | None:
        if v is None:
            return None
        s = v.strip()
        return s if s else None

    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = []
        for row in reader:
            normalized = {k: _norm(v) for k, v in row.items()}
            normalized["is_spear"] = (row.get("is_spear", "").strip().lower() == "true")
            records.append(normalized)
    return records


def _get_anchor() -> datetime | None:
    """Returns MAX(discover_time) from raw_openphish_academic, None if empty."""
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT MAX(discover_time) FROM raw_openphish_academic")
        return cur.fetchone()[0]


def _parse_isotime(s: str | None) -> datetime | None:
    """Parse '2026-04-30T23:59:53Z' to tz-aware datetime.
    Python 3.11+ accepts 'Z' suffix in fromisoformat directly.
    """
    if not s:
        return None
    return datetime.fromisoformat(s)


def routine_fetch() -> int:
    """Incremental fetch: clone repo, read feed.csv (24h, strictly desc by isotime),
    break early on isotime <= anchor.

    Short-circuit IS safe here (verified empirically: feed.csv 100% strict desc).
    Contrast with PhishTank where ~1.4% local reversals make break unsafe.
    """
    anchor = _get_anchor()
    if anchor:
        print(f"  Anchor: discover_time > {anchor.isoformat()}")
    else:
        print("  Anchor: empty table, all rows considered new")

    repo_path = _clone_repo()
    try:
        records = _read_feed_csv(repo_path)
        print(f"  feed.csv has {len(records)} rows")

        new: list[dict] = []
        for r in records:
            iso_dt = _parse_isotime(r.get("isotime"))
            if iso_dt is None:
                continue   # malformed row — skip but don't break
            if anchor is None or iso_dt > anchor:
                new.append(r)
            else:
                break      # strict desc: subsequent rows are all older

        print(f"  New entries beyond anchor: {len(new)} (out of {len(records)} feed rows)")
        affected = _upsert(new)
        print(f"  Upsert affected {affected} rows")
        return affected
    finally:
        shutil.rmtree(repo_path, ignore_errors=True)


if __name__ == "__main__":
    affected = routine_fetch()
    print(f"\n=== routine_fetch done: {affected} rows ===")
