"""OpenPhish Academic fetcher.

Source: private GitHub repo `openphish/academic` containing `archive.tar.gz`
(30-day rolling JSON archive) and `feed.csv` (24h CSV). Bootstrap uses the
30-day JSON archive (null-faithful). Source occasionally refreshes per-URL
metadata, so writes use UPSERT (DO UPDATE).

Env: OPENPHISH_GITHUB_USER, OPENPHISH_GITHUB_PAT
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile

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
