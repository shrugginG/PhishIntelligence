"""CrUX top-1M fetcher (Strategy A global hot table + cold Storage archive of all scopes).

Source: https://github.com/zakird/crux-top-lists — monthly snapshots of the Chrome
User Experience Report top-1M (origins ranked by real Chrome user traffic, bucketed),
cached from Google BigQuery. Files:
  data/global/<YYYYMM>.csv.gz            global top-1M (1,000,000 origins)
  data/global/current.csv.gz             pointer-copy of the latest month (we ignore it)
  data/country/<cc>/<YYYYMM>.csv.gz       per-country lists (238 countries)
Each CSV is `origin,rank` with a header; origin has a scheme (https://...); rank is
the CrUX bucket ceiling (1000/5000/.../1000000); origins are unique per list.

Layout here (global/country split):
  HOT  reference.crux_top1m   — current-only mirror of the latest GLOBAL list ONLY
       (~1M rows). Refreshed via TRUNCATE+COPY. Country lists are NOT loaded into PG.
  COLD bucket `crux-top-archive` — mirrors the repo data/ tree verbatim (data/ →
       bucket root): global/<YYYYMM>.csv.gz + country/<cc>/<YYYYMM>.csv.gz. BOTH
       global and all countries archived (lossless, re-importable).
  reference.crux_archive — manifest, one row per (scope, yyyymm).

Enumeration: a single GitHub git-tree API call lists every scope's latest month.
Idempotency = (scope, yyyymm) in the manifest (CrUX monthly data is immutable);
failed scopes retry independently next day. The hot table is refreshed only when
the GLOBAL scope gets a new month. Daily cadence → most days are a full no-op.

Storage writes need SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY (same as tranco).
bootstrap_fetch == routine_fetch.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import re

import httpx

from src.shared.db import get_connection

REPO = "zakird/crux-top-lists"
REPO_REF = "main"
TREE_API = f"https://api.github.com/repos/{REPO}/git/trees/{REPO_REF}?recursive=1"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/{REPO_REF}"
STORAGE_BUCKET = os.environ.get("CRUX_STORAGE_BUCKET", "crux-top-archive")

_GLOBAL_RE = re.compile(r"^data/global/(\d{6})\.csv\.gz$")
_COUNTRY_RE = re.compile(r"^data/country/([a-z0-9]+)/(\d{6})\.csv\.gz$")


# ────────────────────────────── GitHub helpers ──────────────────────────────
def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _latest_scopes(client: httpx.Client) -> dict[str, tuple[int, str]]:
    """One git-tree call → {scope: (yyyymm, repo_path)} for the latest month of
    each scope. scope = 'global' or a country code."""
    r = client.get(TREE_API, headers=_github_headers())
    r.raise_for_status()
    data = r.json()
    if data.get("truncated"):
        raise RuntimeError("git tree truncated — repo grew past one page; add pagination")

    latest: dict[str, tuple[int, str]] = {}
    for e in data["tree"]:
        if e.get("type") != "blob":
            continue
        path = e["path"]
        m = _GLOBAL_RE.match(path)
        if m:
            scope, mm = "global", int(m.group(1))
        else:
            m = _COUNTRY_RE.match(path)
            if not m:
                continue
            scope, mm = m.group(1), int(m.group(2))
        cur = latest.get(scope)
        if cur is None or mm > cur[0]:
            latest[scope] = (mm, path)
    return latest


def _download_raw(client: httpx.Client, repo_path: str) -> bytes:
    r = client.get(f"{RAW_BASE}/{repo_path}")
    r.raise_for_status()
    return r.content


# ────────────────────────────── Storage helpers ──────────────────────────────
def _supabase_url() -> str:
    v = os.environ.get("SUPABASE_URL")
    if not v:
        raise RuntimeError("SUPABASE_URL not set (Kong gateway; self-host = http://192.168.1.21:8000)")
    return v.rstrip("/")


def _service_key() -> str:
    v = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
    if not v:
        raise RuntimeError("SUPABASE_SERVICE_ROLE_KEY not set (required to write the crux-top-archive bucket)")
    return v


def _storage_put(client: httpx.Client, object_path: str, gz_bytes: bytes) -> None:
    key = _service_key()
    url = f"{_supabase_url()}/storage/v1/object/{STORAGE_BUCKET}/{object_path}"
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/gzip",
        "x-upsert": "true",
    }
    r = client.post(url, headers=headers, content=gz_bytes)
    r.raise_for_status()


# ────────────────────────────── CSV helpers ──────────────────────────────
def _iter_rows(gz_bytes: bytes):
    """Yield (origin, rank:int) from the inner `origin,rank` CSV (skips header)."""
    with gzip.open(io.BytesIO(gz_bytes), mode="rt", encoding="utf-8") as f:
        first = True
        for line in f:
            if first:
                first = False
                continue  # header: origin,rank
            line = line.strip()
            if not line:
                continue
            origin, _, rank_s = line.partition(",")
            if not rank_s:
                continue
            yield origin, int(rank_s)


def _count_rows(gz_bytes: bytes) -> int:
    n = 0
    for _ in _iter_rows(gz_bytes):
        n += 1
    return n


# ────────────────────────────── Orchestration ──────────────────────────────
def routine_fetch() -> int:
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        scopes = _latest_scopes(client)  # {scope: (yyyymm, repo_path)}
        print(f"  enumerated {len(scopes)} scopes (global + {len(scopes) - 1} countries)")

        with get_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT scope, yyyymm FROM reference.crux_archive")
            archived = {(s, m) for s, m in cur.fetchall()}

            todo = [(scope, mm, path) for scope, (mm, path) in scopes.items()
                    if (scope, mm) not in archived]
            if not todo:
                print("  all scopes already archived for their latest month; no-op")
                return 0
            print(f"  {len(todo)} scope(s) to fetch")

            # process global first so any failure surfaces before the long country tail
            todo.sort(key=lambda t: (t[0] != "global", t[0]))

            global_gz: bytes | None = None
            n_archived = 0
            for scope, yyyymm, repo_path in todo:
                gz = _download_raw(client, repo_path)
                row_count = _count_rows(gz)
                object_path = repo_path[len("data/"):]   # data/ → bucket root (verbatim mirror)
                _storage_put(client, object_path, gz)
                cur.execute(
                    """INSERT INTO reference.crux_archive
                         (scope, yyyymm, row_count, sha256, source_size, object_path)
                       VALUES (%s, %s, %s, %s, %s, %s)
                       ON CONFLICT (scope, yyyymm) DO NOTHING""",
                    (scope, yyyymm, row_count, hashlib.sha256(gz).hexdigest(),
                     len(gz), object_path),
                )
                n_archived += 1
                if scope == "global":
                    global_gz = gz
                    print(f"  archived global {yyyymm}: {row_count} rows → {object_path}")

            # refresh hot table only when the GLOBAL scope got a new month
            if global_gz is not None:
                cur.execute("TRUNCATE reference.crux_top1m")
                with cur.copy("COPY reference.crux_top1m (origin, rank) FROM STDIN") as cp:
                    for origin, rank in _iter_rows(global_gz):
                        cp.write_row((origin, rank))
                print("  hot table refreshed (global)")

            print(f"  archived {n_archived} scope file(s) to {STORAGE_BUCKET}")
    return n_archived


def bootstrap_fetch(size: int | None = None) -> int:
    """CrUX is monthly; bootstrap == routine. `size` for signature parity."""
    return routine_fetch()


if __name__ == "__main__":
    n = routine_fetch()
    print(f"\n=== crux routine_fetch done: {n} scope file(s) archived ===")
