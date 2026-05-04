"""urlscan.io routine fetcher — runs on home NAS, not GitHub Actions.

Triggered by DSM Task Scheduler every 15 min via docker run; the container
exits after a single tick. Two-phase per-tick state machine:

  Phase 1 (poll first to drain previous-tick stragglers):
    SELECT submitted/failed-with-uuid → GET /api/v1/result/{uuid}/
       200          → fetch screenshot+dom → write NAS 4-pack → UPDATE done
       404          → still queued, no DB change
       timeout-aged → clear uuid + UPDATE pending (next tick re-POSTs)
       4xx/5xx      → UPDATE failed, attempts++

  Phase 2 (POST):
    SELECT pending/failed-without-uuid → POST /api/v1/scan/
       200 → UPDATE submitted, uuid filled, last_fetched_at=now
       4xx → UPDATE failed, attempts++
       429 → no DB change (next tick retries naturally)

API key pool: URLSCAN_API_KEYS env var holds one or more comma-separated keys.
Round-robin across keys multiplies effective daily quota by pool size; helpful
for both throughput and resilience (one key 429s, the next picks up).

NAS layout (DATA_ROOT defaults to /data inside container, bind-mounted from
~/data/phishing/urlscan_results on host):

    {DATA_ROOT}/{url_sha256}/{uuid}/
      ├── result.json.gz       gzip of GET /api/v1/result/{uuid}/
      ├── screenshot.png       raw bytes of /screenshots/{uuid}.png
      ├── dom.html.gz          gzip of /dom/{uuid}/
      └── meta.json            self-describing audit record (written LAST as
                               the completion marker — its presence means the
                               scan landed atomically)

Layout rationale: url_sha256 as the primary partition co-locates every scan
of the same URL (default scan + future language_followup + manual rescans)
under one parent directory, making "what data do we have for URL X" a one-
liner. uuid is unique per scan and remains the inner directory.

Concurrency via asyncio.Semaphore(CONCURRENCY); each request picks the next
key from the pool. HARD_BUDGET_SEC enforces a hard tick deadline so the
container never overlaps with its successor.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import time
from datetime import datetime, timezone
from itertools import cycle
from pathlib import Path
from typing import Any

import httpx

from src.shared.db import get_connection


# ═══════════════════════════ tunables (env-driven) ═══════════════════════════

API_BASE              = "https://urlscan.io"
DATA_ROOT             = Path(os.environ.get("URLSCAN_DATA_ROOT", "/data"))
PHASE_1_LIMIT         = int(os.environ.get("PHASE_1_LIMIT", "200"))
PHASE_2_LIMIT         = int(os.environ.get("PHASE_2_LIMIT", "100"))
CONCURRENCY           = int(os.environ.get("CONCURRENCY", "5"))
HARD_BUDGET_SEC       = int(os.environ.get("HARD_BUDGET_SEC", "720"))   # 12 min
# Submitted-state timeout. Must exceed cron interval so a missed poll isn't
# falsely declared timed out. urlscan typically completes in 5–60s, so 2h is
# generous and matches vt fetcher.
SUBMITTED_TIMEOUT_SEC = int(os.environ.get("SUBMITTED_TIMEOUT_SEC", "7200"))
MAX_ATTEMPTS          = int(os.environ.get("MAX_ATTEMPTS", "3"))
QUOTA_ABORT_RATIO     = float(os.environ.get("QUOTA_ABORT_RATIO", "0.95"))
HTTP_TIMEOUT_SEC      = float(os.environ.get("HTTP_TIMEOUT_SEC", "30"))
HTTP_CONNECT_TIMEOUT  = float(os.environ.get("HTTP_CONNECT_TIMEOUT", "10"))


# ═══════════════════════════ API key pool ═══════════════════════════

class UrlscanApiPool:
    """Round-robin selector over one or more urlscan API keys.

    Race-y on the cycle iterator under high concurrency, but the worst case is
    two coroutines getting the same key — completely harmless. No locking.
    """

    def __init__(self, keys: list[str]):
        if not keys:
            raise RuntimeError(
                "URLSCAN_API_KEYS not set or empty. Provide one or more "
                "comma-separated keys via env (e.g. URLSCAN_API_KEYS=k1,k2)."
            )
        self._all_keys = list(keys)
        self._cycle = cycle(self._all_keys)

    def next(self) -> str:
        return next(self._cycle)

    @property
    def size(self) -> int:
        return len(self._all_keys)

    @property
    def all_keys(self) -> list[str]:
        return list(self._all_keys)


def _build_pool() -> UrlscanApiPool:
    raw = os.environ.get("URLSCAN_API_KEYS", "").strip()
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    return UrlscanApiPool(keys)


def _headers(api_key: str) -> dict[str, str]:
    return {"API-Key": api_key, "User-Agent": "phish-intelligence-fetcher/0.1"}


# ═══════════════════════════ HTTP layer (async) ═══════════════════════════

async def _check_pool_quota(client: httpx.AsyncClient, pool: UrlscanApiPool) -> bool:
    """Sum daily public-scan usage across all keys; abort if combined > QUOTA_ABORT_RATIO."""
    total_used = 0
    total_limit = 0
    for k in pool.all_keys:
        try:
            r = await client.get(f"{API_BASE}/user/quotas/", headers=_headers(k), timeout=10)
            r.raise_for_status()
            day = r.json()["limits"]["public"]["day"]
            total_used  += day.get("used",  0)
            total_limit += day.get("limit", 0)
        except Exception as e:
            print(f"  Pool quota check failed for key …{k[-6:]}: {e}; proceeding optimistically")
            return True

    ratio = (total_used / total_limit) if total_limit else 1.0
    print(f"  Pool quota: {total_used}/{total_limit} ({ratio*100:.1f}%) over {pool.size} key(s)")
    return ratio < QUOTA_ABORT_RATIO


async def _post_scan(
    client: httpx.AsyncClient,
    api_key: str,
    url: str,
    scan_params: dict[str, Any],
) -> dict[str, Any]:
    body = {"url": url, "visibility": "public", **scan_params}
    try:
        r = await client.post(
            f"{API_BASE}/api/v1/scan/",
            headers={**_headers(api_key), "Content-Type": "application/json"},
            json=body,
        )
        if r.status_code == 200:
            return {"ok": True, "uuid": r.json()["uuid"]}
        if r.status_code == 429:
            return {"ok": False, "throttled": True, "error": "HTTP 429 throttled"}
        if r.status_code in (401, 403):
            return {"ok": False, "abort": True,
                    "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def _get_result(
    client: httpx.AsyncClient,
    api_key: str,
    uuid: str,
) -> dict[str, Any]:
    """GET /api/v1/result/{uuid}/. urlscan returns 404 while still queued (not 'missing')."""
    try:
        r = await client.get(f"{API_BASE}/api/v1/result/{uuid}/", headers=_headers(api_key))
        if r.status_code == 200:
            return {"ok": True, "data": r.json()}
        if r.status_code == 404:
            return {"ok": True, "still_queued": True}
        if r.status_code in (401, 403):
            return {"ok": False, "abort": True,
                    "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def _get_bytes(client: httpx.AsyncClient, api_key: str, path: str) -> bytes | None:
    """Fetch a binary asset (screenshot.png / dom.html). Returns None on 404 or error."""
    try:
        r = await client.get(f"{API_BASE}{path}", headers=_headers(api_key))
        if r.status_code == 200:
            return r.content
        if r.status_code == 404:
            return None
        return None
    except Exception:
        return None


# ═══════════════════════════ NAS storage layer ═══════════════════════════

def _scan_dir(url_sha256: str, uuid: str) -> Path:
    """Derive the per-scan directory: {DATA_ROOT}/{url_sha256}/{uuid}/.

    url_sha256 as the outer partition co-locates all scans of the same URL.
    uuid is the inner per-scan directory (unique by urlscan's own ID).
    """
    return DATA_ROOT / url_sha256 / uuid


def _write_to_nas(
    *,
    uuid: str,
    url_sha256: str,
    url: str,
    scan_purpose: str,
    scan_params: dict,
    submitted_at: datetime | None,
    api_key_used: str,
    result_json: dict,
    screenshot: bytes | None,
    dom: bytes | None,
) -> Path:
    """Write the 4-pack to NAS. meta.json is written LAST as the completion marker:
    its presence means everything else for this uuid is on disk.
    """
    target = _scan_dir(url_sha256, uuid)
    target.mkdir(parents=True, exist_ok=True)

    # 1. result.json.gz
    with gzip.open(target / "result.json.gz", "wb", compresslevel=6) as f:
        f.write(json.dumps(result_json, ensure_ascii=False, separators=(",", ":")).encode())

    # 2. screenshot.png (PNG already compressed; don't gzip)
    if screenshot is not None:
        (target / "screenshot.png").write_bytes(screenshot)

    # 3. dom.html.gz
    if dom is not None:
        with gzip.open(target / "dom.html.gz", "wb", compresslevel=6) as f:
            f.write(dom)

    # 4. meta.json — written LAST = completion marker
    page             = result_json.get("page",     {}) if isinstance(result_json, dict) else {}
    scanner          = result_json.get("scanner",  {}) if isinstance(result_json, dict) else {}
    verdicts_overall = (
        result_json.get("verdicts", {}).get("overall", {})
        if isinstance(result_json, dict) else {}
    )
    meta = {
        "uuid":             uuid,
        "url_sha256":       url_sha256,
        "url":              url,
        "scan_purpose":     scan_purpose,
        "scan_params":      scan_params,
        "submitted_at":     submitted_at.isoformat() if submitted_at else None,
        "completed_at":     datetime.now(timezone.utc).isoformat(),
        "api_key_used":     f"…{api_key_used[-6:]}",   # never persist full key
        "scanner_country":  scanner.get("country"),
        "page_language":    page.get("language"),
        "page_domain":      page.get("domain"),
        "page_title":       page.get("title"),
        "page_ip":          page.get("ip"),
        "page_country":     page.get("country"),
        "verdicts_overall_malicious": verdicts_overall.get("malicious"),
        "verdicts_overall_score":     verdicts_overall.get("score"),
        "has_screenshot":   screenshot is not None,
        "has_dom":          dom        is not None,
    }
    (target / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2)
    )
    return target


# ═══════════════════════════ DB layer ═══════════════════════════

def _select_pending_batch(conn, limit: int) -> list[dict]:
    sql = """
        SELECT s.scan_id, s.url_sha256, p.url, s.scan_params, s.fetch_attempts
        FROM urlscan_url_scans s
        JOIN phishing_urls p USING (url_sha256)
        WHERE s.fetch_status IN ('pending', 'failed')
          AND s.uuid IS NULL
          AND s.fetch_attempts < %s
        ORDER BY s.fetch_attempts ASC, s.ingested_at ASC
        LIMIT %s
    """
    with conn.cursor() as cur:
        cur.execute(sql, (MAX_ATTEMPTS, limit))
        cols = [c.name for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def _select_submitted_batch(conn, limit: int) -> list[dict]:
    sql = """
        SELECT s.scan_id, s.url_sha256, p.url, s.uuid, s.scan_purpose, s.scan_params,
               s.fetch_attempts, s.last_fetched_at
        FROM urlscan_url_scans s
        JOIN phishing_urls p USING (url_sha256)
        WHERE s.fetch_status IN ('submitted', 'failed')
          AND s.uuid IS NOT NULL
          AND s.fetch_attempts < %s
        ORDER BY s.last_fetched_at ASC NULLS FIRST
        LIMIT %s
    """
    with conn.cursor() as cur:
        cur.execute(sql, (MAX_ATTEMPTS, limit))
        cols = [c.name for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def _apply_post_result(conn, scan_id: int, result: dict, counts: dict) -> None:
    if result.get("ok"):
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE urlscan_url_scans
                SET fetch_status   = 'submitted',
                    uuid           = %s,
                    fetch_attempts = 0,
                    last_fetched_at = now(),
                    last_error     = NULL
                WHERE scan_id = %s
            """, (result["uuid"], scan_id))
        counts["submitted"] += 1
    elif result.get("throttled"):
        # 429: don't bump attempts (it's a rate-limit, not a real failure).
        # Leave row in current state; next tick will retry.
        counts["throttled_post"] += 1
    else:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE urlscan_url_scans
                SET fetch_status   = 'failed',
                    fetch_attempts = fetch_attempts + 1,
                    last_fetched_at = now(),
                    last_error     = %s
                WHERE scan_id = %s
            """, (result.get("error", "unknown")[:1000], scan_id))
        counts["failed_post"] += 1
    conn.commit()


def _apply_poll_done(conn, scan_id: int) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE urlscan_url_scans
            SET fetch_status   = 'done',
                fetch_attempts = 0,
                last_fetched_at = now(),
                last_error     = NULL
            WHERE scan_id = %s
        """, (scan_id,))
    conn.commit()


def _apply_poll_timeout(conn, scan_id: int) -> None:
    """Reset to pending (clear uuid) so next tick re-POSTs from scratch."""
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE urlscan_url_scans
            SET fetch_status   = 'pending',
                uuid           = NULL,
                fetch_attempts = fetch_attempts + 1,
                last_fetched_at = now(),
                last_error     = 'submitted timeout exceeded; clearing uuid for re-POST'
            WHERE scan_id = %s
        """, (scan_id,))
    conn.commit()


def _apply_poll_failure(conn, scan_id: int, err: str) -> None:
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE urlscan_url_scans
            SET fetch_status   = 'failed',
                fetch_attempts = fetch_attempts + 1,
                last_fetched_at = now(),
                last_error     = %s
            WHERE scan_id = %s
        """, (err[:1000], scan_id))
    conn.commit()


# ═══════════════════════════ Per-row processors ═══════════════════════════

async def _do_post(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    pool: UrlscanApiPool,
    row: dict,
) -> dict:
    async with sem:
        api_key = pool.next()
        scan_params = dict(row.get("scan_params") or {})
        result = await _post_scan(client, api_key, row["url"], scan_params)
        return {"row": row, "api_key": api_key, **result}


async def _do_poll_and_fetch(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    pool: UrlscanApiPool,
    row: dict,
) -> dict:
    async with sem:
        # 1. Pre-check timeout (last_fetched_at was set by POST and isn't bumped
        #    by still-queued polls, so its age = "submitted age").
        lf = row.get("last_fetched_at")
        if lf is not None:
            age = (datetime.now(timezone.utc) - lf).total_seconds()
            if age > SUBMITTED_TIMEOUT_SEC:
                return {"row": row, "outcome": "timeout", "age": age}

        api_key = pool.next()
        # 2. Poll
        res = await _get_result(client, api_key, row["uuid"])
        if not res.get("ok"):
            return {"row": row, "outcome": "fail", "api_key": api_key, **res}
        if res.get("still_queued"):
            return {"row": row, "outcome": "still_queued", "api_key": api_key}

        result_json = res["data"]
        # 3. On done, fetch screenshot + dom in same coroutine (sequential,
        #    sharing the semaphore slot — keeps total in-flight bounded).
        screenshot = await _get_bytes(client, api_key, f"/screenshots/{row['uuid']}.png")
        dom        = await _get_bytes(client, api_key, f"/dom/{row['uuid']}/")
        return {
            "row":         row,
            "outcome":     "done",
            "api_key":     api_key,
            "result_json": result_json,
            "screenshot":  screenshot,
            "dom":         dom,
        }


# ═══════════════════════════ Phase orchestration ═══════════════════════════

async def _run_phase_1(
    client: httpx.AsyncClient,
    conn,
    sem: asyncio.Semaphore,
    pool: UrlscanApiPool,
    deadline: float,
    counts: dict,
) -> None:
    rows = _select_submitted_batch(conn, PHASE_1_LIMIT)
    print(f"\n=== Phase 1 (poll): {len(rows)} candidate row(s) ===")
    if not rows:
        return
    if time.monotonic() > deadline:
        print("  ⚠ deadline already passed before Phase 1 dispatch")
        return

    tasks = [_do_poll_and_fetch(client, sem, pool, r) for r in rows]
    results = await asyncio.gather(*tasks)

    abort = next((r for r in results if r.get("abort")), None)
    if abort:
        print(f"  ✗ Auth/quota error mid-phase: {abort['error']}")
        return

    for r in results:
        scan_id = r["row"]["scan_id"]
        outcome = r["outcome"]

        if outcome == "still_queued":
            counts["polled_pending"] += 1
            continue

        if outcome == "timeout":
            _apply_poll_timeout(conn, scan_id)
            counts["timeout"] += 1
            continue

        if outcome == "fail":
            _apply_poll_failure(conn, scan_id, r.get("error", "unknown"))
            counts["failed_poll"] += 1
            continue

        # outcome == "done": write NAS first, then mark done.
        # If NAS write fails, leave DB as-is (next tick retries via the SELECT
        # because fetch_status is still 'submitted' or we mark failed).
        try:
            _write_to_nas(
                uuid         = r["row"]["uuid"],
                url_sha256   = r["row"]["url_sha256"],
                url          = r["row"]["url"],
                scan_purpose = r["row"]["scan_purpose"],
                scan_params  = dict(r["row"].get("scan_params") or {}),
                submitted_at = r["row"].get("last_fetched_at"),
                api_key_used = r["api_key"],
                result_json  = r["result_json"],
                screenshot   = r["screenshot"],
                dom          = r["dom"],
            )
            _apply_poll_done(conn, scan_id)
            counts["done"] += 1
        except Exception as e:
            print(f"  ✗ NAS write failed for scan_id={scan_id}: {type(e).__name__}: {e}")
            _apply_poll_failure(conn, scan_id, f"NAS write: {type(e).__name__}: {e}")
            counts["nas_write_fail"] += 1

    print(f"  → done={counts['done']}  still_queued={counts['polled_pending']}  "
          f"timeout={counts['timeout']}  failed={counts['failed_poll']}  "
          f"nas_fail={counts['nas_write_fail']}")


async def _run_phase_2(
    client: httpx.AsyncClient,
    conn,
    sem: asyncio.Semaphore,
    pool: UrlscanApiPool,
    deadline: float,
    counts: dict,
) -> None:
    rows = _select_pending_batch(conn, PHASE_2_LIMIT)
    print(f"\n=== Phase 2 (POST): {len(rows)} candidate row(s) ===")
    if not rows:
        return
    if time.monotonic() > deadline:
        print("  ⚠ deadline already passed before Phase 2 dispatch")
        return

    tasks = [_do_post(client, sem, pool, r) for r in rows]
    results = await asyncio.gather(*tasks)

    abort = next((r for r in results if r.get("abort")), None)
    if abort:
        print(f"  ✗ Auth/quota error mid-phase: {abort['error']}")
        return

    for r in results:
        _apply_post_result(conn, r["row"]["scan_id"], r, counts)

    print(f"  → submitted={counts['submitted']}  failed={counts['failed_post']}  "
          f"throttled={counts['throttled_post']}")


# ═══════════════════════════ Top-level entry ═══════════════════════════

async def routine_fetch_once_async() -> dict:
    counts = {
        "polled_pending":  0,
        "done":            0,
        "submitted":       0,
        "failed_post":     0,
        "failed_poll":     0,
        "throttled_post":  0,
        "timeout":         0,
        "nas_write_fail":  0,
    }

    pool = _build_pool()
    print(f"=== urlscan fetcher tick @ {datetime.now(timezone.utc).isoformat()} ===")
    print(f"  API pool size:   {pool.size}")
    print(f"  Data root:       {DATA_ROOT}")
    print(f"  Time budget:     {HARD_BUDGET_SEC}s")
    print(f"  Phase 1 limit:   {PHASE_1_LIMIT}")
    print(f"  Phase 2 limit:   {PHASE_2_LIMIT}")
    print(f"  Concurrency:     {CONCURRENCY}")

    DATA_ROOT.mkdir(parents=True, exist_ok=True)

    deadline = time.monotonic() + HARD_BUDGET_SEC
    timeout = httpx.Timeout(HTTP_TIMEOUT_SEC, connect=HTTP_CONNECT_TIMEOUT)
    limits  = httpx.Limits(max_connections=CONCURRENCY * 2,
                           max_keepalive_connections=CONCURRENCY * 2)

    async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=True) as client:
        if not await _check_pool_quota(client, pool):
            print("⚠ Pool quota threshold reached, exiting early")
            return counts

        with get_connection() as conn:
            sem = asyncio.Semaphore(CONCURRENCY)
            await _run_phase_1(client, conn, sem, pool, deadline, counts)
            if time.monotonic() < deadline:
                await _run_phase_2(client, conn, sem, pool, deadline, counts)
            else:
                print("\n  ⚠ Time budget exhausted before Phase 2; deferring")

    return counts


def main() -> None:
    t0 = time.time()
    counts = asyncio.run(routine_fetch_once_async())
    elapsed = time.time() - t0
    print(f"\n=== Summary ({elapsed:.1f}s) ===")
    for k, v in counts.items():
        print(f"  {k:18}  {v}")


if __name__ == "__main__":
    main()
