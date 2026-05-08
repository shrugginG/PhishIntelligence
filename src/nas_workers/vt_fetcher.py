"""VirusTotal URL reports — NAS-side routine fetcher.

Triggered by DSM Task Scheduler every 30 min via docker run; the container
exits after a single tick. Two-phase per-tick state machine:

  Phase 1 (poll first to drain previous-tick stragglers):
    SELECT submitted/failed-with-analysis_id → GET /analyses/{id}
       completed     → GET /urls/{vt_id} → UPDATE done with full report
       not completed → still queued, last_fetched_at NOT bumped (so
                       SUBMITTED_TIMEOUT_SEC still measures "age since POST")
       timeout-aged  → UPDATE failed + clear analysis_id (next tick re-POSTs)

  Phase 2 (POST):
    SELECT pending/failed-without-analysis_id → POST /urls
       200 → UPDATE submitted, vt_id + analysis_id filled
       4xx → UPDATE failed, attempts++

Independent NAS implementation paralleling src/sources/vt.py (which still runs
on GitHub Actions as fallback). The two diverge in:

  - Tunable defaults (smaller per-tick batches because NAS cron is 30 min
    while GH Actions cron is best-effort with ~110 min real-world gaps)
  - HARD_BUDGET_SEC enforcement (so a stuck tick can't hold the --name lock
    past the next DSM fire window)
  - All constants are env-driven for runtime override

Smart retry routing on (fetch_status, analysis_id):
  pending   + NULL     → POST          (Phase 2)
  failed    + NULL     → POST  (retry) (Phase 2)
  submitted + NOT NULL → poll          (Phase 1)
  failed    + NOT NULL → poll  (retry) (Phase 1)

Concurrency via asyncio.Semaphore(CONCURRENCY); single API key (academic_january
20k req/day quota). Pool-style multi-key not implemented — one key is enough
for current 4k URL/day inflow × 3 calls = 12k/day usage.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timezone

import httpx

from src.shared.db import get_connection


# ═══════════════════════════ tunables (env-driven) ═══════════════════════════

API_BASE              = "https://www.virustotal.com/api/v3"
# Per-tick batch caps. Smaller than the GH Actions sibling because NAS fires
# 48×/day reliably (vs GH's ~14/day best-effort), so per-tick capacity needs
# don't have to absorb multi-hour gaps. Steady-state inflow ~4k URL/day = ~83
# URL per 30-min tick; 200 gives 2.4× headroom for catch-up after outages.
PHASE_1_LIMIT         = int(os.environ.get("PHASE_1_LIMIT", "200"))
PHASE_2_LIMIT         = int(os.environ.get("PHASE_2_LIMIT", "200"))
CONCURRENCY           = int(os.environ.get("CONCURRENCY", "10"))
HARD_BUDGET_SEC       = int(os.environ.get("HARD_BUDGET_SEC", "720"))   # 12 min
# 2h is comfortably > the 30 min DSM cron interval. Compared to the GH Actions
# sibling's 4h (which had to absorb GH's ~110 min real-world cron gaps), NAS
# can run tighter — submitted rows that haven't completed in 2h almost
# certainly never will.
SUBMITTED_TIMEOUT_SEC = int(os.environ.get("SUBMITTED_TIMEOUT_SEC", "7200"))
MAX_ATTEMPTS          = int(os.environ.get("MAX_ATTEMPTS", "3"))
QUOTA_ABORT_RATIO     = float(os.environ.get("QUOTA_ABORT_RATIO", "0.95"))
HTTP_TIMEOUT_SEC      = float(os.environ.get("HTTP_TIMEOUT_SEC", "20"))
HTTP_CONNECT_TIMEOUT  = float(os.environ.get("HTTP_CONNECT_TIMEOUT", "10"))


# ═══════════════════════════ API key + helpers ═══════════════════════════

def _api_key() -> str:
    k = os.environ.get("VIRUSTOTAL_ACADEMIC_API_KEY")
    if not k:
        raise RuntimeError(
            "VIRUSTOTAL_ACADEMIC_API_KEY not set. "
            "Configure it in the container's --env-file."
        )
    return k


def _headers() -> dict[str, str]:
    return {"x-apikey": _api_key(), "User-Agent": "phish-intelligence-fetcher/0.1"}


def _extract_vt_id(analysis_id: str) -> str | None:
    """analysis_id format: 'u-<sha256_64hex>-<opaque_suffix>'.

    The trailing suffix is opaque hex (NOT a timestamp — empirically decodes to
    1992 for analyses created in 2026). Use vt_url_reports.last_fetched_at for
    "submitted age" instead.
    """
    parts = analysis_id.split("-")
    if len(parts) >= 3 and len(parts[1]) == 64:
        return parts[1]
    return None


# ═══════════════════════════ HTTP layer (async) ═══════════════════════════

async def _check_quota(client: httpx.AsyncClient) -> bool:
    """Return True if OK to proceed, False if user-daily usage > QUOTA_ABORT_RATIO."""
    url = f"{API_BASE}/users/{_api_key()}/overall_quotas"
    try:
        r = await client.get(url, headers=_headers(), timeout=10)
        r.raise_for_status()
        d = r.json()["data"]
        used    = d["api_requests_daily"]["user"]["used"]
        allowed = d["api_requests_daily"]["user"]["allowed"]
        ratio   = used / allowed if allowed else 1.0
        print(f"  Quota daily (user): {used}/{allowed} ({ratio*100:.1f}%)")
        return ratio < QUOTA_ABORT_RATIO
    except Exception as e:
        print(f"  Quota check failed (proceeding optimistically): {e}")
        return True


async def _vt_post(client: httpx.AsyncClient, url: str) -> dict:
    """POST /urls — submit URL for scan."""
    api = f"{API_BASE}/urls"
    try:
        r = await client.post(api, headers=_headers(), data={"url": url})
        if r.status_code == 200:
            j = r.json()
            aid = j["data"]["id"]
            return {"ok": True, "analysis_id": aid, "vt_id": _extract_vt_id(aid)}
        if r.status_code in (401, 403):
            return {"ok": False, "abort": True,
                    "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def _vt_get_analysis(client: httpx.AsyncClient, analysis_id: str) -> dict:
    """GET /analyses/{id} — poll analysis status."""
    api = f"{API_BASE}/analyses/{analysis_id}"
    try:
        r = await client.get(api, headers=_headers())
        if r.status_code == 200:
            attrs = r.json()["data"]["attributes"]
            return {"ok": True, "status": attrs.get("status")}
        if r.status_code in (401, 403):
            return {"ok": False, "abort": True,
                    "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


async def _vt_get_url_report(client: httpx.AsyncClient, vt_id: str) -> dict:
    """GET /urls/{id} — full URL report (categories, votes, dates, etc.)."""
    api = f"{API_BASE}/urls/{vt_id}"
    try:
        r = await client.get(api, headers=_headers())
        if r.status_code == 200:
            return {"ok": True, "data": r.json()["data"]}
        if r.status_code in (401, 403):
            return {"ok": False, "abort": True,
                    "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ═══════════════════════════ DB layer ═══════════════════════════

def _select_pending_batch(conn, limit: int) -> list[dict]:
    sql = """
        SELECT v.url_sha256, p.url, v.fetch_attempts
        FROM vt_url_reports v
        JOIN phishing_urls p USING (url_sha256)
        WHERE v.fetch_status IN ('pending', 'failed')
          AND v.analysis_id IS NULL
          AND v.fetch_attempts < %s
        ORDER BY v.fetch_attempts ASC, v.ingested_at ASC
        LIMIT %s
    """
    with conn.cursor() as cur:
        cur.execute(sql, (MAX_ATTEMPTS, limit))
        cols = [c.name for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def _select_submitted_batch(conn, limit: int) -> list[dict]:
    sql = """
        SELECT v.url_sha256, v.vt_id, v.analysis_id, v.fetch_attempts, v.last_fetched_at
        FROM vt_url_reports v
        WHERE v.fetch_status IN ('submitted', 'failed')
          AND v.analysis_id IS NOT NULL
          AND v.fetch_attempts < %s
        ORDER BY v.last_fetched_at ASC NULLS FIRST
        LIMIT %s
    """
    with conn.cursor() as cur:
        cur.execute(sql, (MAX_ATTEMPTS, limit))
        cols = [c.name for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def _apply_post_result(conn, result: dict, counts: dict) -> None:
    sha = result["row"]["url_sha256"]
    if result.get("ok"):
        sql = """
            UPDATE vt_url_reports
            SET fetch_status   = 'submitted',
                vt_id          = COALESCE(%s, vt_id),
                analysis_id    = %s,
                fetch_attempts = 0,
                last_fetched_at = now(),
                last_error     = NULL
            WHERE url_sha256 = %s
        """
        with conn.cursor() as cur:
            cur.execute(sql, (result.get("vt_id"), result["analysis_id"], sha))
        counts["submitted"] += 1
    else:
        sql = """
            UPDATE vt_url_reports
            SET fetch_status   = 'failed',
                fetch_attempts = fetch_attempts + 1,
                last_fetched_at = now(),
                last_error     = %s
            WHERE url_sha256 = %s
        """
        with conn.cursor() as cur:
            cur.execute(sql, (result["error"][:1000], sha))
        counts["failed_post"] += 1
    conn.commit()


def _apply_poll_result(conn, result: dict, counts: dict) -> None:
    sha = result["row"]["url_sha256"]

    # Timeout: clear analysis_id so next tick re-POSTs from scratch
    if result.get("timeout"):
        sql = """
            UPDATE vt_url_reports
            SET fetch_status   = 'failed',
                analysis_id    = NULL,
                fetch_attempts = fetch_attempts + 1,
                last_fetched_at = now(),
                last_error     = %s
            WHERE url_sha256 = %s
        """
        with conn.cursor() as cur:
            cur.execute(sql, (result["error"][:1000], sha))
        counts["timeout"] += 1
        conn.commit()
        return

    # Network/HTTP failure
    if not result.get("ok"):
        sql = """
            UPDATE vt_url_reports
            SET fetch_status   = 'failed',
                fetch_attempts = fetch_attempts + 1,
                last_fetched_at = now(),
                last_error     = %s
            WHERE url_sha256 = %s
        """
        with conn.cursor() as cur:
            cur.execute(sql, (result["error"][:1000], sha))
        counts["failed_poll"] += 1
        conn.commit()
        return

    # Still queued/in-progress — leave last_fetched_at untouched on purpose so
    # the SUBMITTED_TIMEOUT_SEC clock still measures from POST time.
    if not result.get("completed"):
        counts["polled_pending"] += 1
        return

    # Completed with full report → done
    a = result["data"]["attributes"]
    sql = """
        UPDATE vt_url_reports SET
            fetch_status            = 'done',
            fetch_attempts          = 0,
            last_fetched_at         = now(),
            last_error              = NULL,
            analysis_id             = NULL,
            vt_id                   = %s,
            last_analysis_stats     = %s::jsonb,
            last_analysis_results   = %s::jsonb,
            categories              = %s::jsonb,
            tags                    = %s,
            threat_names            = %s,
            reputation              = %s,
            total_votes             = %s::jsonb,
            times_submitted         = %s,
            first_submission_date   = CASE WHEN %s::bigint IS NULL THEN NULL ELSE to_timestamp(%s::bigint) END,
            last_submission_date    = CASE WHEN %s::bigint IS NULL THEN NULL ELSE to_timestamp(%s::bigint) END,
            last_analysis_date      = CASE WHEN %s::bigint IS NULL THEN NULL ELSE to_timestamp(%s::bigint) END,
            last_modification_date  = CASE WHEN %s::bigint IS NULL THEN NULL ELSE to_timestamp(%s::bigint) END,
            vt_data_upserted_at     = now()
        WHERE url_sha256 = %s
    """
    fsd = a.get("first_submission_date")
    lsd = a.get("last_submission_date")
    lad = a.get("last_analysis_date")
    lmd = a.get("last_modification_date")
    with conn.cursor() as cur:
        cur.execute(sql, (
            result["data"]["id"],
            json.dumps(a.get("last_analysis_stats")),
            json.dumps(a.get("last_analysis_results")),
            json.dumps(a.get("categories")),
            a.get("tags") or [],
            a.get("threat_names") or [],
            a.get("reputation"),
            json.dumps(a.get("total_votes")),
            a.get("times_submitted"),
            fsd, fsd, lsd, lsd, lad, lad, lmd, lmd,
            sha,
        ))
    counts["done"] += 1
    conn.commit()


# ═══════════════════════════ Per-row processors ═══════════════════════════

async def _do_post(client: httpx.AsyncClient, sem: asyncio.Semaphore, row: dict) -> dict:
    async with sem:
        result = await _vt_post(client, row["url"])
        return {"row": row, **result}


async def _do_poll(client: httpx.AsyncClient, sem: asyncio.Semaphore, row: dict) -> dict:
    async with sem:
        # Pre-check timeout via row.last_fetched_at (set by POST, NOT bumped by
        # still-queued polls).
        lf = row.get("last_fetched_at")
        if lf is not None:
            age = (datetime.now(timezone.utc) - lf).total_seconds()
            if age > SUBMITTED_TIMEOUT_SEC:
                return {"row": row, "ok": False, "timeout": True,
                        "error": f"submitted age {int(age)}s > {SUBMITTED_TIMEOUT_SEC}s "
                                 f"— clearing analysis_id for re-POST"}

        ana = await _vt_get_analysis(client, row["analysis_id"])
        if not ana.get("ok"):
            return {"row": row, **ana}

        if ana.get("status") != "completed":
            return {"row": row, "ok": True, "completed": False,
                    "vt_status": ana.get("status")}

        # Completed → fetch full report
        if not row.get("vt_id"):
            row["vt_id"] = _extract_vt_id(row["analysis_id"])
        if not row.get("vt_id"):
            return {"row": row, "ok": False,
                    "error": "completed but no vt_id available to GET /urls"}

        url_resp = await _vt_get_url_report(client, row["vt_id"])
        if not url_resp.get("ok"):
            return {"row": row, **url_resp}
        return {"row": row, "ok": True, "completed": True, "data": url_resp["data"]}


# ═══════════════════════════ Phase orchestration ═══════════════════════════

async def _run_phase_1(
    client: httpx.AsyncClient,
    conn,
    sem: asyncio.Semaphore,
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

    tasks   = [_do_poll(client, sem, r) for r in rows]
    results = await asyncio.gather(*tasks)

    abort = next((r for r in results if r.get("abort")), None)
    if abort:
        print(f"  ✗ Auth/quota error mid-phase: {abort['error']}")
        return

    for r in results:
        _apply_poll_result(conn, r, counts)
    print(f"  → done={counts['done']}  still_queued={counts['polled_pending']}  "
          f"timeout={counts['timeout']}  failed={counts['failed_poll']}")


async def _run_phase_2(
    client: httpx.AsyncClient,
    conn,
    sem: asyncio.Semaphore,
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

    tasks   = [_do_post(client, sem, r) for r in rows]
    results = await asyncio.gather(*tasks)

    abort = next((r for r in results if r.get("abort")), None)
    if abort:
        print(f"  ✗ Auth/quota error mid-phase: {abort['error']}")
        return

    for r in results:
        _apply_post_result(conn, r, counts)
    print(f"  → submitted={counts['submitted']}  failed={counts['failed_post']}")


# ═══════════════════════════ Top-level entry ═══════════════════════════

async def routine_fetch_once_async() -> dict:
    counts = {
        "polled_pending": 0,
        "done":           0,
        "submitted":      0,
        "failed_post":    0,
        "failed_poll":    0,
        "timeout":        0,
    }

    print(f"=== VT fetcher tick @ {datetime.now(timezone.utc).isoformat()} ===")
    print(f"  Time budget:     {HARD_BUDGET_SEC}s")
    print(f"  Phase 1 limit:   {PHASE_1_LIMIT}")
    print(f"  Phase 2 limit:   {PHASE_2_LIMIT}")
    print(f"  Concurrency:     {CONCURRENCY}")

    deadline = time.monotonic() + HARD_BUDGET_SEC
    timeout  = httpx.Timeout(HTTP_TIMEOUT_SEC, connect=HTTP_CONNECT_TIMEOUT)
    limits   = httpx.Limits(max_connections=CONCURRENCY * 2,
                            max_keepalive_connections=CONCURRENCY * 2)

    async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
        if not await _check_quota(client):
            print("⚠ Quota threshold reached, exiting early")
            return counts

        with get_connection() as conn:
            sem = asyncio.Semaphore(CONCURRENCY)
            await _run_phase_1(client, conn, sem, deadline, counts)
            if time.monotonic() < deadline:
                await _run_phase_2(client, conn, sem, deadline, counts)
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
