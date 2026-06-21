"""VirusTotal URL reports — bootstrap + routine fetcher.

bootstrap_fetch: idempotent INSERT INTO vt_url_reports SELECT FROM phishing_urls
                 (orchestrator's --mark-stale sweep flips these to 'stale')

routine_fetch:   async pipeline that processes vt_url_reports rows in two phases:
  Phase 1: poll submitted (and failed-with-analysis_id) rows
           → GET /analyses/{id}; if completed → GET /urls/{vt_id} → done
  Phase 2: process pending (and failed-without-analysis_id) rows
           → POST /urls → submitted (vt_id + analysis_id saved)

Concurrency: asyncio.Semaphore(10) over httpx.AsyncClient → ~20 req/s
sustained (latency-bound, not API-throttle-bound; verified empirically up to
100 r/s targets without any 429 from VT).

Smart retry routing on (fetch_status, analysis_id):
  pending  +   NULL       → POST          (Phase 2)
  failed   +   NULL       → POST  (retry) (Phase 2)
  submitted +  NOT NULL   → poll          (Phase 1)
  failed   +   NOT NULL   → poll  (retry) (Phase 1)

Submitted row whose analysis_id timestamp is older than SUBMITTED_TIMEOUT_SEC
is force-failed with analysis_id cleared (next cron will re-POST).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from datetime import datetime, timezone

import httpx

from src.shared.db import get_connection

# ───── tunables ─────
API_BASE                = "https://www.virustotal.com/api/v3"
CONCURRENCY             = 10
# PHASE_1_LIMIT must be > expected POST rate per cron, otherwise submitted
# backlog grows unbounded and rows time out before being polled.
PHASE_1_LIMIT           = 1000       # poll batch
# GH Actions free-tier cron is best-effort: observed ~14/day fires (median gap
# ~90 min), single gaps up to 226 min. At 400 the system can only process
# ~3k/day vs 4k/day inflow → backlog grows ~1k/day. Bumped to 800 so each run
# can both clear submitted and absorb the larger batch of accumulated pending
# from a long cron gap. Steady-state cost stays at inflow×3 ≈ 12k/day calls,
# safely under VT academic quota (20k/day); QUOTA_ABORT_RATIO=0.95 is the
# final hard stop.
PHASE_2_LIMIT           = 800        # POST batch
MAX_ATTEMPTS            = 3
# Must exceed observed cron gap so rows submitted in run N aren't falsely timed
# out before run N+1 polls them. With ~110 min real-world cron interval, 4h
# gives 2× safety margin against GH Actions cron drift.
SUBMITTED_TIMEOUT_SEC   = 4 * 60 * 60
QUOTA_ABORT_RATIO       = 0.95
HTTP_TIMEOUT_SEC        = 20.0
HTTP_CONNECT_TIMEOUT    = 10.0


# ═════════════════════ bootstrap (existing) ═════════════════════

def bootstrap_fetch(size: int | None = None) -> int:
    """Register every phishing_urls row in vt_url_reports.

    The size parameter is accepted for orchestrator signature compatibility
    but ignored — vt bootstrap is always set-based over the full phishing_urls.
    Status assignment ('pending' vs 'stale') is handled by the orchestrator's
    --mark-stale sweep, not here.

    Returns the number of rows actually inserted (excluding ON CONFLICT skips).
    """
    if size is not None:
        print(f"  Note: size={size} ignored — vt bootstrap is set-based")

    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM phishing_urls")
        (n_phish,) = cur.fetchone()
        cur.execute("SELECT count(*) FROM vt_url_reports")
        (n_vt_before,) = cur.fetchone()

        cur.execute("""
            INSERT INTO vt_url_reports (url_sha256)
            SELECT url_sha256 FROM phishing_urls
            ON CONFLICT (url_sha256) DO NOTHING
        """)
        affected = cur.rowcount

        print(f"  phishing_urls: {n_phish} rows")
        print(f"  vt_url_reports before: {n_vt_before}")
        print(f"  newly registered:      {affected}")
        return affected


# ═════════════════════ routine_fetch helpers ═════════════════════

def _api_key() -> str:
    k = os.environ.get("VIRUSTOTAL_ACADEMIC_API_KEY")
    if not k:
        raise RuntimeError(
            "VIRUSTOTAL_ACADEMIC_API_KEY not set. "
            "For local dev: export it; in CI: configure as a GitHub Secret."
        )
    return k


def _headers() -> dict:
    return {"x-apikey": _api_key()}


def _b64url(url: str) -> str:
    """VT URL identifier: base64url(url) without '=' padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _extract_vt_id(analysis_id: str) -> str | None:
    """analysis_id format 'u-<sha256_64hex>-<opaque_suffix>' — extract the sha256.

    The trailing suffix is NOT a unix timestamp (empirically: hex decodes to
    1992 for analyses created in 2026). Treat it as opaque; for "submitted age"
    use vt_url_reports.last_fetched_at instead.
    """
    parts = analysis_id.split("-")
    if len(parts) >= 3 and len(parts[1]) == 64:
        return parts[1]
    return None


# ───── async HTTP layer ─────

async def _check_quota(client: httpx.AsyncClient) -> bool:
    """Returns True if OK to proceed, False if user-daily usage > QUOTA_ABORT_RATIO."""
    url = f"{API_BASE}/users/{_api_key()}/overall_quotas"
    try:
        r = await client.get(url, headers=_headers(), timeout=10)
        r.raise_for_status()
        d = r.json()["data"]
        used    = d["api_requests_daily"]["user"]["used"]
        allowed = d["api_requests_daily"]["user"]["allowed"]
        ratio   = used / allowed if allowed else 1.0
        print(f"  Quota daily (user): {used}/{allowed} ({ratio*100:.1f}%)")
        if ratio >= QUOTA_ABORT_RATIO:
            return False
        return True
    except Exception as e:
        print(f"  Quota check failed (proceeding anyway): {e}")
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
            return {"ok": False, "abort": True, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
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
            return {"ok": False, "abort": True, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
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
            return {"ok": False, "abort": True, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


# ───── per-row processors (async, semaphore-gated) ─────

async def _do_post(client: httpx.AsyncClient, sem: asyncio.Semaphore, row: dict) -> dict:
    async with sem:
        result = await _vt_post(client, row["url"])
        return {"row": row, "phase": "post", **result}


async def _do_poll(client: httpx.AsyncClient, sem: asyncio.Semaphore, row: dict) -> dict:
    async with sem:
        # Pre-check timeout using row.last_fetched_at (set by POST, NOT bumped by still-queued polls)
        lf = row.get("last_fetched_at")
        if lf is not None:
            age = (datetime.now(timezone.utc) - lf).total_seconds()
            if age > SUBMITTED_TIMEOUT_SEC:
                return {"row": row, "phase": "poll", "ok": False, "timeout": True,
                        "error": f"submitted age {int(age)}s > {SUBMITTED_TIMEOUT_SEC}s — clearing analysis_id for re-POST"}

        ana = await _vt_get_analysis(client, row["analysis_id"])
        if not ana.get("ok"):
            return {"row": row, "phase": "poll", **ana}

        if ana.get("status") != "completed":
            return {"row": row, "phase": "poll", "ok": True, "completed": False, "vt_status": ana.get("status")}

        # Completed → fetch full report
        if not row.get("vt_id"):
            # vt_id was unknown when we POSTed (parse failed?). Try extract again.
            row["vt_id"] = _extract_vt_id(row["analysis_id"])
        if not row.get("vt_id"):
            return {"row": row, "phase": "poll", "ok": False,
                    "error": "completed but no vt_id available to GET /urls"}

        url_resp = await _vt_get_url_report(client, row["vt_id"])
        if not url_resp.get("ok"):
            return {"row": row, "phase": "url", **url_resp}
        return {"row": row, "phase": "url", "ok": True, "completed": True, "data": url_resp["data"]}


# ───── DB sync ops (run inside async context but block briefly) ─────

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
        # Successful POST → submitted, reset attempts (polling has its own budget)
        sql = """
            UPDATE vt_url_reports
            SET fetch_status = 'submitted',
                vt_id        = COALESCE(%s, vt_id),
                analysis_id  = %s,
                fetch_attempts = 0,
                last_fetched_at = now(),
                last_error   = NULL
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

    # Timeout: clear analysis_id so next cron re-POSTs from scratch
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

    # Still queued/in-progress — leave last_fetched_at untouched on purpose,
    # so the SUBMITTED_TIMEOUT_SEC clock still measures from POST time, not last poll.
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


# ───── orchestration ─────

async def _routine_fetch_async() -> dict:
    counts = {
        "polled_pending": 0,   # submitted row polled, still queued/in-progress
        "done":           0,   # transitioned to done with full report
        "submitted":      0,   # newly POSTed, awaiting analysis
        "failed_post":    0,   # POST stage failures
        "failed_poll":    0,   # poll/GET-urls stage failures
        "timeout":        0,   # analysis age > SUBMITTED_TIMEOUT_SEC
    }

    timeout = httpx.Timeout(HTTP_TIMEOUT_SEC, connect=HTTP_CONNECT_TIMEOUT)
    limits  = httpx.Limits(max_connections=CONCURRENCY * 2,
                           max_keepalive_connections=CONCURRENCY * 2)

    async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
        if not await _check_quota(client):
            print("⚠ Quota threshold reached, exiting early")
            return counts

        with get_connection() as conn:
            sem = asyncio.Semaphore(CONCURRENCY)

            # ───── Phase 1: poll submitted (and failed-with-analysis_id) ─────
            poll_rows = _select_submitted_batch(conn, PHASE_1_LIMIT)
            print(f"\nPhase 1: polling {len(poll_rows)} submitted/retry rows")
            if poll_rows:
                tasks   = [_do_poll(client, sem, r) for r in poll_rows]
                results = await asyncio.gather(*tasks)
                for r in results:
                    if r.get("abort"):
                        print(f"⚠ Auth/quota error mid-phase, aborting: {r['error']}")
                        return counts
                for r in results:
                    _apply_poll_result(conn, r, counts)
                print(f"  → done={counts['done']}  polled_pending={counts['polled_pending']}  "
                      f"failed_poll={counts['failed_poll']}  timeout={counts['timeout']}")

            # ───── Phase 2: POST pending (and failed-without-analysis_id) ─────
            post_rows = _select_pending_batch(conn, PHASE_2_LIMIT)
            print(f"\nPhase 2: POSTing {len(post_rows)} pending/retry rows")
            if post_rows:
                tasks   = [_do_post(client, sem, r) for r in post_rows]
                results = await asyncio.gather(*tasks)
                for r in results:
                    if r.get("abort"):
                        print(f"⚠ Auth/quota error mid-phase, aborting: {r['error']}")
                        return counts
                for r in results:
                    _apply_post_result(conn, r, counts)
                print(f"  → submitted={counts['submitted']}  failed_post={counts['failed_post']}")

    return counts


def routine_fetch() -> dict:
    print(f"=== VT routine_fetch started at {datetime.now(timezone.utc).isoformat()} ===")
    t0 = time.time()
    counts = asyncio.run(_routine_fetch_async())
    elapsed = time.time() - t0
    print(f"\n=== Summary ({elapsed:.1f}s) ===")
    for k, v in counts.items():
        print(f"  {k:18}  {v}")
    return counts


if __name__ == "__main__":
    routine_fetch()
