"""tweetfeed.live fetcher (OBSERVATION mode).

Source: https://api.tweetfeed.live/v1/{time}/url — community IOCs shared on
Twitter/X (scraped from ~95 RSS feeds, deduped + republished every 15 min).
No auth. We store ONLY type=url and do NOT filter by tag (49% of url IOCs are
untagged; tag-filtering would drop half). Tags are kept for decision-time
filtering.

raw_tweetfeed has NO propagation trigger into phishing_urls — isolated.

Write model: url_sha256 PK. Provenance is {user: [tweet, ...]} (reporters
JSONB) — a URL may be tweeted by N users, and a user may tweet the same URL N
times (1:N), so each reporter key maps to a list of their tweets. tags is a
deduped TEXT[]. Accumulated across sightings: two-level merge — pre-aggregate
the batch by url_sha256 in Python, then SQL deep-merge (per-reporter tweet
union) on conflict. raw_payload keeps the lossless per-sighting tuples.

Incremental: routine uses the `since/{ISO8601}` endpoint anchored on
MAX(last_reported_at); bootstrap pulls a month window.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import httpx

from src.shared.db import get_connection

API_BASE = "https://api.tweetfeed.live/v1"


def _fetch_window(window: str) -> list[dict]:
    """Pull type=url IOCs for a time window (today/week/month/year)."""
    url = f"{API_BASE}/{window}/url"
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        data = resp.json()
    records = data if isinstance(data, list) else []
    print(f"  Fetched {len(records)} url IOCs from /{window}/url")
    return records


def _fetch_since(iso_ts: str) -> list[dict]:
    """Pull type=url IOCs added after an ISO 8601 timestamp (incremental)."""
    url = f"{API_BASE}/since/{iso_ts}/url"
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        resp = client.get(url)
        # 410 Gone = anchor older than 365 days; caller should fall back to a window
        if resp.status_code == 410:
            print("  since anchor >365d old (410 Gone); fall back to month window")
            return _fetch_window("month")
        resp.raise_for_status()
        data = resp.json()
    records = data if isinstance(data, list) else []
    print(f"  Fetched {len(records)} url IOCs from /since/{iso_ts}/url")
    return records


def _norm_tag(t: str) -> str:
    return t.lstrip("#").strip().lower()


def _pg_array(items: list[str]) -> str:
    """Render a Postgres array literal. Passing bare empty Python lists to
    psycopg3 can adapt to NULL (type unknown when the row is the only one in a
    batch); a literal string with a ::text[] cast is deterministic: '{}' → empty
    array, never NULL."""
    if not items:
        return "{}"
    esc = []
    for s in items:
        s = s.replace("\\", "\\\\").replace('"', '\\"')
        esc.append(f'"{s}"')
    return "{" + ",".join(esc) + "}"


def _aggregate(records: list[dict]) -> list[tuple]:
    """Group a batch by url_sha256, merging provenance into a
    {user: [tweet, ...]} dict + tags into a deduped set, and aggregating dates.
    Returns rows ready for UPSERT."""
    by_url: dict[str, dict] = {}
    for r in records:
        url = r.get("value")
        if not url:
            continue
        h = hashlib.sha256(url.encode()).hexdigest()
        date = r.get("date")
        slot = by_url.get(h)
        if slot is None:
            slot = by_url[h] = {
                "url": url,
                "tags": set(),
                "reporters": {},   # user -> set(tweet_url)
                "dates": [],
                "payload": [],
                "seen": set(),     # tweet-dedup for payload
            }
        for t in r.get("tags", []) or []:
            nt = _norm_tag(t)
            if nt:
                slot["tags"].add(nt)
        user = r.get("user")
        tweet = r.get("tweet")
        # provenance: key by reporter; a user with no tweet still gets a key
        rkey = user or "_unknown"
        bucket = slot["reporters"].setdefault(rkey, set())
        if tweet:
            bucket.add(tweet)
        if date:
            slot["dates"].append(date)
        # dedup payload by tweet so len(raw_payload) == total distinct tweets;
        # the source feed can list the same (url, tweet) pair more than once.
        key = tweet if tweet else f"__notweet_{len(slot['payload'])}"
        if key not in slot["seen"]:
            slot["seen"].add(key)
            slot["payload"].append(r)

    rows = []
    for h, s in by_url.items():
        dates = sorted(s["dates"])
        reporters = {u: sorted(tws) for u, tws in s["reporters"].items()}
        rows.append(
            (
                h,
                s["url"],
                json.dumps(reporters, ensure_ascii=False),
                _pg_array(sorted(s["tags"])),
                dates[0] if dates else None,   # first_seen = min(date)
                dates[-1] if dates else None,  # last_reported_at = max(date)
                json.dumps(s["payload"], ensure_ascii=False),
            )
        )
    return rows


def _upsert(records: list[dict]) -> int:
    rows = _aggregate(records)
    if not rows:
        return 0

    sql = """
        INSERT INTO raw_tweetfeed (
            url_sha256, url, reporters, tags,
            first_seen, last_reported_at, raw_payload
        ) VALUES (
            %s, %s, %s::jsonb, %s::text[],
            %s::timestamptz, %s::timestamptz, %s::jsonb
        )
        ON CONFLICT (url_sha256) DO UPDATE SET
            -- deep-merge {user: [tweets]}: union the tweet arrays per reporter
            -- across all keys present in either the existing or incoming row.
            reporters        = COALESCE((
                                 SELECT jsonb_object_agg(k, COALESCE(
                                          (SELECT jsonb_agg(DISTINCT e)
                                           FROM jsonb_array_elements(
                                                  COALESCE(raw_tweetfeed.reporters -> k, '[]'::jsonb)
                                               || COALESCE(EXCLUDED.reporters     -> k, '[]'::jsonb)) e),
                                          '[]'::jsonb))
                                 FROM jsonb_object_keys(raw_tweetfeed.reporters || EXCLUDED.reporters) AS k
                               ), '{}'::jsonb),
            -- COALESCE: array_agg over an empty unnest returns NULL, not '{}';
            -- a no-tag URL (empty old+new tags) would otherwise violate NOT NULL.
            tags             = COALESCE((SELECT array_agg(DISTINCT t) FROM unnest(raw_tweetfeed.tags || EXCLUDED.tags) t), '{}'),
            first_seen       = LEAST(raw_tweetfeed.first_seen, EXCLUDED.first_seen),
            last_reported_at = GREATEST(raw_tweetfeed.last_reported_at, EXCLUDED.last_reported_at),
            -- idempotent: the `since` anchor is inclusive, so a boundary record
            -- re-arrives each tick. Append only entries whose tweet isn't yet
            -- recorded (flatten existing tweets out of reporters), so
            -- re-fetching the same tweet doesn't bloat raw_payload.
            raw_payload      = raw_tweetfeed.raw_payload || COALESCE(
                                 (SELECT jsonb_agg(e)
                                  FROM jsonb_array_elements(EXCLUDED.raw_payload) e
                                  WHERE (e->>'tweet') IS NULL
                                     OR (e->>'tweet') NOT IN (
                                          SELECT jsonb_array_elements_text(v)
                                          FROM jsonb_each(raw_tweetfeed.reporters) AS r(k, v))),
                                 '[]'::jsonb)
    """

    with get_connection() as conn, conn.cursor() as cur:
        cur.executemany(sql, rows)
        return len(rows)


def _get_anchor() -> str | None:
    """MAX(last_reported_at) as ISO 8601 Z string, or None if table empty."""
    with get_connection() as conn, conn.cursor() as cur:
        cur.execute("SELECT MAX(last_reported_at) FROM raw_tweetfeed")
        (ts,) = cur.fetchone()
    if ts is None:
        return None
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def routine_fetch() -> int:
    """Incremental: pull /since/{anchor}/url. Empty table → seed with month."""
    anchor = _get_anchor()
    if anchor is None:
        print("  Empty table; seeding with month window")
        records = _fetch_window("month")
    else:
        print(f"  Anchor: since {anchor}")
        records = _fetch_since(anchor)
    affected = _upsert(records)
    print(f"  Upserted {affected} unique URLs")
    return affected


def bootstrap_fetch(size: int | None = None) -> int:
    """Pull the month window of url IOCs. `size` accepted for signature parity
    (slices the pull if provided)."""
    records = _fetch_window("month")
    if size is not None:
        records = records[:size]
    affected = _upsert(records)
    print(f"  Upserted {affected} unique URLs")
    return affected


if __name__ == "__main__":
    affected = routine_fetch()
    print(f"\n=== tweetfeed routine_fetch done: {affected} unique URLs ===")
