-- 0006_reference_crux.sql
--
-- Third `reference` source: CrUX (Chrome User Experience Report) top-1M, via the
-- caching repo https://github.com/zakird/crux-top-lists (monthly snapshots pulled
-- from Google BigQuery `chrome-ux-report.experimental.*`). A strong benign-domain
-- prior based on REAL Chrome user traffic (Google releases monthly, 2nd Tuesday).
--
-- Same Strategy A (current-mirror) + cold Storage archive as Tranco, with the
-- global/country split decided per the project's needs:
--   HOT  reference.crux_top1m  — current-only mirror of the latest GLOBAL top-1M
--        ONLY (~1M rows). Country lists are NOT loaded into PG (238 countries ≈
--        22M rows would bloat the shared instance and have low whitelist value).
--        Refreshed by TRUNCATE+COPY → the table IS the latest global list.
--   COLD Supabase Storage bucket `crux-top-archive` — mirrors the repo's data/
--        tree verbatim (top-level data/ → bucket):
--          global/<YYYYMM>.csv.gz           ← data/global/<YYYYMM>.csv.gz
--          country/<cc>/<YYYYMM>.csv.gz     ← data/country/<cc>/<YYYYMM>.csv.gz
--        BOTH global and all 238 countries are archived (lossless, re-importable).
--   reference.crux_archive — manifest: one row per (scope, month) archived.
--
-- Data shape (verified): CSV `origin,rank` with header. `origin` is a full origin
-- WITH scheme (https://news.google.com), host-level (incl www/subdomains), unique
-- per list. `rank` is the CrUX bucket ceiling — only 7 discrete values in top-1M:
-- 1000 / 5000 / 10000 / 50000 / 100000 / 500000 / 1000000 (intra-bucket order is
-- arbitrary). Stored as-is (no host/PLD/scheme derivation — that's downstream).
--
-- Idempotency key = (scope, yyyymm); CrUX monthly data is immutable. Daily cadence,
-- but real work only when a new month appears (most days are a no-op).
--
-- NAS-only apply, same as the other reference/observation migrations.

-- ──────────────────────────────────────────────────────────────────────────
-- HOT: current-only GLOBAL top-1M mirror
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE reference.crux_top1m (
  origin  TEXT    PRIMARY KEY,    -- full origin with scheme, e.g. https://news.google.com
  rank    INTEGER NOT NULL        -- CrUX bucket: 1000/5000/10000/50000/100000/500000/1000000
);

-- bucket-tier scans ("all origins in the top-1k bucket")
CREATE INDEX ix_crux_top1m_rank ON reference.crux_top1m (rank);

-- ──────────────────────────────────────────────────────────────────────────
-- MANIFEST: cold-archive catalog (global + all 238 countries, per month)
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE reference.crux_archive (
  scope        TEXT    NOT NULL,    -- 'global' or lowercase ISO country code 'us'/'de'/...
  yyyymm       INTEGER NOT NULL,    -- 202605
  row_count    INTEGER,
  sha256       TEXT,                -- of the raw .csv.gz bytes
  source_size  BIGINT,             -- raw .csv.gz byte size
  object_path  TEXT    NOT NULL,    -- path within the crux-top-archive bucket
  fetched_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, yyyymm)       -- idempotency key (monthly data is immutable)
);

-- "all scopes archived for month M" / latest-month browsing
CREATE INDEX ix_crux_archive_month ON reference.crux_archive (yyyymm DESC);
