-- 0005_reference_tranco.sql
--
-- Second `reference` source: Tranco (https://tranco-list.eu/) — a research-
-- oriented, manipulation-hardened top-sites ranking, updated daily by 0:00 UTC.
-- A strong benign-domain prior for downstream phishing-URL allowlisting.
--
-- Strategy A (current-mirror) + cold Storage archive, NO history kept in PG:
--   HOT  reference.tranco_top1m  — current-only mirror of the latest top-1M,
--        holding BOTH granularities (default pay-level-domain list + the
--        with-subdomains list) via a `subdomains` discriminator. Refreshed by
--        TRUNCATE+COPY each sync → the whole table IS the latest list, so there
--        is NO `current` flag and no historical rows (zero bloat).
--   COLD Supabase Storage bucket `tranco-archive` — every day's raw .csv.zip,
--        immutable, keyed by date+list_id. Lossless history, re-importable on
--        demand (this is where "Strategy B" can always be reconstructed from).
--   reference.tranco_archive — tiny manifest: one row per archived day/granularity,
--        the queryable catalog of what's in cold storage + provenance.
--
-- Idempotency key = Tranco's permanent list_id (from /top-1m-id). Tranco updates
-- once/day; the fetcher may tick 3x/day, so a run whose list_ids are already in
-- tranco_archive is a no-op.
--
-- NAS-only apply (cloud not built), same as the other reference/observation migrations.

-- ──────────────────────────────────────────────────────────────────────────
-- HOT: current-only top-1M mirror (both granularities)
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE reference.tranco_top1m (
  subdomains  BOOLEAN NOT NULL,        -- false = default pay-level-domain list, true = with-subdomains list
  domain      TEXT    NOT NULL,
  rank        INTEGER NOT NULL,
  PRIMARY KEY (subdomains, domain)
);

-- cross-granularity lookup by domain (whitelist point query: "is X listed, at what rank")
CREATE INDEX ix_tranco_top1m_domain ON reference.tranco_top1m (domain);
-- per-granularity top-N / ordered scans
CREATE INDEX ix_tranco_top1m_rank   ON reference.tranco_top1m (subdomains, rank);

-- ──────────────────────────────────────────────────────────────────────────
-- MANIFEST: catalog of cold-archived daily lists (one row per day × granularity)
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE reference.tranco_archive (
  list_id       TEXT        PRIMARY KEY,   -- Tranco permanent list ID (idempotency key)
  list_date     DATE        NOT NULL,      -- derived from the file's Last-Modified header
  subdomains    BOOLEAN     NOT NULL,
  row_count     INTEGER,
  sha256        TEXT,                      -- of the raw zip bytes (integrity / dedup)
  object_path   TEXT        NOT NULL,      -- path within the tranco-archive bucket
  last_modified TIMESTAMPTZ,               -- upstream Last-Modified header
  fetched_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- "what's the latest archived list per granularity" + date-range browsing.
-- NOT unique on (list_date, subdomains): if Tranco ever re-issues a same-date
-- list with a new ID, we keep both rows faithfully rather than hard-failing.
CREATE INDEX ix_tranco_archive_date ON reference.tranco_archive (list_date DESC, subdomains);
