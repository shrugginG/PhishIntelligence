-- 0002_raw_phishunt.sql
--
-- Experimental ingestion of phishunt.io as a 6th raw source, in OBSERVATION
-- mode. Source: https://phishunt.io/feed.json — a rolling set of currently
-- "active" suspicious phishing sites, re-checked every 6h, refreshed hourly.
--
-- DELIBERATELY ISOLATED: unlike the other 5 raw_* tables, raw_phishunt has NO
-- propagation trigger into phishing_urls. Writes here do NOT cascade into the
-- phishing_urls / vt_url_reports / urlscan_url_scans pipeline. The goal is to
-- accumulate a few days of data and measure phishunt's true net-new URL
-- contribution before deciding whether to promote it to a real source.
--
-- Write semantics: UPSERT on uuid (phishunt's stable per-entry id). Each fetch
-- pulls the full active set and refreshes the re-check fields + observation
-- instruments (last_seen_at, fetch_count). first_seen / url / ingested_at are
-- immutable after first capture.

CREATE TABLE raw_phishunt (
  uuid                 UUID        PRIMARY KEY,
  url                  TEXT        NOT NULL,
  url_sha256           TEXT        NOT NULL CHECK (length(url_sha256) = 64),
  domain               TEXT,
  company              TEXT,                          -- targeted brand slug

  -- hosting enrichment (100% filled in sampling)
  ip                   INET,
  country              TEXT,                          -- full country name (no ISO code from source)
  asn                  TEXT,                          -- bare AS number string, e.g. "15169"
  org                  TEXT,
  cert                 TEXT,                          -- TLS certificate issuer

  -- detection verdicts (5 upstream sources)
  malicious_google     BOOLEAN,
  malicious_openphish  BOOLEAN,
  malicious_phishtank  BOOLEAN,
  malicious_tweetfeed  BOOLEAN,
  malicious_urlscan    BOOLEAN,

  -- phishunt times
  first_seen           TIMESTAMPTZ,                   -- phishunt discovery time (stable per entry)
  source_date          TIMESTAMPTZ,                   -- phishunt 'date' = feed batch re-check stamp

  -- repo meta + observation instruments
  raw_payload          JSONB       NOT NULL,
  ingested_at          TIMESTAMPTZ NOT NULL DEFAULT now(),   -- when WE first captured it (immutable)
  last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),   -- last fetch this entry was still active
  fetch_count          INTEGER     NOT NULL DEFAULT 1,       -- how many of our fetches saw it

  -- derived: cross-source ASN join (matches raw_openphish_academic / raw_phishstats)
  asn_number           INTEGER GENERATED ALWAYS AS (
    CASE
      WHEN asn ~ '^AS\d+$' THEN substring(asn FROM 3)::int
      WHEN asn ~ '^\d+$'   THEN asn::int
      ELSE NULL
    END
  ) STORED
);

CREATE INDEX ix_raw_phishunt_url_sha256  ON raw_phishunt (url_sha256);
CREATE INDEX ix_raw_phishunt_first_seen  ON raw_phishunt (first_seen DESC);
CREATE INDEX ix_raw_phishunt_ingested_at ON raw_phishunt (ingested_at DESC);
CREATE INDEX ix_raw_phishunt_last_seen   ON raw_phishunt (last_seen_at DESC);
CREATE INDEX ix_raw_phishunt_company     ON raw_phishunt (company);
CREATE INDEX ix_raw_phishunt_asn_number  ON raw_phishunt (asn_number);

-- NOTE: intentionally NO `CREATE TRIGGER ... propagate` here. raw_phishunt is
-- observed in isolation until we decide to integrate it.
