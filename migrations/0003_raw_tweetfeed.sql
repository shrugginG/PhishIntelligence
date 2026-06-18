-- 0003_raw_tweetfeed.sql
--
-- Experimental ingestion of tweetfeed.live as a 7th raw source, in OBSERVATION
-- mode. Source: https://api.tweetfeed.live/v1/{time}/url — community IOCs shared
-- on Twitter/X, scraped from ~95 RSS feeds, deduped + republished every 15 min.
--
-- We store ONLY type=url, and DELIBERATELY do NOT filter by tag: ~49% of url
-- IOCs carry no tag at all, so tag-filtering would discard half the URLs. We
-- keep all url entries + their tags, and filter at decision/query time (e.g.
-- `WHERE tags && '{phishing,scam}'` or `WHERE NOT tags && '{kimsuky,dprk,c2}'`).
--
-- DELIBERATELY ISOLATED: like raw_phishunt, NO propagation trigger into
-- phishing_urls — writes stay out of the vt/urlscan pipeline until we decide.
--
-- url_sha256 PK; a single URL may be tweeted by multiple users, and a single
-- user may tweet the same URL multiple times (1:N). So provenance is stored as
-- `reporters JSONB` = {user: [tweet_url, ...]} — keyed by reporter, value is the
-- list of that reporter's tweets about this URL. Merged across sightings by
-- deep JSONB union. The exact per-sighting (date,user,tags,tweet) tuples are
-- preserved losslessly in raw_payload (array of entries).

CREATE TABLE raw_tweetfeed (
  url_sha256        TEXT        PRIMARY KEY CHECK (length(url_sha256) = 64),
  url               TEXT        NOT NULL,

  -- provenance: {user: [tweet_url, ...]} (who reported this URL via which tweets)
  reporters         JSONB       NOT NULL DEFAULT '{}'::jsonb,

  -- tags: union across sightings (normalized: lowercase, no '#')
  tags              TEXT[]      NOT NULL DEFAULT '{}',

  -- source times (aggregated over per-sighting `date`)
  first_seen        TIMESTAMPTZ,                         -- min(date): earliest community report
  last_reported_at  TIMESTAMPTZ,                         -- max(date): most recent report

  -- lossless backstop + observation instrument
  raw_payload       JSONB       NOT NULL,                -- array of original entries (keeps per-sighting tuples)
  ingested_at       TIMESTAMPTZ NOT NULL DEFAULT now()   -- when WE first captured it (immutable)
);

CREATE INDEX ix_raw_tweetfeed_first_seen  ON raw_tweetfeed (first_seen DESC);
CREATE INDEX ix_raw_tweetfeed_ingested_at ON raw_tweetfeed (ingested_at DESC);
CREATE INDEX ix_raw_tweetfeed_tags        ON raw_tweetfeed USING GIN (tags);
CREATE INDEX ix_raw_tweetfeed_reporters   ON raw_tweetfeed USING GIN (reporters);  -- reporters ? 'user'

-- NOTE: intentionally NO `CREATE TRIGGER ... propagate`. raw_tweetfeed is
-- observed in isolation until we decide whether/how to promote it.
