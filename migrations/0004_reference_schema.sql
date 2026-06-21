-- 0004_reference_schema.sql
--
-- Introduces the `reference` schema: a namespace for domain/URL *reference
-- lists* (rankings, categorized domain catalogs) used downstream to build
-- benign-domain allowlists for filtering phishing URLs. Kept separate from the
-- phishing pipeline in `public` (no triggers, no FK), but in the SAME database
-- so it stays JOIN-able with public.phishing_urls for filtering.
--
-- First member: v2fly/domain-list-community (https://github.com/v2fly/domain-list-community)
-- — the community geosite source used by V2Ray routing. We ingest the RAW
-- source `data/` directory (NOT the compiled dlc.dat), preserving the include
-- graph, attributes, affiliations and inline comments. Resolution / allowlist
-- curation is deliberately deferred to downstream workflows.
--
-- The two main tables mirror the upstream parser's own data model
-- (ParsedList { Entries[], Inclusions[] }, see main.go):
--   v2fly_domain_rules  ← Entries     (domain/full/keyword/regexp)
--   v2fly_list_includes ← Inclusions  (the list→list inclusion graph)
--   v2fly_sync_runs     ← ingestion provenance / churn audit
--
-- Refresh semantics: snapshot + last_seen (same model as raw_phishunt). Each
-- sync pulls a commit-pinned snapshot, UPSERTs the full set, bumps last_seen_at
-- / sync_count / source_commit. Rows that drop out of upstream are NOT deleted;
-- their source_commit stops advancing (→ "vanished upstream", detectable).

CREATE SCHEMA IF NOT EXISTS reference;


-- ──────────────────────────────────────────────────────────────────────────
-- v2fly_domain_rules — one row per source domain rule (Entries)
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE reference.v2fly_domain_rules (
  rule_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

  list_name      TEXT    NOT NULL,                  -- on-disk filename (lowercase) = geosite name
  rule_type      TEXT    NOT NULL
                         CHECK (rule_type IN ('domain', 'full', 'keyword', 'regexp')),
  value          TEXT    NOT NULL,                  -- domain/full/keyword lowercased; regexp case-preserved
  attributes     TEXT[]  NOT NULL DEFAULT '{}',     -- @attrs, SORTED (mirrors parser); vocab cn/ads/!cn/...
  affiliations   TEXT[]  NOT NULL DEFAULT '{}',     -- &targets (0 usage upstream today; kept for fidelity)
  source_comment TEXT,                              -- trailing inline `# ...` comment (punycode gloss / geo note)
  raw_line       TEXT    NOT NULL,                  -- comment-stripped, trimmed logical line (forensic)

  -- snapshot provenance (same instruments as raw_phishunt)
  source_commit  TEXT    NOT NULL,                  -- git sha this row was last seen in
  first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sync_count     INTEGER NOT NULL DEFAULT 1,

  -- matches the parser's per-list dedup key (type:value:@sorted_attrs)
  UNIQUE (list_name, rule_type, value, attributes)
);

CREATE INDEX ix_v2fly_rules_value     ON reference.v2fly_domain_rules (value);
CREATE INDEX ix_v2fly_rules_list      ON reference.v2fly_domain_rules (list_name);
CREATE INDEX ix_v2fly_rules_type      ON reference.v2fly_domain_rules (rule_type);
CREATE INDEX ix_v2fly_rules_attrs_gin ON reference.v2fly_domain_rules USING GIN (attributes);
CREATE INDEX ix_v2fly_rules_last_seen ON reference.v2fly_domain_rules (last_seen_at DESC);


-- ──────────────────────────────────────────────────────────────────────────
-- v2fly_list_includes — the list→list inclusion graph (Inclusions)
-- `include:listb @attr @-attr2` in file lista becomes one edge with optional
-- must/ban attribute filters. NOT resolved here; downstream walks the graph.
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE reference.v2fly_list_includes (
  include_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

  list_name      TEXT    NOT NULL,                  -- including list (file)
  included_list  TEXT    NOT NULL,                  -- referenced list name (lowercase as written)
  must_attrs     TEXT[]  NOT NULL DEFAULT '{}',     -- include:x @attr   → only entries WITH these attrs
  ban_attrs      TEXT[]  NOT NULL DEFAULT '{}',     -- include:x @-attr  → exclude entries WITH these attrs
  source_comment TEXT,
  raw_line       TEXT    NOT NULL,

  source_commit  TEXT    NOT NULL,
  first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  sync_count     INTEGER NOT NULL DEFAULT 1,

  UNIQUE (list_name, included_list, must_attrs, ban_attrs)
);

CREATE INDEX ix_v2fly_inc_list     ON reference.v2fly_list_includes (list_name);
CREATE INDEX ix_v2fly_inc_included ON reference.v2fly_list_includes (included_list);


-- ──────────────────────────────────────────────────────────────────────────
-- v2fly_sync_runs — one row per fetch; provenance + churn metrics
-- ──────────────────────────────────────────────────────────────────────────
CREATE TABLE reference.v2fly_sync_runs (
  run_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  source_commit   TEXT    NOT NULL,
  repo_ref        TEXT    NOT NULL DEFAULT 'master',
  file_count      INTEGER,
  rule_rows       INTEGER,           -- domain rules parsed from this snapshot
  include_rows    INTEGER,           -- include edges parsed from this snapshot
  rules_inserted  INTEGER,           -- net-new rule rows this run
  rules_refreshed INTEGER,           -- existing rule rows whose last_seen bumped
  rules_vanished  INTEGER,           -- rows in DB no longer in upstream (source_commit <> current)
  parse_errors    INTEGER NOT NULL DEFAULT 0,
  started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at     TIMESTAMPTZ,
  status          TEXT    NOT NULL DEFAULT 'running'
                          CHECK (status IN ('running', 'done', 'failed'))
);

CREATE INDEX ix_v2fly_sync_runs_started ON reference.v2fly_sync_runs (started_at DESC);
