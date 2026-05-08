-- ============================================================
-- PhishIntelligence schema — migrated from cloud Supabase
-- Source: project ptkgclhdngmalfjzioqy (us-west-1) as of 2026-05-08
-- Target: self-hosted Supabase on NAS (Postgres 15.8)
-- Build order: tables (no-FK first) → indexes → functions → triggers → publication
-- ============================================================

BEGIN;

-- ============================================================
-- SECTION 1: Tables (5 raw_* with no FK first)
-- ============================================================

-- 1.1 raw_phishtank
CREATE TABLE public.raw_phishtank (
    phish_id          BIGINT      PRIMARY KEY,
    url               TEXT        NOT NULL,
    url_sha256        TEXT        NOT NULL CHECK (length(url_sha256) = 64),
    submission_time   TIMESTAMPTZ NOT NULL,
    verification_time TIMESTAMPTZ NOT NULL,
    target            TEXT,
    details           JSONB       NOT NULL DEFAULT '[]'::jsonb,
    raw_payload       JSONB       NOT NULL,
    ingested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    phish_detail_url  TEXT        GENERATED ALWAYS AS (
        'http://www.phishtank.com/phish_detail.php?phish_id=' || phish_id::text
    ) STORED
);

-- 1.2 raw_openphish_academic
CREATE TABLE public.raw_openphish_academic (
    url_sha256         TEXT        PRIMARY KEY CHECK (length(url_sha256) = 64),
    url                TEXT        NOT NULL,
    brand              TEXT,
    ip                 INET,
    asn                TEXT,
    asn_name           TEXT,
    country_code       CHAR(2),
    country_name       TEXT,
    tld                TEXT,
    discover_time      TIMESTAMPTZ,
    family_id          TEXT,
    host               TEXT,
    page_language      TEXT,
    ssl_cert_issued_by TEXT,
    ssl_cert_issued_to TEXT,
    ssl_cert_serial    TEXT,
    is_spear           BOOLEAN     NOT NULL DEFAULT false,
    sector             TEXT,
    raw_payload        JSONB       NOT NULL,
    ingested_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    asn_number         INTEGER     GENERATED ALWAYS AS (
        CASE
            WHEN asn ~ '^AS\d+$' THEN substring(asn FROM 3)::int
            WHEN asn ~ '^\d+$'   THEN asn::int
            ELSE NULL
        END
    ) STORED
);

-- 1.3 raw_openphish_community
CREATE TABLE public.raw_openphish_community (
    url_sha256  TEXT        PRIMARY KEY CHECK (length(url_sha256) = 64),
    url         TEXT        NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 1.4 raw_ecrimex (note: cloud has dropped columns at pos 6/10/13 from v1.0; clean schema below)
CREATE TABLE public.raw_ecrimex (
    phish_id      BIGINT      PRIMARY KEY,
    url           TEXT        NOT NULL,
    url_sha256    TEXT        NOT NULL CHECK (length(url_sha256) = 64),
    brand         TEXT        NOT NULL,
    confidence    SMALLINT    NOT NULL CHECK (confidence IN (0, 50, 90, 100)),
    ip            INET[]      NOT NULL DEFAULT '{}'::inet[],
    asn           INTEGER[]   NOT NULL DEFAULT '{}'::integer[],
    tld           TEXT,
    discovered_at TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    raw_payload   JSONB       NOT NULL,
    ingested_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 1.5 raw_phishstats
CREATE TABLE public.raw_phishstats (
    id                           BIGINT         PRIMARY KEY,
    url                          TEXT           NOT NULL,
    url_sha256                   TEXT           NOT NULL CHECK (length(url_sha256) = 64),
    redirect_url                 TEXT,
    ip                           INET,
    bgp                          CIDR,
    asn                          TEXT,
    isp                          TEXT,
    ports                        TEXT,
    http_code                    SMALLINT,
    http_server                  TEXT,
    os                           TEXT,
    technology                   TEXT,
    country_code                 CHAR(2),
    country_name                 TEXT,
    region_code                  TEXT,
    region_name                  TEXT,
    city                         TEXT,
    zipcode                      TEXT,
    latitude                     NUMERIC(10,7),
    longitude                    NUMERIC(10,7),
    host                         TEXT,
    domain                       TEXT,
    tld                          TEXT,
    title                        TEXT,
    ssl_issuer                   TEXT,
    ssl_subject                  TEXT,
    ssl_fingerprint              TEXT,
    score                        NUMERIC(4,2),
    google_safebrowsing          TEXT,
    virus_total                  TEXT,
    abuse_ch_malware             TEXT,
    vulns                        TEXT,
    tags                         TEXT,
    abuse_contact                TEXT,
    screenshot                   TEXT,
    domain_registered_n_days_ago INTEGER,
    rank_host                    BIGINT,
    rank_domain                  BIGINT,
    n_times_seen_ip              INTEGER,
    n_times_seen_host            INTEGER,
    n_times_seen_domain          INTEGER,
    discovered_at                TIMESTAMPTZ    NOT NULL,
    updated_at                   TIMESTAMPTZ,
    raw_payload                  JSONB          NOT NULL,
    ingested_at                  TIMESTAMPTZ    NOT NULL DEFAULT now(),
    asn_number                   INTEGER        GENERATED ALWAYS AS (
        CASE
            WHEN asn ~ '^AS\d+$' THEN substring(asn FROM 3)::int
            WHEN asn ~ '^\d+$'   THEN asn::int
            ELSE NULL
        END
    ) STORED
);

-- 1.6 phishing_urls (must be created before vt_url_reports / urlscan_url_scans for FK)
CREATE TABLE public.phishing_urls (
    url_sha256       TEXT        PRIMARY KEY CHECK (length(url_sha256) = 64),
    url              TEXT        NOT NULL,
    sources          TEXT[]      NOT NULL DEFAULT '{}'::text[],
    brand            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    ip               JSONB       NOT NULL DEFAULT '{}'::jsonb,
    asn              JSONB       NOT NULL DEFAULT '{}'::jsonb,
    country_code     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    discovered_at    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    ingested_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_upserted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    crawl_status     TEXT        NOT NULL DEFAULT 'pending'
                                 CHECK (crawl_status IN ('pending','running','done','failed','skipped','stale')),
    crawl_attempts   SMALLINT    NOT NULL DEFAULT 0,
    last_crawled_at  TIMESTAMPTZ
);

-- 1.7 vt_url_reports
CREATE TABLE public.vt_url_reports (
    url_sha256             TEXT        PRIMARY KEY
                                       REFERENCES public.phishing_urls(url_sha256) ON DELETE CASCADE
                                       CHECK (length(url_sha256) = 64),
    vt_id                  TEXT        CHECK (vt_id IS NULL OR length(vt_id) = 64),
    fetch_status           TEXT        NOT NULL DEFAULT 'pending'
                                       CHECK (fetch_status IN ('pending','submitted','done','not_found','failed','skipped','stale')),
    fetch_attempts         SMALLINT    NOT NULL DEFAULT 0,
    last_fetched_at        TIMESTAMPTZ,
    last_error             TEXT,
    analysis_id            TEXT,
    last_analysis_stats    JSONB,
    last_analysis_results  JSONB,
    categories             JSONB,
    tags                   TEXT[]      NOT NULL DEFAULT '{}'::text[],
    threat_names           TEXT[]      NOT NULL DEFAULT '{}'::text[],
    reputation             INTEGER,
    total_votes            JSONB,
    times_submitted        INTEGER,
    first_submission_date  TIMESTAMPTZ,
    last_submission_date   TIMESTAMPTZ,
    last_analysis_date     TIMESTAMPTZ,
    last_modification_date TIMESTAMPTZ,
    ingested_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    vt_data_upserted_at    TIMESTAMPTZ,
    gui_url                TEXT        GENERATED ALWAYS AS (
        CASE WHEN vt_id IS NOT NULL
             THEN 'https://www.virustotal.com/gui/url/' || vt_id
             ELSE NULL END
    ) STORED
);

-- 1.8 urlscan_url_scans
CREATE TABLE public.urlscan_url_scans (
    scan_id         BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    url_sha256      TEXT        NOT NULL
                                REFERENCES public.phishing_urls(url_sha256) ON DELETE CASCADE
                                CHECK (length(url_sha256) = 64),
    uuid            TEXT        UNIQUE,
    scan_purpose    TEXT        NOT NULL DEFAULT 'default',
    scan_params     JSONB       NOT NULL DEFAULT '{"country": "us"}'::jsonb,
    fetch_status    TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (fetch_status IN ('pending','submitted','done','failed','skipped','stale')),
    fetch_attempts  SMALLINT    NOT NULL DEFAULT 0 CHECK (fetch_attempts >= 0),
    last_fetched_at TIMESTAMPTZ,
    last_error      TEXT,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    result_url      TEXT        GENERATED ALWAYS AS (
        CASE WHEN uuid IS NOT NULL
             THEN 'https://urlscan.io/result/' || uuid || '/'
             ELSE NULL END
    ) STORED
);

-- ============================================================
-- SECTION 2: Indexes (41 non-PK indexes)
-- ============================================================

-- raw_phishtank
CREATE INDEX ix_raw_phishtank_url_sha256        ON public.raw_phishtank (url_sha256);
CREATE INDEX ix_raw_phishtank_target            ON public.raw_phishtank (target);
CREATE INDEX ix_raw_phishtank_verification_time ON public.raw_phishtank (verification_time DESC);
CREATE INDEX ix_raw_phishtank_ingested_at       ON public.raw_phishtank (ingested_at DESC);

-- raw_openphish_academic
CREATE INDEX ix_raw_openphish_academic_brand         ON public.raw_openphish_academic (brand);
CREATE INDEX ix_raw_openphish_academic_family_id     ON public.raw_openphish_academic (family_id);
CREATE INDEX ix_raw_openphish_academic_sector        ON public.raw_openphish_academic (sector);
CREATE INDEX ix_raw_openphish_academic_asn_number    ON public.raw_openphish_academic (asn_number);
CREATE INDEX ix_raw_openphish_academic_host          ON public.raw_openphish_academic (host);
CREATE INDEX ix_raw_openphish_academic_country_code  ON public.raw_openphish_academic (country_code);
CREATE INDEX ix_raw_openphish_academic_discover_time ON public.raw_openphish_academic (discover_time DESC);
CREATE INDEX ix_raw_openphish_academic_ingested_at   ON public.raw_openphish_academic (ingested_at DESC);
CREATE INDEX ix_raw_openphish_academic_spear_only    ON public.raw_openphish_academic (discover_time DESC)
    WHERE is_spear = true;

-- raw_openphish_community
CREATE INDEX ix_raw_openphish_community_ingested_at ON public.raw_openphish_community (ingested_at DESC);

-- raw_ecrimex
CREATE INDEX ix_raw_ecrimex_url_sha256    ON public.raw_ecrimex (url_sha256);
CREATE INDEX ix_raw_ecrimex_brand         ON public.raw_ecrimex (brand);
CREATE INDEX ix_raw_ecrimex_discovered_at ON public.raw_ecrimex (discovered_at DESC);
CREATE INDEX ix_raw_ecrimex_ingested_at   ON public.raw_ecrimex (ingested_at DESC);

-- raw_phishstats
CREATE INDEX ix_raw_phishstats_url_sha256    ON public.raw_phishstats (url_sha256);
CREATE INDEX ix_raw_phishstats_host          ON public.raw_phishstats (host);
CREATE INDEX ix_raw_phishstats_domain        ON public.raw_phishstats (domain);
CREATE INDEX ix_raw_phishstats_country_code  ON public.raw_phishstats (country_code);
CREATE INDEX ix_raw_phishstats_tld           ON public.raw_phishstats (tld);
CREATE INDEX ix_raw_phishstats_asn_number    ON public.raw_phishstats (asn_number);
CREATE INDEX ix_raw_phishstats_discovered_at ON public.raw_phishstats (discovered_at DESC);
CREATE INDEX ix_raw_phishstats_ingested_at   ON public.raw_phishstats (ingested_at DESC);

-- phishing_urls
CREATE INDEX ix_phishing_urls_crawl_status ON public.phishing_urls (crawl_status);
CREATE INDEX ix_phishing_urls_ingested_at  ON public.phishing_urls (ingested_at DESC);
CREATE INDEX ix_phishing_urls_pending      ON public.phishing_urls (ingested_at)
    WHERE crawl_status = 'pending';

-- vt_url_reports
CREATE INDEX ix_vt_url_reports_vt_id              ON public.vt_url_reports (vt_id);
CREATE INDEX ix_vt_url_reports_fetch_status       ON public.vt_url_reports (fetch_status);
CREATE INDEX ix_vt_url_reports_fetch_queue        ON public.vt_url_reports (fetch_attempts, ingested_at)
    WHERE fetch_status IN ('pending','failed');
CREATE INDEX ix_vt_url_reports_submitted_queue    ON public.vt_url_reports (last_fetched_at)
    WHERE fetch_status = 'submitted';
CREATE INDEX ix_vt_url_reports_stats_malicious    ON public.vt_url_reports
    (((last_analysis_stats->>'malicious')::int) DESC NULLS LAST);
CREATE INDEX ix_vt_url_reports_last_analysis_date ON public.vt_url_reports (last_analysis_date DESC NULLS LAST);
CREATE INDEX ix_vt_url_reports_ingested_at        ON public.vt_url_reports (ingested_at DESC);

-- urlscan_url_scans
CREATE UNIQUE INDEX urlscan_url_scans_default_uniq ON public.urlscan_url_scans (url_sha256)
    WHERE scan_purpose = 'default';
CREATE INDEX urlscan_url_scans_post_queue  ON public.urlscan_url_scans (fetch_attempts, ingested_at)
    WHERE fetch_status IN ('pending','failed') AND fetch_attempts < 3;
CREATE INDEX urlscan_url_scans_poll_queue  ON public.urlscan_url_scans (last_fetched_at)
    WHERE fetch_status = 'submitted';
CREATE INDEX urlscan_url_scans_url_sha256  ON public.urlscan_url_scans (url_sha256);
CREATE INDEX urlscan_url_scans_status      ON public.urlscan_url_scans (fetch_status);
CREATE INDEX urlscan_url_scans_ingested_at ON public.urlscan_url_scans (ingested_at DESC);

-- ============================================================
-- SECTION 3: Functions (helper first, then trigger functions)
-- ============================================================

-- 3.1 Helper: shared UPSERT logic for phishing_urls
CREATE OR REPLACE FUNCTION public.upsert_phishing_urls(
    p_url_sha256    text,
    p_url           text,
    p_source        text,
    p_brand         text DEFAULT NULL,
    p_ip            inet[] DEFAULT '{}'::inet[],
    p_asn           integer[] DEFAULT '{}'::integer[],
    p_country_code  text DEFAULT NULL,
    p_discovered_at timestamptz DEFAULT NULL
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    v_brand_jsonb      JSONB := '{}'::jsonb;
    v_ip_jsonb         JSONB := '{}'::jsonb;
    v_asn_jsonb        JSONB := '{}'::jsonb;
    v_country_jsonb    JSONB := '{}'::jsonb;
    v_discovered_jsonb JSONB := '{}'::jsonb;
BEGIN
    IF p_brand IS NOT NULL THEN
        v_brand_jsonb := jsonb_build_object(p_source, p_brand);
    END IF;
    IF cardinality(p_ip) > 0 THEN
        v_ip_jsonb := jsonb_build_object(p_source, to_jsonb(p_ip));
    END IF;
    IF cardinality(p_asn) > 0 THEN
        v_asn_jsonb := jsonb_build_object(p_source, to_jsonb(p_asn));
    END IF;
    IF p_country_code IS NOT NULL THEN
        v_country_jsonb := jsonb_build_object(p_source, p_country_code);
    END IF;
    IF p_discovered_at IS NOT NULL THEN
        v_discovered_jsonb := jsonb_build_object(p_source, p_discovered_at);
    END IF;

    INSERT INTO phishing_urls
        (url_sha256, url, sources, brand, ip, asn, country_code, discovered_at)
    VALUES
        (p_url_sha256, p_url, ARRAY[p_source],
         v_brand_jsonb, v_ip_jsonb, v_asn_jsonb, v_country_jsonb, v_discovered_jsonb)
    ON CONFLICT (url_sha256) DO UPDATE SET
        sources       = (SELECT array_agg(DISTINCT s ORDER BY s)
                         FROM unnest(phishing_urls.sources || EXCLUDED.sources) AS s),
        brand         = phishing_urls.brand         || EXCLUDED.brand,
        ip            = phishing_urls.ip            || EXCLUDED.ip,
        asn           = phishing_urls.asn           || EXCLUDED.asn,
        country_code  = phishing_urls.country_code  || EXCLUDED.country_code,
        discovered_at = phishing_urls.discovered_at || EXCLUDED.discovered_at;
END;
$$;

-- 3.2 phishing_urls.last_upserted_at smart bumper
CREATE OR REPLACE FUNCTION public.bump_last_upserted_at()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.sources       IS DISTINCT FROM OLD.sources
    OR NEW.brand         IS DISTINCT FROM OLD.brand
    OR NEW.ip            IS DISTINCT FROM OLD.ip
    OR NEW.asn           IS DISTINCT FROM OLD.asn
    OR NEW.country_code  IS DISTINCT FROM OLD.country_code
    OR NEW.discovered_at IS DISTINCT FROM OLD.discovered_at
    THEN
        NEW.last_upserted_at := now();
    END IF;
    RETURN NEW;
END;
$$;

-- 3.3 raw_phishtank → phishing_urls
CREATE OR REPLACE FUNCTION public.trg_raw_phishtank_to_phishing_urls()
RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    v_ips     INET[];
    v_asns    INTEGER[];
    v_country TEXT;
BEGIN
    v_ips := ARRAY(
        SELECT (d->>'ip_address')::inet
        FROM jsonb_array_elements(NEW.details) d
        WHERE d->>'ip_address' IS NOT NULL
    );
    v_asns := ARRAY(
        SELECT (d->>'announcing_network')::int
        FROM jsonb_array_elements(NEW.details) d
        WHERE d->>'announcing_network' ~ '^\d+$'
    );
    SELECT d->>'country' INTO v_country
    FROM jsonb_array_elements(NEW.details) d
    WHERE d->>'country' IS NOT NULL
    LIMIT 1;

    PERFORM upsert_phishing_urls(
        p_url_sha256    => NEW.url_sha256,
        p_url           => NEW.url,
        p_source        => 'phishtank',
        p_brand         => NEW.target,
        p_ip            => v_ips,
        p_asn           => v_asns,
        p_country_code  => v_country,
        p_discovered_at => NEW.submission_time
    );
    RETURN NULL;
END;
$$;

-- 3.4 raw_openphish_academic → phishing_urls
CREATE OR REPLACE FUNCTION public.trg_raw_openphish_academic_to_phishing_urls()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM upsert_phishing_urls(
        p_url_sha256    => NEW.url_sha256,
        p_url           => NEW.url,
        p_source        => 'openphish_academic',
        p_brand         => NEW.brand,
        p_ip            => CASE WHEN NEW.ip IS NULL THEN '{}'::inet[] ELSE ARRAY[NEW.ip] END,
        p_asn           => CASE WHEN NEW.asn_number IS NULL THEN '{}'::integer[] ELSE ARRAY[NEW.asn_number] END,
        p_country_code  => NEW.country_code,
        p_discovered_at => NEW.discover_time
    );
    RETURN NULL;
END;
$$;

-- 3.5 raw_openphish_community → phishing_urls
CREATE OR REPLACE FUNCTION public.trg_raw_openphish_community_to_phishing_urls()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM upsert_phishing_urls(
        p_url_sha256 => NEW.url_sha256,
        p_url        => NEW.url,
        p_source     => 'openphish_community'
    );
    RETURN NULL;
END;
$$;

-- 3.6 raw_ecrimex → phishing_urls
CREATE OR REPLACE FUNCTION public.trg_raw_ecrimex_to_phishing_urls()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM upsert_phishing_urls(
        p_url_sha256    => NEW.url_sha256,
        p_url           => NEW.url,
        p_source        => 'ecrimex',
        p_brand         => NEW.brand,
        p_ip            => NEW.ip,
        p_asn           => NEW.asn,
        p_country_code  => NULL,
        p_discovered_at => NEW.discovered_at
    );
    RETURN NULL;
END;
$$;

-- 3.7 raw_phishstats → phishing_urls
CREATE OR REPLACE FUNCTION public.trg_raw_phishstats_to_phishing_urls()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM upsert_phishing_urls(
        p_url_sha256    => NEW.url_sha256,
        p_url           => NEW.url,
        p_source        => 'phishstats',
        p_brand         => NULL,
        p_ip            => CASE WHEN NEW.ip IS NULL THEN '{}'::inet[] ELSE ARRAY[NEW.ip] END,
        p_asn           => CASE WHEN NEW.asn_number IS NULL THEN '{}'::integer[] ELSE ARRAY[NEW.asn_number] END,
        p_country_code  => NEW.country_code,
        p_discovered_at => NEW.discovered_at
    );
    RETURN NULL;
END;
$$;

-- 3.8 phishing_urls → vt_url_reports (placeholder INSERT)
CREATE OR REPLACE FUNCTION public.trg_phishing_urls_to_vt_url_reports()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO vt_url_reports (url_sha256)
    VALUES (NEW.url_sha256)
    ON CONFLICT (url_sha256) DO NOTHING;
    RETURN NULL;
END;
$$;

-- 3.9 phishing_urls → urlscan_url_scans (default-purpose placeholder INSERT)
CREATE OR REPLACE FUNCTION public.trg_phishing_urls_to_urlscan_default()
RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO urlscan_url_scans (url_sha256)
    VALUES (NEW.url_sha256)
    ON CONFLICT (url_sha256) WHERE scan_purpose = 'default'
    DO NOTHING;
    RETURN NULL;
END;
$$;

-- ============================================================
-- SECTION 4: Triggers (8 attachments)
-- ============================================================

CREATE TRIGGER trg_raw_phishtank_propagate
    AFTER INSERT ON public.raw_phishtank
    FOR EACH ROW EXECUTE FUNCTION trg_raw_phishtank_to_phishing_urls();

CREATE TRIGGER trg_raw_openphish_academic_propagate
    AFTER INSERT OR UPDATE ON public.raw_openphish_academic
    FOR EACH ROW EXECUTE FUNCTION trg_raw_openphish_academic_to_phishing_urls();

CREATE TRIGGER trg_raw_openphish_community_propagate
    AFTER INSERT ON public.raw_openphish_community
    FOR EACH ROW EXECUTE FUNCTION trg_raw_openphish_community_to_phishing_urls();

CREATE TRIGGER trg_raw_ecrimex_propagate
    AFTER INSERT OR UPDATE ON public.raw_ecrimex
    FOR EACH ROW EXECUTE FUNCTION trg_raw_ecrimex_to_phishing_urls();

CREATE TRIGGER trg_raw_phishstats_propagate
    AFTER INSERT ON public.raw_phishstats
    FOR EACH ROW EXECUTE FUNCTION trg_raw_phishstats_to_phishing_urls();

CREATE TRIGGER trg_phishing_urls_bump_last_upserted_at
    BEFORE UPDATE ON public.phishing_urls
    FOR EACH ROW EXECUTE FUNCTION bump_last_upserted_at();

CREATE TRIGGER trg_phishing_urls_propagate_to_vt
    AFTER INSERT ON public.phishing_urls
    FOR EACH ROW EXECUTE FUNCTION trg_phishing_urls_to_vt_url_reports();

CREATE TRIGGER trg_phishing_urls_propagate_to_urlscan
    AFTER INSERT ON public.phishing_urls
    FOR EACH ROW EXECUTE FUNCTION trg_phishing_urls_to_urlscan_default();

-- ============================================================
-- SECTION 5: Realtime publication
-- ============================================================

ALTER PUBLICATION supabase_realtime ADD TABLE public.phishing_urls;

COMMIT;
