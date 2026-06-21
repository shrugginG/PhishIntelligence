# reference_list_fetcher

NAS-side fetcher for **domain/URL reference lists** → the `reference` Postgres
schema. Separate from the phishing fetchers (`phishing_intelligence_fetcher/*`):
these are relatively static reference catalogs used downstream to build
benign-domain allowlists for filtering phishing URLs. **Isolated** — no triggers,
no FK into `public`, but in the same Supabase instance so `reference.*` stays
JOIN-able with `public.phishing_urls`.

## Sources

| action | source | tables |
|---|---|---|
| `v2fly` | [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) raw `data/` dir | `reference.v2fly_domain_rules`, `reference.v2fly_list_includes`, `reference.v2fly_sync_runs` |

(future: `tranco`, `crux`)

We ingest the **raw source** `data/` directory (NOT the compiled `dlc.dat`),
preserving the include graph, attributes, affiliations and inline comments.
Resolution / allowlist curation is deferred to downstream workflows.

## Refresh model

Snapshot + last_seen (same as `raw_phishunt`): each sync pulls a
**commit-pinned** tarball, UPSERTs the full set, bumps `last_seen_at` /
`sync_count` / `source_commit`. Rows that drop out of upstream are NOT deleted;
their `source_commit` stops advancing (→ "vanished upstream"). One
`v2fly_sync_runs` row records provenance + churn per fetch.

## Setup (NAS)

```bash
cd ~/projects/PhishIntelligence/docker/reference_list_fetcher
cp .env.example .env && chmod 600 .env   # then fill SUPABASE_DB_URL
```

Apply the schema once (NAS-first; cloud optional):

```bash
sudo /usr/local/bin/docker exec -i supabase-db psql -U postgres -d postgres \
  < ~/projects/PhishIntelligence/migrations/0004_reference_schema.sql
```

Build the image (from repo root):

```bash
cd ~/projects/PhishIntelligence
sudo /usr/local/bin/docker build -f docker/reference_list_fetcher/Dockerfile \
  -t reference_list_fetcher:latest .
```

## Run

```bash
./run.sh v2fly                 # one sync (DSM calls this)
./run.sh reset WIPE-REFERENCE  # TRUNCATE reference.v2fly_* (destructive)
```

## DSM Task Scheduler

One task, **every 8 hours (3×/day)**:

| task name | schedule | command |
|---|---|---|
| `reference_list_fetcher_v2fly` | 00:00 / 08:00 / 16:00 | `.../reference_list_fetcher/run.sh v2fly` |

`--name` lock + `timeout --kill-after=30 600` wrapper, same robustness pattern as
the phishing fetchers.
