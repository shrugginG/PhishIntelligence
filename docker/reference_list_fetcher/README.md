# reference_list_fetcher

NAS-side fetcher for **domain/URL reference lists** → the `reference` Postgres
schema. Separate from the phishing fetchers (`phishing_intelligence_fetcher/*`):
these are relatively static reference catalogs used downstream to build
benign-domain allowlists for filtering phishing URLs. **Isolated** — no triggers,
no FK into `public`, but in the same Supabase instance so `reference.*` stays
JOIN-able with `public.phishing_urls`.

## Sources

| action | source | tables / storage |
|---|---|---|
| `v2fly` | [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community) raw `data/` dir | `reference.v2fly_domain_rules`, `reference.v2fly_list_includes`, `reference.v2fly_sync_runs` |
| `tranco` | [Tranco](https://tranco-list.eu/) top-1M (both granularities) | `reference.tranco_top1m`, `reference.tranco_archive` + Storage bucket `tranco-archive` |
| `crux` | [zakird/crux-top-lists](https://github.com/zakird/crux-top-lists) CrUX top-1M (global + 238 countries) | `reference.crux_top1m` (global only), `reference.crux_archive` + Storage bucket `crux-top-archive` |

## Refresh models (per source)

**v2fly** — raw `data/` dir (NOT the compiled `dlc.dat`), preserving include
graph / attributes / affiliations / inline comments. Snapshot + last_seen (same
as `raw_phishunt`): commit-pinned tarball → UPSERT full set → bump `last_seen_at`
/ `sync_count` / `source_commit`; vanished rows kept (source_commit stops). One
`v2fly_sync_runs` row per fetch.

**tranco** — Strategy A (current-mirror) + cold Storage archive, NO history in PG:
- HOT `tranco_top1m`: current-only mirror of the latest top-1M, BOTH
  granularities (`subdomains` flag). Refreshed via TRUNCATE+COPY → the table IS
  the latest list (no `current` flag, zero bloat).
- COLD bucket `tranco-archive`: each day's raw `.csv.zip` (both granularities),
  immutable, keyed by `<date>__<list_id>`. `tranco_archive` manifest catalogs it.
- Idempotent on Tranco's permanent `list_id`; a tick whose list_ids are already
  archived is a no-op (Tranco updates 1×/day, we tick 3×/day).

**crux** — Strategy A (GLOBAL hot table) + cold Storage archive of ALL scopes:
- HOT `crux_top1m`: current-only mirror of the latest GLOBAL top-1M (~1M rows,
  `origin,rank`; rank = CrUX bucket). Refreshed via TRUNCATE+COPY. Country lists
  are NOT loaded into PG (~22M rows; low whitelist value).
- COLD bucket `crux-top-archive`: mirrors the repo `data/` tree verbatim —
  `global/<YYYYMM>.csv.gz` + `country/<cc>/<YYYYMM>.csv.gz` (global + all 238
  countries archived). `crux_archive` manifest catalogs one row per (scope, month).
- One git-tree API call enumerates each scope's latest month; idempotent on
  `(scope, yyyymm)` (CrUX monthly data is immutable). Daily cadence → most days
  are a no-op; the hot table refreshes only when the GLOBAL scope gets a new month.

## Setup (NAS)

```bash
cd ~/projects/PhishIntelligence/docker/reference_list_fetcher
cp .env.example .env && chmod 600 .env
# fill SUPABASE_DB_URL (all sources) + SUPABASE_URL & SUPABASE_SERVICE_ROLE_KEY (tranco + crux Storage)
```

Apply the schemas once (NAS-first; cloud optional):

```bash
for m in 0004_reference_schema 0005_reference_tranco 0006_reference_crux; do
  sudo /usr/local/bin/docker exec -i supabase-db psql -U postgres -d postgres \
    < ~/projects/PhishIntelligence/migrations/$m.sql
done
```

Create the cold-archive buckets once (private; service role only):

```bash
SK=$(grep ^SERVICE_ROLE_KEY ~/projects/supabase-self-host/.env | cut -d= -f2)
for b in tranco-archive crux-top-archive; do
  curl -s -X POST "http://192.168.1.21:8000/storage/v1/bucket" \
    -H "apikey: $SK" -H "Authorization: Bearer $SK" -H "Content-Type: application/json" \
    -d "{\"id\":\"$b\",\"name\":\"$b\",\"public\":false}"
done
```

Build the image (from repo root):

```bash
cd ~/projects/PhishIntelligence
sudo /usr/local/bin/docker build -f docker/reference_list_fetcher/Dockerfile \
  -t reference_list_fetcher:latest .
```

## Run

```bash
./run.sh v2fly                 # one v2fly sync
./run.sh tranco                # one tranco sync (DB + Storage)
./run.sh crux                  # one crux sync (global hot + all scopes to Storage)
./run.sh reset WIPE-REFERENCE  # TRUNCATE all reference.* tables (NOT the Storage buckets)
```

## DSM Task Scheduler

| task name | schedule | command |
|---|---|---|
| `reference_list_fetcher_v2fly`  | every 8h, 00:00 / 08:00 / 16:00 | `.../reference_list_fetcher/run.sh v2fly` |
| `reference_list_fetcher_tranco` | every 8h, 02:00 / 10:00 / 18:00 | `.../reference_list_fetcher/run.sh tranco` |
| `reference_list_fetcher_crux`   | daily, 04:00                    | `.../reference_list_fetcher/run.sh crux` |

`--name` lock + `timeout --kill-after=30 1200` wrapper. v2fly/tranco finish in
<60s; crux is a daily no-op except when a new CrUX month appears (then it pulls
~215 MB of global + country files — the 1200s ceiling covers it). Schedules are
offset to avoid the cron cluster.
