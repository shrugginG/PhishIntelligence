# phishing_urlscan_fetcher

NAS-side urlscan.io routine fetcher. DSM Task Scheduler triggers a fresh
`docker run` every 15 min; the container exits after a single tick.

As of Phase 3 of the GH→NAS migration, scan output goes to **Supabase Storage**
(bucket `phishing-urlscan-results`, private) via HTTP PUT — NOT to a host bind
mount. Orchestration state stays in Supabase Postgres.

The actual fetch logic lives in `src/nas_workers/urlscan_fetcher.py`.

## One-time setup on NAS

### 1. Create the Storage bucket (one-time, before first tick)

```bash
ssh nas
SERVICE_KEY=$(grep ^SERVICE_ROLE_KEY ~/projects/supabase-self-host/.env | cut -d= -f2)

curl -s -X POST "http://192.168.1.161:8000/storage/v1/bucket" \
  -H "apikey: $SERVICE_KEY" \
  -H "Authorization: Bearer $SERVICE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"id":"phishing-urlscan-results","name":"phishing-urlscan-results","public":false}'
```

Or via Studio GUI: Storage → New Bucket → name `phishing-urlscan-results`,
public off. Skip if the bucket already exists.

### 2. Build image + configure `.env`

```bash
ssh nas
mkdir -p ~/projects && cd ~/projects
# pull / clone repo to ~/projects/PhishIntelligence (see top-level README)

cd PhishIntelligence/docker/phishing_intelligence_fetcher/phishing_urlscan_fetcher

cp .env.example .env
chmod 600 .env
nano .env    # fill URLSCAN_API_KEYS + SUPABASE_DB_URL +
             # SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY

# Build. Build context = repo ROOT.
cd ~/projects/PhishIntelligence
sudo /usr/local/bin/docker build \
  -f docker/phishing_intelligence_fetcher/phishing_urlscan_fetcher/Dockerfile \
  -t phishing_urlscan_fetcher:latest \
  .

# Smoke test (one tick)
sudo docker/phishing_intelligence_fetcher/phishing_urlscan_fetcher/run.sh
```

## DSM Task Scheduler entry

DSM → Control Panel → Task Scheduler → Create → Scheduled Task → User-defined script

| Setting       | Value                                                                                                                       |
|---------------|-----------------------------------------------------------------------------------------------------------------------------|
| Task name     | `phishing_urlscan_fetcher`                                                                                                  |
| User          | `root` (Docker socket needs root on DSM)                                                                                    |
| Schedule      | Daily, repeat every 15 minutes between 00:00–23:45                                                                          |
| Run command   | `/var/services/homes/jxlu/projects/PhishIntelligence/docker/phishing_intelligence_fetcher/phishing_urlscan_fetcher/run.sh`  |

## Updating after code changes

```bash
ssh nas
cd ~/projects/PhishIntelligence
git pull origin main           # or curl + tar (NAS SSH PATH lacks git — see CLAUDE.md)
sudo /usr/local/bin/docker build \
  -f docker/phishing_intelligence_fetcher/phishing_urlscan_fetcher/Dockerfile \
  -t phishing_urlscan_fetcher:latest \
  .
# Next tick uses the new image. DSM Task Scheduler does NOT need restart.
```

## Verify what just ran

```bash
# Most recent container output
sudo /usr/local/bin/docker logs phishing_urlscan_fetcher 2>&1 | tail -100

# How many done in the last hour
sudo /usr/local/bin/docker exec supabase-db psql -U postgres -d postgres \
  -c "SELECT count(*) FROM urlscan_url_scans
      WHERE fetch_status = 'done' AND last_fetched_at > now() - interval '1 hour';"

# Status distribution
sudo /usr/local/bin/docker exec supabase-db psql -U postgres -d postgres \
  -c "SELECT fetch_status, count(*) FROM urlscan_url_scans GROUP BY 1 ORDER BY 1;"

# Storage object count (should track done count after a small delay)
sudo /usr/local/bin/docker exec supabase-db psql -U postgres -d postgres \
  -c "SELECT count(*) FROM storage.objects WHERE bucket_id = 'phishing-urlscan-results';"
```

## Inspect a single scan's 4-pack

Use Studio Storage GUI to drill into the bucket, OR via API:

```bash
SERVICE_KEY=$(grep ^SERVICE_ROLE_KEY ~/projects/supabase-self-host/.env | cut -d= -f2)
SHA=<url_sha256>
UUID=<scan-uuid>
BASE="http://192.168.1.161:8000/storage/v1/object/phishing-urlscan-results"

# meta.json (small, JSON)
curl -s -H "apikey: $SERVICE_KEY" "$BASE/$SHA/$UUID/meta.json" | jq .

# result.json.gz → decompress on the fly
curl -s -H "apikey: $SERVICE_KEY" "$BASE/$SHA/$UUID/result.json.gz" | gunzip | jq .verdicts.overall

# screenshot.png → save locally
curl -s -H "apikey: $SERVICE_KEY" "$BASE/$SHA/$UUID/screenshot.png" -o /tmp/screenshot.png
```

## Pre-migration archive

The old bind-mount path `~/data/phishing/urlscan_results/` on NAS host still
holds 14k+ scan directories from before Phase 3. The fetcher no longer writes
there; you can keep it as a forensic archive or delete it manually after
verifying everything works:

```bash
# DESTRUCTIVE — only run after verifying Phase 3 is fully working
sudo rm -rf ~/data/phishing/urlscan_results/
```

## Troubleshooting

| Symptom                                                                                                  | Likely cause                                                                                                |
|----------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| `docker: ... container name "phishing_urlscan_fetcher" already in use`                                  | Previous tick still running; DSM should skip but if it fires anyway, this is the safety net.               |
| `psycopg.OperationalError: ... Network is unreachable`                                                   | NAS no IPv6 outbound, DB URL points at `db.<ref>.supabase.co`. Use a pooler URL.                            |
| `URLSCAN_API_KEYS not set or empty`                                                                      | `.env` missing the var or `--env-file` not loading. Verify path + chmod 600.                                |
| `RuntimeError: SUPABASE_URL not set` or `SUPABASE_SERVICE_ROLE_KEY not set`                              | Phase 3 added these. Update `.env` from `.env.example`.                                                    |
| `Storage PUT ... failed [401]` / `[403]`                                                                 | Service role key wrong, expired, or pointing at wrong project. Check the key in Studio → Settings → API.    |
| `Storage PUT ... failed [404]` ending with `Bucket not found`                                            | Bucket not created. Run the curl command in section "1. Create the Storage bucket" above.                  |
| `Storage PUT ... failed [413]`                                                                           | File over Supabase's per-object size limit (50 MiB default). Should never trigger for our typical 4-pack.   |
| Many rows stuck in `submitted`                                                                           | scan_params unsupported, urlscan slow, or auth failure. Check `urlscan_url_scans.last_error` in Supabase.   |
| Many rows stuck in `failed` with `Storage upload: ...`                                                   | Check Storage container logs: `sudo docker logs supabase-storage` and DB row's `last_error`.                |

## Why HTTP API instead of writing to `volumes/storage` directly

Writing files directly to `~/projects/supabase-self-host/volumes/storage/...`
would technically work and avoid the HTTP overhead (~3–4s per tick), but
breaks under any future Supabase Storage upgrade — the on-disk layout
(`stub/stub/<bucket>/<path>/<version-uuid>`) is an internal implementation
detail, not a public contract. Going through the HTTP API:

- Stays compatible across Supabase upgrades
- Maintains `storage.objects` metadata consistency (mime, size, etag)
- Plays nice with imgproxy (screenshot resizing) and signed URLs
- Honors RLS / future per-tenant access policies

The 3-second overhead is invisible at our scale (~30s typical tick).
