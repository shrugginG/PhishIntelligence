# phishing_source_fetcher

NAS-side fetcher container for the 5 raw phishing-intel sources:

- PhishTank
- OpenPhish Academic
- OpenPhish Community
- eCrimeX (APWG)
- PhishStats

Replaces the corresponding GitHub Actions cron workflows
(`.github/workflows/fetch_*.yml`). One image, dispatched by argument.
Bootstrap and reset are bundled as additional subcommands for manual SSH use.

The actual fetch logic lives in `src/sources/<source>.py` — this container only
provides the runtime + scheduling glue.

## One-time setup on NAS

```bash
ssh nas
mkdir -p ~/projects && cd ~/projects
# pull / clone repo to ~/projects/PhishIntelligence (see top-level README)

cd PhishIntelligence/docker/phishing_intelligence_fetcher/phishing_source_fetcher

# .env (chmod 600 — keeps Supabase + source tokens off other-user reads)
cp .env.example .env
chmod 600 .env
nano .env    # fill SUPABASE_DB_URL + PHISHTANK_TOKEN + ECRIMEX_TOKEN
             # + OPENPHISH_GITHUB_USER + OPENPHISH_GITHUB_PAT

# Build the image. Build context = repo ROOT.
cd ~/projects/PhishIntelligence
sudo /usr/local/bin/docker build \
  -f docker/phishing_intelligence_fetcher/phishing_source_fetcher/Dockerfile \
  -t phishing_source_fetcher:latest \
  .

# Smoke test (each is a fresh, isolated docker run)
sudo docker/phishing_intelligence_fetcher/phishing_source_fetcher/run.sh openphish_community
sudo docker/phishing_intelligence_fetcher/phishing_source_fetcher/run.sh phishtank
```

## DSM Task Scheduler entries (5 sources, mirroring the existing GH cron times)

In all entries the **command path** is identical, only the **first argument** changes:

```
/var/services/homes/jxlu/projects/PhishIntelligence/docker/phishing_intelligence_fetcher/phishing_source_fetcher/run.sh <ACTION>
```

| Task name                                       | `<ACTION>`            | Cron schedule           | Reason                              |
|-------------------------------------------------|-----------------------|-------------------------|-------------------------------------|
| `phishing_source_fetcher_phishtank`             | `phishtank`           | `17 * * * *`            | hourly :17 (matches GH workflow)    |
| `phishing_source_fetcher_openphish_academic`    | `openphish_academic`  | `8,23,38,53 * * * *`    | every 15 min (source's own cadence) |
| `phishing_source_fetcher_openphish_community`   | `openphish_community` | `27 */6 * * *`          | every 6 h :27 (12h source cadence ÷ 2) |
| `phishing_source_fetcher_ecrimex`               | `ecrimex`             | `32 * * * *`            | hourly :32                          |
| `phishing_source_fetcher_phishstats`            | `phishstats`          | `48 */2 * * *`          | every 2 h :48 (90-min source cadence) |

Per-entry settings:
- **User**: `root` (Docker socket needs root on DSM)
- **Send run details by email — only on abnormal exit**: optional, recommended once stable
- **Run command**: copy the path above, replace `<ACTION>`

## Manual actions (NOT scheduled)

```bash
# Bootstrap — initial pull from each source. Example: top 100 from each.
ssh nas
cd ~/projects/PhishIntelligence/docker/phishing_intelligence_fetcher/phishing_source_fetcher
sudo ./run.sh bootstrap --targets all
# or selective with sizes:
sudo ./run.sh bootstrap --targets phishtank,ecrimex --phishtank-size 1000 --ecrimex-size 500

# Reset — DESTRUCTIVE. TRUNCATEs all 8 tables. Wrapper requires explicit
# WIPE-ALL confirmation; without it `run.sh reset` exits with usage error
# and never reaches the container.
sudo ./run.sh reset WIPE-ALL
```

## Updating after code changes

```bash
ssh nas
cd ~/projects/PhishIntelligence
git pull origin main           # or curl + tar (NAS SSH PATH lacks git — see CLAUDE.md)
sudo /usr/local/bin/docker build \
  -f docker/phishing_intelligence_fetcher/phishing_source_fetcher/Dockerfile \
  -t phishing_source_fetcher:latest \
  .
# Next tick uses the new image. DSM Task Scheduler does NOT need restart.
```

## Verify what just ran

```bash
# Most recent run output, per source. Each source has its own --name, so the
# logs of one source don't get clobbered by another.
sudo /usr/local/bin/docker logs phishing_source_fetcher_phishtank 2>&1 | tail -50

# DSM Task Scheduler GUI also keeps the last 32 runs in its history pane.

# DB-side smoke check
sudo /usr/local/bin/docker exec supabase-db psql -U postgres -d postgres \
  -c "SELECT 'raw_phishtank' AS t, count(*) FROM raw_phishtank
      UNION ALL SELECT 'raw_openphish_academic', count(*) FROM raw_openphish_academic
      UNION ALL SELECT 'raw_openphish_community', count(*) FROM raw_openphish_community
      UNION ALL SELECT 'raw_ecrimex', count(*) FROM raw_ecrimex
      UNION ALL SELECT 'raw_phishstats', count(*) FROM raw_phishstats;"
```

## Troubleshooting

| Symptom                                                                          | Likely cause                                                                                            |
|----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| `docker: ... container name "phishing_source_fetcher_<x>" already in use`        | Previous tick of THIS source still running. DSM should skip but if it fires anyway, this is the safety net. |
| `psycopg.OperationalError: ... Network is unreachable`                           | NAS has no IPv6 outbound, but the DB URL points at `db.<ref>.supabase.co`. Switch to a pooler URL.      |
| `KeyError: 'PHISHTANK_TOKEN'` (and friends)                                      | `.env` not loaded or missing the variable. Verify `--env-file .env` and the variable's value.           |
| `git: command not found` during `openphish_academic`                             | Image build skipped git. Rebuild — the Dockerfile installs it.                                          |
| `subprocess.CalledProcessError: ... git clone https://<user>:<pat>@github.com/openphish/academic` | OPENPHISH_GITHUB_PAT expired (60-day lifetime). Re-approve on GitHub and update `.env`.                 |
| Phase rebuild produces an image but `run.sh` still uses old code                 | DSM caches nothing here, but the Docker image cache might. Force-rebuild with `--no-cache`.             |

## Why one image, not five

All 5 sources share the same Python deps (`psycopg + httpx`) and the same DB
connection helper. Splitting into 5 images would 5× the disk and rebuild work
without giving meaningful isolation — failure domains are already isolated by
distinct `--name` locks at runtime, and DSM-side per-source schedules. The only
shared concern is the `.env` file, which is fine because all credentials are
in the same trust boundary (NAS jxlu).
