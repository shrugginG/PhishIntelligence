# phishing_virustotal_fetcher

NAS-side VirusTotal URL-report enrichment fetcher. Replaces the GitHub Actions
`fetch_vt.yml` workflow. Single-action image, one routine tick per `docker run`.

The actual fetch logic lives in `src/nas_workers/vt_fetcher.py` — an
independent NAS-tuned implementation paralleling `src/sources/vt.py` (which
remains as the GitHub Actions fallback). The two diverge in:

- **Tunable defaults**: smaller per-tick batches because NAS cron is 30 min
  (vs GH Actions' best-effort ~110 min real-world gap), so per-tick capacity
  doesn't need to absorb multi-hour outages.
- **HARD_BUDGET_SEC**: enforced; a stuck tick can't hold the `--name` lock
  past the next DSM fire window.
- **Env-driven constants**: every tunable can be overridden in `.env` without
  rebuilding the image.

## One-time setup on NAS

```bash
ssh nas
mkdir -p ~/projects && cd ~/projects
# pull / clone repo to ~/projects/PhishIntelligence (see top-level README)

cd PhishIntelligence/docker/phishing_intelligence_fetcher/phishing_virustotal_fetcher

# .env (chmod 600 — keeps Supabase + VT credentials off other-user reads)
cp .env.example .env
chmod 600 .env
nano .env    # fill SUPABASE_DB_URL + VIRUSTOTAL_ACADEMIC_API_KEY

# Build the image. Build context = repo ROOT.
cd ~/projects/PhishIntelligence
sudo /usr/local/bin/docker build \
  -f docker/phishing_intelligence_fetcher/phishing_virustotal_fetcher/Dockerfile \
  -t phishing_virustotal_fetcher:latest \
  .

# Smoke test (one tick)
sudo docker/phishing_intelligence_fetcher/phishing_virustotal_fetcher/run.sh
```

## DSM Task Scheduler entry

DSM → Control Panel → Task Scheduler → Create → Scheduled Task → User-defined script

| Setting       | Value                                                                                                                            |
|---------------|----------------------------------------------------------------------------------------------------------------------------------|
| Task name     | `phishing_virustotal_fetcher`                                                                                                    |
| User          | `root` (Docker socket needs root on DSM)                                                                                         |
| Schedule      | Daily, repeat every 30 minutes between 00:05–23:35                                                                               |
| Run command   | `/var/services/homes/jxlu/projects/PhishIntelligence/docker/phishing_intelligence_fetcher/phishing_virustotal_fetcher/run.sh`    |

The `:5,:35` cron offset matches the existing `.github/workflows/fetch_vt.yml`
schedule and stays out of the integer-minute crunch where most clusters fire.

## Updating after code changes

```bash
ssh nas
cd ~/projects/PhishIntelligence
git pull origin main           # or curl + tar (NAS SSH PATH lacks git — see CLAUDE.md)
sudo /usr/local/bin/docker build \
  -f docker/phishing_intelligence_fetcher/phishing_virustotal_fetcher/Dockerfile \
  -t phishing_virustotal_fetcher:latest \
  .
# Next tick uses the new image. DSM Task Scheduler does NOT need restart.
```

## Verify what just ran

```bash
# Most recent run output
sudo /usr/local/bin/docker logs phishing_virustotal_fetcher 2>&1 | tail -50

# Status distribution snapshot
sudo /usr/local/bin/docker exec supabase-db psql -U postgres -d postgres \
  -c "SELECT fetch_status, count(*) FROM vt_url_reports GROUP BY 1 ORDER BY 1;"

# How many got enriched in the last hour
sudo /usr/local/bin/docker exec supabase-db psql -U postgres -d postgres \
  -c "SELECT count(*) FROM vt_url_reports
      WHERE fetch_status = 'done'
        AND vt_data_upserted_at > now() - interval '1 hour';"

# Stuck submitted rows (older than SUBMITTED_TIMEOUT_SEC = 2h)
sudo /usr/local/bin/docker exec supabase-db psql -U postgres -d postgres \
  -c "SELECT count(*) FROM vt_url_reports
      WHERE fetch_status = 'submitted'
        AND last_fetched_at < now() - interval '2 hour';"
```

## Quota check (manual)

VT enforces both daily-per-user and hourly-per-key limits. The fetcher checks
the user-daily one before each tick and aborts at QUOTA_ABORT_RATIO=0.95.
You can also check manually:

```bash
KEY=<vt-key>
curl -s -H "x-apikey: $KEY" \
  "https://www.virustotal.com/api/v3/users/$KEY/overall_quotas" \
  | jq '.data.api_requests_daily.user'
```

## Troubleshooting

| Symptom                                                                       | Likely cause                                                                                                                |
|-------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| `docker: ... container name "phishing_virustotal_fetcher" already in use`     | Previous tick still running. DSM should skip but if it fires anyway, this is the safety net. Check if a prior tick deadlocked. |
| `psycopg.OperationalError: ... Network is unreachable`                        | NAS no IPv6 outbound, DB URL points at `db.<ref>.supabase.co`. Use a pooler URL.                                            |
| `RuntimeError: VIRUSTOTAL_ACADEMIC_API_KEY not set`                           | `.env` missing the var or `--env-file` not loading. Verify path + chmod 600.                                                |
| `⚠ Quota threshold reached, exiting early`                                    | Daily user quota > 95%. Wait for the daily quota reset (UTC midnight) or upgrade key tier.                                  |
| Many rows stuck in `submitted`                                                | VT slow to complete analyses (rare). After SUBMITTED_TIMEOUT_SEC=2h, rows auto re-POST. Check with the "stuck" SQL above.   |
| `vt_url_reports.last_error` shows `HTTP 401 / 403`                            | API key wrong or revoked. Replace `VIRUSTOTAL_ACADEMIC_API_KEY` and rebuild is NOT needed (just edit `.env` + next tick). |

## Why no API key pool

Unlike `phishing_urlscan_fetcher` (which round-robins 2 keys for 10k/day pool
quota), VT's academic_january tier already gives 20k/day per single key —
plenty for our 4k URL/day inflow. A pool adds complexity without payoff.
