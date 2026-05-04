# NAS urlscan fetcher

Long-shot deployment for the urlscan.io routine fetcher running on the home
NAS (Synology DS1821+ class, DSM 7.x). Each tick is a self-contained docker
run; DSM Task Scheduler triggers it every 15 min. Results land on NAS;
orchestration state lives in Supabase.

See `src/nas_workers/urlscan_fetcher.py` for the actual fetch logic.

## One-time setup on NAS

```bash
ssh nas
mkdir -p ~/data/phishing/urlscan_results
mkdir -p ~/projects && cd ~/projects
git clone https://github.com/shrugginG/PhishIntelligence.git
cd PhishIntelligence/docker/nas-urlscan-fetcher

# Create .env from template
cp .env.example .env
chmod 600 .env
nano .env    # fill URLSCAN_API_KEYS + SUPABASE_DB_URL

# Build the image (Container Manager bundles docker; sudo needed for socket)
sudo /usr/local/bin/docker build \
  -f docker/nas-urlscan-fetcher/Dockerfile \
  -t phish-urlscan-fetcher:latest \
  ../..   # build context = repo root

# Smoke test (one tick)
sudo ./run.sh
```

## DSM Task Scheduler entry

DSM → Control Panel → Task Scheduler → Create → Scheduled Task → User-defined script

- **Task name**: `phish-urlscan-fetcher`
- **User**: `root` (needed because `docker` requires root socket access)
- **Schedule**: Run every day, repeat every 15 minutes between 00:00–23:45
- **Run command** (Task Settings → Run command):
  ```
  /var/services/homes/jxlu/projects/PhishIntelligence/docker/nas-urlscan-fetcher/run.sh
  ```
- **Send run details by email**: optional but useful for failure alerts

## Updating

```bash
ssh nas
cd ~/projects/PhishIntelligence
git pull origin main
sudo /usr/local/bin/docker build \
  -f docker/nas-urlscan-fetcher/Dockerfile \
  -t phish-urlscan-fetcher:latest \
  .
# Next tick will use the new image (DSM Task Scheduler doesn't need restart)
```

## Verify what just happened

```bash
# Most recent run output (from last container exit)
sudo /usr/local/bin/docker logs phish-urlscan-fetcher 2>&1 | tail -100

# DSM Task Scheduler keeps the last 32 runs in its history pane (GUI)
# — easier than digging into docker logs.

# What landed on disk
ls ~/data/phishing/urlscan_results/$(date +%Y-%m)/$(date +%d)/ | head -10
```

## Inspect a single result

```bash
UUID=019df...
DIR=$(find ~/data/phishing/urlscan_results -name "$UUID" -type d)
ls -la "$DIR"
zcat "$DIR/result.json.gz" | jq .verdicts.overall
cat "$DIR/meta.json"
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `docker: Error response from daemon: Conflict. The container name "phish-urlscan-fetcher" is already in use` | Previous tick still running; DSM should skip but if it fires anyway, this is the safety net. Wait for previous tick to finish. |
| `psycopg.OperationalError: connection to server ... failed: Network is unreachable` | NAS has no IPv6 outbound but DB URL points at `db.<ref>.supabase.co`. Switch to Session Pooler URL. |
| `URLSCAN_API_KEYS not set or empty` | `.env` not loaded or key list parses empty. Verify `--env-file .env` and the variable's value. |
| Many rows stuck in `submitted` | scan_params unsupported, or urlscan auth failure. Check `urlscan_url_scans.last_error` in Supabase. |
