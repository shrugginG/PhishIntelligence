# PhishIntelligence

Multi-source phishing URL intelligence aggregation pipeline + per-URL enrichment
(VirusTotal verdicts + urlscan.io rendered scans), funneled into a unified
Postgres registry that serves as the entry point for an LLM-driven Web Agent.

## Pipeline at a glance

```
5 raw sources ──┐
phishtank       │
openphish_acad  │       trigger
openphish_comm  ├──▶ phishing_urls (unified registry, deduped, JSONB-merged)
ecrimex         │           │
phishstats ─────┘           ├──▶ vt_url_reports     (92-engine verdict, votes, dates)
                            └──▶ urlscan_url_scans  (UUID + status; 4-pack written to Storage)
```

## Stack

- **Python 3.11+** with [uv](https://docs.astral.sh/uv/) for dependency management
- **psycopg v3** for Postgres (native INET / CIDR / JSONB / TIMESTAMPTZ)
- **httpx** for HTTP fetching (sync for raw, async for VT/urlscan)
- **Supabase Postgres** as the data backbone — 8 tables + 9 functions + 8 triggers
- **Supabase Storage** for urlscan 4-pack archive (`phishing-urlscan-results` bucket)
- **Self-hosted Supabase on NAS** as the v1.3 primary deployment; cloud Supabase as fallback
- **DSM Task Scheduler** drives 7 cron-style fetcher containers on NAS; **GitHub Actions** mirrors the same 6 cron flows as a parallel fallback

## Schema

`migrations/0001_initial_schema.sql` is the bit-perfect snapshot that any fresh
Postgres can replay. 8 public-schema tables:

- `raw_phishtank` / `raw_openphish_academic` / `raw_openphish_community` / `raw_ecrimex` / `raw_phishstats` — per-source landing tables
- `phishing_urls` — cross-source deduped registry; trigger-driven JSONB merge
- `vt_url_reports` — 1:1 derived; VT engine verdicts
- `urlscan_url_scans` — 1:N derived; urlscan UUID + status; 4-pack lives in Storage

Detailed field-by-field docs live in `CLAUDE.md` (gitignored, contains
credentials).

## Project layout

```
PhishIntelligence/
├── src/
│   ├── shared/db.py                          # psycopg connection helper
│   ├── sources/                              # GH Actions entry points (sync)
│   │   ├── phishtank.py / openphish_academic.py / openphish_community.py
│   │   ├── ecrimex.py / phishstats.py
│   │   ├── vt.py                             # GH-tuned (4h timeout)
│   │   └── urlscan.py                        # bootstrap-only
│   ├── nas_workers/                          # NAS-tuned async workers
│   │   ├── vt_fetcher.py                     # env-driven defaults, HARD_BUDGET_SEC
│   │   └── urlscan_fetcher.py                # writes Supabase Storage
│   ├── bootstrap.py / reset.py
│
├── docker/phishing_intelligence_fetcher/     # NAS-side fetcher containers
│   ├── phishing_source_fetcher/              # 5 raw sources, dispatcher entrypoint
│   ├── phishing_virustotal_fetcher/          # VT enrichment
│   └── phishing_urlscan_fetcher/             # urlscan + Storage upload
│
├── migrations/0001_initial_schema.sql
└── .github/workflows/                        # parallel fallback (writes cloud DB)
    ├── bootstrap.yml / reset.yml
    └── fetch_<source>.yml × 6
```

## Local development

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync

# Use a Pooler URL (direct db.<ref>.supabase.co is IPv6-only on free tier)
export SUPABASE_DB_URL='postgresql://postgres.<ref>:<pwd>@aws-0-<region>.pooler.supabase.com:5432/postgres'
export PHISHTANK_TOKEN='<key>'
uv run python -m src.sources.phishtank
```

## NAS deployment

The NAS-side deployment uses `~/projects/supabase-self-host/` (Supabase docker
compose) plus `docker/phishing_intelligence_fetcher/<sub>/` per-fetcher images.
Each fetcher subdir has its own `README.md` with build, .env, and DSM Task
Scheduler steps. Top-level summary lives in `CLAUDE.md`.

## Credentials

Required for full pipeline. Set as either NAS-side `.env` files (`chmod 600`)
or GitHub Secrets — same names, different stores.

| Variable | Used by |
|---|---|
| `SUPABASE_DB_URL` | All fetchers |
| `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` | urlscan fetcher (Storage writes) |
| `PHISHTANK_TOKEN` | phishtank source |
| `ECRIMEX_TOKEN` | ecrimex source |
| `OPENPHISH_GITHUB_USER` + `OPENPHISH_GITHUB_PAT` | openphish_academic source (60-day expiry) |
| `VIRUSTOTAL_ACADEMIC_API_KEY` | vt enrichment |
| `URLSCAN_API_KEYS` (comma-separated) | urlscan enrichment |

PhishStats and OpenPhish Community need no credentials.
