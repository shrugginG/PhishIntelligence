# PhishIntelligence

Multi-source phishing URL intelligence aggregation pipeline → Supabase Postgres.

Aggregates phishing URLs from 5 upstream sources (PhishTank / OpenPhish Academic /
OpenPhish Community / eCrimeX / PhishStats) into a unified Postgres registry,
serving as the entry point for an LLM-driven Web Agent that performs deep
interactive analysis on each URL.

## Stack

- **Python 3.11+** with [uv](https://docs.astral.sh/uv/) for dependency management
- **psycopg v3** for Postgres (native INET / CIDR / JSONB / TIMESTAMPTZ support)
- **httpx** for HTTP fetching
- **GitHub Actions** for cron-driven routine fetching + manual bootstrap/reset
- **Supabase Postgres** for storage (`raw_*` tables + `phishing_urls` registry)

## Project layout

```
src/
├── shared/                      # cross-source helpers
│   └── db.py                    # PG connection
├── sources/                     # one folder per upstream source
│   ├── phishtank/
│   ├── openphish_academic/
│   ├── openphish_community/
│   ├── ecrimex/
│   └── phishstats/
└── reset.py                     # admin: TRUNCATE all tables

.github/workflows/
├── reset.yml                    # manual + WIPE-ALL confirmation
├── bootstrap.yml                # manual: seed initial data       (TODO)
└── fetch_<source>.yml × 5       # cron: routine incremental       (TODO)
```

## Local development

```bash
# Install uv if needed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Sync dependencies (creates .venv and installs from uv.lock)
uv sync

# Set the Postgres connection string
export SUPABASE_DB_URL='postgresql://postgres:<pwd>@db.<project>.supabase.co:5432/postgres'

# Run reset locally (careful — will TRUNCATE)
uv run python -m src.reset
```

## Required GitHub Secrets

Set these in repo settings → Secrets and variables → Actions:

| Secret | Used by | Purpose |
|---|---|---|
| `SUPABASE_DB_URL` | all | Postgres connection string (service role) |
| `PHISHTANK_TOKEN` | fetch_phishtank | PhishTank bulk dump API key |
| `ECRIMEX_TOKEN` | fetch_ecrimex | eCrimeX `/api/v1` Bearer token |
| `OPENPHISH_GITHUB_USER` | fetch_openphish_academic | GitHub username for academic clone |
| `OPENPHISH_GITHUB_PAT` | fetch_openphish_academic | GitHub PAT for academic clone |

PhishStats and OpenPhish Community require no credentials.

## Schema

Detailed schema docs and DDL are kept in `CLAUDE.md` (gitignored — contains
credentials). The Supabase project's `public` schema has 6 tables:
`raw_phishtank`, `raw_openphish_academic`, `raw_openphish_community`,
`raw_ecrimex`, `raw_phishstats`, plus the unified `phishing_urls` registry.
Five trigger functions on the `raw_*` tables auto-derive the `phishing_urls`
state on every INSERT/UPDATE.
