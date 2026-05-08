# NAS-side urlscan fetcher container.
#
# Build context = repository ROOT (uses pyproject.toml + uv.lock + src/...):
#   docker build -f docker/phishing_intelligence_fetcher/phishing_urlscan_fetcher/Dockerfile \
#                -t phishing_urlscan_fetcher:latest .
#
# Runtime: see ./run.sh for the docker run invocation used by DSM Task Scheduler.
# Output goes to Supabase Storage (bucket `phishing-urlscan-results`); no host
# bind mount required.

FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app

# Dependency layer (cache breaks only when pyproject.toml or uv.lock changes)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Source layer (only what the NAS fetcher actually needs; src/sources/* and
# src/bootstrap.py are intentionally not copied — those run in GitHub Actions)
COPY src/__init__.py     ./src/__init__.py
COPY src/shared/         ./src/shared/
COPY src/nas_workers/    ./src/nas_workers/

# UID 1026 / GID 100 = host 'jxlu', kept for parity with the other
# phishing_intelligence_fetcher containers. With Storage replacing the bind
# mount, the UID no longer affects file ownership — but it keeps the
# convention consistent and is future-proofing.
RUN useradd -u 1026 -g 100 -m -s /bin/bash fetcher
USER 1026:100

ENTRYPOINT ["uv", "run", "python", "-m", "src.nas_workers.urlscan_fetcher"]
