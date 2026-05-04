# NAS-side urlscan fetcher container.
#
# Build context = repository ROOT (uses pyproject.toml + uv.lock + src/...):
#   docker build -f docker/nas-urlscan-fetcher/Dockerfile \
#                -t phish-urlscan-fetcher:latest .
#
# Runtime: see ./run.sh for the docker run invocation used by DSM Task Scheduler.

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

# Run as UID 1026 / GID 100 to match host user 'jxlu'. This makes
# bind-mounted /data writable without sudo or chown gymnastics.
RUN useradd -u 1026 -g 100 -m -s /bin/bash fetcher
USER 1026:100

ENTRYPOINT ["uv", "run", "python", "-m", "src.nas_workers.urlscan_fetcher"]
