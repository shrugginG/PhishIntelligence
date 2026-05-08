# NAS-side raw source fetcher container.
#
# Build context = repository ROOT (uses pyproject.toml + uv.lock + src/...):
#   docker build -f docker/phishing_intelligence_fetcher/phishing_source_fetcher/Dockerfile \
#                -t phishing_source_fetcher:latest .
#
# Runtime: see ./run.sh for the docker run invocation used by DSM Task Scheduler.
# One image dispatches to 5 raw sources plus bootstrap/reset; first arg selects:
#   ./run.sh phishtank | openphish_academic | openphish_community | ecrimex | phishstats
#   ./run.sh bootstrap [--targets ...]
#   ./run.sh reset

FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

# git is required by src/sources/openphish_academic.py (subprocess.run(["git","clone",...])).
# --no-install-recommends + cleanup keeps the image lean (~10 MB extra).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency layer (cache breaks only when pyproject.toml or uv.lock changes).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Source layer — only what this dispatcher actually invokes.
COPY src/__init__.py     ./src/__init__.py
COPY src/shared/         ./src/shared/
COPY src/sources/        ./src/sources/
COPY src/bootstrap.py    ./src/bootstrap.py
COPY src/reset.py        ./src/reset.py

# In-container entrypoint dispatcher (parses arg, delegates to the right module).
COPY docker/phishing_intelligence_fetcher/phishing_source_fetcher/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# UID 1026 / GID 100 = host 'jxlu', kept for parity with phishing_urlscan_fetcher.
# This image has no bind mounts (output is DB-only), but the consistent UID
# makes any future bind mount trivially compatible.
RUN useradd -u 1026 -g 100 -m -s /bin/bash fetcher
USER 1026:100

ENTRYPOINT ["/entrypoint.sh"]
