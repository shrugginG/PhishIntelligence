# NAS-side VirusTotal enrichment fetcher container.
#
# Build context = repository ROOT (uses pyproject.toml + uv.lock + src/...):
#   docker build -f docker/phishing_intelligence_fetcher/phishing_virustotal_fetcher/Dockerfile \
#                -t phishing_virustotal_fetcher:latest .
#
# Runtime: see ./run.sh for the docker run invocation used by DSM Task Scheduler.
# Single-action image — entrypoint runs one routine tick and exits.

FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app

# Dependency layer (cache breaks only when pyproject.toml or uv.lock changes).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Source layer — only what the NAS VT fetcher actually needs. src/sources/*
# is intentionally NOT copied (its routine_fetch is the GH Actions entry point;
# the NAS variant is src/nas_workers/vt_fetcher.py).
COPY src/__init__.py     ./src/__init__.py
COPY src/shared/         ./src/shared/
COPY src/nas_workers/    ./src/nas_workers/

# UID 1026 / GID 100 = host 'jxlu', kept for parity with the other
# phishing_intelligence_fetcher containers. This image has no bind mounts
# (output is DB-only), but the consistent UID is future-proofing.
RUN useradd -u 1026 -g 100 -m -s /bin/bash fetcher
USER 1026:100

ENTRYPOINT ["uv", "run", "python", "-m", "src.nas_workers.vt_fetcher"]
