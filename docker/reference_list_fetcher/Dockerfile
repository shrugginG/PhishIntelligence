# NAS-side reference list fetcher container.
#
# Distinct from the phishing fetchers: this ingests domain/URL *reference lists*
# (rankings, categorized domain catalogs) into the `reference` Postgres schema,
# isolated from the phishing pipeline. One image dispatches to each reference
# source plus a scoped reset; first arg selects:
#   ./run.sh v2fly            # v2fly/domain-list-community → reference.v2fly_*
#   ./run.sh reset WIPE-REFERENCE
#   (future: ./run.sh tranco | crux)
#
# Build context = repository ROOT:
#   docker build -f docker/reference_list_fetcher/Dockerfile \
#                -t reference_list_fetcher:latest .
#
# No git needed (source pulled as a commit-pinned tarball via curl/httpx).

FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app

# Dependency layer (cache breaks only when pyproject.toml or uv.lock changes).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Source layer — only the reference subtree this image invokes.
COPY src/__init__.py             ./src/__init__.py
COPY src/shared/                 ./src/shared/
COPY src/sources/__init__.py     ./src/sources/__init__.py
COPY src/sources/reference/      ./src/sources/reference/

# In-container entrypoint dispatcher.
COPY docker/reference_list_fetcher/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# UID 1026 / GID 100 = host 'jxlu', for parity with the phishing fetchers.
RUN useradd -u 1026 -g 100 -m -s /bin/bash fetcher
USER 1026:100

ENTRYPOINT ["/entrypoint.sh"]
