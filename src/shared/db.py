"""Shared Postgres connection helper for fetchers and admin scripts."""

import os

import psycopg


def get_connection() -> psycopg.Connection:
    db_url = os.environ.get("SUPABASE_DB_URL")
    if not db_url:
        raise RuntimeError(
            "SUPABASE_DB_URL is not set. "
            "For local dev: export SUPABASE_DB_URL=postgresql://...; "
            "in CI: configure the GitHub Secret of the same name."
        )
    return psycopg.connect(db_url)
