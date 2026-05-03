"""Reset all phishing intelligence tables.

Triggered by `.github/workflows/reset.yml`. The user-facing safety check
(typing 'WIPE-ALL') lives in the workflow YAML; by the time this script runs,
GitHub Actions has already validated the input.

Behavior:
  1. Print row count of every target table BEFORE truncate (audit log)
  2. TRUNCATE all tables in one statement (atomic)
  3. Print row counts AFTER (should all be 0)
"""

from src.shared.db import get_connection

# Order doesn't matter for TRUNCATE since we use a single statement
# (CASCADE handles FK ordering); listed roughly bottom-up for log readability:
# raw_* leaves first, then phishing_urls (the hub), then derived-table reports.
TABLES = [
    "raw_phishtank",
    "raw_openphish_academic",
    "raw_openphish_community",
    "raw_ecrimex",
    "raw_phishstats",
    "phishing_urls",
    "vt_url_reports",
]


def _print_counts(cur, header: str) -> None:
    print(f"--- {header} ---")
    for t in TABLES:
        cur.execute(f"SELECT count(*) FROM {t}")
        (n,) = cur.fetchone()
        print(f"  {t}: {n} rows")


def main() -> None:
    with get_connection() as conn:
        with conn.cursor() as cur:
            _print_counts(cur, "BEFORE")

            print(f"\n--- TRUNCATE {len(TABLES)} tables ---")
            cur.execute(
                f"TRUNCATE {', '.join(TABLES)} RESTART IDENTITY CASCADE"
            )

            print()
            _print_counts(cur, "AFTER")


if __name__ == "__main__":
    main()
