"""v2fly/domain-list-community fetcher (RAW ingestion into the `reference` schema).

Source: https://github.com/v2fly/domain-list-community — the community geosite
list compiled into dlc.dat for V2Ray routing. We ingest the RAW source `data/`
directory (NOT the compiled dlc.dat/release), preserving the include graph,
attributes, affiliations and inline comments. Resolution / allowlist curation is
deferred to downstream workflows.

Two tables, mirroring the upstream parser's own model (ParsedList{Entries,Inclusions}):
  reference.v2fly_domain_rules  ← domain/full/keyword/regexp entries
  reference.v2fly_list_includes ← include: edges (the list→list graph)
  reference.v2fly_sync_runs     ← per-fetch provenance/churn audit

Line parsing is a faithful port of main.go's loadData/parseEntry/parseInclusion,
with ONE difference: we are LENIENT — a malformed line is logged + skipped and
counted in parse_errors, instead of aborting the whole sync (upstream's parser
hard-fails; we don't need to).

Refresh = snapshot + last_seen: pull a commit-pinned snapshot, UPSERT the full
set, bump last_seen_at / sync_count / source_commit. Rows that drop out of
upstream are NOT deleted (their source_commit stops advancing → "vanished").

bootstrap_fetch and routine_fetch are identical (full-snapshot UPSERT); both
exist to match the other sources' (size) signature convention.
"""

from __future__ import annotations

import io
import os
import tarfile

import httpx

from src.shared.db import get_connection

REPO = "v2fly/domain-list-community"
REPO_REF = "master"
COMMITS_API = f"https://api.github.com/repos/{REPO}/commits/{REPO_REF}"
ARCHIVE_URL = f"https://github.com/{REPO}/archive/{{sha}}.tar.gz"

VALID_RULE_TYPES = ("domain", "full", "keyword", "regexp")


# ──────────────────────────────────────────────────────────────────────────
# Fetch: commit-pinned source tarball
# ──────────────────────────────────────────────────────────────────────────
def _github_headers() -> dict[str, str]:
    """Optional GITHUB_TOKEN lifts the unauth 60 req/h API limit to 5000/h.
    Not required for a 3×/day cadence; included for robustness."""
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get_head_sha(client: httpx.Client) -> str:
    resp = client.get(COMMITS_API, headers=_github_headers())
    resp.raise_for_status()
    sha = resp.json()["sha"]
    print(f"  HEAD of {REPO}@{REPO_REF} = {sha}")
    return sha


def _download_data_files(client: httpx.Client, sha: str) -> dict[str, str]:
    """Download the commit-pinned tarball and return {list_name: file_text} for
    every file directly under data/. In-memory (the archive is a few MB)."""
    resp = client.get(ARCHIVE_URL.format(sha=sha), follow_redirects=True)
    resp.raise_for_status()
    files: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            # path looks like: domain-list-community-<sha>/data/<name>
            parts = member.name.split("/")
            if len(parts) != 3 or parts[1] != "data":
                continue
            list_name = parts[2]
            fobj = tar.extractfile(member)
            if fobj is None:
                continue
            files[list_name] = fobj.read().decode("utf-8", errors="replace")
    print(f"  Extracted {len(files)} data/ files")
    return files


# ──────────────────────────────────────────────────────────────────────────
# Parse: faithful port of main.go (lenient on errors)
# ──────────────────────────────────────────────────────────────────────────
def _parse_line(line: str):
    """Return one of:
      None                                  → comment-only / blank (skip)
      ("rule", type, value, attrs, affs, comment, raw)
      ("include", included, must, ban, comment, raw)
      ("error", reason, raw)
    Mirrors main.go: strip first '#', trim, cut first ':', default type 'domain',
    Fields() split, '@'→attr (lower), '&'→affiliation (upper); regexp keeps case.
    """
    logical, _, comment_part = line.partition("#")
    comment = comment_part.strip() or None
    logical = logical.strip()
    if not logical:
        return None

    typ, sep, rule = logical.partition(":")
    if not sep:  # no colon → bare domain (prefix omitted)
        typ, rule = "domain", logical
    else:
        typ = typ.strip().lower()
    rule = rule.strip()

    fields = rule.split()
    if not fields:
        return ("error", f"empty rule body: {logical!r}", logical)

    if typ == "include":
        included = fields[0].lower()
        must: list[str] = []
        ban: list[str] = []
        for part in fields[1:]:
            if part.startswith("@-"):
                ban.append(part[2:].lower())
            elif part.startswith("@"):
                must.append(part[1:].lower())
            elif part.startswith("&"):
                return ("error", "affiliation not allowed for inclusion", logical)
            else:
                return ("error", f"unknown include field: {part!r}", logical)
        return ("include", included, sorted(must), sorted(ban), comment, logical)

    if typ in VALID_RULE_TYPES:
        # regexp preserves case; domain/full/keyword are lowercased
        value = fields[0] if typ == "regexp" else fields[0].lower()
        attrs: list[str] = []
        affs: list[str] = []
        for part in fields[1:]:
            if part.startswith("@"):
                attrs.append(part[1:].lower())
            elif part.startswith("&"):
                affs.append(part[1:].upper())
            else:
                return ("error", f"unknown field: {part!r}", logical)
        return ("rule", typ, value, sorted(attrs), sorted(affs), comment, logical)

    return ("error", f"unknown rule type: {typ!r}", logical)


def _parse_files(files: dict[str, str]):
    """Parse every file into (rule_rows, include_rows, n_errors). Rows are tuples
    ready for UPSERT (without source_commit, appended at write time)."""
    rule_rows = []
    include_rows = []
    n_errors = 0
    for list_name, text in files.items():
        for line in text.splitlines():
            parsed = _parse_line(line)
            if parsed is None:
                continue
            kind = parsed[0]
            if kind == "rule":
                _, rtype, value, attrs, affs, comment, raw = parsed
                rule_rows.append((list_name, rtype, value, attrs, affs, comment, raw))
            elif kind == "include":
                _, included, must, ban, comment, raw = parsed
                include_rows.append((list_name, included, must, ban, comment, raw))
            else:  # error
                n_errors += 1
                print(f"  [skip] {list_name}: {parsed[1]}")
    print(f"  Parsed {len(rule_rows)} rules + {len(include_rows)} includes "
          f"({n_errors} skipped)")
    return rule_rows, include_rows, n_errors


# ──────────────────────────────────────────────────────────────────────────
# Write: snapshot UPSERT + sync_runs audit
# ──────────────────────────────────────────────────────────────────────────
_UPSERT_RULES = """
    INSERT INTO reference.v2fly_domain_rules
        (list_name, rule_type, value, attributes, affiliations,
         source_comment, raw_line, source_commit)
    VALUES (%s, %s, %s, %s::text[], %s::text[], %s, %s, %s)
    ON CONFLICT (list_name, rule_type, value, attributes) DO UPDATE SET
        affiliations   = EXCLUDED.affiliations,
        source_comment = EXCLUDED.source_comment,
        raw_line       = EXCLUDED.raw_line,
        source_commit  = EXCLUDED.source_commit,
        last_seen_at   = now(),
        sync_count     = reference.v2fly_domain_rules.sync_count + 1
"""

_UPSERT_INCLUDES = """
    INSERT INTO reference.v2fly_list_includes
        (list_name, included_list, must_attrs, ban_attrs,
         source_comment, raw_line, source_commit)
    VALUES (%s, %s, %s::text[], %s::text[], %s, %s, %s)
    ON CONFLICT (list_name, included_list, must_attrs, ban_attrs) DO UPDATE SET
        source_comment = EXCLUDED.source_comment,
        raw_line       = EXCLUDED.raw_line,
        source_commit  = EXCLUDED.source_commit,
        last_seen_at   = now(),
        sync_count     = reference.v2fly_list_includes.sync_count + 1
"""


def _write(rule_rows, include_rows, n_errors, sha, file_count) -> dict:
    with get_connection() as conn, conn.cursor() as cur:
        # open the audit row first
        cur.execute(
            "INSERT INTO reference.v2fly_sync_runs "
            "(source_commit, repo_ref, file_count, rule_rows, include_rows) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING run_id",
            (sha, REPO_REF, file_count, len(rule_rows), len(include_rows)),
        )
        run_id = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM reference.v2fly_domain_rules")
        rules_before = cur.fetchone()[0]

        cur.executemany(_UPSERT_RULES, [r + (sha,) for r in rule_rows])
        cur.executemany(_UPSERT_INCLUDES, [r + (sha,) for r in include_rows])

        cur.execute("SELECT count(*) FROM reference.v2fly_domain_rules")
        rules_after = cur.fetchone()[0]
        cur.execute(
            "SELECT count(*) FROM reference.v2fly_domain_rules WHERE source_commit <> %s",
            (sha,),
        )
        rules_vanished = cur.fetchone()[0]

        inserted = rules_after - rules_before
        refreshed = len(rule_rows) - inserted

        cur.execute(
            "UPDATE reference.v2fly_sync_runs SET "
            "rules_inserted=%s, rules_refreshed=%s, rules_vanished=%s, "
            "parse_errors=%s, finished_at=now(), status='done' WHERE run_id=%s",
            (inserted, refreshed, rules_vanished, n_errors, run_id),
        )

    stats = {
        "inserted": inserted,
        "refreshed": refreshed,
        "vanished": rules_vanished,
        "errors": n_errors,
        "rules": len(rule_rows),
        "includes": len(include_rows),
    }
    print(f"  Rules: +{inserted} new / {refreshed} refreshed / "
          f"{rules_vanished} vanished upstream; includes: {len(include_rows)}")
    return stats


# ──────────────────────────────────────────────────────────────────────────
# Entry points
# ──────────────────────────────────────────────────────────────────────────
def routine_fetch() -> int:
    """Pull a commit-pinned snapshot of the source data/ dir and UPSERT the full
    set into the reference schema. Returns the number of domain-rule rows seen."""
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        sha = _get_head_sha(client)
        files = _download_data_files(client, sha)
    rule_rows, include_rows, n_errors = _parse_files(files)
    stats = _write(rule_rows, include_rows, n_errors, sha, len(files))
    return stats["rules"]


def bootstrap_fetch(size: int | None = None) -> int:
    """Identical to routine_fetch (the source IS the full set). `size` accepted
    for signature parity with the phishing sources; ignored here."""
    return routine_fetch()


if __name__ == "__main__":
    n = routine_fetch()
    print(f"\n=== v2fly_domain_list routine_fetch done: {n} domain rules ===")
