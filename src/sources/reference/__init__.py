"""Reference domain/URL list sources (allowlist building blocks).

Distinct from the phishing event-stream sources in ``src.sources.phishing``:
these are relatively static, snapshot-style domain/URL lists (rankings,
categorized domain catalogs) used downstream to construct benign-domain
allowlists for filtering phishing URLs.

Data lands in the dedicated ``reference`` Postgres schema (NOT ``public``),
kept isolated from the phishing pipeline (no phishing_urls trigger), but in
the same Supabase instance so it remains JOIN-able for filtering.

Planned members: tranco, crux_top_lists, v2fly_domain_list, ...
"""
