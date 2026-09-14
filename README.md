# security-log-analyzer

A defensive security log analyzer: parses log files, detects brute-force
and account-attack patterns, stores events and alerts in SQLite, and
displays results in a Streamlit dashboard.

> Full README (architecture diagram, detection rules, limitations)
> lands on Day 10. This stub keeps the repo from looking empty.

## Quickstart

    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python scripts/generate_sample_logs.py
    pytest -q

## Status

- [x] Day 7 — scaffold, log generator, parser, parser tests
- [ ] Day 8 — detection engine + rule tests
- [ ] Day 9 — SQLite storage + Streamlit dashboard
- [ ] Day 10 — README, architecture diagram, CI, demo

## Design decisions

See `docs/decisions.md`.