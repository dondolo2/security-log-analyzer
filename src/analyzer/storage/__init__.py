"""Storage layer.

The rest of the app talks to this module, not to sqlite3 directly. Swapping
to Postgres means rewriting db.py — nothing else changes. See
docs/decisions.md §1.
"""