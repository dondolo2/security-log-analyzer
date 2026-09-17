"""SQLite storage: connection, schema init, idempotent loads.

All writes are parameterized. All inserts are idempotent. Loading the
same events twice is a no-op; loading the same alerts twice updates the
existing row rather than inserting a duplicate.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

from analyzer.alerts import Alert

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a SQLite connection, creating the parent directory if needed.

    WAL mode is enabled because the dashboard reads while the CLI writes.
    Without it, a long-running `streamlit run` would hold a read lock and
    the CLI would block on writes. WAL is the standard answer and costs
    nothing here — single file, single process, no replication concerns.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables and indexes if they don't exist. Safe to call repeatedly."""
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.commit()


def _ts(dt: datetime) -> str:
    """Format a datetime for storage. ISO-8601, space separator.

    Space separator (not 'T') because it matches the log file format and
    makes SQLite CLI output readable without conversion.
    """
    return dt.isoformat(sep=" ", timespec="seconds")


def insert_events(conn: sqlite3.Connection, events: list[dict]) -> int:
    """Insert events, ignoring duplicates. Returns the number of NEW rows.

    The returned count is the honest one — a caller asking "how much new
    data did this run add?" gets the right answer, not len(events).
    """
    inserted = 0
    for e in events:
        cur = conn.execute(
            """
            INSERT INTO security_events
                (timestamp, event, username, ip_address, raw_line, source_file)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(timestamp, event, username, ip_address, source_file)
            DO NOTHING
            """,
            (
                _ts(e["timestamp"]),
                e["event"],
                e["username"],
                e["ip_address"],
                e.get("raw_line"),
                e["source_file"],
            ),
        )
        inserted += cur.rowcount
    conn.commit()
    return inserted


def upsert_alerts(conn: sqlite3.Connection, alerts: list[Alert]) -> None:
    """Insert alerts, updating on conflict.

    Why UPDATE and not DO NOTHING? If a re-run sees a longer burst (a
    bigger log file, or a rule that now includes more events in the same
    window), the alert's `last_seen` and `event_count` should reflect the
    bigger burst. Same alert identity, richer data. `details` is replaced
    wholesale because rule-specific context is fully derived from the
    input — no partial merge is meaningful.
    """
    for a in alerts:
        conn.execute(
            """
            INSERT INTO security_alerts
                (alert_type, severity, ip_address, username,
                 first_seen, last_seen, event_count, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(alert_type, ip_address, username, first_seen)
            DO UPDATE SET
                severity    = excluded.severity,
                last_seen   = excluded.last_seen,
                event_count = excluded.event_count,
                details     = excluded.details
            """,
            (
                a.alert_type,
                a.severity,
                a.ip_address or "",
                a.username or "",
                _ts(a.first_seen),
                _ts(a.last_seen),
                a.event_count,
                json.dumps(a.details, sort_keys=True),
            ),
        )
    conn.commit()


def count_events(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]


def count_alerts(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM security_alerts").fetchone()[0]


def reset(conn: sqlite3.Connection) -> None:
    """Drop all rows. Used by --reset for reproducible demos. Not for prod."""
    conn.execute("DELETE FROM security_events")
    conn.execute("DELETE FROM security_alerts")
    conn.commit()