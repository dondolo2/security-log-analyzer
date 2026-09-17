"""Storage tests.

The important tests here are the idempotency ones. Anyone can write to
SQLite. The hard part is: does running the pipeline twice produce the
same database as running it once?
"""
from datetime import datetime, timedelta

import pytest

from analyzer.alerts import Alert
from analyzer.storage import db
from helpers import fail

T0 = datetime(2026, 9, 13, 10, 0, 0)


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "test.db")
    db.init_db(c)
    yield c
    c.close()


def _brute_force_alert(first_seen=T0, last_seen=T0 + timedelta(seconds=40),
                       event_count=5, username="musa", ip="1.1.1.1"):
    return Alert(
        alert_type="BRUTE_FORCE",
        severity="HIGH",
        ip_address=ip,
        username=username,
        first_seen=first_seen,
        last_seen=last_seen,
        event_count=event_count,
        details={"threshold": 5, "window_minutes": 2},
    )


# ---------- schema -----------------------------------------------------

def test_init_db_is_idempotent(tmp_path):
    c = db.connect(tmp_path / "test.db")
    db.init_db(c)
    db.init_db(c)  # must not raise, must not duplicate anything
    tables = {
        row["name"]
        for row in c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"security_events", "security_alerts"} <= tables
    c.close()


# ---------- event idempotency ------------------------------------------

def test_insert_events_dedupes_on_rerun(conn):
    events = [fail(T0, "musa", "1.1.1.1")]
    assert db.insert_events(conn, events) == 1
    assert db.insert_events(conn, events) == 0   # same input, no new rows
    assert db.count_events(conn) == 1


def test_insert_events_counts_only_new_rows(conn):
    e1 = fail(T0, "musa", "1.1.1.1")
    e2 = fail(T0 + timedelta(seconds=10), "musa", "1.1.1.1")
    assert db.insert_events(conn, [e1]) == 1
    # second call includes e1 again plus a new event — only e2 is new
    assert db.insert_events(conn, [e1, e2]) == 1
    assert db.count_events(conn) == 2


def test_events_from_different_files_are_distinct(conn):
    # Same timestamp/event/user/ip, different source_file. Both should land.
    a = fail(T0, "musa", "1.1.1.1")
    b = dict(a, source_file="other.log")
    db.insert_events(conn, [a, b])
    assert db.count_events(conn) == 2


# ---------- alert idempotency ------------------------------------------

def test_upsert_alerts_does_not_duplicate_on_rerun(conn):
    a = _brute_force_alert()
    db.upsert_alerts(conn, [a])
    db.upsert_alerts(conn, [a])
    assert db.count_alerts(conn) == 1


def test_upsert_alerts_updates_counts_when_burst_grows(conn):
    # Same identity (same first_seen), richer data on the second run.
    a1 = _brute_force_alert(event_count=5, last_seen=T0 + timedelta(seconds=40))
    a2 = _brute_force_alert(event_count=14, last_seen=T0 + timedelta(seconds=104))
    db.upsert_alerts(conn, [a1])
    db.upsert_alerts(conn, [a2])

    rows = conn.execute("SELECT * FROM security_alerts").fetchall()
    assert len(rows) == 1
    assert rows[0]["event_count"] == 14
    assert rows[0]["last_seen"] == "2026-09-13 10:01:44"


def test_account_attack_alert_dedupes_despite_null_username(conn):
    """The SQLite NULL-in-UNIQUE trap.

    ACCOUNT_ATTACK alerts have username=None. If the column were nullable,
    SQLite would treat each (…, NULL, …) tuple as distinct from every
    other, and re-running would duplicate the alert. The column is
    NOT NULL DEFAULT '' precisely to prevent this. This test is here so
    that anyone who "simplifies" the schema back to nullable finds out
    immediately.
    """
    a = Alert(
        alert_type="ACCOUNT_ATTACK",
        severity="HIGH",
        ip_address="10.0.0.5",
        username=None,
        first_seen=T0,
        last_seen=T0 + timedelta(seconds=60),
        event_count=10,
        details={"threshold": 5, "distinct_usernames": ["a", "b", "c", "d", "e"]},
    )
    db.upsert_alerts(conn, [a])
    db.upsert_alerts(conn, [a])
    assert db.count_alerts(conn) == 1


def test_different_alert_types_same_identity_both_land(conn):
    # BRUTE_FORCE and SUSPICIOUS_LOGIN can share (ip, username, first_seen)
    # when a burst triggers both rules. They must be two rows, not one.
    bf = _brute_force_alert()
    sl = Alert(
        alert_type="SUSPICIOUS_LOGIN",
        severity="MEDIUM",
        ip_address="1.1.1.1",
        username="musa",
        first_seen=T0,
        last_seen=T0 + timedelta(seconds=40),
        event_count=6,
        details={"failure_count": 5},
    )
    db.upsert_alerts(conn, [bf, sl])
    assert db.count_alerts(conn) == 2


def test_same_attack_later_creates_new_alert(conn):
    # Same type, same ip, same user, DIFFERENT first_seen — a genuinely
    # new incident two hours later.
    a1 = _brute_force_alert(first_seen=T0, last_seen=T0 + timedelta(seconds=40))
    a2 = _brute_force_alert(
        first_seen=T0 + timedelta(hours=2),
        last_seen=T0 + timedelta(hours=2, seconds=40),
    )
    db.upsert_alerts(conn, [a1, a2])
    assert db.count_alerts(conn) == 2


# ---------- reset ------------------------------------------------------

def test_reset_clears_both_tables(conn):
    db.insert_events(conn, [fail(T0, "musa", "1.1.1.1")])
    db.upsert_alerts(conn, [_brute_force_alert()])
    assert db.count_events(conn) == 1
    assert db.count_alerts(conn) == 1

    db.reset(conn)
    assert db.count_events(conn) == 0
    assert db.count_alerts(conn) == 0