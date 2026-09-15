from datetime import datetime, timedelta

from analyzer.detection import suspicious_login
from helpers import fail, ok

T0 = datetime(2026, 9, 13, 10, 0, 0)


def cfg(**over):
    base = {
        "failure_burst_threshold": 3,
        "lookback_minutes": 5,
        "severity": "MEDIUM",
    }
    base.update(over)
    return base


def sec(n: int) -> datetime:
    return T0 + timedelta(seconds=n)


# --- threshold boundaries ---------------------------------------------

def test_fires_on_burst_then_success():
    events = (
        [fail(sec(i * 10), "musa", "1.1.1.1") for i in range(3)]
        + [ok(sec(40), "musa", "1.1.1.1")]
    )
    alerts = suspicious_login.detect(events, cfg())
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_type == "SUSPICIOUS_LOGIN"
    assert a.ip_address == "1.1.1.1"
    assert a.username == "musa"
    assert a.severity == "MEDIUM"
    assert a.details["failure_count"] == 3
    assert a.event_count == 4     # 3 failures + the success


def test_no_alert_below_failure_threshold():
    events = (
        [fail(sec(i * 10), "musa", "1.1.1.1") for i in range(2)]
        + [ok(sec(30), "musa", "1.1.1.1")]
    )
    assert suspicious_login.detect(events, cfg()) == []


# --- time boundaries ---------------------------------------------------

def test_no_alert_when_success_outside_lookback():
    events = (
        [fail(sec(i * 10), "musa", "1.1.1.1") for i in range(3)]
        + [ok(T0 + timedelta(minutes=10), "musa", "1.1.1.1")]
    )
    assert suspicious_login.detect(events, cfg()) == []


def test_failure_outside_lookback_is_not_counted():
    # 3 failures exist, but only the last one falls inside the 5-minute
    # lookback from the success. Without the lookback filter, this would
    # fire. With it, only 1 failure counts, below threshold.
    events = [
        fail(T0, "musa", "1.1.1.1"),                              # t=0s   outside
        fail(T0 + timedelta(seconds=60), "musa", "1.1.1.1"),      # t=60s  outside
        fail(T0 + timedelta(seconds=350), "musa", "1.1.1.1"),     # t=350s inside
        ok(T0 + timedelta(seconds=400), "musa", "1.1.1.1"),       # t=400s
    ]
    assert suspicious_login.detect(events, cfg()) == []


# --- grouping key ------------------------------------------------------

def test_keyed_on_ip_not_user():
    # Burst targets user_a, user_b, user_c; the success is user_d.
    # Same IP. The rule should fire because the burst is the signal,
    # not the target of the burst.
    events = [
        fail(sec(0),  "user_a", "1.1.1.1"),
        fail(sec(10), "user_b", "1.1.1.1"),
        fail(sec(20), "user_c", "1.1.1.1"),
        ok(sec(30),   "user_d", "1.1.1.1"),
    ]
    alerts = suspicious_login.detect(events, cfg())
    assert len(alerts) == 1
    assert alerts[0].username == "user_d"


def test_no_alert_when_success_from_different_ip():
    events = (
        [fail(sec(i * 10), "musa", "1.1.1.1") for i in range(3)]
        + [ok(sec(40), "musa", "9.9.9.9")]
    )
    assert suspicious_login.detect(events, cfg()) == []


# --- documented behaviours --------------------------------------------

def test_typo_then_success_fires_documented_false_positive():
    # 3 failures + success within lookback. This IS the false positive
    # named in docs/decisions.md §5. Asserting it here means any future
    # change to reduce it is a deliberate, visible change to a test —
    # not an accidental behaviour shift.
    events = (
        [fail(sec(i * 5), "alice", "192.168.1.40") for i in range(3)]
        + [ok(sec(20), "alice", "192.168.1.40")]
    )
    assert len(suspicious_login.detect(events, cfg())) == 1


def test_multiple_successes_each_fire():
    # Documented: each success within the lookback of a burst is its
    # own alert. If this turns out to be too noisy in practice, the fix
    # is a real design change (dedupe by burst), not a bug fix.
    events = (
        [fail(sec(i * 5), "musa", "1.1.1.1") for i in range(3)]
        + [ok(sec(30), "musa", "1.1.1.1")]
        + [ok(sec(60), "musa", "1.1.1.1")]
    )
    assert len(suspicious_login.detect(events, cfg())) == 2


def test_empty_events():
    assert suspicious_login.detect([], cfg()) == []