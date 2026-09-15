from datetime import datetime, timedelta

from analyzer.detection import brute_force
from helpers import fail, ok

T0 = datetime(2026, 9, 13, 10, 0, 0)


def cfg(**over):
    base = {"max_failed_logins": 5, "time_window_minutes": 2, "severity": "HIGH"}
    base.update(over)
    return base


def sec(n: int) -> datetime:
    return T0 + timedelta(seconds=n)


# --- threshold boundaries ---------------------------------------------

def test_no_alert_below_threshold():
    events = [fail(sec(i * 10), "musa", "1.1.1.1") for i in range(4)]
    assert brute_force.detect(events, cfg()) == []


def test_fires_at_threshold():
    events = [fail(sec(i * 10), "musa", "1.1.1.1") for i in range(5)]
    alerts = brute_force.detect(events, cfg())
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_type == "BRUTE_FORCE"
    assert a.ip_address == "1.1.1.1"
    assert a.username == "musa"
    assert a.severity == "HIGH"
    assert a.event_count == 5


def test_threshold_is_configurable():
    # Same data, two thresholds, two outcomes. Proves the rule reads
    # config rather than a hardcoded constant.
    events = [fail(sec(i * 5), "musa", "1.1.1.1") for i in range(3)]
    assert brute_force.detect(events, cfg(max_failed_logins=3)) != []
    assert brute_force.detect(events, cfg(max_failed_logins=4)) == []


# --- time boundaries ---------------------------------------------------

def test_no_alert_when_failures_spread_beyond_window():
    # 5 failures, one per hour, threshold is 5. Window is 2 minutes.
    events = [fail(T0 + timedelta(hours=i), "musa", "1.1.1.1") for i in range(5)]
    assert brute_force.detect(events, cfg()) == []


# --- burst collapsing --------------------------------------------------

def test_burst_collapses_to_single_alert():
    # 14 failures in 104 seconds -> 1 alert, not 14.
    events = [fail(sec(i * 8), "musa", "1.1.1.1") for i in range(14)]
    alerts = brute_force.detect(events, cfg())
    assert len(alerts) == 1
    assert alerts[0].event_count == 14


def test_two_bursts_long_apart_produce_two_alerts():
    # Same (user, ip), two separated bursts. Each is its own incident.
    burst1 = [fail(sec(i * 5), "musa", "1.1.1.1") for i in range(5)]
    burst2 = [
        fail(T0 + timedelta(hours=1, seconds=i * 5), "musa", "1.1.1.1")
        for i in range(5)
    ]
    assert len(brute_force.detect(burst1 + burst2, cfg())) == 2


# --- grouping key ------------------------------------------------------

def test_same_user_different_ips_produce_separate_alerts():
    events = (
        [fail(sec(i * 5), "musa", "1.1.1.1") for i in range(5)]
        + [fail(sec(i * 5), "musa", "2.2.2.2") for i in range(5)]
    )
    alerts = brute_force.detect(events, cfg())
    assert len(alerts) == 2
    assert {a.ip_address for a in alerts} == {"1.1.1.1", "2.2.2.2"}


def test_failures_split_across_ips_do_not_alert():
    # 3 + 2 from two different IPs, same user. Neither IP reaches 5.
    # This is the test that proves grouping is by (user, ip), not user.
    events = (
        [fail(sec(i * 5), "musa", "1.1.1.1") for i in range(3)]
        + [fail(sec(i * 5), "musa", "2.2.2.2") for i in range(2)]
    )
    assert brute_force.detect(events, cfg()) == []


def test_same_ip_different_users_produce_separate_alerts():
    events = (
        [fail(sec(i * 5), "musa", "1.1.1.1") for i in range(5)]
        + [fail(sec(i * 5), "alice", "1.1.1.1") for i in range(5)]
    )
    alerts = brute_force.detect(events, cfg())
    assert len(alerts) == 2
    assert {a.username for a in alerts} == {"musa", "alice"}


# --- event-type filtering ---------------------------------------------

def test_successes_do_not_count_toward_threshold():
    events = (
        [fail(sec(i * 5), "musa", "1.1.1.1") for i in range(4)]
        + [ok(sec(25), "musa", "1.1.1.1")]
    )
    assert brute_force.detect(events, cfg()) == []


def test_empty_events():
    assert brute_force.detect([], cfg()) == []