from datetime import datetime, timedelta

from analyzer.detection import account_attack
from helpers import fail, ok

T0 = datetime(2026, 9, 13, 10, 0, 0)


def cfg(**over):
    base = {"max_distinct_usernames": 5, "time_window_minutes": 5, "severity": "HIGH"}
    base.update(over)
    return base


def sec(n: int) -> datetime:
    return T0 + timedelta(seconds=n)


def test_no_alert_below_threshold():
    events = [fail(sec(i * 10), f"user{i}", "1.1.1.1") for i in range(4)]
    assert account_attack.detect(events, cfg()) == []


def test_fires_at_threshold():
    events = [fail(sec(i * 10), f"user{i}", "1.1.1.1") for i in range(5)]
    alerts = account_attack.detect(events, cfg())
    assert len(alerts) == 1
    a = alerts[0]
    assert a.alert_type == "ACCOUNT_ATTACK"
    assert a.ip_address == "1.1.1.1"
    # No single target user — the IP is the subject.
    assert a.username is None
    assert a.event_count == 5
    assert a.details["distinct_usernames"] == ["user0", "user1", "user2", "user3", "user4"]


def test_repeated_attempts_on_same_user_do_not_count_as_distinct():
    # 10 failures, all for musa. One distinct username. No alert.
    events = [fail(sec(i * 5), "musa", "1.1.1.1") for i in range(10)]
    assert account_attack.detect(events, cfg()) == []


def test_no_alert_when_attempts_spread_beyond_window():
    # 5 distinct users, one every 10 minutes. Window is 5 minutes.
    events = [
        fail(T0 + timedelta(minutes=i * 10), f"user{i}", "1.1.1.1")
        for i in range(5)
    ]
    assert account_attack.detect(events, cfg()) == []


def test_distinct_ips_fire_independently():
    events = (
        [fail(sec(i * 10), f"a{i}", "1.1.1.1") for i in range(5)]
        + [fail(sec(i * 10), f"b{i}", "2.2.2.2") for i in range(5)]
    )
    alerts = account_attack.detect(events, cfg())
    assert len(alerts) == 2
    assert {a.ip_address for a in alerts} == {"1.1.1.1", "2.2.2.2"}


def test_successes_are_ignored():
    events = (
        [fail(sec(i * 5), f"user{i}", "1.1.1.1") for i in range(5)]
        + [ok(sec(50), "user5", "1.1.1.1")]
    )
    alerts = account_attack.detect(events, cfg())
    assert len(alerts) == 1
    # The success is NOT included in the count.
    assert alerts[0].event_count == 5


def test_empty_events():
    assert account_attack.detect([], cfg()) == []