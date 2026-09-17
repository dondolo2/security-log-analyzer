from datetime import datetime, timedelta

from analyzer.detection import engine
from helpers import fail, ok

T0 = datetime(2026, 9, 13, 10, 0, 0)


def _full_config() -> dict:
    return {
        "brute_force": {
            "max_failed_logins": 5, "time_window_minutes": 2, "severity": "HIGH",
        },
        "account_attack": {
            "max_distinct_usernames": 5, "time_window_minutes": 5, "severity": "HIGH",
        },
        "suspicious_login": {
            "failure_burst_threshold": 3, "lookback_minutes": 5, "severity": "MEDIUM",
        },
    }


def _t(seconds: int) -> datetime:
    return T0 + timedelta(seconds=seconds)


def test_no_alerts_on_empty_input():
    assert engine.run_detection([], _full_config()) == []


def test_rules_run_independently_on_same_input():
    # 5 failures + a success from one IP triggers BOTH brute force and
    # suspicious login. Proves the engine runs all rules, not short-circuits.
    events = (
        [fail(_t(i * 5), "musa", "1.1.1.1") for i in range(5)]
        + [ok(_t(30), "musa", "1.1.1.1")]
    )
    alerts = engine.run_detection(events, _full_config())
    types = {a.alert_type for a in alerts}
    assert types == {"BRUTE_FORCE", "SUSPICIOUS_LOGIN"}


def test_missing_rule_config_is_skipped_not_crashed():
    partial = {"brute_force": _full_config()["brute_force"]}
    events = [fail(_t(i * 5), "musa", "1.1.1.1") for i in range(5)]
    alerts = engine.run_detection(events, partial)
    assert [a.alert_type for a in alerts] == ["BRUTE_FORCE"]


def test_one_broken_rule_does_not_stop_others(monkeypatch):
    def boom(events, config):
        raise RuntimeError("boom")

    monkeypatch.setattr(engine, "RULES", (
        ("broken", boom),
        ("brute_force", engine.brute_force.detect),
    ))
    events = [fail(_t(i * 5), "musa", "1.1.1.1") for i in range(5)]
    alerts = engine.run_detection(events, _full_config())
    assert [a.alert_type for a in alerts] == ["BRUTE_FORCE"]