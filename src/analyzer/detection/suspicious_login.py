"""Suspicious-login rule.

Signal: a LOGIN_SUCCESS from an IP that has produced >= N LOGIN_FAILED
events in the preceding lookback window.

Keyed on IP, not (username, ip). Rationale: the classic attack is a
burst of failures followed by a success — and the burst may have been
aimed at other usernames. If we keyed on (username, ip), a burst that
tried alice/bob/carol and then succeeded as dave would be invisible.

This is also the rule with the documented false positive: a user who
mistypes their password three times and then gets it right produces
exactly the same pattern. See docs/decisions.md point 5.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from analyzer.alerts import Alert


def detect(events: list[dict], config: dict) -> list[Alert]:
    threshold = config["failure_burst_threshold"]
    lookback = timedelta(minutes=config["lookback_minutes"])
    severity = config["severity"]

    # Index failures by IP once, up front. Naive scanning would be
    # O(successes * failures); this is O(failures) + O(successes * k)
    # where k is the failures-per-IP average.
    failures_by_ip: dict[str, list[datetime]] = defaultdict(list)
    for e in events:
        if e["event"] == "LOGIN_FAILED":
            failures_by_ip[e["ip_address"]].append(e["timestamp"])

    for ts_list in failures_by_ip.values():
        ts_list.sort()

    alerts: list[Alert] = []
    for e in events:
        if e["event"] != "LOGIN_SUCCESS":
            continue

        ip = e["ip_address"]
        success_ts = e["timestamp"]
        window_start = success_ts - lookback

        prior = [
            t for t in failures_by_ip.get(ip, [])
            if window_start <= t <= success_ts
        ]
        if len(prior) < threshold:
            continue

        alerts.append(Alert(
            alert_type="SUSPICIOUS_LOGIN",
            severity=severity,
            ip_address=ip,
            # The success is the concrete fact worth surfacing. The
            # burst may have been against other users; that's what
            # `details.failure_count` and the BRUTE_FORCE rule cover.
            username=e["username"],
            first_seen=prior[0],
            last_seen=success_ts,
            event_count=len(prior) + 1,   # failures + the success
            details={
                "threshold": threshold,
                "lookback_minutes": config["lookback_minutes"],
                "failure_count": len(prior),
            },
        ))

    return alerts