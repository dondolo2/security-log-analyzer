"""Account-attack rule.

Signal: one IP accumulates >= N DISTINCT usernames as LOGIN_FAILED
targets inside a sliding window.

Different shape from brute force: brute force is about volume against
one target, this is about breadth against many. Both come from
LOGIN_FAILED, but the grouping key and the counter differ — which is
why they're separate rules, not one rule with a flag.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from analyzer.alerts import Alert


def detect(events: list[dict], config: dict) -> list[Alert]:
    threshold = config["max_distinct_usernames"]
    window = timedelta(minutes=config["time_window_minutes"])
    severity = config["severity"]

    failures = [e for e in events if e["event"] == "LOGIN_FAILED"]

    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in failures:
        by_ip[e["ip_address"]].append(e)

    alerts: list[Alert] = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["timestamp"])

        i = 0
        while i < len(evs):
            window_end = evs[i]["timestamp"] + window

            j = i
            while j < len(evs) and evs[j]["timestamp"] < window_end:
                j += 1

            distinct = {evs[k]["username"] for k in range(i, j)}
            if len(distinct) >= threshold:
                alerts.append(Alert(
                    alert_type="ACCOUNT_ATTACK",
                    # Deliberate: no single target user, the IP is the
                    # subject. A reviewer asking "which user was attacked?"
                    # gets "all of them, that's the point".
                    username=None,
                    severity=severity,
                    ip_address=ip,
                    first_seen=evs[i]["timestamp"],
                    last_seen=evs[j - 1]["timestamp"],
                    event_count=j - i,
                    details={
                        "threshold": threshold,
                        "window_minutes": config["time_window_minutes"],
                        "distinct_usernames": sorted(distinct),
                    },
                ))
                i = j
            else:
                i += 1

    return alerts