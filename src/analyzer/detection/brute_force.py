"""Brute-force rule.

Signal: one (username, ip_address) pair accumulates >= N LOGIN_FAILED
events inside a sliding time window.

Design choices worth stating:
- Grouping is by (username, ip), not by username alone. 5 failures
  spread across two IPs is not a brute-force attack from either IP.
- A burst collapses into ONE alert covering the whole burst, not one
  alert per event. 14 failures in 2 minutes is one incident.
- Window is half-open: [start, start + window). A failure exactly at
  start + window is in the NEXT window. This makes the boundary
  unambiguous rather than "depends how you read 'within'".
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from analyzer.alerts import Alert


def detect(events: list[dict], config: dict) -> list[Alert]:
    threshold = config["max_failed_logins"]
    window = timedelta(minutes=config["time_window_minutes"])
    severity = config["severity"]

    failures = [e for e in events if e["event"] == "LOGIN_FAILED"]

    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in failures:
        groups[(e["username"], e["ip_address"])].append(e)

    alerts: list[Alert] = []
    for (username, ip), evs in groups.items():
        evs.sort(key=lambda e: e["timestamp"])

        i = 0
        while i < len(evs):
            window_end = evs[i]["timestamp"] + window

            # Advance j to the first event outside the window.
            j = i
            while j < len(evs) and evs[j]["timestamp"] < window_end:
                j += 1

            count = j - i
            if count >= threshold:
                alerts.append(Alert(
                    alert_type="BRUTE_FORCE",
                    severity=severity,
                    ip_address=ip,
                    username=username,
                    first_seen=evs[i]["timestamp"],
                    last_seen=evs[j - 1]["timestamp"],
                    event_count=count,
                    details={
                        "threshold": threshold,
                        "window_minutes": config["time_window_minutes"],
                    },
                ))
                # Skip past this burst. Two bursts an hour apart are
                # two incidents; overlapping them would collapse them.
                i = j
            else:
                i += 1

    return alerts