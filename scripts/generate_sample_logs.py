"""Generate synthetic log files with known scenarios.

Why synthetic logs?
    Real formats (syslog, nginx, Windows Event Log) each need their own
    parser. One correct parser + detector demonstrates more than three
    half-broken ones. See docs/decisions.md.

Determinism
    Fixed base timestamp. No randomness. Every run produces byte-identical
    files, so sample_logs/expected_alerts.json stays true across runs.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

BASE_TIME = datetime(2026, 9, 13, 10, 0, 0)
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "sample_logs"


def _line(ts: datetime, event: str, user: str, ip: str) -> str:
    return f"{ts.strftime('%Y-%m-%d %H:%M:%S')} {event} user={user} ip={ip}"


def brute_force_scenario() -> list[str]:
    """14 failures, one user, one IP, ~104 seconds -> 1 BRUTE_FORCE alert."""
    return [
        _line(BASE_TIME + timedelta(seconds=i * 8),
              "LOGIN_FAILED", "musa", "192.168.1.20")
        for i in range(14)
    ]


def account_attack_scenario() -> list[str]:
    """10 distinct usernames from one IP over 4.5 min -> 1 ACCOUNT_ATTACK alert."""
    return [
        _line(BASE_TIME + timedelta(seconds=i * 30),
              "LOGIN_FAILED", f"user{i:02d}", "10.0.0.5")
        for i in range(10)
    ]


def normal_traffic_scenario() -> list[str]:
    """Scattered failures and successes across different users/IPs -> 0 alerts."""
    return [
        _line(BASE_TIME + timedelta(minutes=5),  "LOGIN_FAILED",  "alice", "192.168.1.40"),
        _line(BASE_TIME + timedelta(minutes=10), "LOGIN_SUCCESS", "alice", "192.168.1.40"),
        _line(BASE_TIME + timedelta(minutes=15), "LOGIN_FAILED",  "bob",   "192.168.1.41"),
        _line(BASE_TIME + timedelta(minutes=20), "LOGIN_SUCCESS", "bob",   "192.168.1.41"),
        _line(BASE_TIME + timedelta(minutes=25), "LOGIN_FAILED",  "carol", "192.168.1.42"),
        _line(BASE_TIME + timedelta(minutes=30), "LOGIN_SUCCESS", "carol", "192.168.1.42"),
    ]


def borderline_scenario() -> list[str]:
    """4 failures -- one below the 5-failure threshold -> 0 alerts.

    This is the scenario that matters most. It proves the rule uses '>='
    and not '>', and that the detector is not just firing on any failure.
    """
    return [
        _line(BASE_TIME + timedelta(seconds=i * 10),
              "LOGIN_FAILED", "fatima", "192.168.1.30")
        for i in range(4)
    ]


SCENARIOS = {
    "brute_force.log": brute_force_scenario,
    "account_attack.log": account_attack_scenario,
    "normal.log": normal_traffic_scenario,
    "borderline.log": borderline_scenario,
}


def main() -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)
    for filename, scenario in SCENARIOS.items():
        lines = scenario()
        path = OUTPUT_DIR / filename
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"wrote {path} ({len(lines)} lines)")


if __name__ == "__main__":
    main()