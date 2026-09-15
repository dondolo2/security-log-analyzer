"""Shared event constructors for detection tests.

Three-line helpers, but used in four test files. Duplicating them would
mean four places to update if the event dict shape ever changes — which
it will, once storage lands on Day 3.
"""
from datetime import datetime


def fail(ts: datetime, user: str, ip: str) -> dict:
    return {
        "timestamp": ts,
        "event": "LOGIN_FAILED",
        "username": user,
        "ip_address": ip,
        "raw_line": f"{ts} LOGIN_FAILED user={user} ip={ip}",
        "source_file": "test.log",
    }


def ok(ts: datetime, user: str, ip: str) -> dict:
    return {
        "timestamp": ts,
        "event": "LOGIN_SUCCESS",
        "username": user,
        "ip_address": ip,
        "raw_line": f"{ts} LOGIN_SUCCESS user={user} ip={ip}",
        "source_file": "test.log",
    }