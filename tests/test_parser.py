"""Parser tests.

These test failure modes first. The happy path is one test; the
rejection paths are seven. That ratio is deliberate — the parser's
job is to say no to bad input, and the bad input is where the bugs live.
"""
from datetime import datetime
from pathlib import Path

import pytest

from analyzer.parser.log_parser import parse_line, parse_file


SOURCE = "test.log"
VALID = "2026-09-13 10:01:32 LOGIN_FAILED user=musa ip=192.168.1.20"


# ---------- happy path ----------

def test_parses_valid_login_failed():
    event = parse_line(VALID, SOURCE)
    assert event is not None
    assert event["timestamp"] == datetime(2026, 9, 13, 10, 1, 32)
    assert event["event"] == "LOGIN_FAILED"
    assert event["username"] == "musa"
    assert event["ip_address"] == "192.168.1.20"
    assert event["source_file"] == SOURCE
    assert event["raw_line"] == VALID


def test_parses_valid_login_success():
    line = "2026-09-13 10:02:10 LOGIN_SUCCESS user=musa ip=192.168.1.20"
    event = parse_line(line, SOURCE)
    assert event is not None
    assert event["event"] == "LOGIN_SUCCESS"


# ---------- whitespace handling ----------

def test_tolerates_extra_internal_whitespace():
    line = "2026-09-13 10:01:32   LOGIN_FAILED   user=musa   ip=192.168.1.20"
    event = parse_line(line, SOURCE)
    assert event is not None
    assert event["username"] == "musa"


def test_tolerates_trailing_newline_and_whitespace():
    line = "2026-09-13 10:01:32 LOGIN_FAILED user=musa ip=192.168.1.20\n"
    event = parse_line(line, SOURCE)
    assert event is not None
    assert event["raw_line"] == line.rstrip("\n")


def test_preserves_raw_line_including_internal_spacing():
    line = "2026-09-13 10:01:32   LOGIN_FAILED   user=musa   ip=192.168.1.20"
    event = parse_line(line, SOURCE)
    assert event is not None
    assert event["raw_line"] == line


# ---------- rejection paths ----------

@pytest.mark.parametrize("bad", [
    "",
    "   ",
    "\n",
    "not a log line at all",
    # missing ip
    "2026-09-13 10:01:32 LOGIN_FAILED user=musa",
    # missing user
    "2026-09-13 10:01:32 LOGIN_FAILED ip=192.168.1.20",
    # missing event
    "2026-09-13 10:01:32 user=musa ip=192.168.1.20",
    # impossible month
    "2026-13-13 10:01:32 LOGIN_FAILED user=musa ip=192.168.1.20",
    # impossible hour
    "2026-09-13 25:01:32 LOGIN_FAILED user=musa ip=192.168.1.20",
    # unknown event
    "2026-09-13 10:01:32 LOGIN user=musa ip=192.168.1.20",
    # wrong timestamp separator (ISO 8601 'T')
    "2026-09-13T10:01:32 LOGIN_FAILED user=musa ip=192.168.1.20",
    # extra trailing garbage
    "2026-09-13 10:01:32 LOGIN_FAILED user=musa ip=192.168.1.20 extra",
])
def test_rejects_malformed_lines(bad):
    assert parse_line(bad, SOURCE) is None


# ---------- file-level behaviour ----------

def test_parse_file_keeps_valid_and_skips_malformed(tmp_path: Path):
    log = tmp_path / "mixed.log"
    log.write_text(
        "2026-09-13 10:01:32 LOGIN_FAILED user=musa ip=192.168.1.20\n"
        "this is not a log line\n"
        "2026-09-13 10:01:45 LOGIN_FAILED user=musa ip=192.168.1.20\n"
        "\n"
        "2026-09-13 10:02:10 LOGIN_SUCCESS user=musa ip=192.168.1.20\n",
        encoding="utf-8",
    )
    events = parse_file(log)
    assert len(events) == 3
    assert [e["event"] for e in events] == [
        "LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_SUCCESS",
    ]
    assert all(e["source_file"] == "mixed.log" for e in events)


def test_parse_file_returns_empty_for_all_garbage(tmp_path: Path):
    log = tmp_path / "junk.log"
    log.write_text("nope\nstill nope\n", encoding="utf-8")
    assert parse_file(log) == []