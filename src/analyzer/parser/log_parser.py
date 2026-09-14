"""Raw log line -> structured event dict.

Log format (v1) is fully controlled by scripts/generate_sample_logs.py:

    2026-09-13 10:01:32 LOGIN_FAILED user=musa ip=192.168.1.20

Why this format and not syslog / JSON / nginx?
    See docs/decisions.md. Short version: one correct parser + detector
    demonstrates more than three half-built parsers.

Contract
    parse_line() returns a dict on success and None on any malformed input.
    It does not raise. The caller decides how to log, skip, or count bad
    lines — parser shouldn't own pipeline policy.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Events the parser accepts. Anything else is rejected as malformed —
# this is intentional. Adding new event types should be a deliberate
# edit, not an accidental acceptance of whatever appears in a log file.
KNOWN_EVENTS = frozenset({"LOGIN_FAILED", "LOGIN_SUCCESS"})

_TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"

# Anchored on both ends. Optional trailing whitespace, required single
# space between fields. `\s+` between fields tolerates the extra spaces
# that hand-edited or pasted logs sometimes carry.
_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<event>[A-Z_]+)\s+"
    r"user=(?P<user>\S+)\s+"
    r"ip=(?P<ip>\S+)\s*$"
)


def parse_line(line: str, source_file: str) -> Optional[dict]:
    """Parse one log line.

    Returns a structured event on success, or None if the line is
    malformed (wrong shape, unknown event, invalid timestamp).
    """
    stripped = line.strip()
    if not stripped:
        return None

    match = _LINE_RE.match(stripped)
    if not match:
        return None

    event = match.group("event")
    if event not in KNOWN_EVENTS:
        return None

    try:
        ts = datetime.strptime(match.group("ts"), _TIMESTAMP_FMT)
    except ValueError:
        return None

    return {
        "timestamp": ts,
        "event": event,
        "username": match.group("user"),
        "ip_address": match.group("ip"),
        # Preserve the original for traceability — an alert should be
        # able to point back to the exact line that triggered it.
        "raw_line": line.rstrip("\n"),
        "source_file": source_file,
    }


def parse_file(path: Path) -> list[dict]:
    """Parse every line of `path`. Malformed lines are skipped and counted.

    Skips rather than raises because a single bad line in a 100k-line
    file should not lose the other 99,999 events. The count is logged
    so operators can spot a systematic parsing problem.
    """
    path = Path(path)
    events: list[dict] = []
    skipped = 0

    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            event = parse_line(line, source_file=path.name)
            if event is None:
                skipped += 1
                logger.debug("Skipped malformed line %s:%d", path.name, lineno)
                continue
            events.append(event)

    if skipped:
        logger.warning("Skipped %d malformed line(s) in %s", skipped, path.name)

    return events