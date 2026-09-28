"""End-to-end: generator -> parser -> detection -> storage, against ground truth.

Two tests, both doing real work:

1. test_scenario_matches_ground_truth — parametrised over every scenario.
   Reads sample_logs/expected_alerts.json (hand-authored, committed before
   the detector existed) and asserts detection output matches it exactly.
   If a rule's behaviour changes, this test fails and the diff shows which
   scenario was affected.

2. test_pipeline_is_idempotent_end_to_end — runs the full pipeline twice
   and asserts the database is byte-for-byte equivalent. The unit tests in
   test_storage.py check insert/upsert in isolation; this checks the whole
   loop, where a rule bug, a parser bug, or a storage bug could hide.

No network, no subprocess, no shell. Everything runs in tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from analyzer.detection.engine import load_config, run_detection
from analyzer.parser.log_parser import parse_file
from analyzer.storage import db
from generate_sample_logs import SCENARIOS

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_PATH = REPO_ROOT / "sample_logs" / "expected_alerts.json"
CONFIG_PATH = REPO_ROOT / "config" / "detection.yaml"


def _write_scenario(directory: Path, filename: str) -> Path:
    path = directory / filename
    path.write_text("\n".join(SCENARIOS[filename]()) + "\n", encoding="utf-8")
    return path


def _alert_key(alert) -> tuple[str, str, str]:
    """Normalise an Alert into a comparable tuple.

    None becomes "" so that (str, None, str) and (str, "", str) compare
    equally — the storage layer makes the same normalisation, and the
    ground truth file uses JSON null for 'no username'.
    """
    return (alert.alert_type, alert.ip_address or "", alert.username or "")


def _expected_key(entry: dict) -> tuple[str, str, str]:
    return (entry["alert_type"], entry["ip_address"] or "", entry["username"] or "")


@pytest.mark.parametrize("filename", sorted(SCENARIOS.keys()))
def test_scenario_matches_ground_truth(tmp_path: Path, filename: str):
    expected_all = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    expected = sorted(_expected_key(e) for e in expected_all[filename])

    log = _write_scenario(tmp_path, filename)
    events = parse_file(log)
    alerts = run_detection(events, load_config(CONFIG_PATH))
    actual = sorted(_alert_key(a) for a in alerts)

    assert actual == expected, (
        f"{filename}: detection output did not match ground truth.\n"
        f"  expected: {expected}\n"
        f"  actual:   {actual}"
    )


def test_pipeline_is_idempotent_end_to_end(tmp_path: Path):
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    for name in SCENARIOS:
        _write_scenario(logs_dir, name)

    db_file = tmp_path / "test.db"
    config = load_config(CONFIG_PATH)

    def run_once() -> tuple[int, int, int]:
        conn = db.connect(db_file)
        db.init_db(conn)
        new_events = 0
        for log in sorted(logs_dir.glob("*.log")):
            events = parse_file(log)
            new_events += db.insert_events(conn, events)
            db.upsert_alerts(conn, run_detection(events, config))
        result = (db.count_events(conn), db.count_alerts(conn), new_events)
        conn.close()
        return result

    events_1, alerts_1, new_1 = run_once()
    events_2, alerts_2, new_2 = run_once()

    assert events_1 == events_2, "event count changed on second run"
    assert alerts_1 == alerts_2, "alert count changed on second run"
    assert new_1 == events_1, "first run should have inserted every event"
    assert new_2 == 0, "second run should have inserted nothing new"