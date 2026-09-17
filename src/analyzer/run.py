"""CLI entrypoint: parse logs, detect, store. Idempotent.

    python -m analyzer.run --logs sample_logs --config config/detection.yaml

Re-running this command with the same inputs produces the same database
state. That's the contract — same idempotency guarantee the DE project
made, applied here.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from analyzer.detection.engine import load_config, run_detection
from analyzer.parser.log_parser import parse_file
from analyzer.storage import db

logger = logging.getLogger("analyzer")


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def process_log_file(path: Path, config: dict, conn) -> tuple[int, int, int]:
    """Parse, detect, store one file. Returns (parsed, new_events, alerts)."""
    events = parse_file(path)
    alerts = run_detection(events, config)
    new_events = db.insert_events(conn, events)
    db.upsert_alerts(conn, alerts)
    return len(events), new_events, len(alerts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description="Parse log files, detect patterns, store results.",
    )
    parser.add_argument("--logs", default="sample_logs",
                        help="Directory containing .log files (default: sample_logs)")
    parser.add_argument("--config", default="config/detection.yaml",
                        help="Path to detection config YAML")
    parser.add_argument("--db-path", default="data/security.db",
                        help="SQLite database path (default: data/security.db)")
    parser.add_argument("--log-level", default="INFO",
                        help="DEBUG, INFO, WARNING, ERROR (default: INFO)")
    parser.add_argument("--reset", action="store_true",
                        help="Delete all rows before running. Reproducible demos.")
    args = parser.parse_args(argv)

    configure_logging(args.log_level)

    logs_dir = Path(args.logs)
    if not logs_dir.is_dir():
        logger.error("Logs directory not found: %s", logs_dir)
        return 1

    log_files = sorted(logs_dir.glob("*.log"))
    if not log_files:
        logger.error("No .log files in %s", logs_dir)
        return 1

    config = load_config(args.config)
    conn = db.connect(args.db_path)
    db.init_db(conn)

    if args.reset:
        logger.info("Resetting database at %s", args.db_path)
        db.reset(conn)

    total_parsed = total_new = total_alerts = 0
    print(f"{'file':<28} {'parsed':>8} {'new':>8} {'alerts':>8}")
    print("-" * 56)

    for path in log_files:
        parsed, new, alerts = process_log_file(path, config, conn)
        total_parsed += parsed
        total_new += new
        total_alerts += alerts
        print(f"{path.name:<28} {parsed:>8} {new:>8} {alerts:>8}")

    print("-" * 56)
    print(f"{'TOTAL':<28} {total_parsed:>8} {total_new:>8} {total_alerts:>8}")
    print()
    print(f"Database: {args.db_path}")
    print(f"  events: {db.count_events(conn)}")
    print(f"  alerts: {db.count_alerts(conn)}")

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())