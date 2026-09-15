"""Detection engine: load config, fan out to rules, collect alerts.

The engine knows nothing about rule internals. Adding a rule is:
    1. write the module with a `detect(events, rule_config)` function
    2. add it to RULES below
    3. add its config block to config/detection.yaml
"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml

from analyzer.alerts import Alert
from analyzer.detection import account_attack, brute_force, suspicious_login

logger = logging.getLogger(__name__)

# Order is not significant for correctness — rules are independent.
# It IS significant for output stability, so tests can rely on it.
RULES = (
    ("brute_force", brute_force.detect),
    ("account_attack", account_attack.detect),
    ("suspicious_login", suspicious_login.detect),
)


def load_config(path: str | Path) -> dict:
    """Load detection config from YAML.

    Missing file or bad YAML should raise — the pipeline cannot run
    without thresholds, and silently falling back to defaults is exactly
    the kind of hidden behaviour that produces wrong alerts at 3am.
    """
    with Path(path).open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def run_detection(events: list[dict], config: dict) -> list[Alert]:
    """Run every registered rule against `events`.

    If one rule raises, the others still run. Rationale: in production,
    one broken rule should not blind the detector. In development, the
    traceback is logged at ERROR and the failing test catches it. Both
    audiences are served.
    """
    alerts: list[Alert] = []
    for name, rule_fn in RULES:
        rule_config = config.get(name)
        if rule_config is None:
            logger.warning("No config block for rule %r — skipping", name)
            continue
        try:
            alerts.extend(rule_fn(events, rule_config))
        except Exception:
            logger.exception("Rule %r raised — skipping", name)
    return alerts