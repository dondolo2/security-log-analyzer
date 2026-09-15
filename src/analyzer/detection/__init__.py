"""Detection rules.

Contract: every rule module exposes

    detect(events: list[dict], rule_config: dict) -> list[Alert]

`events` come from the parser. `rule_config` is the sub-dict of
config/detection.yaml named after the rule. Rules are pure: same input,
same output, no I/O, no globals. That's what makes boundary tests one-liners.
"""