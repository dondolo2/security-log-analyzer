"""Alert domain type.

Lives at the analyzer package root, not under `detection/`, because it's
not a detection-internal concept — the storage layer maps it to
security_alerts columns and the dashboard reads it back. Putting it
under detection/ forced detection modules to import from a peer module
and made the import graph awkward.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Alert:
    """One detection finding.

    Frozen because an Alert is a value, not a mutable record. If a rule
    wants to change one, it constructs a new one. That makes alerts safe
    to hash, compare, and pass between layers without defensive copies.
    """
    alert_type: str
    severity: str
    ip_address: str | None
    username: str | None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    details: dict[str, Any] = field(default_factory=dict)