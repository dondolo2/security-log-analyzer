-- Schema for security-log-analyzer.
--
-- On types:
--   SQLite has no native TIMESTAMP, BOOLEAN, or JSON. TIMESTAMP and TEXT
--   are declared for documentation. Datetimes are written as ISO-8601 with
--   a space separator ('2026-09-13 10:00:00') so lexicographic comparison
--   matches chronological order and SQLite's TEXT storage sorts correctly.
--
-- On NULL vs '' in security_alerts.username:
--   A username of '' means "not applicable" — e.g. an ACCOUNT_ATTACK
--   alert has no single target user, the IP is the subject.
--   NULL is deliberately avoided in this column. SQLite treats NULLs as
--   DISTINCT inside UNIQUE constraints, so a nullable username would let
--   re-running detection duplicate every ACCOUNT_ATTACK alert. Making the
--   column NOT NULL DEFAULT '' makes the constraint work as intended.
--   This is tested in test_account_attack_alert_dedupes_despite_null_username.
--
-- Idempotency keys:
--   security_events: (timestamp, event, username, ip_address, source_file)
--     — the same raw line in the same file is one event, always.
--   security_alerts: (alert_type, ip_address, username, first_seen)
--     — a re-run on the same input computes the same first_seen and
--       updates the existing row. A NEW attack later computes a different
--       first_seen and gets a new row. Both behaviours are required.

CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TIMESTAMP NOT NULL,
    event       TEXT      NOT NULL,
    username    TEXT      NOT NULL,
    ip_address  TEXT      NOT NULL,
    raw_line    TEXT,
    source_file TEXT      NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(timestamp, event, username, ip_address, source_file)
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip        ON security_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_events_event     ON security_events(event);

CREATE TABLE IF NOT EXISTS security_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type  TEXT      NOT NULL,
    severity    TEXT      NOT NULL,
    ip_address  TEXT      NOT NULL,
    username    TEXT      NOT NULL DEFAULT '',
    first_seen  TIMESTAMP NOT NULL,
    last_seen   TIMESTAMP NOT NULL,
    event_count INTEGER   NOT NULL,
    details     TEXT,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(alert_type, ip_address, username, first_seen)
);

CREATE INDEX IF NOT EXISTS idx_alerts_type     ON security_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_ip       ON security_alerts(ip_address);