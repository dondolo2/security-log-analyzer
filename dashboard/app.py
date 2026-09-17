"""Streamlit dashboard.

Reads the same SQLite file the CLI writes to. Read-only. No auth, no
writes, no background jobs. See docs/decisions.md §9.

Two charts per tab, maximum. This is a demo, not an ops console.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Security Log Analyzer", layout="wide")

DB_PATH = os.environ.get("DB_PATH", "data/security.db")


@st.cache_data(ttl=5)
def load_events(db_path: str) -> pd.DataFrame:
    if not Path(db_path).exists():
        return pd.DataFrame()
    conn = sqlite3.connect(db_path)
    try:
        df = pd.read_sql_query(
            "SELECT timestamp, event, username, ip_address, source_file "
            "FROM security_events",
            conn,
        )
    finally:
        conn.close()
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


@st.cache_data(ttl=5)
def load_alerts(db_path: str) -> pd.DataFrame:
    if not Path(db_path).exists():
        return pd.DataFrame()
    conn = sqlite3.connect(db_path)
    try:
        df = pd.read_sql_query("SELECT * FROM security_alerts", conn)
    finally:
        conn.close()
    if not df.empty:
        df["first_seen"] = pd.to_datetime(df["first_seen"])
        df["last_seen"] = pd.to_datetime(df["last_seen"])
    return df


def main() -> None:
    st.title("Security Log Analyzer")

    events = load_events(DB_PATH)
    alerts = load_alerts(DB_PATH)

    if events.empty and alerts.empty:
        st.warning(
            f"No data found at `{DB_PATH}`. Run the pipeline first:\n\n"
            "```\npython -m analyzer.run --reset\n```"
        )
        return

    # --- metric row (shared, above tabs) -------------------------------

    failed = events[events["event"] == "LOGIN_FAILED"] if not events.empty else events
    critical_high = (
        alerts[alerts["severity"].isin(["HIGH", "CRITICAL"])]
        if not alerts.empty else alerts
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total events", len(events))
    c2.metric("Failed logins", len(failed))
    c3.metric("Unique source IPs",
              events["ip_address"].nunique() if not events.empty else 0)
    c4.metric("High + critical alerts", len(critical_high))

    st.divider()

    tab_events, tab_alerts = st.tabs(["Events", "Alerts"])

    # --- tab 1: events --------------------------------------------------

    with tab_events:
        if events.empty:
            st.info("No events.")
        else:
            st.subheader("Events over time")
            series = (
                events.set_index("timestamp")
                .resample("1min").size()
                .rename("events")
            )
            st.line_chart(series, height=260)

            st.subheader("Failed logins by IP (top 10)")
            top_ips = (
                failed.groupby("ip_address").size()
                .sort_values(ascending=False).head(10)
                .rename("failures")
            )
            st.bar_chart(top_ips, height=260)

    # --- tab 2: alerts --------------------------------------------------

    with tab_alerts:
        if alerts.empty:
            st.info("No alerts.")
        else:
            left, right = st.columns(2)

            with left:
                st.subheader("Alerts by severity")
                sev = (
                    alerts.groupby("severity").size()
                    .reindex(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
                    .dropna().rename("alerts")
                )
                st.bar_chart(sev, height=260)

            with right:
                st.subheader("Most targeted accounts")
                targeted = (
                    alerts[alerts["username"] != ""]
                    .groupby("username").size()
                    .sort_values(ascending=False).head(10)
                    .rename("alerts")
                )
                if targeted.empty:
                    st.caption("No alerts with a specific target account.")
                else:
                    st.bar_chart(targeted, height=260)

            st.subheader("Alert list")
            display = alerts[[
                "alert_type", "severity", "ip_address", "username",
                "first_seen", "last_seen", "event_count",
            ]].sort_values("first_seen", ascending=False)
            st.dataframe(display, use_container_width=True, hide_index=True)

            with st.expander("Rule-specific details"):
                for _, row in alerts.iterrows():
                    detail = row.get("details")
                    if isinstance(detail, str):
                        try:
                            detail = json.loads(detail)
                        except json.JSONDecodeError:
                            detail = {"raw": detail}
                    label = f"{row['alert_type']} · {row['ip_address']} · {row['first_seen']}"
                    st.markdown(f"**{label}**")
                    st.json(detail or {})


if __name__ == "__main__":
    main()