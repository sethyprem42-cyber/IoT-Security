import ipaddress
import random
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st


st.set_page_config(
    page_title="Virtual IoT Security",
    page_icon="🔐",
    layout="wide",
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "iot_security.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

EVENT_TYPES = (
    "Normal telemetry",
    "Failed login",
    "Traffic spike",
    "Unknown destination",
)
DESTINATION_ALLOWLIST = {"local-gateway"}


def connect_db():
    return sqlite3.connect(DB_PATH, timeout=10)


def init_db():
    with connect_db() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                device_type TEXT NOT NULL,
                simulated_ip TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Online'
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                device TEXT NOT NULL,
                event_type TEXT NOT NULL,
                destination TEXT NOT NULL,
                packet_size INTEGER NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                device TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        count = con.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        if count == 0:
            con.executemany(
                """
                INSERT INTO devices (name, device_type, simulated_ip, status)
                VALUES (?, ?, ?, ?)
                """,
                [
                    ("Smart Camera", "Camera", "192.168.1.10", "Online"),
                    ("Smart Bulb", "Lighting", "192.168.1.11", "Online"),
                    ("Temperature Sensor", "Sensor", "192.168.1.12", "Online"),
                    ("Smart Door Lock", "Lock", "192.168.1.13", "Online"),
                    ("Energy Meter", "Meter", "192.168.1.14", "Offline"),
                ],
            )


def read_table(table):
    if table not in {"devices", "events", "alerts"}:
        raise ValueError(f"Unsupported table: {table}")
    with connect_db() as con:
        return pd.read_sql_query(f"SELECT * FROM {table} ORDER BY id DESC", con)


def generate_event(scenario, device, failed_login_limit, packet_size_limit):
    devices = read_table("devices")
    online_devices = devices.loc[devices["status"] == "Online", "name"].tolist()
    if device not in online_devices:
        st.warning("There are no online virtual devices. Activate a device first.")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    destination = "local-gateway"
    packet_size = random.randint(80, 500)
    message = "Normal simulated device activity."

    if scenario == "Failed login":
        packet_size = 120
        message = "A failed login attempt was simulated."
    elif scenario == "Traffic spike":
        packet_size = random.randint(5000, 10000)
        message = "Unusually large simulated traffic was generated."
    elif scenario == "Unknown destination":
        destination = "unapproved-simulated-host"
        message = "The device contacted an unapproved simulated destination."

    severity = "LOW"
    alert_message = None
    if destination not in DESTINATION_ALLOWLIST:
        severity = "HIGH"
        alert_message = message
    elif packet_size > packet_size_limit:
        severity = "MEDIUM"
        alert_message = (
            f"Packet size ({packet_size} bytes) exceeded the "
            f"{packet_size_limit}-byte policy limit."
        )
    elif scenario == "Failed login":
        cutoff = (datetime.now() - timedelta(minutes=15)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        with connect_db() as con:
            event_cursor = con.execute(
                """
                INSERT INTO events
                (timestamp, device, event_type, destination, packet_size, severity, message)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    device,
                    scenario,
                    destination,
                    packet_size,
                    "HIGH",
                    message,
                ),
            )
            failure_count = con.execute(
                """
                SELECT COUNT(*) FROM events
                WHERE device = ? AND event_type = 'Failed login' AND timestamp >= ?
                """,
                (device, cutoff),
            ).fetchone()[0]
            if failure_count >= failed_login_limit:
                severity = "CRITICAL"
                alert_message = (
                    f"{failure_count} failed logins from this device in 15 minutes "
                    f"(policy threshold: {failed_login_limit})."
                )
            else:
                alert_message = (
                    "Failed login attempt simulated. Repeated attempts are monitored."
                )
            con.execute(
                "UPDATE events SET severity = ? WHERE id = ?",
                (severity, event_cursor.lastrowid),
            )
            con.execute(
                """
                INSERT INTO alerts (timestamp, device, severity, message)
                VALUES (?, ?, ?, ?)
                """,
                (timestamp, device, severity, alert_message),
            )
        return

    with connect_db() as con:
        con.execute(
            """
            INSERT INTO events
            (timestamp, device, event_type, destination, packet_size, severity, message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                device,
                scenario,
                destination,
                packet_size,
                severity,
                message,
            ),
        )
        if alert_message:
            con.execute(
                """
                INSERT INTO alerts (timestamp, device, severity, message)
                VALUES (?, ?, ?, ?)
                """,
                (timestamp, device, severity, alert_message),
            )


init_db()

st.sidebar.title("🔐 Security Center")
st.sidebar.caption("Software-only IoT security simulator")
page = st.sidebar.radio(
    "Navigate",
    ["Overview", "Devices", "Event Log", "Alerts"],
)

st.sidebar.divider()
st.sidebar.subheader("Detection policy")
failed_login_limit = st.sidebar.number_input(
    "Failed logins per device in 15 minutes",
    min_value=2,
    max_value=20,
    value=3,
    step=1,
)
packet_size_limit = st.sidebar.number_input(
    "Maximum packet size (bytes)",
    min_value=500,
    max_value=20000,
    value=1500,
    step=500,
)

st.sidebar.divider()
st.sidebar.subheader("Simulate an event")
online_devices = read_table("devices")
online_devices = online_devices.loc[
    online_devices["status"] == "Online", "name"
].tolist()
if online_devices:
    target_device = st.sidebar.selectbox("Target virtual device", online_devices)
    for scenario in EVENT_TYPES:
        if st.sidebar.button(scenario, use_container_width=True):
            generate_event(
                scenario,
                target_device,
                int(failed_login_limit),
                int(packet_size_limit),
            )
            st.rerun()
else:
    st.sidebar.warning("Activate a virtual device before simulating events.")

st.title("🔐 Virtual IoT Security Monitoring System")
st.caption(
    "Synthetic events only · Local SQLite storage · "
    f"Updated {datetime.now().strftime('%d %b %Y, %H:%M:%S')}"
)
st.info(
    "This educational simulator does not capture real network traffic, "
    "monitor real devices, or block connections."
)

devices = read_table("devices")
events = read_table("events")
alerts = read_table("alerts")
online_count = int((devices["status"] == "Online").sum())
pending_alerts = alerts.loc[alerts["acknowledged"] == 0]
critical_alerts = int((pending_alerts["severity"] == "CRITICAL").sum())

metric_columns = st.columns(4)
metric_columns[0].metric("Virtual devices", len(devices))
metric_columns[1].metric("Devices online", online_count)
metric_columns[2].metric("Events recorded", len(events))
metric_columns[3].metric(
    "Unacknowledged alerts",
    len(pending_alerts),
    delta=f"{critical_alerts} critical",
    delta_color="inverse",
)

if page == "Overview":
    st.subheader("Security overview")
    chart_column, alert_column = st.columns(2)
    with chart_column:
        st.markdown("#### Device status")
        status_counts = (
            devices["status"].value_counts().rename_axis("Status")
            .reset_index(name="Devices")
        )
        st.plotly_chart(
            px.pie(status_counts, names="Status", values="Devices"),
            use_container_width=True,
        )
    with alert_column:
        st.markdown("#### Alert severity")
        if alerts.empty:
            st.success("No alerts recorded. Use the sidebar to simulate activity.")
        else:
            severity_counts = (
                alerts["severity"].value_counts().rename_axis("Severity")
                .reset_index(name="Alerts")
            )
            st.plotly_chart(
                px.bar(severity_counts, x="Severity", y="Alerts", color="Severity"),
                use_container_width=True,
            )

    st.markdown("#### Recent events")
    if events.empty:
        st.info("No events yet. Generate a synthetic event from the sidebar.")
    else:
        st.dataframe(events.head(10), use_container_width=True, hide_index=True)

elif page == "Devices":
    st.subheader("Virtual device inventory")
    st.dataframe(devices, use_container_width=True, hide_index=True)

    if not devices.empty:
        st.markdown("#### Update device status")
        with st.form("device_status_form"):
            selected_device = st.selectbox("Device", devices["name"].tolist())
            selected_status = st.selectbox("Status", ["Online", "Offline"])
            update_status = st.form_submit_button("Update status")
        if update_status:
            with connect_db() as con:
                con.execute(
                    "UPDATE devices SET status = ? WHERE name = ?",
                    (selected_status, selected_device),
                )
            st.success(f"{selected_device} is now {selected_status.lower()}.")
            st.rerun()

    st.markdown("#### Register a virtual device")
    with st.form("add_device_form", clear_on_submit=True):
        new_name = st.text_input("Device name")
        new_type = st.text_input("Device type")
        new_ip = st.text_input("Simulated IPv4 address")
        add_device = st.form_submit_button("Add device")
    if add_device:
        name = new_name.strip()
        device_type = new_type.strip()
        try:
            valid_ip = str(ipaddress.IPv4Address(new_ip.strip()))
            if not name or not device_type:
                st.error("Enter both a device name and device type.")
            else:
                with connect_db() as con:
                    con.execute(
                        """
                        INSERT INTO devices (name, device_type, simulated_ip, status)
                        VALUES (?, ?, ?, 'Online')
                        """,
                        (name, device_type, valid_ip),
                    )
                st.success(f"Added {name} as an online virtual device.")
                st.rerun()
        except ipaddress.AddressValueError:
            st.error("Enter a valid IPv4 address, such as 192.168.1.20.")
        except sqlite3.IntegrityError:
            st.error("A device with that name already exists.")

elif page == "Event Log":
    st.subheader("Security event log")
    if events.empty:
        st.info("No events recorded yet. Generate an event from the sidebar.")
    else:
        filter_column, device_column = st.columns(2)
        severity_filter = filter_column.selectbox(
            "Filter by severity",
            ["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        )
        device_filter = device_column.selectbox(
            "Filter by device",
            ["All"] + devices["name"].tolist(),
        )
        filtered_events = events.copy()
        if severity_filter != "All":
            filtered_events = filtered_events[
                filtered_events["severity"] == severity_filter
            ]
        if device_filter != "All":
            filtered_events = filtered_events[
                filtered_events["device"] == device_filter
            ]
        st.dataframe(filtered_events, use_container_width=True, hide_index=True)
        st.download_button(
            "Download filtered events as CSV",
            data=filtered_events.to_csv(index=False).encode("utf-8"),
            file_name="iot_security_events.csv",
            mime="text/csv",
        )
        chart_events = events.copy()
        chart_events["timestamp"] = pd.to_datetime(
            chart_events["timestamp"], errors="coerce"
        )
        st.plotly_chart(
            px.scatter(
                chart_events.sort_values("timestamp"),
                x="timestamp",
                y="packet_size",
                color="severity",
                hover_data=["device", "event_type", "destination"],
                labels={"packet_size": "Simulated packet size (bytes)"},
                title="Synthetic event activity",
            ),
            use_container_width=True,
        )

else:
    st.subheader("Alert management")
    if alerts.empty:
        st.success("No security alerts recorded.")
    else:
        st.write(f"Pending alerts: {len(pending_alerts)}")
        st.dataframe(alerts, use_container_width=True, hide_index=True)
        if not pending_alerts.empty:
            with st.form("acknowledge_form"):
                selected_alert_id = st.selectbox(
                    "Choose an alert to acknowledge",
                    pending_alerts["id"].tolist(),
                )
                acknowledge = st.form_submit_button("Acknowledge alert")
            if acknowledge:
                with connect_db() as con:
                    con.execute(
                        "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                        (int(selected_alert_id),),
                    )
                st.success(f"Alert #{selected_alert_id} acknowledged.")
                st.rerun()

st.divider()
st.caption(
    "Security decisions are based on the synthetic events and policy thresholds "
    "shown here; this application does not secure or monitor physical devices."
)
