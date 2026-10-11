import sqlite3
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from security_core import (
    DB_PATH,
    EVENT_TYPES,
    DeviceUnavailableError,
    acknowledge_alert,
    add_device,
    generate_event,
    init_db,
    read_table,
    update_device_status,
)


st.set_page_config(
    page_title="Virtual IoT Security",
    page_icon="🔐",
    layout="wide",
)

init_db()

st.sidebar.title("🔐 Security Center")
st.sidebar.caption("Software-only IoT security simulator")
page = st.sidebar.radio(
    "Navigate",
    ["Main Dashboard", "Devices", "Event History", "Alerts"],
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
devices = read_table("devices")
online_devices = devices.loc[
    devices["status"] == "Online", "name"
].tolist()
if online_devices:
    target_device = st.sidebar.selectbox("Target virtual device", online_devices)
    for scenario, button_label in zip(
        EVENT_TYPES,
        [
            "Simulate Normal Telemetry",
            "Simulate Failed Login",
            "Simulate Traffic Spike",
            "Simulate Unknown Destination",
        ],
    ):
        if st.sidebar.button(button_label, use_container_width=True):
            try:
                st.session_state["last_simulation"] = generate_event(
                    scenario,
                    target_device,
                    int(failed_login_limit),
                    int(packet_size_limit),
                )
            except DeviceUnavailableError as exc:
                st.sidebar.error(str(exc))
            st.rerun()
else:
    st.sidebar.warning("Activate a virtual device before simulating events.")

st.title("🔐 Virtual IoT Security Monitoring System")
st.subheader("Main Security Dashboard" if page == "Main Dashboard" else page)
st.caption(
    "Synthetic events only · Local SQLite storage · "
    f"Updated {datetime.now().strftime('%d %b %Y, %H:%M:%S')}"
)
st.info(
    "This educational simulator does not capture real network traffic, "
    "monitor real devices, or block connections."
)

last_simulation = st.session_state.pop("last_simulation", None)
if last_simulation:
    st.success(
        f"{last_simulation['event_type']} recorded for {last_simulation['device']} "
        "in the SQLite event history."
    )
    if last_simulation["severity"] == "CRITICAL":
        st.error(f"CRITICAL security alert: {last_simulation['alert_message']}")
    elif last_simulation["severity"] == "HIGH":
        st.error(f"HIGH security alert: {last_simulation['alert_message']}")
    elif last_simulation["severity"] == "MEDIUM":
        st.warning(f"MEDIUM security alert: {last_simulation['alert_message']}")
    else:
        st.info("No security alert was triggered; the simulated event met policy.")

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

if page == "Main Dashboard":
    st.markdown("#### Security overview")
    chart_column, alert_column = st.columns(2)
    with chart_column:
        st.markdown("#### Device status")
        status_counts = (
            devices["status"]
            .value_counts()
            .rename_axis("Status")
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
                alerts["severity"]
                .value_counts()
                .rename_axis("Severity")
                .reset_index(name="Alerts")
            )
            st.plotly_chart(
                px.bar(
                    severity_counts,
                    x="Severity",
                    y="Alerts",
                    color="Severity",
                ),
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
            update_device_status(selected_device, selected_status)
            st.success(f"{selected_device} is now {selected_status.lower()}.")
            st.rerun()

    st.markdown("#### Register a virtual device")
    with st.form("add_device_form", clear_on_submit=True):
        new_name = st.text_input("Device name")
        new_type = st.text_input("Device type")
        new_ip = st.text_input("Simulated IPv4 address")
        add_device_form = st.form_submit_button("Add device")
    if add_device_form:
        try:
            add_device(new_name, new_type, new_ip)
            st.success(f"Added {new_name.strip()} as an online virtual device.")
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))
        except sqlite3.IntegrityError:
            st.error("A device with that name already exists.")

elif page == "Event History":
    st.markdown("#### Security event history")
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
                if acknowledge_alert(int(selected_alert_id)):
                    st.success(f"Alert #{selected_alert_id} acknowledged.")
                    st.rerun()
                st.warning("That alert is already acknowledged.")

st.divider()
st.caption(
    "Security decisions are based on the synthetic events and policy thresholds "
    "shown here; this application does not secure or monitor physical devices."
)
