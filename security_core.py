"""Database and synthetic detection logic for the security simulator."""

import ipaddress
import random
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "iot_security.db"
EVENT_TYPES = (
    "Normal telemetry",
    "Failed login",
    "Traffic spike",
    "Unknown destination",
)
DESTINATION_ALLOWLIST = {"local-gateway"}
TABLES = {"devices", "events", "alerts"}


class DeviceUnavailableError(ValueError):
    """Raised when an event is requested for a device that is not online."""


def connect_db(db_path=DB_PATH):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(path, timeout=10)


@contextmanager
def database(db_path=DB_PATH):
    con = connect_db(db_path)
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db(db_path=DB_PATH):
    with database(db_path) as con:
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


def read_table(table, db_path=DB_PATH):
    if table not in TABLES:
        raise ValueError(f"Unsupported table: {table}")
    with database(db_path) as con:
        return pd.read_sql_query(f"SELECT * FROM {table} ORDER BY id DESC", con)


def add_device(name, device_type, simulated_ip, db_path=DB_PATH):
    clean_name = name.strip()
    clean_type = device_type.strip()
    if not clean_name or not clean_type:
        raise ValueError("Device name and type are required.")
    try:
        valid_ip = str(ipaddress.IPv4Address(simulated_ip.strip()))
    except ipaddress.AddressValueError as exc:
        raise ValueError("Enter a valid IPv4 address.") from exc

    with database(db_path) as con:
        con.execute(
            """
            INSERT INTO devices (name, device_type, simulated_ip, status)
            VALUES (?, ?, ?, 'Online')
            """,
            (clean_name, clean_type, valid_ip),
        )


def update_device_status(name, status, db_path=DB_PATH):
    if status not in {"Online", "Offline"}:
        raise ValueError("Device status must be Online or Offline.")
    with database(db_path) as con:
        cursor = con.execute(
            "UPDATE devices SET status = ? WHERE name = ?",
            (status, name),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"Device not found: {name}")


def generate_event(
    scenario,
    device,
    failed_login_limit,
    packet_size_limit,
    db_path=DB_PATH,
    now=None,
    rng=None,
):
    if scenario not in EVENT_TYPES:
        raise ValueError(f"Unsupported event type: {scenario}")
    if not isinstance(failed_login_limit, int) or failed_login_limit < 2:
        raise ValueError("Failed-login threshold must be an integer of at least 2.")
    if not isinstance(packet_size_limit, int) or packet_size_limit < 1:
        raise ValueError("Packet-size limit must be a positive integer.")

    current_time = now or datetime.now()
    timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S")
    generator = rng or random

    with database(db_path) as con:
        device_row = con.execute(
            "SELECT status FROM devices WHERE name = ?",
            (device,),
        ).fetchone()
        if device_row is None or device_row[0] != "Online":
            raise DeviceUnavailableError(
                "Select an existing online virtual device."
            )

        destination = "local-gateway"
        packet_size = generator.randint(80, 500)
        message = "Normal simulated device activity."

        if scenario == "Failed login":
            packet_size = 120
            message = "A failed login attempt was simulated."
        elif scenario == "Traffic spike":
            packet_size = generator.randint(5000, 10000)
            message = "Unusually large simulated traffic was generated."
        elif scenario == "Unknown destination":
            destination = "unapproved-simulated-host"
            message = "The device contacted an unapproved simulated destination."

        severity = "LOW"
        alert_message = None

        if destination not in DESTINATION_ALLOWLIST:
            severity = "HIGH"
            alert_message = message
        elif scenario == "Failed login":
            severity = "HIGH"
            cursor = con.execute(
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
            cutoff = (current_time - timedelta(minutes=15)).strftime(
                "%Y-%m-%d %H:%M:%S"
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
                (severity, cursor.lastrowid),
            )
        elif packet_size > packet_size_limit:
            severity = "MEDIUM"
            alert_message = (
                f"Packet size ({packet_size} bytes) exceeded the "
                f"{packet_size_limit}-byte policy limit."
            )

        if scenario != "Failed login":
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

    return {
        "timestamp": timestamp,
        "device": device,
        "event_type": scenario,
        "destination": destination,
        "packet_size": packet_size,
        "severity": severity,
        "message": message,
        "alert_message": alert_message,
    }


def acknowledge_alert(alert_id, db_path=DB_PATH):
    with database(db_path) as con:
        cursor = con.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ? AND acknowledged = 0",
            (alert_id,),
        )
        return cursor.rowcount == 1
