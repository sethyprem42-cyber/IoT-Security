import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from security_core import (
    DeviceUnavailableError,
    acknowledge_alert,
    add_device,
    generate_event,
    init_db,
    read_table,
    update_device_status,
)


class FixedRandom:
    def __init__(self, value):
        self.value = value

    def randint(self, lower, upper):
        return self.value


class SecurityCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        init_db(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_initialization_seeds_devices_once(self):
        init_db(self.db_path)
        self.assertEqual(len(read_table("devices", self.db_path)), 5)

    def test_normal_event_is_stored_without_alert(self):
        event = generate_event(
            "Normal telemetry",
            "Smart Camera",
            3,
            1500,
            db_path=self.db_path,
            now=datetime(2026, 1, 1, 12),
            rng=FixedRandom(250),
        )
        self.assertEqual(event["severity"], "LOW")
        self.assertIsNone(event["alert_message"])
        self.assertEqual(len(read_table("events", self.db_path)), 1)
        self.assertTrue(read_table("alerts", self.db_path).empty)

    def test_traffic_above_limit_creates_medium_alert(self):
        event = generate_event(
            "Traffic spike",
            "Smart Camera",
            3,
            1500,
            db_path=self.db_path,
            rng=FixedRandom(5000),
        )
        self.assertEqual(event["severity"], "MEDIUM")
        self.assertEqual(len(read_table("alerts", self.db_path)), 1)

    def test_unknown_destination_creates_high_alert(self):
        event = generate_event(
            "Unknown destination",
            "Smart Camera",
            3,
            1500,
            db_path=self.db_path,
            rng=FixedRandom(250),
        )
        self.assertEqual(event["severity"], "HIGH")
        self.assertEqual(
            event["destination"],
            "unapproved-simulated-host",
        )

    def test_failed_login_threshold_is_scoped_to_device_and_time_window(self):
        current_time = datetime(2026, 1, 1, 12)
        old_time = current_time - timedelta(minutes=16)
        con = sqlite3.connect(self.db_path)
        try:
            con.execute(
                """
                INSERT INTO events
                (timestamp, device, event_type, destination, packet_size, severity, message)
                VALUES (?, ?, 'Failed login', 'local-gateway', 120, 'HIGH', 'old event')
                """,
                (old_time.strftime("%Y-%m-%d %H:%M:%S"), "Smart Camera"),
            )
            con.commit()
        finally:
            con.close()
        first = generate_event(
            "Failed login",
            "Smart Camera",
            3,
            1500,
            db_path=self.db_path,
            now=current_time - timedelta(minutes=1),
        )
        second = generate_event(
            "Failed login",
            "Smart Bulb",
            3,
            1500,
            db_path=self.db_path,
            now=current_time,
        )
        self.assertEqual(first["severity"], "HIGH")
        self.assertEqual(second["severity"], "HIGH")
        third = generate_event(
            "Failed login",
            "Smart Camera",
            3,
            1500,
            db_path=self.db_path,
            now=current_time,
        )
        self.assertEqual(third["severity"], "HIGH")
        critical = generate_event(
            "Failed login",
            "Smart Camera",
            3,
            1500,
            db_path=self.db_path,
            now=current_time,
        )
        self.assertEqual(critical["severity"], "CRITICAL")

    def test_offline_device_cannot_generate_event(self):
        with self.assertRaises(DeviceUnavailableError):
            generate_event(
                "Normal telemetry",
                "Energy Meter",
                3,
                1500,
                db_path=self.db_path,
            )
        self.assertTrue(read_table("events", self.db_path).empty)

    def test_invalid_event_and_policy_values_are_rejected(self):
        with self.assertRaises(ValueError):
            generate_event(
                "Not a scenario",
                "Smart Camera",
                3,
                1500,
                db_path=self.db_path,
            )
        with self.assertRaises(ValueError):
            generate_event(
                "Normal telemetry",
                "Smart Camera",
                1,
                1500,
                db_path=self.db_path,
            )
        with self.assertRaises(ValueError):
            generate_event(
                "Normal telemetry",
                "Smart Camera",
                3,
                0,
                db_path=self.db_path,
            )
        self.assertTrue(read_table("events", self.db_path).empty)

    def test_table_reader_rejects_unknown_table_names(self):
        with self.assertRaises(ValueError):
            read_table("devices; DROP TABLE alerts", self.db_path)

    def test_device_registration_validates_and_normalizes_fields(self):
        add_device("  Lab Sensor ", " Sensor ", "192.168.1.20", self.db_path)
        device = read_table("devices", self.db_path)
        sensor = device.loc[device["name"] == "Lab Sensor"].iloc[0]
        self.assertEqual(sensor["device_type"], "Sensor")
        self.assertEqual(sensor["simulated_ip"], "192.168.1.20")
        self.assertEqual(sensor["status"], "Online")
        with self.assertRaises(ValueError):
            add_device("Invalid IP", "Sensor", "999.999.1.1", self.db_path)

    def test_device_status_rejects_invalid_values(self):
        with self.assertRaises(ValueError):
            update_device_status("Smart Camera", "Unknown", self.db_path)
        update_device_status("Smart Camera", "Offline", self.db_path)
        self.assertEqual(
            read_table("devices", self.db_path)
            .set_index("name")
            .loc["Smart Camera", "status"],
            "Offline",
        )

    def test_alert_acknowledgement_is_idempotent(self):
        generate_event(
            "Unknown destination",
            "Smart Camera",
            3,
            1500,
            db_path=self.db_path,
        )
        alert_id = int(read_table("alerts", self.db_path).iloc[0]["id"])
        self.assertTrue(acknowledge_alert(alert_id, self.db_path))
        self.assertFalse(acknowledge_alert(alert_id, self.db_path))
        self.assertEqual(
            int(read_table("alerts", self.db_path).iloc[0]["acknowledged"]),
            1,
        )


if __name__ == "__main__":
    unittest.main()
