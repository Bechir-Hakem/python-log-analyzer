import unittest
from log_analyzer import is_valid_ip, analyze_logs
from log_reader import read_logs
import tempfile
from pathlib import Path
from report_generator import generate_report





class TestIPValidation(unittest.TestCase):

    def test_valid_ip(self):
        result = is_valid_ip("192.168.1.1")
        self.assertTrue(result)

    def test_invalid_ip(self):
        result = is_valid_ip("256.168.1.1")
        self.assertFalse(result)

    def test_wrong_number_of_groups(self):
        result = is_valid_ip("192.168.1")
        self.assertFalse(result)

    def test_integer_input(self):
        result = is_valid_ip(12345)
        self.assertFalse(result)

class TestLogAnalysis(unittest.TestCase):

    def test_info_event_count(self):
        lines = [
            "2026-11-08 08:15:22 INFO Server started successfully"
        ]

        result = analyze_logs(lines)
        events = result[0]

        self.assertEqual(events["INFO"], 1)

    def test_all_event_counts(self):
        lines = [
            "2026-11-08 08:15:22 INFO Server started",
            "2026-11-08 08:16:22 WARNING High memory usage",
            "2026-11-08 08:17:22 ERROR Database failed",
            "2026-11-08 08:18:22 ERROR Network timeout",
            "2026-11-08 08:19:22 DEBUG Cache cleared"
        ]

        result = analyze_logs(lines)
        events = result[0]

        self.assertEqual(events["INFO"], 1)
        self.assertEqual(events["WARNING"], 1)
        self.assertEqual(events["ERROR"], 2)

    def test_failed_login_count(self):
        lines = [
            "2026-11-08 08:15:22 ERROR Login failed for user john from 192.168.1.15",
            "2026-11-08 08:16:22 ERROR Login failed for user alice from 10.0.0.5",
            "2026-11-08 08:17:22 ERROR Login failed for user john from 192.168.1.15"
        ]

        result = analyze_logs(lines)

        failed_logins = result[1]
        failed_by_user = result[2]

        self.assertEqual(failed_logins, 3)
        self.assertEqual(failed_by_user["john"], 2)
        self.assertEqual(failed_by_user["alice"], 1)

    def test_failed_login_by_ip(self):
        lines = [
            "2026-11-08 08:15:22 ERROR Login failed for user john from 192.168.1.15",
            "2026-11-08 08:16:22 ERROR Login failed for user alice from 10.0.0.5",
            "2026-11-08 08:17:22 ERROR Login failed for user john from 192.168.1.15"
        ]

        result = analyze_logs(lines)
        failed_by_ip = result[3]

        self.assertEqual(failed_by_ip["192.168.1.15"], 2)
        self.assertEqual(failed_by_ip["10.0.0.5"], 1)

    def test_error_message_count(self):
        lines = [
            "2026-11-08 08:15:22 ERROR Database connection failed",
            "2026-11-08 08:16:22 ERROR Database connection failed",
            "2026-11-08 08:17:22 ERROR Network timeout"
        ]

        result = analyze_logs(lines)
        error_messages = result[4]

        self.assertEqual(error_messages["Database connection failed"], 2)
        self.assertEqual(error_messages["Network timeout"], 1)

    def test_ip_activity_count(self):
        lines = [
            "2026-11-08 08:15:22 INFO Connection from 192.168.1.15",
            "2026-11-08 08:16:22 INFO Connection from 10.0.0.5",
            "2026-11-08 08:17:22 WARNING Connection from 192.168.1.15"
        ]

        result = analyze_logs(lines)
        ip_counts = result[5]

        self.assertEqual(ip_counts["192.168.1.15"], 2)
        self.assertEqual(ip_counts["10.0.0.5"], 1)

class TestLogReader(unittest.TestCase):

    def test_read_existing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "test.log"

            with open(file_path, "w", encoding="utf-8") as file:
                file.write("INFO Server started")

            result = read_logs(file_path)

            self.assertEqual(result, ["INFO Server started"])

    def test_read_missing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "missing.log"

            result = read_logs(file_path)

            self.assertIsNone(result)

class TestReportGenerator(unittest.TestCase):

    def test_report_creation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.txt"

            events = {
                "INFO": 2,
                "WARNING": 1,
                "ERROR": 1
            }

            failed_logins = 2
            failed_by_user = {"john": 2}
            failed_by_ip = {"192.168.1.15": 2}
            error_messages = {"Login failed": 2}
            ip_counts = {"192.168.1.15": 3}

            generate_report(
                report_path,
                events,
                failed_logins,
                failed_by_user,
                failed_by_ip,
                error_messages,
                ip_counts
            )

            self.assertTrue(report_path.exists())
            with open(report_path, "r", encoding="utf-8") as file:
                content = file.read()

            self.assertIn("EVENT SUMMARY", content)
            self.assertIn("FAILED LOGINS", content)
            self.assertIn("john", content)