"""Offline behavioral tests. A small HTTP stub ensures no network is contacted."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


class RequestError(Exception):
    pass


def forbidden_request(*args, **kwargs):
    raise AssertionError("An offline test attempted a network request")


http_stub = types.SimpleNamespace(
    get=forbidden_request,
    exceptions=types.SimpleNamespace(RequestException=RequestError),
)
spec = importlib.util.spec_from_file_location(
    "course_analyzer", Path(__file__).resolve().parents[1] / "src" / "skript.py"
)
analyzer = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"requests": http_stub}):
    spec.loader.exec_module(analyzer)


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "auth.log"
        self.path.write_text(
            "Failed login from 192.0.2.10\n"
            "Another login from 192.0.2.10\n"
            "Connection from 198.51.100.7\n"
            "Invalid address 355.355.355.0\n",
            encoding="utf-8",
        )

    def run_main(self, *options):
        output = io.StringIO()
        with patch.object(sys, "argv", ["skript.py", str(self.path), *options]):
            with contextlib.redirect_stdout(output):
                analyzer.main()
        return output.getvalue()

    def test_invalid_addresses_are_rejected_and_duplicates_retained(self):
        self.assertEqual(
            analyzer.find_ip_addresses(self.path),
            ["192.0.2.10", "192.0.2.10", "198.51.100.7"],
        )

    def test_threshold_is_inclusive(self):
        output = self.run_main("--threshold", "2", "--dry-run")
        self.assertIn("IP: 192.0.2.10 | Occurrences: 2", output)
        self.assertNotIn("IP: 198.51.100.7", output)

    def test_dry_run_does_not_write_a_report(self):
        original = Path.cwd()
        import os
        try:
            os.chdir(self.temp.name)
            self.run_main("--threshold", "1", "--dry-run")
            self.assertFalse(Path("threat_report.json").exists())
        finally:
            os.chdir(original)

    def test_high_threshold_explains_most_common_address(self):
        output = self.run_main("--threshold", "9", "--dry-run")
        self.assertIn("Highest occurrence found: 192.0.2.10 (2 times)", output)

    def test_empty_log_returns_without_requests(self):
        self.path.write_text("", encoding="utf-8")
        self.assertIn("No valid IP addresses found", self.run_main("--dry-run"))

    def test_missing_log_has_nonzero_exit(self):
        self.path.unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                analyzer.find_ip_addresses(self.path)
        self.assertEqual(result.exception.code, 1)

    def test_default_threshold_is_five(self):
        with patch.object(sys, "argv", ["skript.py", str(self.path)]):
            self.assertEqual(analyzer.parse_arguments().threshold, 5)


if __name__ == "__main__":
    unittest.main()
