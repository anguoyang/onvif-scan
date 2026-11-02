import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from onvifscan.cli import main


class TestQuietMode(unittest.TestCase):
    def test_quiet_prints_only_summary_and_report_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            json_path = root / "inventory.json"
            html_path = root / "inventory.html"
            output = io.StringIO()
            with patch("onvifscan.cli.discover", return_value=([], {
                    "interfaces": [], "subnets": [], "probe_count": 0})), \
                    contextlib.redirect_stdout(output):
                result = main(["scan", "--quiet", "--json", str(json_path),
                               "--html", str(html_path)])

            lines = output.getvalue().splitlines()
            self.assertEqual(result, 0)
            self.assertEqual(len(lines), 2)
            self.assertIn("discovered 0", lines[0])
            self.assertEqual(lines[1], "reports: %s + %s" % (json_path, html_path))
            self.assertTrue(json_path.is_file())
            self.assertTrue(html_path.is_file())
            self.assertEqual(json.loads(json_path.read_text())["summary"]["discovered"], 0)

    def test_normal_mode_keeps_zero_result_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch("onvifscan.cli.discover", return_value=([], {
                    "interfaces": [], "subnets": [], "probe_count": 0})), \
                    contextlib.redirect_stdout(output):
                result = main(["scan", "--no-html", "--json",
                               str(Path(directory) / "inventory.json")])

            self.assertEqual(result, 0)
            self.assertIn("No ONVIF responses.", output.getvalue())
            self.assertIn("reports:", output.getvalue())


if __name__ == "__main__":
    unittest.main()
