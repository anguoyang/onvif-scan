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

    def test_lang_defaults_to_en_and_accepts_zh_cn_without_changing_json(self):
        sample_device = {
            "ip": "192.0.2.10", "port": 80, "endpoint": "urn:uuid:abc", "types": None,
            "xaddrs": ["http://192.0.2.10/onvif/device_service"], "source_ips": ["192.0.2.10"],
            "scopes": {}, "device_info": {"Manufacturer": "Acme", "Model": "Cam1",
                                          "FirmwareVersion": "1.0", "SerialNumber": "SN1"},
            "hostname": None, "mac": "aa:bb:cc:dd:ee:ff", "mac_source": "scopes", "ipv4": None,
            "clock": {"device_time": None, "offset_s": 120.0, "skew": True},
            "services": {}, "service_sources": {}, "services_declared": None,
            "profiles": [], "channel_count": 0, "channel_count_basis": "profiles",
            "ptz": {"present": False, "evidence": None, "nodes_status": "unqueried",
                    "nodes_reason": "no PTZ service route", "nodes": []},
            "auth": {"mode": "none", "username": None, "result": "not_tried"},
            "level": "PARTIAL",
            "findings": [{"code": "CLOCK_SKEW", "severity": "warn",
                          "detail": "device clock offset 120s; check NTP on the device"}],
            "next_steps": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            json_en = root / "en.json"
            html_en = root / "en.html"
            json_zh = root / "zh.json"
            html_zh = root / "zh.html"
            out_en = io.StringIO()
            out_zh = io.StringIO()
            with patch("onvifscan.cli.discover", return_value=([{"xaddrs": ["http://192.0.2.10/onvif/device_service"]}],
                                                               {"interfaces": [], "subnets": ["192.0.2.0/24"], "probe_count": 1})), \
                    patch("onvifscan.cli.scan_device", return_value=sample_device):
                with contextlib.redirect_stdout(out_en):
                    rc_en = main(["scan", "--json", str(json_en), "--html", str(html_en)])
                with contextlib.redirect_stdout(out_zh):
                    rc_zh = main(["scan", "--lang", "zh-CN", "--json", str(json_zh), "--html", str(html_zh)])

            self.assertEqual(rc_en, 0)
            self.assertEqual(rc_zh, 0)
            data_en = json.loads(json_en.read_text(encoding="utf-8"))
            data_zh = json.loads(json_zh.read_text(encoding="utf-8"))
            data_en.pop("generated_at", None)
            data_zh.pop("generated_at", None)
            data_en["scan"].pop("duration_s", None)
            data_zh["scan"].pop("duration_s", None)
            self.assertEqual(data_en, data_zh)
            self.assertEqual(out_en.getvalue().splitlines()[0], out_zh.getvalue().splitlines()[0])

            text_en = html_en.read_text(encoding="utf-8")
            text_zh = html_zh.read_text(encoding="utf-8")
            self.assertIn('<html lang="en">', text_en)
            self.assertIn("device clock offset 120s; check NTP on the device", text_en)
            self.assertIn('<html lang="zh-CN">', text_zh)
            self.assertIn("ONVIF 摄像头资产盘点", text_zh)
            self.assertIn("<b>CLOCK_SKEW</b> (警告) — 设备时钟偏移 120s；请检查设备上的 NTP 配置", text_zh)


if __name__ == "__main__":
    unittest.main()
