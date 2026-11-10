import base64
import hashlib
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from onvifscan import cli
from onvifscan.discovery import merge_matches, parse_probe_matches
from onvifscan.parse import parse_scopes
from onvifscan.report import build_report, render_html, scrub_secrets, terminal_lines
from onvifscan.soap import build_wsse_header, password_digest

PACKET = b"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
 <s:Body><d:ProbeMatches><d:ProbeMatch>
  <wsa:EndpointReference><wsa:Address>urn:uuid:abc</wsa:Address></wsa:EndpointReference>
  <d:Types>dn:NetworkVideoTransmitter</d:Types>
  <d:Scopes>onvif://www.onvif.org/Profile/Streaming</d:Scopes>
  <d:XAddrs>http://192.0.2.10/onvif/device_service</d:XAddrs>
  <d:MetadataVersion>1</d:MetadataVersion>
 </d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"""


class TestWsse(unittest.TestCase):
    def test_digest_formula(self):
        nonce = b"\x01\x02\x03\x04"
        expect = base64.b64encode(
            hashlib.sha1(nonce + b"2026-01-02T03:04:05Z" + b"pw").digest()).decode()
        self.assertEqual(password_digest(nonce, "2026-01-02T03:04:05Z", "pw"), expect)

    def test_created_uses_device_clock(self):
        now = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        header = build_wsse_header("u", "pw", device_offset_s=3723, nonce=b"\x00" * 16, now=now)
        self.assertIn("<wsu:Created>2026-01-02T04:06:08Z</wsu:Created>", header)


class TestDiscoveryParse(unittest.TestCase):
    def test_parse_packet(self):
        matches = parse_probe_matches(PACKET)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["endpoint"], "urn:uuid:abc")
        self.assertEqual(matches[0]["xaddrs"], ["http://192.0.2.10/onvif/device_service"])

    def test_merge_dedupes_and_keeps_richest_scopes(self):
        raw = [{"endpoint": "urn:uuid:abc", "types": "t", "scopes": "short",
                "xaddrs": ["http://192.0.2.10/a"], "metadata_version": "1",
                "source_ip": "192.0.2.10"},
               {"endpoint": "urn:uuid:abc", "types": "t",
                "scopes": "a much longer scopes string", "xaddrs": ["http://192.0.2.10/b"],
                "metadata_version": "1", "source_ip": "192.0.2.10"}]
        merged = merge_matches(raw)
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0]["xaddrs"]), 2)
        self.assertEqual(merged[0]["scopes"], "a much longer scopes string")

    def test_hosts_file_combines_with_host_and_ignores_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            hosts_path = os.path.join(directory, "hosts.txt")
            with open(hosts_path, "w", encoding="utf-8") as hosts_file:
                hosts_file.write("# full-line comment\n\n192.0.2.10\n192.0.2.11\n192.0.2.13:4567\n")
            with patch.object(cli, "discover", return_value=([], {"interfaces": [], "subnets": [], "probe_count": 0})) as discover:
                with patch.object(cli, "write_json"):
                    cli.main(["scan", "--host", "192.0.2.12:1234", "--hosts", hosts_path,
                              "--no-html", "--json", os.path.join(directory, "out.json")])
            discover.assert_called_once()
            self.assertEqual(discover.call_args.kwargs["directed"], [
                ("192.0.2.12", 1234), ("192.0.2.10", 3702),
                ("192.0.2.11", 3702), ("192.0.2.13", 4567)])

    def test_dual_stack_fixture_parses_and_merges_all_xaddrs(self):
        fixture = Path(__file__).parent / "fixtures" / "dual_stack_probe.xml"
        parsed = parse_probe_matches(fixture.read_bytes())
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["xaddrs"], [
            "http://[2001:db8::10]:80/onvif/device_service",
            "http://192.0.2.10/onvif/device_service",
        ])

        repeated = dict(parsed[0], xaddrs=[parsed[0]["xaddrs"][1]],
                        source_ip="192.0.2.10")
        parsed[0]["source_ip"] = "192.0.2.10"
        merged = merge_matches([parsed[0], repeated])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["xaddrs"], parsed[0]["xaddrs"])

    def test_scopes_minimal_fixture_parses_and_merges(self):
        fixture = Path(__file__).parent / "fixtures" / "scopes_minimal_probe.xml"
        parsed = parse_probe_matches(fixture.read_bytes())
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["endpoint"], "urn:uuid:scopes-minimal-camera")
        self.assertEqual(parsed[0]["xaddrs"], [
            "http://192.0.2.20/onvif/device_service",
        ])

        scopes = parse_scopes(parsed[0]["scopes"])
        self.assertIsNone(scopes["mac"])
        self.assertIsNone(scopes["name"])
        self.assertEqual(scopes["profiles"], ["Streaming"])
        self.assertEqual(scopes["hardware"], "IPC-200")
        self.assertEqual(scopes["location"], "country/example")

        minimal = dict(parsed[0], source_ip="192.0.2.20")
        merged_alone = merge_matches([minimal])
        self.assertEqual(len(merged_alone), 1)
        alone_scopes = parse_scopes(merged_alone[0]["scopes"])
        self.assertIsNone(alone_scopes["mac"])
        self.assertIsNone(alone_scopes["name"])
        self.assertEqual(alone_scopes["profiles"], ["Streaming"])
        self.assertEqual(alone_scopes["hardware"], "IPC-200")
        self.assertEqual(alone_scopes["location"], "country/example")

        richer_scopes_str = (
            parsed[0]["scopes"]
            + " onvif://www.onvif.org/name/Minimal%20Camera"
            + " onvif://www.onvif.org/mac/00:11:22:33:44:55"
        )
        richer = dict(
            parsed[0],
            scopes=richer_scopes_str,
            xaddrs=["http://[2001:db8::20]:80/onvif/device_service"],
            source_ip="2001:db8::20",
        )
        merged_with_richer = merge_matches([minimal, richer])
        self.assertEqual(len(merged_with_richer), 1)
        self.assertEqual(merged_with_richer[0]["scopes"], richer_scopes_str)
        self.assertEqual(merged_with_richer[0]["xaddrs"], [
            "http://192.0.2.20/onvif/device_service",
            "http://[2001:db8::20]:80/onvif/device_service",
        ])
        merged_scopes = parse_scopes(merged_with_richer[0]["scopes"])
        self.assertEqual(merged_scopes["name"], "Minimal Camera")
        self.assertEqual(merged_scopes["mac"], "00:11:22:33:44:55")


def _device(level="FULL"):
    return {"ip": "192.0.2.10", "port": 80, "endpoint": "urn:uuid:abc", "types": None,
            "xaddrs": [], "source_ips": [], "scopes": {}, "device_info":
            {"Manufacturer": "Acme", "Model": "ViewCam", "FirmwareVersion": "1",
             "SerialNumber": "S", "HardwareId": "H"},
            "hostname": None, "mac": None, "mac_source": None, "ipv4": None,
            "clock": {"device_time": None, "offset_s": 0, "skew": False},
            "services": {}, "profiles": [], "channel_count": 0,
            "ptz": {"present": False, "evidence": None},
            "auth": {"mode": "none", "username": None, "result": "not_tried"},
            "level": level, "findings": [], "next_steps": []}


class TestReport(unittest.TestCase):
    def test_scrub_removes_password_everywhere(self):
        dirty = {"a": ["token is SimPass123 ok"], "b": {"c": "SimPass123"}}
        clean = scrub_secrets(dirty, ["SimPass123"])
        self.assertNotIn("SimPass123", str(clean))
        self.assertIn("***", clean["a"][0])

    def test_build_and_render(self):
        report = build_report("0.1.0", {"interfaces": [], "subnets": [], "probe_count": 2},
                              [_device()], 1.25)
        self.assertEqual(report["summary"]["full"], 1)
        html = render_html(report)
        self.assertIn("Generated by onvif-scan", html)
        self.assertIn("Acme", html)
        self.assertTrue(any("FULL" in line for line in terminal_lines(report)))

    def test_render_html_en_contract_and_zh_cn_labels(self):
        dev = _device()
        dev["mac"] = "aa:bb:cc:dd:ee:ff"
        dev["mac_source"] = "scopes"
        dev["channel_count"] = 1
        dev["channel_count_basis"] = "video_source"
        dev["ptz"] = {
            "present": True, "evidence": "capability_xaddr",
            "nodes_status": "ok", "nodes_reason": None,
            "nodes": [{"token": "N1", "status": "ok", "reason": None, "source": "GetNodes",
                       "data": {"name": "MainNode", "maximum_number_of_presets": 80,
                                "home_supported": True, "fixed_home_position": False,
                                "supported_preset_tour": {"maximum_number_of_preset_tours": 2,
                                                          "operations": ["Start"]}}}],
        }
        dev["services_declared"] = [{
            "namespace": "http://www.onvif.org/ver10/media/wsdl",
            "xaddr": "http://192.0.2.10/onvif/Media",
            "version": {"major": 2, "minor": 6},
            "missing_fields": [], "invalid_fields": [],
        }]
        dev["service_sources"] = {"media": "GetCapabilities"}
        dev["profiles"] = [{
            "token": "P1", "media_gen": 1, "video_source_token": "VS_SRC",
            "source_token": "VS_CFG", "source_configuration_name": "FrontCam",
            "source_name_origin": "VideoSourceConfiguration.Name",
            "codec": "H264", "width": 1920, "height": 1080, "fps_limit": 25,
            "stream_uri": "rtsp://admin:***@192.0.2.10/stream1",
            "ptz_configuration_token": "PTZ_CFG", "ptz_node_token": "N1",
            "ptz_node_status": "ok", "ptz_node_reason": None,
            "ptz_presets": {"status": "ok", "reason": None, "data": {"count": 2, "names": ["Home", "Gate"]}},
            "encoder_options": {"status": "ok", "reason": None,
                                "data": {"encodings": ["H264"],
                                         "declarations": [{"encoding": "H264", "origin": "H264"}]}},
        }]
        dev["next_steps"] = ["rkdoctor rtsp rtsp://admin:***@192.0.2.10/stream1"]
        report = build_report("0.2.0", {"interfaces": ["eth0"], "subnets": ["192.0.2.0/24"], "probe_count": 1},
                              [dev], 1.5)
        html_default = render_html(report)
        html_en = render_html(report, lang="en")
        self.assertEqual(html_default, html_en)
        self.assertIn('<html lang="en">', html_en)

        html_zh = render_html(report, lang="zh-CN")
        self.assertIn('<html lang="zh-CN">', html_zh)
        self.assertIn("<title>ONVIF 资产盘点 — ", html_zh)
        self.assertIn("<h1>ONVIF 摄像头资产盘点</h1>", html_zh)
        for label in ("已发现", "完整", "部分", "仅发现", "不可达", "有发现项",
                      "<th>厂商</th>", "<th>型号</th>", "<th>固件</th>", "<th>通道数</th>",
                      "<th>主码流</th>", "<th>级别</th>", "<td>是</td>",
                      "级别 FULL · MAC aa:bb:cc:dd:ee:ff (scopes) · 时钟偏移 0 s · 鉴权 none/not_tried · 序列号 S",
                      "声明的服务 (GetServices)", "<th>命名空间</th>", "<th>版本</th>",
                      "<th>缺失字段</th>", "<th>无效字段</th>", "选定路由来源：media: GetCapabilities",
                      "<h4>配置文件 P1 (Media1)</h4><p>编码器选项：ok · —</p>",
                      "仅为设备声明；不保证编码、分辨率与帧率的任意组合均可用。",
                      "PTZ 配置 PTZ_CFG · 节点 N1 · 节点状态 ok (—)",
                      "预置位：ok (—) · 实际数量 2 · 名称 [&#x27;Home&#x27;, &#x27;Gate&#x27;]",
                      "<h4>PTZ 节点声明</h4><p>GetNodes：ok (—)</p>",
                      "预置位容量 (MaximumNumberOfPresets)",
                      "仅限配置文件可见源；配置名称并非物理源名称。通道数计算依据：video_source。",
                      "<th>流地址（密码已脱敏）</th>",
                      "<p>下一步（流验收）：</p>",
                      "<code>rkdoctor rtsp rtsp://admin:***@192.0.2.10/stream1</code>"):
            self.assertIn(label, html_zh)

    def test_render_html_zh_cn_findings_parameterized_and_fallback(self):
        from onvifscan.report import FINDING_DETAILS_ZH
        dev = _device()
        dev["findings"] = [
            {"code": "UNREACHABLE", "severity": "warn",
             "detail": "device service did not answer: URLError: <urlopen error timed out>"},
            {"code": "CLOCK_SKEW", "severity": "warn",
             "detail": "device clock offset -3600s; check NTP on the device"},
            {"code": "XADDR_MISMATCH", "severity": "info",
             "detail": "XAddr host 192.168.10.5 differs from responder 10.0.0.12"},
            {"code": "NO_XADDR", "severity": "warn", "detail": "ProbeMatch carried no XAddr"},
            {"code": "UNAUTH_CAPS_DISCLOSURE", "severity": "info",
             "detail": "GetCapabilities answered without authentication"},
            {"code": "CAPS_FALLBACK", "severity": "info",
             "detail": "no capabilities/services response; conventional service paths assumed"},
            {"code": "UNAUTH_INFO_DISCLOSURE", "severity": "warn",
             "detail": "GetDeviceInformation answered without authentication (loose/legacy firmware)"},
            {"code": "SCOPES_MINIMAL", "severity": "info",
             "detail": "discovery Scopes lack mac/name; identity completed from other sources where possible"},
            {"code": "MEDIA2_ONLY", "severity": "info",
             "detail": "profiles only via Media2 (Profile T generation)"},
            {"code": "LEGACY_MEDIA_ONLY", "severity": "info",
             "detail": "profiles only via Media ver10"},
            {"code": "AUTH_FAILED", "severity": "warn",
             "detail": "supplied credential rejected once; not retried. Note many vendors keep a separate ONVIF user (distinct from the web user)"},
            {"code": "STREAM_URI_MISSING", "severity": "warn",
             "detail": "profiles found but GetStreamUri returned nothing; rkdoctor hand-off unavailable"},
            {"code": "NO_PTZ", "severity": "info", "detail": "no PTZ capability found"},
            {"code": "RESPONSE_MALFORMED", "severity": "warn",
             "detail": "at least one SOAP response needed loose parsing (non-conformant XML)"},
            {"code": "CLOCK_SKEW", "severity": "warn",
             "detail": "unexpected format offset=99s"},
        ]
        self.assertEqual(len(FINDING_DETAILS_ZH), 14)
        report = build_report("0.2.0", {"interfaces": [], "subnets": [], "probe_count": 1}, [dev], 0.5)
        html_zh = render_html(report, lang="zh-CN")
        self.assertIn("<li><b>UNREACHABLE</b> (警告) — 设备服务未响应：URLError: &lt;urlopen error timed out&gt;</li>", html_zh)
        self.assertIn("<li><b>CLOCK_SKEW</b> (警告) — 设备时钟偏移 -3600s；请检查设备上的 NTP 配置</li>", html_zh)
        self.assertIn("<li><b>XADDR_MISMATCH</b> (信息) — XAddr 主机 192.168.10.5 与响应源 10.0.0.12 不一致</li>", html_zh)
        self.assertIn("<li><b>NO_PTZ</b> (信息) — 未发现 PTZ 能力</li>", html_zh)
        self.assertIn("<li><b>AUTH_FAILED</b> (警告) — 提供的凭据被拒绝一次；未再重试。", html_zh)
        self.assertIn("<li><b>CLOCK_SKEW</b> (警告) — unexpected format offset=99s</li>", html_zh)


if __name__ == "__main__":
    unittest.main()
