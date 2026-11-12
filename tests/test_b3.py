"""B3 independent video source enumeration (GetVideoSources /
GetVideoSourceConfigurations). Evidence only: no device-type inference."""
import copy
import csv
import io
import tempfile
import unittest
from pathlib import Path

from onvifscan import parse as P
from onvifscan.diff import compare_inventories
from onvifscan.report import build_report, render_html, write_csv
from onvifscan.scan import scan_device
from sim_device import SimDevices, USER, PASSWORD, fault
from test_wsse_discovery_report import _device

CRED = {"user": USER, "password": PASSWORD}

SOURCES_XML = (
    '<trt:GetVideoSourcesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
    'xmlns:tt="http://www.onvif.org/ver10/schema">'
    '<tt:VideoSource token="Sensor_1"><tt:Name>Front</tt:Name><tt:Framerate>30</tt:Framerate>'
    '<tt:Resolution><tt:Width>1920</tt:Width><tt:Height>1080</tt:Height></tt:Resolution>'
    '</tt:VideoSource>'
    '<tt:VideoSource token="Sensor_2"><tt:Name>Side</tt:Name></tt:VideoSource>'
    '</trt:GetVideoSourcesResponse>')

CONFIGS_XML = (
    '<trt:GetVideoSourceConfigurationsResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl" '
    'xmlns:tt="http://www.onvif.org/ver10/schema">'
    '<tt:VideoSourceConfiguration token="VS_1" SourceToken="Sensor_1"><tt:Name>VS</tt:Name>'
    '</tt:VideoSourceConfiguration>'
    '<tt:VideoSourceConfiguration token="VS_2"><tt:Name>VS2</tt:Name>'
    '<tt:SourceToken>Sensor_2</tt:SourceToken></tt:VideoSourceConfiguration>'
    '</trt:GetVideoSourceConfigurationsResponse>')

CONFIGS_XML_M2 = (
    '<tr2:GetVideoSourceConfigurationsResponse xmlns:tr2="http://www.onvif.org/ver20/media/wsdl" '
    'xmlns:tt="http://www.onvif.org/ver10/schema"><tr2:Configurations>'
    '<tt:VideoSourceConfiguration token="VS_1" SourceToken="Sensor_1"><tt:Name>VS</tt:Name>'
    '</tt:VideoSourceConfiguration>'
    '<tt:VideoSourceConfiguration token="VS_2" SourceToken="Sensor_2"><tt:Name>VS2</tt:Name>'
    '</tt:VideoSourceConfiguration></tr2:Configurations>'
    '</tr2:GetVideoSourceConfigurationsResponse>')


class TestParseSources(unittest.TestCase):
    def test_parse_video_sources(self):
        sources, malformed = P.parse_video_sources(SOURCES_XML)
        self.assertFalse(malformed)
        self.assertEqual(sources[0], {"token": "Sensor_1", "name": "Front",
                                      "framerate": 30.0,
                                      "resolution": {"width": 1920, "height": 1080}})
        self.assertEqual(sources[1]["token"], "Sensor_2")
        self.assertIsNone(sources[1]["framerate"])
        self.assertIsNone(sources[1]["resolution"])
        empty, _ = P.parse_video_sources(
            '<trt:GetVideoSourcesResponse xmlns:trt="http://www.onvif.org/ver10/media/wsdl"/>')
        self.assertEqual(empty, [])
        none, malformed = P.parse_video_sources('<Other/>')
        self.assertIsNone(none)
        self.assertTrue(malformed)

    def test_parse_video_source_configurations_both_gens(self):
        configs, malformed = P.parse_video_source_configurations(CONFIGS_XML)
        self.assertFalse(malformed)
        self.assertEqual(configs, [{"token": "VS_1", "name": "VS", "source_token": "Sensor_1"},
                                   {"token": "VS_2", "name": "VS2", "source_token": "Sensor_2"}])
        configs2, malformed = P.parse_video_source_configurations(CONFIGS_XML_M2)
        self.assertFalse(malformed)
        self.assertEqual(configs2, configs)
        none, malformed = P.parse_video_source_configurations('<Other/>')
        self.assertIsNone(none)
        self.assertTrue(malformed)


class TestScanSources(unittest.TestCase):
    def start_sim(self, name="standard", **overrides):
        sim = SimDevices([name], http_only=True, overrides={name: overrides}).__enter__()
        self.addCleanup(sim.__exit__)
        p = sim.personas[name]
        url = "http://127.0.0.1:%d/onvif/device_service" % p["port"]
        return p, {"xaddrs": [url], "source_ips": ["127.0.0.1"], "scopes": p["scopes"]}

    def scan(self, entry, cred=CRED):
        return scan_device(entry, lambda *_: cred, timeout=2)

    def sources_by_token(self, rec):
        return {s["token"]: s for s in rec["sources"]}

    def test_standard_sources_enumerated_and_channel_count_unchanged(self):
        p, entry = self.start_sim("standard")
        rec = self.scan(entry)
        self.assertEqual(rec["sources_status"], "ok")
        self.assertIsNone(rec["sources_reason"])
        by_token = self.sources_by_token(rec)
        self.assertEqual(set(by_token), {"Sensor_1", "Sensor_2"})
        self.assertTrue(by_token["Sensor_1"]["bound_to_profile"])
        self.assertFalse(by_token["Sensor_2"]["bound_to_profile"])
        self.assertEqual(by_token["Sensor_1"]["name"], "Front")
        self.assertEqual(by_token["Sensor_1"]["name_origin"], "VideoSource.Name")
        self.assertEqual(by_token["Sensor_1"]["configuration_tokens"], ["VS_1"])
        self.assertEqual(by_token["Sensor_2"]["configuration_tokens"], ["VS_2"])
        # Enumeration never feeds channel_count: both profiles share Sensor_1.
        self.assertEqual(rec["channel_count"], 1)
        self.assertEqual(rec["channel_count_basis"], "video_source")
        self.assertEqual({c["operation"] for c in p["calls"] if c["operation"].startswith("GetVideoSource")},
                         {"GetVideoSources", "GetVideoSourceConfigurations"})

    def test_strict_media2_configs_only(self):
        p, entry = self.start_sim("strict")
        rec = self.scan(entry)
        self.assertEqual(rec["sources_status"], "ok")
        by_token = self.sources_by_token(rec)
        self.assertEqual(set(by_token), {"Sensor_1", "Sensor_2"})
        self.assertTrue(by_token["Sensor_1"]["bound_to_profile"])
        self.assertFalse(by_token["Sensor_2"]["bound_to_profile"])
        self.assertEqual(by_token["Sensor_2"]["name_origin"], "VideoSourceConfiguration.Name")
        ops = [c["operation"] for c in p["calls"]]
        self.assertNotIn("GetVideoSources", ops)
        self.assertIn("GetVideoSourceConfigurations", ops)
        qname = next(c["qname"] for c in p["calls"]
                     if c["operation"] == "GetVideoSourceConfigurations")
        self.assertEqual(qname, "{http://www.onvif.org/ver20/media/wsdl}"
                                "GetVideoSourceConfigurations")

    def test_legacy_bound_via_config_token_resolution(self):
        # Legacy profiles carry no SourceToken; the enumerated VS_1 config
        # resolves the profile's source configuration token to Sensor_1.
        _, entry = self.start_sim("legacy")
        rec = self.scan(entry)
        by_token = self.sources_by_token(rec)
        self.assertEqual(set(by_token), {"Sensor_1"})
        self.assertTrue(by_token["Sensor_1"]["bound_to_profile"])
        self.assertEqual(rec["channel_count"], 1)
        self.assertEqual(rec["channel_count_basis"], "profiles")

    def test_nvr_variant_shared_source_and_unbound_source(self):
        overrides = {
            "video_sources": [
                {"token": "Sensor_1", "name": "Front", "framerate": 30,
                 "width": 1920, "height": 1080},
                {"token": "Sensor_3", "name": "Rear", "framerate": 15,
                 "width": 640, "height": 480}],
            "video_source_configurations": [
                {"token": "VS_1", "source_token": "Sensor_1", "name": "Main"},
                {"token": "VS_2", "source_token": "Sensor_1", "name": "Sub"},
                {"token": "VS_3", "source_token": "Sensor_3", "name": "Rear"}],
        }
        _, entry = self.start_sim("standard", **overrides)
        rec = self.scan(entry)
        by_token = self.sources_by_token(rec)
        self.assertEqual(set(by_token), {"Sensor_1", "Sensor_3"})
        self.assertTrue(by_token["Sensor_1"]["bound_to_profile"])
        self.assertEqual(by_token["Sensor_1"]["configuration_tokens"], ["VS_1", "VS_2"])
        self.assertFalse(by_token["Sensor_3"]["bound_to_profile"])
        self.assertEqual(by_token["Sensor_3"]["configuration_tokens"], ["VS_3"])
        self.assertEqual(rec["channel_count"], 1)

    def test_sources_unsupported(self):
        overrides = {"responses": {
            "GetVideoSources": (400, fault("unsupported", "ActionNotSupported")),
            "GetVideoSourceConfigurations": (400, fault("unsupported", "ActionNotSupported"))}}
        _, entry = self.start_sim("standard", **overrides)
        rec = self.scan(entry)
        self.assertEqual(rec["sources_status"], "unsupported")
        self.assertEqual(rec["sources"], [])

    def test_sources_partial_coverage_when_sources_unsupported(self):
        overrides = {"responses": {
            "GetVideoSources": (400, fault("unsupported", "ActionNotSupported"))}}
        _, entry = self.start_sim("standard", **overrides)
        rec = self.scan(entry)
        self.assertEqual(rec["sources_status"], "ok")
        self.assertIn("unsupported", rec["sources_reason"])
        self.assertEqual(set(self.sources_by_token(rec)), {"Sensor_1", "Sensor_2"})

    def test_sources_failed_on_transport_error(self):
        overrides = {"responses": {"GetVideoSources": (503, "offline"),
                                   "GetVideoSourceConfigurations": (503, "offline")}}
        _, entry = self.start_sim("standard", **overrides)
        rec = self.scan(entry)
        self.assertEqual(rec["sources_status"], "failed")
        self.assertEqual(rec["sources"], [])

    def test_rejection_stops_credentials_at_sources(self):
        p, entry = self.start_sim("standard", reject_at="GetVideoSources")
        rec = self.scan(entry)
        calls = p["calls"]
        rejected = next(i for i, c in enumerate(calls)
                        if c["operation"] == "GetVideoSources" and c["credentialed"])
        self.assertFalse(any(c["credentialed"] for c in calls[rejected + 1:]), calls)
        self.assertEqual(rec["sources_status"], "auth_blocked")
        self.assertEqual(rec["sources"], [])
        allowed = {"GetSystemDateAndTime", "GetCapabilities", "GetServices",
                   "GetDeviceInformation", "GetHostname", "GetNetworkInterfaces",
                   "GetProfiles", "GetStreamUri", "GetSnapshotUri",
                   "GetVideoEncoderConfigurationOptions", "GetNodes", "GetNode",
                   "GetPresets", "GetVideoSources", "GetVideoSourceConfigurations"}
        self.assertTrue(all(c["operation"] in allowed for c in calls))


class TestReportSources(unittest.TestCase):
    def setUp(self):
        self.device = _device()
        self.device["mac"] = "aa:bb:cc:dd:ee:ff"
        self.device["sources"] = [
            {"token": "Sensor_1", "name": "Front", "name_origin": "VideoSource.Name",
             "framerate": 30.0, "resolution": {"width": 1920, "height": 1080},
             "bound_to_profile": True, "configuration_tokens": ["VS_1"]},
            {"token": "Sensor_2", "name": "Side", "name_origin": "VideoSource.Name",
             "framerate": 30.0, "resolution": {"width": 1280, "height": 720},
             "bound_to_profile": False, "configuration_tokens": ["VS_2"]},
        ]
        self.device["sources_status"] = "ok"
        self.device["sources_reason"] = None
        self.report = build_report("test", {}, [self.device], 0)

    def test_csv_source_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "out.csv"
            write_csv(self.report, path)
            with path.open(encoding="utf-8-sig", newline="") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_count"], "2")
        self.assertEqual(rows[0]["unbound_source_count"], "1")

    def test_html_sources_section_and_unbound_marker(self):
        html = render_html(self.report)
        self.assertIn("Visible video sources: 2, of which 1 are not bound to any profile.", html)
        self.assertIn("Sensor_2", html)
        self.assertIn("no device-type inference is made", html)
        html_zh = render_html(self.report, lang="zh-CN")
        self.assertIn("可见视频源 2 个，其中 1 个未绑定任何配置文件。", html_zh)
        self.assertEqual(self.report["schema"], 1)

    def test_diff_sources_change(self):
        old = copy.deepcopy(self.report)
        new = copy.deepcopy(self.report)
        new["devices"][0]["sources"] = [self.device["sources"][0]]
        result = compare_inventories(old, new)
        self.assertEqual(result["changed"], [{
            "key": self.device["mac"].lower(), "identity_basis": "mac",
            "changes": [{"field": "sources", "old": ["Sensor_1", "Sensor_2"],
                         "new": ["Sensor_1"]}]}])
        self.assertEqual(compare_inventories(old, copy.deepcopy(old))["unchanged"], 1)

    def test_html_sources_status_when_unqueried(self):
        device = _device()
        device["sources"] = []
        device["sources_status"] = "auth_blocked"
        device["sources_reason"] = "authentication gate closed"
        html = render_html(build_report("test", {}, [device], 0))
        self.assertIn("Video sources: auth_blocked (authentication gate closed)", html)
