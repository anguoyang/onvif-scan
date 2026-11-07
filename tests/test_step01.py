"""HTTP-only regressions using the existing three-persona simulator."""
import unittest

from onvifscan import parse as P
from onvifscan.scan import _Caller, BODY_HOSTNAME, BODY_NETIF, BODY_PROFILES2, scan_device
from onvifscan.soap import fault_kind, soap_call
from sim_device import SimDevices, USER, PASSWORD, fault
from test_parse import PROFILES

CRED = {"user": USER, "password": PASSWORD}


class TestProfilesV02(unittest.TestCase):
    def test_media1_tokens_and_source_attribute(self):
        xml = PROFILES.replace('token="VS1"', 'token="VS1" SourceToken="sensor"')
        profiles, malformed = P.parse_profiles(xml, 1)
        self.assertFalse(malformed)
        p = profiles[0]
        self.assertEqual(p["source_token"], "VS1")
        self.assertEqual(p["video_source_token"], "sensor")
        self.assertEqual(p["encoder_configuration_token"], "VE1")
        self.assertEqual(p["ptz_configuration_token"], "P1")
        self.assertEqual(p["ptz_node_token"], "N")

    def test_media2_old_shape_tolerance(self):
        xml = PROFILES.replace("ver10/media/wsdl", "ver20/media/wsdl")
        profiles, malformed = P.parse_profiles(xml, 2)
        self.assertFalse(malformed)
        self.assertEqual(profiles[0]["media_gen"], 2)
        self.assertEqual(profiles[0]["encoder_configuration_token"], "VE1")
        self.assertIsNone(profiles[0]["video_source_token"])

    def test_absent_configurations(self):
        profiles, _ = P.parse_profiles('<Profiles token="p"><Name>P</Name></Profiles>', 2)
        for key in ("source_token", "video_source_token", "encoder_configuration_token",
                    "ptz_configuration_token", "ptz_node_token"):
            self.assertIsNone(profiles[0][key])
        self.assertFalse(profiles[0]["ptz_config"])


class TestScanHTTP(unittest.TestCase):
    def start_sim(self, name="standard", **overrides):
        sim = SimDevices([name], http_only=True, overrides={name: overrides}).__enter__()
        self.addCleanup(sim.__exit__)
        p = sim.personas[name]
        url = "http://127.0.0.1:%d/onvif/device_service" % p["port"]
        return p, {"xaddrs": [url], "source_ips": ["127.0.0.1"], "scopes": p["scopes"]}

    def scan(self, entry, cred=CRED):
        return scan_device(entry, lambda *_: cred, timeout=2)

    def assert_stopped(self, p, operation):
        calls = p["calls"]
        rejected = next(i for i, c in enumerate(calls)
                        if c["operation"] == operation and c["credentialed"])
        self.assertFalse(any(c["credentialed"] for c in calls[rejected + 1:]), calls)
        allowed = {"GetSystemDateAndTime", "GetCapabilities", "GetServices",
                   "GetDeviceInformation", "GetHostname", "GetNetworkInterfaces",
                   "GetProfiles", "GetStreamUri", "GetSnapshotUri"}
        self.assertTrue(all(c["operation"] in allowed for c in calls))

    def test_caller_gate_blocks_even_direct_call_after_rejection(self):
        p, entry = self.start_sim(reject_at="GetHostname")
        caller = _Caller(2, "127.0.0.1")
        caller.cred = CRED
        caller.call(entry["xaddrs"][0], BODY_HOSTNAME, auth=True)
        self.assertTrue(caller.auth_failed)
        count = len(p["calls"])
        self.assertIsNone(caller.call(entry["xaddrs"][0], BODY_NETIF, auth=True)[0])
        self.assertEqual(len(p["calls"]), count)
        caller.call(entry["xaddrs"][0], BODY_NETIF)
        self.assertEqual(len(p["calls"]), count + 1)
        self.assertFalse(p["calls"][-1]["credentialed"])

    def test_rejection_stops_hostname_and_stream_chains(self):
        for operation in ("GetHostname", "GetStreamUri", "GetProfiles", "GetCapabilities"):
            with self.subTest(operation=operation):
                p, entry = self.start_sim("strict", reject_at=operation)
                rec = self.scan(entry)
                self.assert_stopped(p, operation)
                self.assertEqual(rec["auth"]["result"], "failed")
                self.assertIn("AUTH_FAILED", [f["code"] for f in rec["findings"]])

    def test_bare_401_stops_credentials(self):
        p, entry = self.start_sim(reject_at="GetHostname", bare_401=True)
        rec = self.scan(entry)
        self.assert_stopped(p, "GetHostname")
        self.assertEqual(rec["auth"]["result"], "failed")
        self.assertIn("AUTH_FAILED", [f["code"] for f in rec["findings"]])

    def test_unsupported_operation_is_not_auth_failure(self):
        response = fault("unsupported operation", "ActionNotSupported")
        self.assertEqual(fault_kind(response), "NotSupported")
        p, entry = self.start_sim(responses={"GetHostname": (400, response)})
        rec = self.scan(entry)
        self.assertEqual(rec["auth"]["result"], "ok")
        self.assertNotIn("AUTH_FAILED", [f["code"] for f in rec["findings"]])
        self.assertTrue(any(c["operation"] == "GetNetworkInterfaces" and c["credentialed"]
                            for c in p["calls"]))

    def test_wrong_supplied_credential_is_never_retried(self):
        p, entry = self.start_sim("strict")
        rec = self.scan(entry, {"user": USER, "password": "deliberately-wrong-fixture"})
        self.assertEqual(rec["auth"]["result"], "failed")
        self.assertEqual(sum(c["credentialed"] for c in p["calls"]), 1)

    def test_strict_real_media2_structure(self):
        p, entry = self.start_sim("strict")
        rec = self.scan(entry)
        self.assertEqual(rec["level"], "FULL")
        status, xml = soap_call(rec["services"]["media2"], BODY_PROFILES2,
                                USER, PASSWORD, p["clock_offset_s"], timeout=2)
        self.assertEqual(status, 200)
        root, malformed = P.safe_parse(xml)
        self.assertFalse(malformed)
        configs = [el for el in root.iter() if P.local(el) == "Configurations"]
        self.assertEqual(len(configs), 2)
        self.assertEqual([P.local(el) for el in configs[0]],
                         ["VideoSource", "VideoEncoder", "PTZ"])
        self.assertNotIn("VideoSourceConfiguration", xml)
        self.assertEqual(len(rec["profiles"]), 2)
        for profile in rec["profiles"]:
            self.assertEqual(profile["media_gen"], 2)
            self.assertEqual(profile["source_token"], "VS_1")
            self.assertEqual(profile["video_source_token"], "Sensor_1")
            self.assertEqual(profile["encoder_configuration_token"], "VE_1")
            self.assertEqual(profile["ptz_configuration_token"], "PTZ_1")
            self.assertEqual(profile["ptz_node_token"], "PTZNode")
            self.assertEqual(profile["width"], 1920)
            self.assertEqual(profile["fps_limit"], 30)
        self.assertEqual(rec["channel_count"], 1)
        self.assertEqual(rec["channel_count_basis"], "video_source")

    def test_channel_count_falls_back_to_profiles(self):
        _, entry = self.start_sim(source_tokens=False)
        rec = self.scan(entry)
        self.assertEqual(len(rec["profiles"]), 2)
        self.assertEqual(rec["channel_count"], 2)
        self.assertEqual(rec["channel_count_basis"], "profiles")

    def test_channel_count_deduplicates_source_across_configurations(self):
        xml = ('<GetProfilesResponse><Profiles token="main">'
               '<VideoSourceConfiguration token="config1" SourceToken="sensor1"/>'
               '</Profiles><Profiles token="sub">'
               '<VideoSourceConfiguration token="config2"><SourceToken>sensor1</SourceToken>'
               '</VideoSourceConfiguration></Profiles></GetProfilesResponse>')
        _, entry = self.start_sim(responses={"GetProfiles": (200, xml)})
        rec = self.scan(entry)
        self.assertEqual([p["source_token"] for p in rec["profiles"]], ["config1", "config2"])
        self.assertEqual(rec["channel_count"], 1)
        self.assertEqual(rec["channel_count_basis"], "video_source")

    def test_services_queried_despite_successful_capabilities(self):
        p, entry = self.start_sim()
        rec = self.scan(entry)
        self.assertEqual(rec["level"], "FULL")
        calls = [c for c in p["calls"] if c["operation"] == "GetServices"]
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0]["credentialed"])
        self.assertEqual(len(rec["services_declared"]), 6)
        self.assertIn("urn:fictional:sim:extra", [s["namespace"] for s in rec["services_declared"]])
        self.assertTrue(rec["services"]["media"].endswith("/onvif/Media"))
        self.assertIn("events", rec["services"])
        self.assertEqual(rec["services_declared"][0]["version"], {"major": 2, "minor": 6})

    def test_strict_services_do_not_invent_media1(self):
        _, entry = self.start_sim("strict")
        rec = self.scan(entry)
        self.assertNotIn("media", rec["services"])
        self.assertIn("media2", rec["services"])
        namespaces = [s["namespace"] for s in rec["services_declared"]]
        self.assertIn("http://www.onvif.org/ver20/media/wsdl", namespaces)
        self.assertNotIn("http://www.onvif.org/ver10/media/wsdl", namespaces)

    def test_legacy_services_missing_version(self):
        _, entry = self.start_sim("legacy")
        rec = self.scan(entry)
        self.assertEqual(rec["level"], "FULL")
        for service in rec["services_declared"]:
            self.assertEqual(service["version"], {"major": None, "minor": None})
            self.assertEqual(service["missing_fields"], ["version.major", "version.minor"])

    def test_services_failures_preserve_profile_and_null(self):
        for response in ((400, fault("unsupported", "ActionNotSupported")),
                         (200, fault("unsupported", "OptionalActionNotImplemented")),
                         (503, "unavailable"), (200, '<GetServicesResponse>'),
                         (200, '<Unexpected/>')):
            with self.subTest(response=response):
                _, entry = self.start_sim("legacy", responses={"GetServices": response})
                rec = self.scan(entry)
                self.assertEqual(rec["level"], "FULL")
                self.assertIsNone(rec["services_declared"])
                self.assertNotIn("AUTH_FAILED", [f["code"] for f in rec["findings"]])

    def test_services_empty_success(self):
        _, entry = self.start_sim(responses={"GetServices": (200, '<GetServicesResponse/>')})
        rec = self.scan(entry)
        self.assertEqual(rec["services_declared"], [])
        self.assertEqual(rec["level"], "FULL")

    def test_services_rejection_stops_credentials(self):
        for bare in (False, True):
            with self.subTest(bare=bare):
                p, entry = self.start_sim(reject_at="GetServices", bare_401=bare)
                rec = self.scan(entry)
                self.assert_stopped(p, "GetServices")
                self.assertEqual(rec["auth"]["result"], "failed")
                self.assertIsNone(rec["services_declared"])

    def test_anonymous_services_once_without_credentials(self):
        for allowed in (True, False):
            with self.subTest(allowed=allowed):
                p, entry = self.start_sim("legacy", auth_services=not allowed)
                rec = self.scan(entry, None)
                self.assertEqual(sum(c["operation"] == "GetServices" for c in p["calls"]), 1)
                self.assertFalse(any(c["credentialed"] for c in p["calls"]))
                if allowed:
                    self.assertEqual(len(rec["services_declared"]), 2)
                else:
                    self.assertIsNone(rec["services_declared"])

    def test_services_blocked_by_previous_rejection(self):
        p, entry = self.start_sim("strict", reject_at="GetCapabilities")
        rec = self.scan(entry)
        self.assertFalse(any(c["operation"] == "GetServices" for c in p["calls"]))
        self.assertIsNone(rec["services_declared"])

    def test_routes_keep_caps_priority_and_mask_declared_uri_password(self):
        xml = ('<GetServicesResponse><Service>'
               '<Namespace>http://www.onvif.org/ver10/media/wsdl</Namespace>'
               '<XAddr>http://fixture:uri-secret@192.0.2.1/alternate</XAddr>'
               '</Service></GetServicesResponse>')
        _, entry = self.start_sim(responses={"GetServices": (200, xml)})
        rec = self.scan(entry)
        self.assertEqual(rec["level"], "FULL")
        self.assertTrue(rec["services"]["media"].endswith("/onvif/Media"))
        self.assertEqual(rec["services_declared"][0]["xaddr"],
                         "http://fixture:***@192.0.2.1/alternate")
        self.assertNotIn("uri-secret", str(rec))


class TestServicesParse(unittest.TestCase):
    def test_full_unknown_duplicate_and_version_values(self):
        xml = ('<GetServicesResponse>'
               '<Service><Namespace>http://www.onvif.org/ver10/media/wsdl</Namespace>'
               '<XAddr>http://192.0.2.1/first</XAddr>'
               '<Version><Major>23</Major><Minor>12</Minor></Version></Service>'
               '<Service><Namespace>urn:fictional:extra</Namespace><XAddr>http://192.0.2.1/x</XAddr>'
               '<Version><Major>0</Major><Minor>0</Minor></Version></Service>'
               '<Service><Namespace>http://www.onvif.org/ver10/media/wsdl</Namespace>'
               '<XAddr>http://192.0.2.1/second</XAddr></Service></GetServicesResponse>')
        routes, declared, malformed = P.parse_services(xml)
        self.assertFalse(malformed)
        self.assertEqual(routes, {"media": "http://192.0.2.1/first"})
        self.assertEqual(len(declared), 3)
        self.assertEqual(declared[0]["version"], {"major": 23, "minor": 12})
        self.assertEqual(declared[1]["namespace"], "urn:fictional:extra")
        self.assertEqual(declared[1]["version"], {"major": 0, "minor": 0})
        self.assertEqual(declared[2]["xaddr"], "http://192.0.2.1/second")
        self.assertEqual(declared[2]["missing_fields"], ["version.major", "version.minor"])

    def test_missing_fields_and_invalid_version(self):
        routes, declared, malformed = P.parse_services(
            '<GetServicesResponse><Service/><Service><Namespace>urn:fictional:x</Namespace>'
            '<Version><Major>n/a</Major><Minor>-1</Minor></Version></Service>'
            '<Service><Version><Major>2</Major></Version></Service></GetServicesResponse>')
        self.assertTrue(malformed)
        self.assertEqual(routes, {})
        self.assertEqual(len(declared), 3)
        self.assertEqual(declared[0]["missing_fields"],
                         ["namespace", "xaddr", "version.major", "version.minor"])
        self.assertEqual(declared[1]["invalid_fields"], ["version.major", "version.minor"])
        self.assertEqual(declared[2]["version"], {"major": 2, "minor": None})

    def test_empty_success_is_distinct_from_failure(self):
        self.assertEqual(P.parse_services('<GetServicesResponse/>'), ({}, [], False))
        for xml in ('<GetServicesResponse>', '<OtherResponse/>', fault()):
            with self.subTest(xml=xml):
                self.assertIsNone(P.parse_services(xml)[1])

    def test_loose_xml_and_scoped_version(self):
        _, declared, malformed = P.parse_services(
            '<tds:GetServicesResponse><tds:Service><tds:Namespace>urn:fictional:x</tds:Namespace>'
            '<tds:Capabilities><Version><Major>999</Major></Version></tds:Capabilities>'
            '<tds:Version><tt:Major>2</tt:Major><tt:Minor>1</tt:Minor></tds:Version>'
            '</tds:Service></tds:GetServicesResponse>')
        self.assertTrue(malformed)
        self.assertEqual(declared[0]["version"], {"major": 2, "minor": 1})


class TestServicesReport(unittest.TestCase):
    def test_json_html_preserve_declarations_and_escape(self):
        import json
        import tempfile
        from pathlib import Path
        from onvifscan.report import build_report, render_html, scrub_secrets, terminal_lines, write_json
        from test_wsse_discovery_report import _device
        device = _device()
        report = build_report("0.2-dev", {}, [device], 0)
        terminal = terminal_lines(report)
        _, declared, _ = P.parse_services(
            '<GetServicesResponse><Service><Namespace>urn:fictional:&lt;script&gt;</Namespace>'
            '<XAddr>http://fixture:uri-secret@192.0.2.1/?a=1&amp;b=2</XAddr>'
            '<Version><Major>9</Major><Minor>3</Minor></Version></Service>'
            '<Service><Namespace>urn:fictional:SimPass123</Namespace></Service></GetServicesResponse>')
        device["services_declared"] = declared
        report = scrub_secrets(report, [PASSWORD])
        self.assertEqual(report["schema"], 1)
        self.assertEqual(terminal_lines(report), terminal)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            write_json(report, path)
            saved = path.read_text()
            self.assertEqual(json.loads(saved)["devices"][0]["services_declared"],
                             report["devices"][0]["services_declared"])
        html = render_html(report)
        self.assertIn("urn:fictional:&lt;script&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertIn("9.3", html)
        self.assertIn("version.major", html)
        self.assertIn("?a=1&amp;b=2", html)
        for secret in ("uri-secret", PASSWORD):
            self.assertNotIn(secret, html + saved)
        # HTML also masks userinfo when rendering a caller-provided record.
        report["devices"][0]["services_declared"][0]["xaddr"] = 'http://u:extra-secret@192.0.2.1/'
        self.assertNotIn("extra-secret", render_html(report))

    def test_html_unknown_and_empty_are_distinct(self):
        from onvifscan.report import build_report, render_html
        from test_wsse_discovery_report import _device
        device = _device()
        report = build_report("0.2-dev", {}, [device], 0)
        self.assertIn("Services declared: not obtained", render_html(report))
        device["services_declared"] = None
        self.assertIn("Services declared: not obtained", render_html(report))
        device["services_declared"] = []
        self.assertIn("Services declared: 0", render_html(report))
