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
        profiles, malformed = P.parse_profiles(PROFILES, 2)
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
