"""End-to-end against the simulated devices in tests/sim_device.py.

Needs loopback UDP. Where UDP is unavailable (some sandboxes block it
entirely), the whole class skips instead of failing.
"""
import socket
import unittest

from onvifscan.discovery import discover
from onvifscan.scan import scan_device
from sim_device import PERSONAS, SimDevices

CRED = {"user": "onvif_user", "password": "SimPass123"}


def _udp_works():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"x", ("127.0.0.1", 9))
        s.close()
        return True
    except OSError:
        return False


@unittest.skipUnless(_udp_works(), "loopback UDP unavailable in this environment")
class TestSimE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sim = SimDevices().__enter__()
        targets = [("127.0.0.1", PERSONAS[n]["disc_port"]) for n in PERSONAS]
        devices, _meta = discover(ifaces=[("lo", "127.0.0.1")], timeout=3.0,
                                  directed=targets)
        cls.by_port = {}
        for entry in devices:
            for x in entry["xaddrs"]:
                cls.by_port[x] = entry

    @classmethod
    def tearDownClass(cls):
        cls.sim.__exit__()

    def _scan(self, name):
        port = PERSONAS[name]["port"]
        entry = self.by_port.get("http://127.0.0.1:%d/onvif/device_service" % port)
        self.assertIsNotNone(entry, "device %s not discovered" % name)
        return scan_device(entry, lambda ip, ep, mac: CRED, timeout=3.0)

    def test_all_discovered(self):
        expected = {
            "http://127.0.0.1:%d/onvif/device_service" % PERSONAS[name]["port"]
            for name in PERSONAS
        }
        self.assertTrue(expected.issubset(self.by_port))
        self.assertEqual(
            len(PERSONAS),
            len({self.by_port[xaddr]["endpoint"] for xaddr in expected}),
        )

    def test_standard_full_with_redacted_stream_uri(self):
        rec = self._scan("standard")
        self.assertEqual(rec["level"], "FULL")
        self.assertEqual(rec["ip"], "127.0.0.1", "IPv4 XAddr is preferred for inventory")
        self.assertIn("http://[2001:db8::1]:18081/onvif/device_service", rec["xaddrs"])
        self.assertIn("http://127.0.0.1:18081/onvif/device_service", rec["xaddrs"])
        self.assertEqual(rec["device_info"]["Model"], "ViewCam AC-200")
        self.assertTrue(rec["ptz"]["present"])
        self.assertEqual(rec["channel_count"], 1)
        self.assertEqual(len(rec["profiles"]), 2)
        uri = rec["profiles"][0]["stream_uri"]
        self.assertIn(":***@", uri)
        self.assertNotIn("SimPass123", str(rec))

    def test_legacy_unauth_info_disclosure(self):
        rec = self._scan("legacy")
        self.assertEqual(rec["level"], "FULL")
        codes = [f["code"] for f in rec["findings"]]
        self.assertIn("UNAUTH_INFO_DISCLOSURE", codes)
        self.assertIn("SCOPES_MINIMAL", codes)
        self.assertFalse(rec["ptz"]["present"])

    def test_strict_clock_skew_and_media2(self):
        rec = self._scan("strict")
        self.assertEqual(rec["level"], "FULL")
        self.assertEqual(rec["auth"]["result"], "ok")
        self.assertTrue(rec["clock"]["skew"])
        self.assertGreater(rec["clock"]["offset_s"], 3600)
        codes = [f["code"] for f in rec["findings"]]
        self.assertIn("CLOCK_SKEW", codes)
        self.assertIn("MEDIA2_ONLY", codes)
        self.assertTrue(all(p["media_gen"] == 2 for p in rec["profiles"]))

    def test_no_cred_caps_level(self):
        entry = self.by_port["http://127.0.0.1:%d/onvif/device_service" % PERSONAS["strict"]["port"]]
        rec = scan_device(entry, lambda ip, ep, mac: None, timeout=3.0)
        self.assertIn(rec["level"], ("PARTIAL", "DISCOVERED_ONLY"))
        self.assertIsNone(rec["device_info"])
        self.assertEqual(rec["auth"]["result"], "not_tried")


if __name__ == "__main__":
    unittest.main()
