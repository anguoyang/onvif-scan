"""Step 2–4 fixtures and HTTP-only behaviour on the existing simulator."""
import unittest

from onvifscan import parse as P
from onvifscan.report import build_report, render_html, scrub_secrets
from test_wsse_discovery_report import _device


class TestChannelView(unittest.TestCase):
    def test_source_name_is_configuration_name_in_both_generations(self):
        for gen, config in ((1, 'VideoSourceConfiguration'), (2, 'VideoSource')):
            xml = ('<Profiles token="p"><Name>Profile name</Name><Configurations>'
                   '<%s token="config"><Name>Input &lt;A&gt;</Name>'
                   '<SourceToken>sensor</SourceToken></%s></Configurations></Profiles>'
                   % (config, config))
            profiles, _ = P.parse_profiles(xml, gen)
            p = profiles[0]
            self.assertEqual(p['source_token'], 'config')
            self.assertEqual(p['video_source_token'], 'sensor')
            self.assertEqual(p['source_configuration_name'], 'Input <A>')
            self.assertEqual(p['source_name_origin'], 'VideoSourceConfiguration.Name')
            d = _device()
            d['profiles'] = profiles
            html = render_html(build_report('test', {}, [d], 0))
            for value in ('sensor', 'config', 'Input &lt;A&gt;', 'VideoSourceConfiguration.Name'):
                self.assertIn(value, html)
            self.assertNotIn('Input <A>', html)

    def test_missing_source_name_does_not_borrow_profile_name(self):
        profiles, _ = P.parse_profiles('<Profiles token="p"><Name>P</Name>'
                                       '<VideoSourceConfiguration token="c"/></Profiles>', 1)
        self.assertIsNone(profiles[0]['source_configuration_name'])
        self.assertIsNone(profiles[0]['source_name_origin'])
        self.assertIsNone(profiles[0]['video_source_token'])

from onvifscan.scan import scan_device, _encoder_options_body
from onvifscan.soap import soap_call, fault_kind
from sim_device import SimDevices, USER, PASSWORD, fault, encoder_options_response


class SimCase(unittest.TestCase):
    def start(self, name='standard', **overrides):
        sim = SimDevices([name], http_only=True, overrides={name: overrides})
        sim.__enter__()
        self.addCleanup(sim.__exit__, None, None, None)
        p = sim.personas[name]
        entry = {'xaddrs': ['http://127.0.0.1:%d/onvif/device_service' % p['port']],
                 'source_ips': ['127.0.0.1'], 'scopes': p['scopes']}
        return p, entry

    def scan(self, entry):
        return scan_device(entry, lambda *_: {'user': USER, 'password': PASSWORD}, timeout=2)


class TestOptionsParse(unittest.TestCase):
    def test_media1_ranges_and_extension_bitrate_stay_separate(self):
        data, malformed = P.parse_encoder_options(encoder_options_response(), 1)
        self.assertFalse(malformed)
        self.assertEqual(data['encodings'], ['JPEG', 'H264'])
        h264, extension = data['declarations'][1:]
        self.assertEqual(h264['frame_rate_range'], {'min': 1, 'max': 30})
        self.assertIsNone(h264['frame_rates_supported'])
        self.assertIsNone(h264['bitrate_range_kbps'])
        self.assertEqual(extension['bitrate_range_kbps'], {'min': 64, 'max': 8192})
        self.assertEqual(h264['resolutions'][0], {'width': 1920, 'height': 1080})
        self.assertEqual(h264['profiles_supported'], ['Main'])

    def test_media2_float_lists(self):
        data, malformed = P.parse_encoder_options(encoder_options_response(True), 2)
        self.assertFalse(malformed)
        self.assertEqual(data['encodings'], ['H264', 'H265'])
        for declaration in data['declarations']:
            self.assertEqual(declaration['frame_rates_supported'], [1, 15, 29.97, 59.94])
            self.assertIsNone(declaration['frame_rate_range'])
            self.assertEqual(declaration['gov_length_range'], [1, 120])
            self.assertEqual(declaration['profiles_supported'], ['Main', 'High'])

    def test_missing_and_invalid_options_are_unknown(self):
        data, _ = P.parse_encoder_options('<GetVideoEncoderConfigurationOptionsResponse>'
                                          '<Options><H264/></Options>'
                                          '</GetVideoEncoderConfigurationOptionsResponse>', 1)
        for key, value in data['declarations'][0].items():
            if key not in ('encoding', 'origin'):
                self.assertIsNone(value, key)
        data, _ = P.parse_encoder_options('<GetVideoEncoderConfigurationOptionsResponse>'
                                          '<Options FrameRatesSupported="NaN bad 29.97">'
                                          '<Encoding>H265</Encoding></Options>'
                                          '</GetVideoEncoderConfigurationOptionsResponse>', 2)
        self.assertEqual(data['declarations'][0]['frame_rates_supported'], [None, None, 29.97])

    def test_empty_response_and_failed_response_are_distinct(self):
        self.assertEqual(P.parse_encoder_options('<GetVideoEncoderConfigurationOptionsResponse/>', 1)[0],
                         {'encodings': [], 'declarations': []})
        for xml in ('<Other/>', '<broken', fault()):
            self.assertIsNone(P.parse_encoder_options(xml, 1)[0])


class TestOptionsScan(SimCase):
    def test_every_profile_including_ninth_and_shared_encoder(self):
        profiles = [('p%d' % i, 'H264', 1920, 1080, 25, False) for i in range(10)]
        p, entry = self.start(profiles=profiles)
        rec = self.scan(entry)
        self.assertEqual(sum(c['operation'] == 'GetVideoEncoderConfigurationOptions' for c in p['calls']), 10)
        self.assertEqual([p['encoder_options']['status'] for p in rec['profiles']], ['ok'] * 10)
        self.assertTrue(all(p['fps_limit'] == 25 for p in rec['profiles']))

    def test_legacy_options_and_media2_explicit_d1_blocker(self):
        for name in ('legacy', 'strict'):
            p, entry = self.start(name)
            rec = self.scan(entry)
            for profile in rec['profiles']:
                self.assertEqual(profile['encoder_options']['status'], 'unqueried' if name == 'strict' else 'ok')
            if name == 'strict':
                self.assertFalse(any(c['operation'] == 'GetVideoEncoderConfigurationOptions' for c in p['calls']))
                self.assertIn('D1 conflict', render_html(build_report('test', {}, [rec], 0)))

    def test_options_failure_states(self):
        for response, expected in (((400, fault('unsupported', 'ActionNotSupported')), 'unsupported'),
                                   ((503, 'offline'), 'failed'), ((200, '<Other/>'), 'failed'),
                                   ((200, '<broken'), 'failed')):
            p, entry = self.start(responses={'GetVideoEncoderConfigurationOptions': response})
            rec = self.scan(entry)
            self.assertTrue(all(p['encoder_options']['status'] == expected for p in rec['profiles']))
            self.assertTrue(all(p['encoder_options']['data'] is None for p in rec['profiles']))
            self.assertEqual(rec['level'], 'FULL')
            self.assertIn(expected, render_html(build_report('test', {}, [rec], 0)))

    def test_rejection_stops_credentials_and_marks_remaining_profiles(self):
        for bare in (False, True):
            p, entry = self.start(reject_at='GetVideoEncoderConfigurationOptions', bare_401=bare)
            rec = self.scan(entry)
            i = next(i for i, c in enumerate(p['calls']) if c['operation'] == 'GetVideoEncoderConfigurationOptions')
            self.assertFalse(any(c['credentialed'] for c in p['calls'][i + 1:]))
            self.assertEqual([p['encoder_options']['status'] for p in rec['profiles']], ['auth_blocked'] * 2)

    def test_missing_encoder_is_visible(self):
        _, entry = self.start(responses={'GetProfiles': (200, '<GetProfilesResponse><Profiles token="p"/></GetProfilesResponse>')})
        rec = self.scan(entry)
        self.assertEqual(rec['profiles'][0]['encoder_options']['status'], 'unqueried')

    def test_media1_request_qnames_shape_and_token_escaping(self):
        import xml.etree.ElementTree as ET
        token = 'c<&"'
        root = ET.fromstring(_encoder_options_body(token))
        ns = 'http://www.onvif.org/ver10/media/wsdl'
        self.assertEqual(root.tag, '{%s}GetVideoEncoderConfigurationOptions' % ns)
        self.assertEqual([c.tag for c in root], ['{%s}ConfigurationToken' % ns])
        self.assertEqual(root[0].text, token)
        p, entry = self.start(encoder_token=token)
        url = entry['xaddrs'][0].replace('device_service', 'Media')
        code, _ = soap_call(url, _encoder_options_body(token), USER, PASSWORD, timeout=2)
        self.assertEqual(code, 200)
        code, text = soap_call(url, _encoder_options_body(token).replace('ConfigurationToken', 'ProfileToken'),
                               USER, PASSWORD, timeout=2)
        self.assertEqual(code, 400)
        self.assertNotEqual(fault_kind(text), 'NotAuthorized')
