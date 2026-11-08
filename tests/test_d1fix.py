"""Revised D1: Media2 options through the existing HTTP simulator and gate."""
import xml.etree.ElementTree as ET

from onvifscan.report import build_report, render_html
from onvifscan.scan import TR2, TRT, _encoder_options_body
from onvifscan.soap import fault_kind, is_fault, soap_call
from sim_device import USER, PASSWORD, fault
from test_step234 import SimCase
import test_step01


class TestMedia2Options(SimCase):
    def test_strict_options_every_profile_and_fractional_rates(self):
        profiles = [('p%d' % i, 'H264', 1920, 1080, 30, True) for i in range(10)]
        p, entry = self.start('strict', profiles=profiles)
        rec = self.scan(entry)
        self.assertEqual(rec['level'], 'FULL')
        self.assertEqual(rec['auth']['result'], 'ok')
        calls = [c for c in p['calls'] if c['operation'] == 'GetVideoEncoderConfigurationOptions']
        self.assertEqual(len(calls), 10)
        self.assertTrue(all(c['qname'] == '{%s}GetVideoEncoderConfigurationOptions' % TR2
                            and c['path'] == '/onvif/media2' and c['credentialed'] for c in calls))
        self.assertEqual(len(rec['profiles']), 10)
        for profile in rec['profiles']:
            self.assertEqual(profile['media_gen'], 2)
            self.assertEqual(profile['fps_limit'], 30)
            options = profile['encoder_options']
            self.assertEqual(options['status'], 'ok')
            self.assertIsNone(options['reason'])
            self.assertEqual(options['data']['encodings'], ['H264', 'H265'])
            self.assertEqual(len(options['data']['declarations']), 2)
            for declaration in options['data']['declarations']:
                self.assertEqual(declaration['frame_rates_supported'], [1, 15, 29.97, 59.94])
                self.assertIsNone(declaration['frame_rate_range'])
        html = render_html(build_report('test', {}, [rec], 0))
        self.assertIn('29.97', html)
        self.assertIn('59.94', html)
        self.assertNotIn('D1 conflict', html)

    def test_request_shape_escaping_and_simulator_faults(self):
        token = 'c<&"'
        request = _encoder_options_body(token, TR2, 'tr2')
        root = ET.fromstring(request)
        self.assertEqual(root.tag, '{%s}GetVideoEncoderConfigurationOptions' % TR2)
        self.assertEqual([c.tag for c in root], ['{%s}ConfigurationToken' % TR2])
        self.assertEqual(root[0].text, token)
        self.assertEqual(len(root[0]), 0)
        p, entry = self.start('strict', encoder_token=token)
        url = entry['xaddrs'][0].replace('device_service', 'media2')
        code, xml = soap_call(url, request, USER, PASSWORD, p['clock_offset_s'], timeout=2)
        self.assertEqual(code, 200)
        response = ET.fromstring(xml).find('{http://www.w3.org/2003/05/soap-envelope}Body')[0]
        self.assertEqual(response.tag, '{%s}GetVideoEncoderConfigurationOptionsResponse' % TR2)
        self.assertEqual([c.tag for c in response], ['{%s}Options' % TR2] * 2)
        self.assertEqual(response[0].get('FrameRatesSupported'), '1 15 29.97 59.94')
        wrapped = request.replace('<tr2:ConfigurationToken>',
                                  '<tr2:GetConfiguration><tr2:ConfigurationToken>').replace(
                                      '</tr2:ConfigurationToken>',
                                      '</tr2:ConfigurationToken></tr2:GetConfiguration>')
        invalid = (
            wrapped,
            request.replace('ConfigurationToken', 'ProfileToken'),
            request.replace(TR2, TRT),
            request.replace('</tr2:ConfigurationToken>', '<tr2:GetConfiguration/></tr2:ConfigurationToken>'),
            _encoder_options_body('unknown', TR2, 'tr2'),
        )
        for malformed in invalid:
            with self.subTest(request=malformed):
                code, xml = soap_call(url, malformed, USER, PASSWORD, p['clock_offset_s'], timeout=2)
                self.assertEqual(code, 400)
                self.assertTrue(is_fault(xml))
                self.assertNotEqual(fault_kind(xml), 'NotAuthorized')

    def test_not_authorized_and_bare_401_stop_credentials(self):
        for bare in (False, True):
            with self.subTest(bare_401=bare):
                p, entry = self.start('strict', reject_at='GetVideoEncoderConfigurationOptions', bare_401=bare)
                rec = self.scan(entry)
                test_step01.TestScanHTTP.assert_stopped(self, p, 'GetVideoEncoderConfigurationOptions')
                self.assertEqual(sum(c['operation'] == 'GetVideoEncoderConfigurationOptions'
                                     for c in p['calls']), 1)
                self.assertEqual([p['encoder_options']['status'] for p in rec['profiles']],
                                 ['auth_blocked'] * 2)
                self.assertTrue(all(p['encoder_options']['data'] is None for p in rec['profiles']))
                self.assertEqual(rec['auth']['result'], 'failed')
                self.assertIn('AUTH_FAILED', [f['code'] for f in rec['findings']])

    def test_optional_failure_states(self):
        for response, expected in (((400, fault('unsupported', 'ActionNotSupported')), 'unsupported'),
                                   ((401, fault('unsupported', 'ActionNotSupported')), 'unsupported'),
                                   ((503, 'offline'), 'failed'), ((200, '<Other/>'), 'failed'),
                                   ((200, '<broken'), 'failed')):
            with self.subTest(response=response):
                _, entry = self.start('strict', responses={'GetVideoEncoderConfigurationOptions': response})
                rec = self.scan(entry)
                self.assertEqual([p['encoder_options']['status'] for p in rec['profiles']], [expected] * 2)
                self.assertTrue(all(p['encoder_options']['data'] is None for p in rec['profiles']))
                self.assertEqual(rec['auth']['result'], 'ok')
                self.assertEqual(rec['level'], 'FULL')

    def test_missing_encoder_remains_unqueried(self):
        p, entry = self.start('strict', responses={'GetProfiles': (200,
            '<GetProfilesResponse><Profiles token="p"/></GetProfilesResponse>')})
        rec = self.scan(entry)
        self.assertEqual(rec['profiles'][0]['encoder_options'], {
            'status': 'unqueried', 'reason': 'missing encoder configuration token', 'data': None})
        self.assertFalse(any(c['operation'] == 'GetVideoEncoderConfigurationOptions' for c in p['calls']))
