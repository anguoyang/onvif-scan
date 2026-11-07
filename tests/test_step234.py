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
