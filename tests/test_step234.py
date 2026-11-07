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
                                   ((401, fault('unsupported', 'ActionNotSupported')), 'unsupported'),
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

from onvifscan.scan import _ptz_body
from sim_device import envelope, ptz_node_xml, TT


def nodes_response(payload, operation='GetNodes'):
    return envelope('<t:%sResponse xmlns:t="http://www.onvif.org/ver20/ptz/wsdl" xmlns:tt="%s">'
                    '%s</t:%sResponse>' % (operation, TT, payload, operation))


class TestPTZParse(unittest.TestCase):
    def test_nodes_preserve_capacity_home_and_tour_declarations(self):
        data, malformed = P.parse_ptz_nodes(nodes_response(ptz_node_xml()))
        self.assertFalse(malformed)
        node = data[0]
        self.assertEqual(node['maximum_number_of_presets'], 80)
        self.assertTrue(node['home_supported'])
        self.assertFalse(node['fixed_home_position'])
        self.assertEqual(node['supported_preset_tour']['maximum_number_of_preset_tours'], 2)
        self.assertEqual(node['supported_preset_tour']['operations'], ['Start'])

    def test_missing_false_zero_and_invalid_are_distinct(self):
        data, _ = P.parse_ptz_nodes('<GetNodesResponse><PTZNode token="unknown"/>'
                                    '<PTZNode token="invalid" FixedHomePosition="bad">'
                                    '<MaximumNumberOfPresets>bad</MaximumNumberOfPresets>'
                                    '<HomeSupported>bad</HomeSupported></PTZNode></GetNodesResponse>')
        for node in data:
            for key in ('maximum_number_of_presets', 'home_supported', 'fixed_home_position', 'supported_preset_tour'):
                self.assertIsNone(node[key])
        node = P.parse_ptz_nodes(nodes_response(ptz_node_xml(capacity=0, home=False, tours=0)))[0][0]
        self.assertEqual(node['maximum_number_of_presets'], 0)
        self.assertFalse(node['home_supported'])
        self.assertEqual(node['supported_preset_tour']['maximum_number_of_preset_tours'], 0)
        self.assertIsNone(P.parse_ptz_nodes(nodes_response(ptz_node_xml(tours=None)))[0][0]['supported_preset_tour'])

    def test_presets_count_duplicates_names_only(self):
        data, _ = P.parse_ptz_presets('<GetPresetsResponse><Preset token="1"><Name>A</Name>'
                                      '<PTZPosition><PanTilt x="0.123" y="0.456"/></PTZPosition></Preset>'
                                      '<Preset token="2"><Name>A</Name></Preset><Preset token="3"/>'
                                      '</GetPresetsResponse>')
        self.assertEqual(data, {'count': 3, 'names': ['A', 'A', None]})
        self.assertNotIn('0.123', str(data))

    def test_ptz_empty_success_vs_unusable_response(self):
        self.assertEqual(P.parse_ptz_nodes('<GetNodesResponse/>')[0], [])
        self.assertEqual(P.parse_ptz_presets('<GetPresetsResponse/>')[0], {'count': 0, 'names': []})
        for parser in (P.parse_ptz_nodes, P.parse_ptz_presets):
            for xml in ('<Other/>', '<broken', fault()):
                self.assertIsNone(parser(xml)[0])


class TestPTZScan(SimCase):
    def test_node_dedup_capacity_separate_from_profile_actual_counts(self):
        p, entry = self.start('strict')
        rec = self.scan(entry)
        self.assertEqual(len(rec['ptz']['nodes']), 1)
        self.assertEqual(rec['ptz']['nodes'][0]['data']['maximum_number_of_presets'], 80)
        self.assertEqual([p['ptz_presets']['data']['count'] for p in rec['profiles']], [2, 2])
        self.assertEqual(sum(c['operation'] == 'GetNodes' for c in p['calls']), 1)
        self.assertFalse(any(c['operation'] == 'GetNode' for c in p['calls']))
        self.assertEqual([c['token'] for c in p['calls'] if c['operation'] == 'GetPresets'],
                         [p['token'] for p in rec['profiles']])
        self.assertNotIn('PTZPosition', str(rec))
        html = render_html(build_report('test', {}, [rec], 0))
        self.assertIn('Preset capacity', html)
        self.assertIn('actual count 2', html)

    def test_standard_two_nodes_and_no_ptz_legacy(self):
        _, entry = self.start()
        rec = self.scan(entry)
        self.assertEqual(len(rec['ptz']['nodes']), 2)
        self.assertEqual(rec['profiles'][1]['ptz_presets']['status'], 'unqueried')
        p, entry = self.start('legacy')
        rec = self.scan(entry)
        self.assertEqual(rec['ptz']['nodes_status'], 'unqueried')
        self.assertFalse(rec['ptz']['present'])
        self.assertFalse(any(c['operation'] in ('GetNodes', 'GetNode', 'GetPresets') for c in p['calls']))

    def test_nodes_without_tour_and_explicit_zero(self):
        for tours in (None, 0):
            p, entry = self.start('strict', preset_tours=tours)
            rec = self.scan(entry)
            tour = rec['ptz']['nodes'][0]['data']['supported_preset_tour']
            if tours is None:
                self.assertIsNone(tour)
            else:
                self.assertEqual(tour['maximum_number_of_preset_tours'], 0)
            self.assertFalse(any(c['operation'] == 'GetNode' for c in p['calls']))

    def test_missing_or_incomplete_node_gets_one_supplement(self):
        for payload in ('', '<t:PTZNode token="PTZNode"/>'):
            p, entry = self.start('strict', responses={'GetNodes': (200, nodes_response(payload))})
            rec = self.scan(entry)
            self.assertEqual(sum(c['operation'] == 'GetNode' for c in p['calls']), 1)
            self.assertEqual(rec['ptz']['nodes'][0]['source'], 'GetNode')
            self.assertEqual(rec['ptz']['nodes'][0]['status'], 'ok')
            self.assertEqual(rec['ptz']['nodes'][0]['data']['maximum_number_of_presets'], 80)

    def test_failed_enumeration_still_queries_known_node(self):
        p, entry = self.start('strict', responses={'GetNodes': (400, fault('unsupported', 'ActionNotSupported'))})
        rec = self.scan(entry)
        self.assertEqual(rec['ptz']['nodes_status'], 'unsupported')
        self.assertEqual(rec['ptz']['nodes'][0]['status'], 'ok')
        self.assertEqual(sum(c['operation'] == 'GetNode' for c in p['calls']), 1)

    def test_failed_node_is_unknown_not_zero(self):
        for response, status in (((503, 'unavailable'), 'failed'),
                                 ((400, fault('unsupported', 'ActionNotSupported')), 'unsupported'),
                                 ((200, nodes_response('', 'GetNode')), 'failed')):
            p, entry = self.start('strict', responses={'GetNodes': (200, nodes_response('')), 'GetNode': response})
            rec = self.scan(entry)
            self.assertEqual(rec['ptz']['nodes'][0]['status'], status)
            self.assertIsNone(rec['ptz']['nodes'][0]['data'])
            self.assertEqual([p['ptz_node_status'] for p in rec['profiles']], [status] * 2)

    def test_presets_empty_and_failures(self):
        for response, expected in (((200, '<GetPresetsResponse/>'), 'ok'),
                                   ((503, 'unavailable'), 'failed'),
                                   ((400, fault('unsupported', 'ActionNotSupported')), 'unsupported'),
                                   ((200, '<Other/>'), 'failed')):
            _, entry = self.start(responses={'GetPresets': response})
            rec = self.scan(entry)
            presets = rec['profiles'][0]['ptz_presets']
            self.assertEqual(presets['status'], expected)
            if expected == 'ok':
                self.assertEqual(presets['data'], {'count': 0, 'names': []})
            else:
                self.assertIsNone(presets['data'])

    def test_each_ptz_operation_rejection_stops_all_credentialed_calls(self):
        for operation in ('GetNodes', 'GetNode', 'GetPresets'):
            for bare in (True, False):
                responses = {'GetNodes': (200, nodes_response(''))} if operation == 'GetNode' else {}
                p, entry = self.start('strict', reject_at=operation, bare_401=bare, responses=responses)
                rec = self.scan(entry)
                i = next(i for i, c in enumerate(p['calls']) if c['operation'] == operation)
                self.assertFalse(any(c['credentialed'] for c in p['calls'][i + 1:]), p['calls'])
                self.assertEqual(rec['auth']['result'], 'failed')
                self.assertEqual([p['ptz_presets']['status'] for p in rec['profiles']], ['auth_blocked'] * 2)
                allowed = {'GetSystemDateAndTime', 'GetCapabilities', 'GetServices', 'GetDeviceInformation',
                           'GetHostname', 'GetNetworkInterfaces', 'GetProfiles', 'GetStreamUri', 'GetSnapshotUri',
                           'GetVideoEncoderConfigurationOptions', 'GetNodes', 'GetNode', 'GetPresets'}
                self.assertTrue(all(c['operation'] in allowed for c in p['calls']))

    def test_node_and_presets_requests_use_correct_scope_and_escape(self):
        import xml.etree.ElementTree as ET
        for operation, parameter in (('GetNode', 'NodeToken'), ('GetPresets', 'ProfileToken')):
            root = ET.fromstring(_ptz_body(operation, parameter, 'x<&'))
            ns = 'http://www.onvif.org/ver20/ptz/wsdl'
            self.assertEqual(root.tag, '{%s}%s' % (ns, operation))
            self.assertEqual([c.tag for c in root], ['{%s}%s' % (ns, parameter)])
            self.assertEqual(root[0].text, 'x<&')
        p, entry = self.start()
        url = entry['xaddrs'][0].replace('device_service', 'PTZ')
        code, _ = soap_call(url, _ptz_body('GetPresets', 'NodeToken', 'PTZNode'), USER, PASSWORD, timeout=2)
        self.assertEqual(code, 400)

    def test_many_profiles_and_nodes_have_no_hidden_limit(self):
        profiles = [('p%d' % i, 'H264', 640, 480, 20, True) for i in range(10)]
        xml = '<GetProfilesResponse>' + ''.join(
            '<Profiles token="p%d"><PTZConfiguration token="c%d"><NodeToken>n%d</NodeToken>'
            '</PTZConfiguration></Profiles>' % (i, i, i) for i in range(10)) + '</GetProfilesResponse>'
        p, entry = self.start(profiles=profiles, responses={
            'GetProfiles': (200, xml), 'GetNodes': (200, nodes_response(''))})
        rec = self.scan(entry)
        self.assertEqual(len(rec['ptz']['nodes']), 10)
        self.assertEqual(sum(c['operation'] == 'GetNode' for c in p['calls']), 10)
        self.assertEqual(sum(c['operation'] == 'GetPresets' for c in p['calls']), 10)
        self.assertTrue(all(p['ptz_node_status'] == 'failed' for p in rec['profiles']))
        self.assertTrue(all(p['ptz_presets']['status'] == 'ok' for p in rec['profiles']))

    def test_missing_node_token_and_service_route_are_visible(self):
        for node_config in ('<NodeToken>n</NodeToken>', ''):
            _, entry = self.start('legacy', responses={'GetProfiles': (200,
                '<GetProfilesResponse><Profiles token="p"><PTZConfiguration token="c">%s'
                '</PTZConfiguration></Profiles></GetProfilesResponse>' % node_config)})
            rec = self.scan(entry)
            profile = rec['profiles'][0]
            self.assertEqual(profile['ptz_node_status'], 'unqueried')
            self.assertEqual(profile['ptz_presets']['status'], 'unqueried')
            self.assertEqual(profile['ptz_presets']['reason'], 'no PTZ service route')
            self.assertIsNone(profile['ptz_presets']['data'])

    def test_complete_duplicate_nodes_are_not_summed_or_requeried(self):
        p, entry = self.start('strict', responses={'GetNodes': (200, nodes_response(ptz_node_xml() * 2))})
        rec = self.scan(entry)
        self.assertEqual(len(rec['ptz']['nodes']), 1)
        self.assertEqual(rec['ptz']['nodes'][0]['data']['maximum_number_of_presets'], 80)
        self.assertFalse(any(c['operation'] == 'GetNode' for c in p['calls']))


class TestNewFieldsReport(SimCase):
    def test_json_html_scrub_escape_and_no_coordinates(self):
        import json
        import tempfile
        from pathlib import Path
        from onvifscan.report import write_json
        from test_parse import PROFILES
        profile_xml = PROFILES.replace('<tt:Name>VS</tt:Name>',
                                      '<tt:Name>&lt;script&gt;SimPass123</tt:Name>'
                                      '<tt:SourceToken>source-SimPass123</tt:SourceToken>')
        presets_xml = ('<GetPresetsResponse><Preset token="secret-token"><Name>&lt;script&gt;SimPass123</Name>'
                       '<PTZPosition><PanTilt x="0.1234567" y="0.7654321"/></PTZPosition>'
                       '</Preset></GetPresetsResponse>')
        node_xml = nodes_response(ptz_node_xml('N').replace('Sim node', '&lt;node&gt;SimPass123'))
        _, entry = self.start(responses={'GetProfiles': (200, profile_xml),
                                        'GetNodes': (200, node_xml),
                                        'GetPresets': (200, presets_xml),
                                        'GetVideoEncoderConfigurationOptions': (200,
                                            encoder_options_response().replace('>Main<', '>&lt;profile&gt;SimPass123<'))})
        rec = self.scan(entry)
        report = scrub_secrets(build_report('test', {}, [rec], 0), [PASSWORD])
        self.assertEqual(report['schema'], 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inventory.json'
            write_json(report, path)
            saved = path.read_text()
            self.assertEqual(json.loads(saved)['devices'][0], report['devices'][0])
        html = render_html(report)
        for forbidden in (PASSWORD, '0.1234567', '0.7654321', 'secret-token', 'PTZPosition'):
            self.assertNotIn(forbidden, saved + html)
        self.assertNotIn('<script>', html)
        self.assertNotIn('<profile>', html)
        self.assertIn('&lt;script&gt;***', html)
        self.assertIn('&lt;profile&gt;***', html)
        self.assertIn('&lt;node&gt;***', html)
        self.assertIn('source-***', html)
        self.assertIn('frame_rate_range', html)
        self.assertIn('actual count 1', html)

    def test_media2_fractional_rates_survive_json_and_html(self):
        import json
        d = _device()
        options, _ = P.parse_encoder_options(encoder_options_response(True), 2)
        d['profiles'] = P.parse_profiles('<Profiles token="p"/>', 2)[0]
        d['profiles'][0]['encoder_options'] = {'status': 'ok', 'reason': None, 'data': options}
        report = build_report('test', {}, [d], 0)
        encoded = json.dumps(report)
        html = render_html(report)
        for value in ('29.97', '59.94'):
            self.assertIn(value, html)
            self.assertIn(value, encoded)
        self.assertIn('arbitrary combinations', html)
