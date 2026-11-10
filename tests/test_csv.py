"""CSV export contracts; reuse the existing fictional devices and HTTP simulator."""
import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from onvifscan.cli import main
from onvifscan.report import build_report, write_csv
from sim_device import PERSONAS, SimDevices, USER, PASSWORD
from test_wsse_discovery_report import _device


class TestCSV(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.path = self.root / 'inventory.csv'
        self.device = _device()

    def export(self, devices=None):
        write_csv(build_report('test', {}, devices if devices is not None else [self.device], 0),
                  self.path)
        with self.path.open(encoding='utf-8-sig', newline='') as f:
            return list(csv.DictReader(f))

    def test_header_bom_and_empty_inventory(self):
        self.assertEqual(self.export([]), [])
        self.assertTrue(self.path.read_bytes().startswith(b'\xef\xbb\xbf'))
        self.assertEqual(self.path.read_text(encoding='utf-8-sig').strip(),
                         'ip,port,mac,manufacturer,model,firmware_version,hostname,level,'
                         'profile_token,profile_name,media_gen,video_source_token,'
                         'encoder_options_status,ptz_node_token,preset_count,channel_count,'
                         'clock_offset_s,findings')

    def test_no_profile_still_has_one_row_and_empty_profile_cells(self):
        rows = self.export()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['firmware_version'], '1')
        for field in ('profile_token', 'profile_name', 'media_gen', 'video_source_token',
                      'encoder_options_status', 'ptz_node_token', 'preset_count'):
            self.assertEqual(rows[0][field], '')

    def test_multiple_profiles_repeat_device_fields(self):
        self.device['profiles'] = [{'token': 'one', 'name': '主码流', 'media_gen': 1},
                                   {'token': 'two', 'name': '子码流', 'media_gen': 2}]
        rows = self.export([self.device, _device('PARTIAL')])
        self.assertEqual(len(rows), 3)
        self.assertEqual([r['profile_token'] for r in rows], ['one', 'two', ''])
        self.assertEqual([r['profile_name'] for r in rows], ['主码流', '子码流', ''])
        self.assertTrue(all(r['ip'] == self.device['ip'] for r in rows))
        self.assertEqual([r['media_gen'] for r in rows], ['1', '2', ''])

    def test_nulls_are_empty_and_numeric_zero_is_preserved(self):
        self.device.update(device_info=None, port=None, clock={'offset_s': -1.25})
        self.device['profiles'] = [{'ptz_presets': {'data': {'count': 0}},
                                   'encoder_options': {'status': 'ok'},
                                   'ptz_node_token': 'node', 'video_source_token': 'sensor'},
                                  {'ptz_presets': {'data': None}}]
        rows = self.export()
        for field in ('manufacturer', 'model', 'firmware_version', 'mac', 'port', 'hostname'):
            self.assertEqual(rows[0][field], '')
        self.assertEqual(rows[0]['channel_count'], '0')
        self.assertEqual(rows[0]['clock_offset_s'], '-1.25')
        self.assertEqual(rows[0]['preset_count'], '0')
        self.assertEqual(rows[1]['preset_count'], '')
        self.assertEqual(rows[0]['encoder_options_status'], 'ok')
        self.assertEqual(rows[0]['ptz_node_token'], 'node')
        self.assertEqual(rows[0]['video_source_token'], 'sensor')

    def test_csv_quoting_unicode_and_newlines_round_trip(self):
        value = '虚构摄像机,"实验室"\n二层'
        self.device['device_info']['Model'] = value
        self.assertEqual(self.export()[0]['model'], value)

    def test_findings_are_unique_codes_without_details(self):
        self.device['findings'] = [{'code': code, 'detail': PASSWORD} for code in ('Z', 'A', 'Z')]
        self.assertEqual(self.export()[0]['findings'], 'A;Z')
        self.assertNotIn(PASSWORD, self.path.read_text(encoding='utf-8-sig'))

    def test_cli_scrubs_all_exported_text_fields(self):
        self.device.update(ip=PASSWORD, mac=PASSWORD, hostname=PASSWORD, level='FULL')
        self.device['device_info'] = dict.fromkeys(('Manufacturer', 'Model', 'FirmwareVersion'), PASSWORD)
        self.device['profiles'] = [dict.fromkeys(('token', 'name', 'video_source_token',
                                                 'ptz_node_token'), PASSWORD)]
        self.device['profiles'][0]['encoder_options'] = {'status': PASSWORD}
        self.device['findings'] = [{'code': PASSWORD, 'detail': PASSWORD}]
        output = io.StringIO()
        with patch('onvifscan.cli.discover', return_value=([{}], {})), \
                patch('onvifscan.cli.scan_device', return_value=self.device), \
                contextlib.redirect_stdout(output):
            rc = main(['scan', '--user', USER, '--password', PASSWORD, '--no-html',
                       '--csv', str(self.path), '--json', str(self.root / 'inventory.json')])
        self.assertEqual(rc, 0)
        for path in self.root.iterdir():
            self.assertNotIn(PASSWORD, path.read_text(encoding='utf-8-sig'))
        self.assertNotIn(PASSWORD, output.getvalue())
        self.assertIn('***', self.path.read_text(encoding='utf-8-sig'))

    def test_cli_explicit_csv_quiet_and_no_html_coexist(self):
        for csv_enabled, no_html in ((False, True), (True, True), (True, False)):
            with self.subTest(csv=csv_enabled, no_html=no_html):
                output = io.StringIO()
                jp, hp = self.root / 'report.json', self.root / 'report.html'
                args = ['scan', '--quiet', '--json', str(jp), '--html', str(hp)]
                if no_html:
                    args.append('--no-html')
                if csv_enabled:
                    args.extend(['--csv', str(self.path)])
                with patch('onvifscan.cli.discover', return_value=([], {})), \
                        contextlib.redirect_stdout(output):
                    self.assertEqual(main(args), 0)
                lines = output.getvalue().splitlines()
                self.assertEqual(len(lines), 2)
                expected = 'reports: ' + str(jp)
                if not no_html:
                    expected += ' + ' + str(hp)
                if csv_enabled:
                    expected += ' + ' + str(self.path)
                self.assertEqual(lines[-1], expected)
                self.assertEqual(self.path.exists(), csv_enabled)
                self.assertEqual(hp.exists(), not no_html)
                self.assertFalse((self.root / 'onvif-inventory.csv').exists())

    def test_http_only_three_personas_export_through_real_cli_scan(self):
        with SimDevices(http_only=True) as sim:
            args = ['scan', '--quiet', '--no-html', '--user', USER, '--password', PASSWORD,
                    '--json', str(self.root / 'scan.json'), '--csv', str(self.path)]
            for name in PERSONAS:
                args.extend(['--device-url', 'http://127.0.0.1:%d/onvif/device_service'
                             % sim.personas[name]['port']])
            with patch('onvifscan.cli.discover', return_value=([], {})), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
        report = json.loads((self.root / 'scan.json').read_text())
        with self.path.open(encoding='utf-8-sig', newline='') as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(report['devices']), 3)
        self.assertEqual(len(rows), sum(max(1, len(d['profiles'])) for d in report['devices']))
        self.assertEqual({r['manufacturer'] for r in rows},
                         {p['manufacturer'] for p in PERSONAS.values()})
        self.assertNotIn(PASSWORD, self.path.read_text(encoding='utf-8-sig'))
