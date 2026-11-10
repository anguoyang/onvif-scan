"""Offline diff: identities, six field classes, noise, validation and CLI exits."""
import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from onvifscan.cli import main
from onvifscan.diff import compare_inventories
from onvifscan.report import build_report, scrub_secrets, write_json
from sim_device import PASSWORD
from test_wsse_discovery_report import _device


class TestDiff(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.old = build_report('test', {}, [_device()], 0)
        self.new = copy.deepcopy(self.old)
        self.device = self.new['devices'][0]

    def diff(self):
        return compare_inventories(self.old, self.new)

    def assert_change(self, field, old, new, basis='ip'):
        self.assertEqual(self.diff(), {
            'added': [], 'removed': [], 'unchanged': 0,
            'changed': [{'key': self.device['mac'].lower() if basis == 'mac' else self.device['ip'],
                         'identity_basis': basis,
                         'changes': [{'field': field, 'old': old, 'new': new}]}]})

    def cli(self, extra=(), write_inputs=True):
        if write_inputs:
            write_json(self.old, self.root / 'old.json')
            write_json(self.new, self.root / 'new.json')
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = main(['diff', str(self.root / 'old.json'), str(self.root / 'new.json'), *extra])
        return rc, stdout.getvalue(), stderr.getvalue()

    def test_mac_is_case_insensitive_and_survives_ip_move(self):
        self.old['devices'][0]['mac'] = 'AA:BB:CC:00:00:01'
        self.device.update(mac='aa:bb:cc:00:00:01', ip='192.0.2.99')
        self.assertEqual(self.diff()['unchanged'], 1)
        self.device['level'] = 'PARTIAL'
        self.assert_change('level', 'FULL', 'PARTIAL', basis='mac')

    def test_ip_fallback_and_added_removed_keys(self):
        self.device['level'] = 'PARTIAL'
        self.assert_change('level', 'FULL', 'PARTIAL')
        self.device['ip'] = '192.0.2.99'
        self.assertEqual(self.diff(), {'added': ['192.0.2.99'], 'removed': ['192.0.2.10'],
                                      'changed': [], 'unchanged': 0})
        self.device['mac'] = 'AA:BB:CC:00:00:02'
        self.assertEqual(self.diff()['added'], ['aa:bb:cc:00:00:02'])

    def test_firmware_version(self):
        self.device['device_info']['FirmwareVersion'] = '2'
        self.assert_change('device_info.FirmwareVersion', '1', '2')

    def test_level(self):
        self.device['level'] = 'UNREACHABLE'
        self.assert_change('level', 'FULL', 'UNREACHABLE')

    def test_profile_token_set_add_remove_and_media_generation(self):
        old_profile = {'token': 'main', 'media_gen': 1}
        self.old['devices'][0]['profiles'] = [old_profile]
        for profiles in ([], [{'token': 'sub', 'media_gen': 1}],
                         [{'token': 'main', 'media_gen': 2}],
                         [old_profile, {'token': 'sub', 'media_gen': 2}],
                         [{'token': None, 'media_gen': None}, {'token': '', 'media_gen': 0}]):
            with self.subTest(profiles=profiles):
                self.device['profiles'] = profiles
                self.assert_change('profiles', [old_profile], profiles)

    def test_channel_count(self):
        self.device['channel_count'] = 2
        self.assert_change('channel_count', 0, 2)

    def test_findings_code_set(self):
        self.device['findings'] = [{'code': 'B'}, {'code': 'A'}, {'code': 'B'}]
        self.assert_change('findings.code', [], ['A', 'B'])

    def test_services_namespace_set(self):
        self.device['services_declared'] = [{'namespace': ns} for ns in ('urn:b', None, 'urn:a', 'urn:b')]
        self.assert_change('services_declared.namespace', [], ['urn:a', 'urn:b'])

    def test_metadata_details_order_and_uncompared_fields_are_noise(self):
        before = self.old['devices'][0]
        before.update(profiles=[{'token': 'b', 'media_gen': 2}, {'token': 'a', 'media_gen': 1}],
                      findings=[{'code': 'B', 'detail': 'before'}, {'code': 'A'}],
                      services_declared=[{'namespace': 'urn:b'}, {'namespace': 'urn:a'}])
        self.new = copy.deepcopy(self.old)
        after = self.new['devices'][0]
        self.new.update(generated_at='later', tool_version='other', scan={'duration_s': 100})
        after.update(hostname='changed', clock={'offset_s': 120}, channel_count_basis='other')
        after['device_info']['Model'] = 'Other fictional model'
        for field in ('profiles', 'findings', 'services_declared'):
            after[field].reverse()
            after[field].append(copy.deepcopy(after[field][0]))
        after['profiles'][0].update(name='renamed', encoder_options={'status': 'failed'})
        after['findings'][0].update(detail='after', severity='warn')
        after['services_declared'][0].update(xaddr='http://192.0.2.20/', version={'major': 9})
        self.assertEqual(self.diff(), {'added': [], 'removed': [], 'changed': [], 'unchanged': 1})

    def test_missing_optional_fields_and_successful_empty_sets(self):
        self.old['devices'][0] = {'ip': '192.0.2.10'}
        self.device = self.new['devices'][0] = {
            'ip': '192.0.2.10', 'mac': None, 'device_info': None, 'profiles': [],
            'findings': [], 'services_declared': [], 'level': None, 'channel_count': None}
        self.assertEqual(self.diff()['unchanged'], 1)
        self.device['device_info'] = {'FirmwareVersion': '1'}
        self.assert_change('device_info.FirmwareVersion', None, '1')

    def test_cli_exit_zero_one_quiet_and_explicit_json(self):
        self.assertEqual(self.cli(['--quiet']), (0, 'diff: +0 -0 ~0 =1\n', ''))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['new.json', 'old.json'])
        self.device['level'] = 'PARTIAL'
        path = self.root / 'diff.json'
        self.assertEqual(self.cli(['--quiet', '--json', str(path)]), (1, 'diff: +0 -0 ~1 =0\n', ''))
        self.assertEqual(json.loads(path.read_text()), self.diff())
        for devices, summary in (([], 'diff: +0 -1 ~0 =0\n'),
                                 ([_device(), dict(_device(), ip='192.0.2.99')],
                                  'diff: +1 -0 ~0 =1\n')):
            self.new['devices'] = devices
            self.assertEqual(self.cli()[:2], (1, summary))

    def test_cli_version_mismatch_warns_without_a_change(self):
        self.new['tool_version'] = 'future'
        rc, out, err = self.cli(['--quiet'])
        self.assertEqual((rc, out), (0, 'diff: +0 -0 ~0 =1\n'))
        self.assertIn('warning: tool_version', err)

    def test_cli_input_errors_exit_two_without_tracebacks(self):
        invalid = [None, [], {}, dict(self.old, schema=2), dict(self.old, schema=True),
                   dict(self.old, kind='diff'), dict(self.old, devices={}),
                   dict(self.old, devices=[{}]), dict(self.old, devices=[_device(), _device()]),
                   dict(self.old, devices=[dict(_device(), profiles=42)]),
                   dict(self.old, devices=[dict(_device(), device_info=['bad'])])]
        for value in invalid:
            for filename in ('old.json', 'new.json'):
                with self.subTest(value=value, filename=filename):
                    self.cli()
                    write_json(value, self.root / filename)
                    rc, out, err = self.cli(write_inputs=False)
                    self.assertEqual((rc, out), (2, ''))
                    self.assertIn('error:', err)
                    self.assertNotIn('Traceback', err)
        for content in (b'{', b'\xff'):
            (self.root / 'old.json').write_bytes(content)
            self.assertEqual(self.cli(write_inputs=False)[0], 2)
        (self.root / 'old.json').unlink()
        self.assertEqual(self.cli(write_inputs=False)[0], 2)
        self.assertEqual(self.cli(['--json', str(self.root / 'missing' / 'out.json')])[0], 2)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
            main(['diff'])
        self.assertEqual(exc.exception.code, 2)

    def test_cli_is_offline_and_never_resolves_credentials(self):
        with patch('onvifscan.cli.discover', side_effect=AssertionError('discovery')), \
                patch('onvifscan.cli.scan_device', side_effect=AssertionError('scan')), \
                patch('onvifscan.cli._load_creds', side_effect=AssertionError('credentials')), \
                patch('onvifscan.cli.getpass.getpass', side_effect=AssertionError('prompt')), \
                patch('onvifscan.cli.iface_ipv4', side_effect=AssertionError('interfaces')), \
                patch('socket.socket', side_effect=AssertionError('network')), \
                patch.dict(os.environ, {'ONVIFSCAN_PASSWORD': PASSWORD}):
            self.assertEqual(self.cli()[0], 0)

    def test_scrubbed_inventory_fields_stay_scrubbed_in_diff_output(self):
        self.device['mac'] = PASSWORD
        self.old['devices'][0]['mac'] = PASSWORD
        self.device['device_info']['FirmwareVersion'] = PASSWORD
        self.device['profiles'] = [{'token': PASSWORD, 'media_gen': 1}]
        self.device['findings'] = [{'code': PASSWORD, 'detail': PASSWORD}]
        self.device['services_declared'] = [{'namespace': PASSWORD}]
        self.old = scrub_secrets(self.old, [PASSWORD])
        self.new = scrub_secrets(self.new, [PASSWORD])
        path = self.root / 'diff.json'
        rc, out, err = self.cli(['--json', str(path)])
        self.assertEqual(rc, 1)
        self.assertNotIn(PASSWORD, out + err)
        for file in self.root.iterdir():
            self.assertNotIn(PASSWORD, file.read_text())
        self.assertIn('***', path.read_text())

    def test_existing_example_is_accepted_and_multiple_changes_share_one_device(self):
        path = Path(__file__).resolve().parents[1] / 'examples' / 'sample-report-simulated.json'
        self.old = json.loads(path.read_text())
        self.new = copy.deepcopy(self.old)
        self.assertEqual(self.cli()[0], 0)
        self.new['devices'][0].update(level='PARTIAL', channel_count=99)
        self.assertEqual(len(self.diff()['changed']), 1)
        self.assertEqual(len(self.diff()['changed'][0]['changes']), 2)
