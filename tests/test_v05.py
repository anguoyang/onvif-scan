"""v0.5 imaging / events / recording inventory (all read-only Get*).

Imaging is per video source; events are declarations only (no subscription
is ever created); recording parsers expose counts and states, never tokens.
"""
import csv
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from onvifscan import parse as P
from onvifscan.report import build_report, render_html, write_csv
from onvifscan.scan import TIMG, _imaging_body
from sim_device import (PASSWORD, event_properties_response, fault,
                        imaging_options_response, imaging_settings_response,
                        recording_jobs_response, recording_summary_response)
from test_step234 import SimCase

SETTINGS_XML = imaging_settings_response({})
OPTIONS_XML = imaging_options_response({})
EVENTS_XML = event_properties_response({})
JOBS_XML = recording_jobs_response({})
SUMMARY_XML = recording_summary_response({})


class TestImagingParse(unittest.TestCase):
    def test_settings_full(self):
        data, malformed = P.parse_imaging_settings(SETTINGS_XML)
        self.assertFalse(malformed)
        self.assertEqual(data, {
            "brightness": 50.0, "color_saturation": 60.0, "contrast": 55.0,
            "sharpness": 40.0, "exposure_mode": "AUTO",
            "white_balance_mode": "AUTO",
            "backlight_compensation_mode": "OFF",
            "wide_dynamic_range_mode": "OFF", "ir_cut_filter": "AUTO",
            "auto_focus_mode": "AUTO"})

    def test_settings_partial_and_empty(self):
        data, _ = P.parse_imaging_settings(
            '<GetImagingSettingsResponse><ImagingSettings>'
            '<Brightness>12.5</Brightness></ImagingSettings>'
            '</GetImagingSettingsResponse>')
        self.assertEqual(data, {"brightness": 12.5})
        data, _ = P.parse_imaging_settings(
            '<GetImagingSettingsResponse><ImagingSettings/></GetImagingSettingsResponse>')
        self.assertIsNone(data)

    def test_settings_missing_or_broken(self):
        for xml in ('<Other/>', '<broken'):
            data, malformed = P.parse_imaging_settings(xml)
            self.assertIsNone(data)
            self.assertTrue(malformed)

    def test_options_ranges(self):
        data, malformed = P.parse_imaging_options(OPTIONS_XML)
        self.assertFalse(malformed)
        self.assertEqual(data, {
            "brightness": {"min": 0.0, "max": 100.0},
            "color_saturation": {"min": 0.0, "max": 100.0},
            "contrast": {"min": 0.0, "max": 100.0},
            "sharpness": {"min": 0.0, "max": 100.0}})

    def test_options_empty_or_missing(self):
        data, _ = P.parse_imaging_options(
            '<GetOptionsResponse><Options/></GetOptionsResponse>')
        self.assertIsNone(data)
        data, malformed = P.parse_imaging_options('<Other/>')
        self.assertIsNone(data)
        self.assertTrue(malformed)


class TestEventsRecordingParse(unittest.TestCase):
    def test_event_properties(self):
        data, malformed = P.parse_event_properties(EVENTS_XML)
        self.assertFalse(malformed)
        self.assertEqual(data["topic_namespaces"],
                         ["http://www.onvif.org/ver10/topics",
                          "http://example.invalid/vendor/topics"])
        self.assertIs(data["fixed_topic_set"], False)
        self.assertEqual(data["topics"], ["Device", "VideoAnalytics"])

    def test_event_properties_empty_or_missing(self):
        data, _ = P.parse_event_properties('<GetEventPropertiesResponse/>')
        self.assertIsNone(data)
        data, malformed = P.parse_event_properties('<Other/>')
        self.assertIsNone(data)
        self.assertTrue(malformed)

    def test_recording_jobs_counts_states_and_no_tokens(self):
        data, malformed = P.parse_recording_jobs(JOBS_XML)
        self.assertFalse(malformed)
        self.assertEqual(data, {"job_count": 1, "states": ["Recording"]})
        self.assertNotIn("REC_1", str(data))
        self.assertNotIn("SCHED_1", str(data))

    def test_recording_jobs_empty_is_valid_zero(self):
        data, _ = P.parse_recording_jobs('<GetRecordingJobsResponse/>')
        self.assertEqual(data, {"job_count": 0, "states": []})
        data, malformed = P.parse_recording_jobs('<Other/>')
        self.assertIsNone(data)
        self.assertTrue(malformed)

    def test_recording_summary(self):
        data, malformed = P.parse_recording_summary(SUMMARY_XML)
        self.assertFalse(malformed)
        self.assertEqual(data, {
            "data_from": "2026-01-01T00:00:00Z",
            "data_until": "2026-01-02T00:00:00Z",
            "number_recordings": 3, "number_recordings_failed": 1})

    def test_recording_summary_partial_and_missing(self):
        data, _ = P.parse_recording_summary(
            '<GetRecordingSummaryResponse><Summary>'
            '<NumberRecordings>7</NumberRecordings></Summary>'
            '</GetRecordingSummaryResponse>')
        self.assertEqual(data, {"number_recordings": 7})
        data, malformed = P.parse_recording_summary('<broken')
        self.assertIsNone(data)
        self.assertTrue(malformed)


class TestRoutingAndBodies(unittest.TestCase):
    def test_services_routes_search_replay_recording(self):
        xml = ('<GetServicesResponse>'
               '<Service><Namespace>http://www.onvif.org/ver10/search/wsdl</Namespace>'
               '<XAddr>http://192.0.2.1/onvif/Search</XAddr></Service>'
               '<Service><Namespace>http://www.onvif.org/ver10/replay/wsdl</Namespace>'
               '<XAddr>http://192.0.2.1/onvif/Replay</XAddr></Service>'
               '<Service><Namespace>http://www.onvif.org/ver10/recording/wsdl</Namespace>'
               '<XAddr>http://192.0.2.1/onvif/Recording</XAddr></Service>'
               '</GetServicesResponse>')
        routes, declared, malformed = P.parse_services(xml)
        self.assertFalse(malformed)
        self.assertEqual(routes, {"search": "http://192.0.2.1/onvif/Search",
                                  "replay": "http://192.0.2.1/onvif/Replay",
                                  "recording": "http://192.0.2.1/onvif/Recording"})
        self.assertEqual(len(declared), 3)

    def test_imaging_body_shape_and_escaping(self):
        for operation in ("GetImagingSettings", "GetOptions"):
            root = ET.fromstring(_imaging_body(operation, 'x<&'))
            self.assertEqual(root.tag, '{%s}%s' % (TIMG, operation))
            self.assertEqual([c.tag for c in root],
                             ['{%s}VideoSourceToken' % TIMG])
            self.assertEqual(root[0].text, 'x<&')
            self.assertEqual(len(root[0]), 0)


class TestScanV05(SimCase):
    def test_standard_all_sections_ok(self):
        p, entry = self.start('standard')
        rec = self.scan(entry)
        self.assertEqual(rec['level'], 'FULL')
        for key in ('imaging', 'search', 'recording'):
            self.assertIn(key, rec['services'])
            self.assertEqual(rec['service_sources'][key], 'GetServices')
        imaging = rec['imaging']
        self.assertEqual(imaging['status'], 'ok')
        self.assertIsNone(imaging['reason'])
        self.assertEqual([s['source_token'] for s in imaging['sources']],
                         ['Sensor_1', 'Sensor_2'])
        for source in imaging['sources']:
            self.assertEqual(source['settings']['status'], 'ok')
            self.assertEqual(source['settings']['data']['brightness'], 50.0)
            self.assertEqual(source['settings']['data']['exposure_mode'], 'AUTO')
            self.assertEqual(source['settings']['data']['ir_cut_filter'], 'AUTO')
            self.assertEqual(source['options']['status'], 'ok')
            self.assertEqual(source['options']['data']['brightness'],
                             {'min': 0.0, 'max': 100.0})
        events = rec['events']
        self.assertEqual(events['status'], 'ok')
        self.assertEqual(events['data']['topics'], ['Device', 'VideoAnalytics'])
        self.assertIs(events['data']['fixed_topic_set'], False)
        self.assertEqual(len(events['data']['topic_namespaces']), 2)
        self.assertEqual(rec['recording']['jobs']['status'], 'ok')
        self.assertEqual(rec['recording']['jobs']['data'],
                         {'job_count': 1, 'states': ['Recording']})
        self.assertEqual(rec['recording']['summary']['status'], 'ok')
        self.assertEqual(rec['recording']['summary']['data']['number_recordings'], 3)
        # No subscription-style operation was ever sent (read-only red line).
        operations = {c['operation'] for c in p['calls']}
        self.assertNotIn('CreatePullPointSubscription', operations)
        self.assertNotIn('Subscribe', operations)
        # Neither the password nor any job/recording token reaches the record.
        blob = json.dumps(rec)
        self.assertNotIn(PASSWORD, blob)
        self.assertNotIn('REC_1', blob)
        self.assertNotIn('SCHED_1', blob)

    def test_legacy_partial_coverage(self):
        _, entry = self.start('legacy')
        rec = self.scan(entry)
        self.assertEqual(rec['level'], 'FULL')
        self.assertEqual(rec['imaging']['status'], 'ok')
        self.assertEqual([s['source_token'] for s in rec['imaging']['sources']],
                         ['Sensor_1'])
        self.assertEqual(rec['events']['status'], 'unsupported')
        self.assertIsNone(rec['events']['data'])
        self.assertEqual(rec['recording']['jobs']['status'], 'unqueried')
        self.assertEqual(rec['recording']['summary']['status'], 'unqueried')

    def test_strict_no_routes_all_unqueried(self):
        p, entry = self.start('strict')
        rec = self.scan(entry)
        self.assertEqual(rec['level'], 'FULL')
        self.assertEqual(rec['imaging'],
                         {'status': 'unqueried', 'reason': 'no imaging service route',
                          'sources': []})
        self.assertEqual(rec['events']['status'], 'unqueried')
        self.assertEqual(rec['recording']['jobs']['status'], 'unqueried')
        self.assertEqual(rec['recording']['summary']['status'], 'unqueried')
        operations = {c['operation'] for c in p['calls']}
        for operation in ('GetImagingSettings', 'GetOptions', 'GetEventProperties',
                          'GetRecordingJobs', 'GetRecordingSummary'):
            self.assertNotIn(operation, operations)

    def test_imaging_rejection_blocks_all_later_sections(self):
        p, entry = self.start('standard', reject_at='GetImagingSettings')
        rec = self.scan(entry)
        self.assertEqual(rec['imaging']['status'], 'auth_blocked')
        self.assertEqual(rec['events']['status'], 'auth_blocked')
        self.assertEqual(rec['recording']['jobs']['status'], 'auth_blocked')
        self.assertEqual(rec['recording']['summary']['status'], 'auth_blocked')
        calls = p['calls']
        rejected = next(i for i, c in enumerate(calls)
                        if c['operation'] == 'GetImagingSettings' and c['credentialed'])
        self.assertFalse(any(c['credentialed'] for c in calls[rejected + 1:]), calls)

    def test_options_unsupported_is_partial_coverage(self):
        _, entry = self.start(
            'standard', responses={'GetOptions': (400, fault(
                'unsupported', 'ActionNotSupported'))})
        rec = self.scan(entry)
        self.assertEqual(rec['imaging']['status'], 'ok')
        self.assertEqual(rec['imaging']['reason'], 'partial coverage: unsupported')
        for source in rec['imaging']['sources']:
            self.assertEqual(source['settings']['status'], 'ok')
            self.assertEqual(source['options']['status'], 'unsupported')


class TestReportV05(SimCase):
    def scan_standard(self):
        _, entry = self.start('standard')
        return build_report('test', {}, [self.scan(entry)], 0)

    def test_csv_new_columns(self):
        report = self.scan_standard()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'out.csv'
            write_csv(report, path)
            with path.open(encoding='utf-8-sig', newline='') as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row['event_topic_count'], '2')
            self.assertEqual(row['recording_count'], '3')

    def test_html_sections_both_languages(self):
        report = self.scan_standard()
        html = render_html(report)
        for text in ('<h4>Imaging</h4>', '<h4>Events</h4>', '<h4>Recording</h4>',
                     'VideoAnalytics', 'Recording jobs: 1', 'Recording'):
            self.assertIn(text, html)
        self.assertNotIn(PASSWORD, html)
        html_zh = render_html(report, lang='zh-CN')
        for text in ('成像设置 (Imaging)', '事件能力 (Events)', '录像盘点 (Recording)'):
            self.assertIn(text, html_zh)
        self.assertEqual(report['schema'], 1)


if __name__ == '__main__':
    unittest.main()
