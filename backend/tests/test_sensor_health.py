import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# Use the same isolated configuration as the route regressions, never private .env data.
import test_regressions as fixtures
from sensor_health import SensorHealth, normalize_health, parser_for
from zeek_reader import ZeekLogReader, ZeekParseError


def stats(**overrides):
    return {'ts': datetime.now(timezone.utc).timestamp(), 'peer': 'standalone', 'pkts_proc': 100,
            'pkts_dropped': 0, 'pkts_link': 100, 'bytes_recv': 4000, 'mem': 50, **overrides}


def loss(**overrides):
    return {'ts': datetime.now(timezone.utc).timestamp(), 'peer': 'standalone', 'ts_delta': 30,
            'acks': 200, 'gaps': 1, 'percent_lost': 0.5, **overrides}


class SensorHealthTests(unittest.TestCase):
    def measured(self, kind, raw):
        health = SensorHealth()
        health.ingest(kind, normalize_health(raw, kind))
        health.logs[kind]['status'] = 'following'
        return health

    def test_packet_drop_counts_are_last_interval_not_cumulative(self):
        health = self.measured('stats', stats(pkts_dropped=3))
        health.ingest('stats', normalize_health(stats(pkts_dropped=1), 'stats'))
        result = health.snapshot()
        sample = result['logs']['stats']['peers']['standalone']
        self.assertEqual(sample['packets_dropped'], 1)
        self.assertEqual(sample['counter_scope'], 'last Zeek reporting interval')
        self.assertEqual(result['status'], 'loss_observed')

    def test_zero_drop_counter_does_not_claim_lossless_network(self):
        health = self.measured('stats', stats())
        self.assertEqual(health.snapshot()['status'], 'no_local_drops_reported')
        self.assertEqual(health.snapshot()['logs']['capture_loss']['status'], 'waiting_for_log')

    def test_missing_drop_counter_remains_unmeasured(self):
        health = self.measured('stats', stats(pkts_dropped=None))
        self.assertEqual(health.snapshot()['status'], 'unmeasured')
        self.assertIsNone(health.snapshot()['logs']['stats']['peers']['standalone']['packets_dropped'])

    def test_tcp_gap_percent_is_already_a_percentage(self):
        health = self.measured('capture_loss', loss())
        self.assertEqual(health.snapshot()['logs']['capture_loss']['peers']['standalone']['tcp_gap_percent'], 0.5)
        self.assertEqual(health.snapshot()['status'], 'loss_observed')

    def test_no_acks_is_insufficient_evidence(self):
        sample = normalize_health(loss(acks=0, gaps=0, percent_lost=0), 'capture_loss')
        self.assertIsNone(sample['tcp_gap_percent'])
        self.assertEqual(sample['evidence'], 'insufficient_tcp_acks')

    def test_stale_zero_drops_does_not_look_healthy(self):
        health = self.measured('stats', stats(ts=(datetime.now(timezone.utc)-timedelta(hours=1)).timestamp()))
        result = health.snapshot()
        self.assertEqual(result['status'], 'telemetry_unavailable')
        self.assertEqual(result['logs']['stats']['status'], 'stale')

    def test_clock_skew_and_malformed_lines_degrade_health(self):
        health = self.measured('stats', stats(ts=(datetime.now(timezone.utc)+timedelta(minutes=1)).timestamp()))
        self.assertEqual(health.snapshot()['logs']['stats']['status'], 'clock_skew')
        self.assertEqual(health.snapshot()['status'], 'degraded')
        health = self.measured('stats', stats())
        health.logs['stats']['malformed_lines'] = 1
        self.assertEqual(health.snapshot()['status'], 'degraded')

    def test_stats_json_and_tsv_agree_including_negative_clock_lag(self):
        raw = stats(pkt_lag=-0.25)
        fields = list(raw)
        kinds = ['time' if key == 'ts' else 'string' if key == 'peer' else 'interval' if key == 'pkt_lag' else 'count' for key in fields]
        parser = parser_for('stats')()
        for header in ['#separator \\x09', '#path\tstats', '#fields\t' + '\t'.join(fields), '#types\t' + '\t'.join(kinds)]:
            parser.parse(header)
        self.assertEqual(parser.parse('\t'.join(str(raw[key]) for key in fields)), parser_for('stats')().parse(json.dumps(raw)))

    def test_wrong_log_and_invalid_counters_are_rejected(self):
        with self.assertRaises(ZeekParseError): parser_for('stats')().parse('#path\tconn')
        for record in [stats(pkts_dropped=-1), stats(pkts_proc=None), stats(pkt_lag=float('inf')),
                       stats(peer=''), stats(pkts_proc=True)]:
            with self.assertRaises(ZeekParseError): normalize_health(record, 'stats')
        with self.assertRaises(ZeekParseError): normalize_health(loss(percent_lost=50), 'capture_loss')

    def test_old_peer_measurement_cannot_overwrite_new_measurement(self):
        health = self.measured('stats', stats(pkts_dropped=1))
        health.ingest('stats', normalize_health(stats(ts=100, pkts_dropped=0), 'stats'))
        self.assertEqual(health.snapshot()['status'], 'loss_observed')

    def test_multiple_peers_are_bounded_and_snapshots_do_not_mutate_state(self):
        health = SensorHealth()
        for index in range(70): health.ingest('stats', normalize_health(stats(peer=f'peer-{index}'), 'stats'))
        self.assertEqual(len(health.logs['stats']['peers']), 64)
        before = deepcopy(health.logs)
        health.snapshot()
        self.assertEqual(before, health.logs)

    def test_health_checkpoints_restore_samples_after_restart(self):
        async def exercise():
            collection = fixtures.Collection()
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory, 'stats.log'); path.write_text(json.dumps(stats()) + '\n')
                configured = fixtures.replace(fixtures.traffic.settings, zeek_log=Path(directory, 'conn.log'))
                async def wait_saved():
                    while not collection.docs: await asyncio.sleep(.01)
                first = SensorHealth(configured, collection)
                task = asyncio.create_task(first.follow('stats'))
                await asyncio.wait_for(wait_saved(), 2)
                task.cancel(); await asyncio.gather(task, return_exceptions=True)
                resumed = SensorHealth(configured, collection)
                task = asyncio.create_task(resumed.follow('stats'))
                for _ in range(100):
                    if resumed.logs['stats']['peers']: break
                    await asyncio.sleep(.01)
                task.cancel(); await asyncio.gather(task, return_exceptions=True)
                self.assertIn('standalone', resumed.logs['stats']['peers'])
                self.assertEqual(len(collection.docs), 1)
        asyncio.run(exercise())
