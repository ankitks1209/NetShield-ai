"""Sustained fixture traffic validates reader behavior, not NIC capture capacity."""
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sensor_audit import audit
from test_zeek_reader import record


class SustainedSensorTests(unittest.TestCase):
    def test_fragmented_writes_rotation_and_health_during_sustained_ingestion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'conn.log'; path.touch()
            ready = threading.Event()
            result = {}
            error = []
            def observe():
                try:
                    ready.set()
                    result.update(audit(root, duration=3, from_start=True, poll_seconds=.005))
                except Exception as exc: error.append(exc)
            thread = threading.Thread(target=observe)
            thread.start(); ready.wait()
            total = 2000
            for batch in range(20):
                if batch == 10:
                    path.rename(root / 'conn.1.log')
                with path.open('ab', buffering=0) as handle:
                    payload = ''.join(json.dumps(record(f'flow-{batch * 100 + i}')) + '\n' for i in range(100)).encode()
                    split = len(payload) // 2 + 13
                    handle.write(payload[:split]); time.sleep(.005); handle.write(payload[split:])
                now = time.time()
                with (root / 'stats.log').open('a') as handle:
                    handle.write(json.dumps({'ts': now, 'peer': 'fixture', 'pkts_proc': 200,
                                             'pkts_dropped': 0, 'pkts_link': 200}) + '\n')
                with (root / 'capture_loss.log').open('a') as handle:
                    handle.write(json.dumps({'ts': now, 'peer': 'fixture', 'acks': 0, 'gaps': 0,
                                             'percent_lost': 0, 'ts_delta': .05}) + '\n')
                time.sleep(.02)
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(error, [])
            self.assertEqual(result['counts']['flow_records'], total)
            self.assertEqual(result['counts'].get('duplicate_records', 0), 0)
            self.assertEqual(result['counts']['originator_packets'], total * 3)
            self.assertEqual(result['counts']['responder_packets'], total * 4)
            self.assertEqual(result['counts']['stats_packets_processed_interval_sum'], 4000)
            self.assertEqual(result['counts']['stats_packets_dropped_interval_sum'], 0)
            self.assertEqual(result['capture_health']['status'], 'no_local_drops_reported')
            self.assertEqual(result['capture_health']['logs']['capture_loss']['peers']['fixture']['evidence'], 'insufficient_tcp_acks')

    def test_tail_only_audit_excludes_preexisting_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'conn.log').write_text(json.dumps(record()) + '\n')
            result = audit(root, .03, from_start=False, poll_seconds=.005)
            self.assertEqual(result['counts'].get('flow_records', 0), 0)
