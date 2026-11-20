import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capture_sensor import capture
from test_zeek_reader import record


class BoundedCaptureTests(unittest.TestCase):
    def test_existing_sensor_logs_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'conn.log').write_text('existing records')
            with self.assertRaisesRegex(RuntimeError, 'empty output'):
                capture('fixture', .1, path, executable=sys.executable)
            self.assertEqual((path / 'conn.log').read_text(), 'existing records')

    def test_capture_permission_failure_does_not_produce_success_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / 'no-permission'
            executable.write_text('#!/bin/sh\necho "permission denied" >&2\nexit 1\n')
            executable.chmod(0o700)
            with self.assertRaisesRegex(RuntimeError, 'exited before'):
                capture('fixture', 1, root / 'output', executable)
            self.assertFalse((root / 'output/sensor-report.json').exists())

    def test_bounded_shutdown_flushes_final_records_before_reporting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / 'fixture-sensor'
            executable.write_text(f'''#!{sys.executable}
import json,signal,sys,time
from pathlib import Path
if '--version' in sys.argv:
    print('fixture sensor, not Zeek')
    sys.exit(0)
def finish(*args):
    Path('conn.log').write_text(json.dumps({record()!r})+'\\n')
    sys.exit(0)
signal.signal(signal.SIGTERM,finish)
while True: time.sleep(.01)
''')
            executable.chmod(0o700)
            report = capture('fixture', 1, root / 'output', executable)
            data = json.loads(report.read_text())
            self.assertTrue(data['log_scan_complete'])
            self.assertEqual(data['counts']['flow_records'], 1)
            self.assertEqual(data['interface'], 'fixture')
            self.assertTrue(data['completed_requested_duration'])
            self.assertFalse(data['interrupted'])
            self.assertNotIn('192.0.2.1', report.read_text())

    def test_ctrl_c_flushes_sensor_and_saves_explicit_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / 'fixture-sensor'
            executable.write_text(f'''#!{sys.executable}
import json,signal,sys,time
from pathlib import Path
if '--version' in sys.argv:
    print('fixture sensor, not Zeek')
    sys.exit(0)
def finish(*args):
    Path('conn.log').write_text(json.dumps({record()!r})+'\\n')
    sys.exit(0)
signal.signal(signal.SIGTERM,finish)
Path('.sensor-ready').touch()
while True: time.sleep(.01)
''')
            executable.chmod(0o700)
            output = root / 'output'
            original_sleep = time.sleep
            did_interrupt = False
            def interrupt_once(seconds):
                nonlocal did_interrupt
                if did_interrupt:
                    return original_sleep(seconds)
                deadline = time.monotonic() + 3
                while not (output / '.sensor-ready').exists():
                    if time.monotonic() > deadline: raise RuntimeError('Fixture sensor failed to start')
                    original_sleep(.01)
                did_interrupt = True
                raise KeyboardInterrupt()
            messages = []
            with patch('capture_sensor.time.sleep', side_effect=interrupt_once):
                report = capture('fixture', 60, output, executable,
                                 progress=lambda message, **kwargs: messages.append(message))
            data = json.loads(report.read_text())
            self.assertTrue(data['interrupted'])
            self.assertFalse(data['completed_requested_duration'])
            self.assertEqual(data['requested_capture_seconds'], 60)
            self.assertLess(data['capture_duration_seconds'], 60)
            self.assertEqual(data['counts']['flow_records'], 1)
            self.assertTrue(data['log_scan_complete'])
            self.assertTrue(any('automatically' in message for message in messages))
            self.assertTrue(any('partial report' in message for message in messages))
