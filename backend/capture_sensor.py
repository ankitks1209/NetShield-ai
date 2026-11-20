"""Run a bounded Zeek sensor observation and write an aggregate verification report.

Run with the capture privileges required by your OS. Never prompts for or stores
passwords. Raw packet payloads are not saved; ordinary Zeek protocol logs may
contain sensitive network metadata and remain in the local output directory.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

from sensor_audit import audit


def capture(interface, duration, output, executable=None):
    executable = executable or shutil.which('zeek')
    if not executable: raise RuntimeError('Zeek executable is not installed or not on PATH')
    output = Path(output).absolute()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()): raise RuntimeError('Use an empty output directory to preserve existing sensor logs')
    policy = Path(__file__).resolve().parents[1] / 'sensor/netshield.zeek'
    started = datetime.now(timezone.utc).isoformat()
    command = [str(executable), '-i', interface, str(policy)]
    stopped = False
    start = time.monotonic()
    with (output / 'zeek.stderr').open('w') as errors, (output / 'zeek.stdout').open('w') as stdout:
        process = subprocess.Popen(command, cwd=output, stdout=stdout, stderr=errors, start_new_session=True)
        try:
            deadline = start + duration
            while process.poll() is None and time.monotonic() < deadline:
                time.sleep(min(.2, max(0, deadline - time.monotonic())))
            stopped = process.poll() is None
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                    raise RuntimeError('Zeek did not flush and exit cleanly after the observation')
        elapsed = time.monotonic() - start
    if not stopped:
        raise RuntimeError(f'Zeek exited before the observation finished (code {process.returncode}); inspect {output / "zeek.stderr"}')
    result = audit(output, duration=30, from_start=True, poll_seconds=.01, until_idle=True)
    complete = result['unread_bytes']['conn'] == 0
    complete &= all(value == 0 for value in result['unread_bytes'].values() if value is not None)
    complete &= all(value == 0 for value in result['incomplete_line_bytes'].values())
    result['log_scan_complete'] = complete
    result.update(capture_started_at=started, capture_duration_seconds=round(elapsed, 3),
                  interface=interface, zeek_exit_code=process.returncode,
                  zeek_version=subprocess.run([str(executable), '--version'], capture_output=True, text=True, check=True).stdout.strip())
    result['flow_records_per_second'] = round(result['counts'].get('flow_records', 0) / elapsed, 3)
    result['scope'] = 'Bounded live Zeek observation; logs flushed at shutdown; zero drops do not establish lossless capture'
    report = output / 'sensor-report.json'
    report.write_text(json.dumps(result, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True, help='Actual authorized capture interface, e.g. en0 or eth0')
    parser.add_argument('--duration', type=float, default=60)
    parser.add_argument('--zeek', type=Path, help='Explicit Zeek executable, useful when sudo resets PATH')
    parser.add_argument('--output', type=Path, required=True, help='New or empty local log directory')
    args = parser.parse_args()
    if not 30 <= args.duration <= 3600: parser.error('duration must be between 30 and 3600 seconds')
    try: report = capture(args.interface, args.duration, args.output, args.zeek)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc: raise SystemExit(str(exc))
    print(f'Capture finished. Aggregate report: {report}')


if __name__ == '__main__': main()
