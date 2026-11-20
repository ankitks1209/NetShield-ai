"""Read-only bounded sensor observation; no database credentials are required.

Reports contain aggregate counters and health only, never addresses or payloads.
Start offset is explicit: --from-start includes existing log history.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time

from sensor_health import SensorHealth, parser_for
from zeek_reader import ZeekLogReader


def audit(directory, duration, from_start=False, poll_seconds=.1, until_idle=False):
    directory = Path(directory)
    health = SensorHealth()
    readers = {'conn': ZeekLogReader(directory / 'conn.log')}
    readers.update({kind: ZeekLogReader(directory / f'{kind}.log', parser_factory=parser_for(kind))
                    for kind in ['stats', 'capture_loss']})
    counts = Counter()
    protocols = Counter()
    duplicate_ids = set()
    health_ids = set()
    started = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    initial_sizes = {kind: reader.path.stat().st_size if reader.path.exists() else 0 for kind, reader in readers.items()}
    first_identity = {}
    # Parse existing TSV headers so tail-only mode still has a valid schema.
    try:
        while time.monotonic() - start < duration:
            had_events = False
            for kind, reader in readers.items():
                events = reader.poll()
                had_events |= bool(events)
                if reader.identity and kind not in first_identity: first_identity[kind] = reader.identity
                if kind != 'conn': health.logs[kind]['status'] = reader.state
                for event in events:
                    historical = (not from_start and tuple(event.cursor['identity']) == first_identity[kind]
                                  and event.cursor['offset'] <= initial_sizes[kind])
                    if historical: continue
                    if event.kind == 'error':
                        counts[f'{kind}_malformed'] += 1
                        if kind != 'conn': health.logs[kind]['malformed_lines'] += 1
                        continue
                    if event.kind != 'flow': continue
                    if kind != 'conn':
                        identity = (kind, event.flow['peer'], event.flow['timestamp'])
                        if identity in health_ids:
                            counts[f'{kind}_duplicate_measurements'] += 1
                            continue
                        health_ids.add(identity)
                        if len(health_ids) > 1000000: raise RuntimeError('Audit exceeded its health measurement bound')
                        health.ingest(kind, event.flow)
                        counts[f'{kind}_measurements'] += 1
                        if kind == 'stats':
                            for field in ['packets_processed', 'packets_dropped', 'packets_seen_on_link']:
                                value = event.flow[field]
                                if value is None: counts[f'stats_{field}_unmeasured_intervals'] += 1
                                else: counts[f'stats_{field}_interval_sum'] += value
                        continue
                    flow = event.flow
                    identity = (flow['uid'], flow['event_time'])
                    if identity in duplicate_ids: counts['duplicate_records'] += 1
                    else: duplicate_ids.add(identity)
                    if len(duplicate_ids) > 1000000:
                        raise RuntimeError('Audit exceeded its one-million-flow bound; shorten the observation')
                    counts['flow_records'] += 1
                    protocols[flow['Protocol']] += 1
                    for field, counter in [('Fwd Packets', 'originator_packets'), ('Bwd Packets', 'responder_packets'),
                                           ('Fwd Bytes', 'originator_payload_bytes'), ('Bwd Bytes', 'responder_payload_bytes'),
                                           ('missed_bytes', 'reported_missed_bytes')]:
                        value = flow[field]
                        if value is None: counts[f'{counter}_unknown_flows'] += 1
                        else: counts[counter] += value
            if not had_events:
                if until_idle: break
                time.sleep(poll_seconds)
        elapsed = time.monotonic() - start
        health_snapshot = health.snapshot()
        return {
            'started_at': started, 'duration_seconds': round(elapsed, 3),
            'includes_existing_history': from_start, 'counts': dict(counts), 'protocols': dict(protocols),
            'flow_records_per_second': round(counts['flow_records'] / elapsed, 3),
            'capture_health': health_snapshot,
            'reader_states': {kind: reader.state for kind, reader in readers.items()},
            'incomplete_line_bytes': {kind: len(reader.pending) for kind, reader in readers.items()},
            'unread_bytes': {kind: max(0, os.fstat(reader.handle.fileno()).st_size - reader.handle.tell()) if reader.handle else None
                             for kind, reader in readers.items()},
            'scope': 'Log ingestion observation; flow count is not a packet count or a held-out detection score',
        }
    finally:
        for reader in readers.values(): reader.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log-dir', type=Path, required=True)
    parser.add_argument('--duration', type=float, default=60)
    parser.add_argument('--from-start', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not 0 < args.duration <= 3600: parser.error('duration must be in (0, 3600] seconds')
    result = audit(args.log_dir, args.duration, args.from_start)
    content = json.dumps(result, indent=2)
    if args.output: args.output.write_text(content + '\n')
    print(content)


if __name__ == '__main__': main()
